#!/usr/bin/env bash
# Phase B5 — security hardening sweep (Stage B PRD §5 B5 steps 6–9, 12). Read-only.
#
#   6. gitleaks across the repository
#   7. pod logs searched for secret-shaped material
#   8. pod security context uniform and enforced on all four
#   9. each ServiceAccount maps to exactly one Vault role; no wildcards
#  12. resource requests and limits on all four
#   +  every Deployment names its serviceAccountName explicitly
#
# Optional env:  VAULT_ADDR, VAULT_CACERT, VAULT_TOKEN — step 9 reads the role
#                definitions and needs a token with `read` on
#                auth/kubernetes/role/*. Without one, step 9 is SKIPPED (and a
#                skip is a failed gate, not a pass).
source "$(dirname "$0")/lib.sh"

require_cmd kubectl jq git
require_lab_cluster
start_results hardening-sweep "Phase B5 — hardening sweep"

# Patterns are assembled from pieces so that THIS file does not match them —
# a sweep that flags its own source is noise (see troubleshooting.md: "keep the
# literal out of the prose it is checking").
TLS_BYPASS_PATTERNS=(
  "Insecure""SkipVerify[[:space:]]*[:=][[:space:]]*true"
  "-tls-skip""-verify"
  "curl[^|]*[[:space:]](-k|--insec""ure)([[:space:]]|$)"
)

# Secret-shaped strings in logs. Matching lines are NEVER printed — only the pod,
# the pattern's name, and how many lines matched. Printing the line would put
# the secret this sweep just found into the terminal and the results file.
declare -A LOG_PATTERNS=(
  ["PGP private key block"]="BEGIN PGP PRIVATE ""KEY BLOCK"
  ["Vault service token"]="hvs\\.[A-Za-z0-9_-]{20,}"
  ["Vault batch token"]="hvb\\.[A-Za-z0-9_-]{20,}"
  ["Vault recovery token"]="hvr\\.[A-Za-z0-9_-]{20,}"
  ["Postgres DSN with password"]="postgres(ql)?://[^:/@[:space:]]+:[^@[:space:]]+@"
  ["passphrase assignment"]="pass""phrase\"?[[:space:]]*[:=][[:space:]]*\"?[^\"[:space:],}]{4,}"
  ["password assignment"]="\"pass""word\"[[:space:]]*:[[:space:]]*\"[^\"]{4,}\""
)

# ---------------------------------------------------------------------------
section "Step 6 — gitleaks"
if command -v gitleaks >/dev/null 2>&1; then
  # --redact: if it does find something, the report must not reprint it.
  if gitleaks detect --source "$REPO_ROOT" --no-banner --redact >/dev/null 2>&1; then
    pass "gitleaks: no leaks in the repository history"
  else
    fail "gitleaks reported findings — run: gitleaks detect --source . --redact -v"
  fi
else
  skip "gitleaks not installed — this gate is not met until it runs"
fi

section "TLS bypass anywhere in the repository"
for p in "${TLS_BYPASS_PATTERNS[@]}"; do
  # -e, not --: one pattern starts with '-' and would otherwise parse as an option.
  hits="$(git -C "$REPO_ROOT" grep -nIE -e "$p" -- applications argocd ':!*.md' 2>/dev/null || true)"
  if [[ -z "$hits" ]]; then
    pass "no match for /$p/"
  else
    fail "TLS bypass pattern /$p/ found: $(echo "$hits" | cut -d: -f1,2 | paste -sd' ' -)"
  fi
done

section "Step 7 — pod logs"
note "Level 4 prints its decrypted fixture to stdout BY DESIGN (Phase B4). That is a demo message, not key material, and the patterns below do not target it."
for lvl in "${LEVELS[@]}"; do
  logs="$(kubectl -n "$NS" logs -l "app=$lvl,!b5-probe" --all-containers --tail=-1 --prefix 2>/dev/null || true)"
  prev="$(kubectl -n "$NS" logs -l "app=$lvl,!b5-probe" --all-containers --tail=-1 --prefix --previous 2>/dev/null || true)"
  all="$logs"$'\n'"$prev"
  if [[ -z "${logs//[$'\n ']/}" ]]; then
    skip "$lvl: no logs retrieved — cannot claim the logs are clean"
    continue
  fi
  clean=true
  for name in "${!LOG_PATTERNS[@]}"; do
    n="$(grep -cE -- "${LOG_PATTERNS[$name]}" <<<"$all" || true)"
    if [[ "${n:-0}" -gt 0 ]]; then
      clean=false
      fail "$lvl: $n log line(s) match '$name' (lines not shown, deliberately)"
    fi
  done
  [[ $clean == true ]] && pass "$lvl: no secret-shaped material in current or previous container logs"
done
note "Log retention is the kubelet's rotation; this sweep covers only what is still retained."

# ---------------------------------------------------------------------------
section "Step 8 / 12 — pod security context and resources (live pods)"
for lvl in "${LEVELS[@]}"; do
  pods="$(kubectl -n "$NS" get pods -l "app=$lvl,!b5-probe" -o json 2>/dev/null || echo '{"items":[]}')"
  count="$(jq '.items | length' <<<"$pods")"
  if [[ "$count" -eq 0 ]]; then
    fail "$lvl: no running pods to inspect"
    continue
  fi
  # One verdict per check, across every container of every pod for the level.
  # Pod-level and container-level settings are both honoured, as Kubernetes does.
  report="$(jq -r '
    [ .items[] as $p | $p.spec.containers[] as $c |
      ($p.spec.securityContext // {}) as $ps | ($c.securityContext // {}) as $cs |
      {
        nonroot:  (($cs.runAsNonRoot // $ps.runAsNonRoot) == true),
        rorootfs: ($cs.readOnlyRootFilesystem == true),
        noescal:  ($cs.allowPrivilegeEscalation == false),
        dropall:  ((($cs.capabilities.drop // []) | index("ALL")) != null),
        seccomp:  ((($cs.seccompProfile.type // $ps.seccompProfile.type) // "") == "RuntimeDefault"),
        requests: (($c.resources.requests.cpu != null) and ($c.resources.requests.memory != null)),
        limits:   (($c.resources.limits.cpu != null) and ($c.resources.limits.memory != null)),
        sa:       ($p.spec.serviceAccountName // "default")
      } ]
    | {
        nonroot:  all(.[]; .nonroot),  rorootfs: all(.[]; .rorootfs),
        noescal:  all(.[]; .noescal),  dropall:  all(.[]; .dropall),
        seccomp:  all(.[]; .seccomp),  requests: all(.[]; .requests),
        limits:   all(.[]; .limits),   sas: ([.[].sa] | unique | join(","))
      } | to_entries[] | "\(.key)=\(.value)"' <<<"$pods")"

  declare -A r=()
  while IFS='=' read -r k v; do r[$k]="$v"; done <<<"$report"

  for check in nonroot:"runs as non-root" rorootfs:"read-only root filesystem" \
               noescal:"privilege escalation disabled" dropall:"capabilities drop ALL" \
               seccomp:"seccomp RuntimeDefault" requests:"cpu+memory requests set" \
               limits:"cpu+memory limits set"; do
    key="${check%%:*}" label="${check#*:}"
    [[ "${r[$key]}" == "true" ]] && pass "$lvl: $label" || fail "$lvl: NOT $label"
  done

  expected_sa="${SAS[$(printf '%s\n' "${LEVELS[@]}" | grep -nx "$lvl" | cut -d: -f1) - 1]}"
  if [[ "${r[sas]}" == "$expected_sa" ]]; then
    pass "$lvl: pods run as ServiceAccount $expected_sa"
  else
    fail "$lvl: pods run as [${r[sas]}], expected $expected_sa — 'default' here means the isolation boundary is gone"
  fi
  unset r
done

section "serviceAccountName is explicit in every Deployment (rendered manifests)"
# A live pod always shows SOME serviceAccountName — Kubernetes fills in
# `default`. Only the manifest shows whether it was set on purpose.
for lvl in "${LEVELS[@]}"; do
  if ! rendered="$(render_json "$(overlay_dir "$lvl")")"; then
    fail "$lvl: overlay did not render — cannot inspect serviceAccountName"
    continue
  fi
  sa="$(jq -r '(.items // [.])[] | select(.kind == "Deployment") | .spec.template.spec.serviceAccountName // "UNSET"' <<<"$rendered")"
  case "$sa" in
    UNSET|"") fail "$lvl: Deployment does not set serviceAccountName — it would silently run as 'default'" ;;
    default)  fail "$lvl: Deployment explicitly uses 'default'" ;;
    *)        pass "$lvl: Deployment sets serviceAccountName=$sa" ;;
  esac
done

# ---------------------------------------------------------------------------
section "Step 9 — each ServiceAccount maps to exactly one Vault role"
if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_CACERT:-}" || -z "${VAULT_TOKEN:-}" ]]; then
  skip "VAULT_ADDR / VAULT_CACERT / VAULT_TOKEN not all set — role bindings not inspected"
  finish
fi
require_vault_env
make_secret_dir
hdr="$SECRET_DIR/admin.hdr"
# printf is a shell builtin: the token is written to the file without ever
# appearing in a process's argv.
printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN" >"$hdr"

list="$SECRET_DIR/roles.json"
code="$(vault_curl LIST auth/kubernetes/role "$hdr" "" "$list")"
if [[ "$code" != "200" ]]; then
  fail "could not list auth/kubernetes/role (HTTP $code: $(vault_errors "$list")) — VAULT_TOKEN needs list+read there"
  finish
fi
mapfile -t role_names < <(jq -r '.data.keys[]' "$list")
note "roles defined: ${role_names[*]}"

declare -A BINDINGS_PER_SA=()
for role in "${role_names[@]}"; do
  def="$SECRET_DIR/role-$role.json"
  vault_curl GET "auth/kubernetes/role/$role" "$hdr" "" "$def" >/dev/null
  names="$(jq -r '(.data.bound_service_account_names // []) | join(",")' "$def")"
  nss="$(jq -r '(.data.bound_service_account_namespaces // []) | join(",")' "$def")"

  [[ ",$names," == *",*,"* ]] && fail "role $role binds service account names '*' — any SA could log in" ||
    pass "role $role: no wildcard service account ($names)"
  [[ ",$nss," == *",*,"* ]] && fail "role $role binds namespaces '*'" ||
    pass "role $role: no wildcard namespace ($nss)"

  # A role named after a policy is the `level4-pgp` confusion made permanent.
  for p in "${POLICY_NAMES[@]}"; do
    [[ "$role" == "$p" ]] && fail "role '$role' shares its name with a policy — see documents/vault-roles-and-policies.md"
  done

  if [[ ",$nss," == *",$NS,"* ]]; then
    IFS=',' read -ra ns_sas <<<"$names"
    for s in "${ns_sas[@]}"; do
      BINDINGS_PER_SA[$s]="${BINDINGS_PER_SA[$s]:+${BINDINGS_PER_SA[$s]},}$role"
    done
  fi
done

for sa in "${SAS[@]}"; do
  bound="${BINDINGS_PER_SA[$sa]:-}"
  n="$(awk -F, '{print NF}' <<<"$bound")"
  if [[ -z "$bound" ]]; then
    fail "$sa is bound to NO role in $NS (owner decision: every level SA has exactly one, including level1-app)"
  elif [[ "$n" -eq 1 && "$bound" == "${ROLE_FOR_SA[$sa]}" ]]; then
    pass "$sa -> exactly one role: $bound"
  else
    fail "$sa -> bound to [$bound]; expected exactly [${ROLE_FOR_SA[$sa]}]"
  fi
done
[[ -z "${BINDINGS_PER_SA[default]:-}" ]] && pass "'default' ServiceAccount is bound to no role" ||
  fail "'default' ServiceAccount is bound to [${BINDINGS_PER_SA[default]}] — any pod that omits serviceAccountName gets those secrets"

finish
