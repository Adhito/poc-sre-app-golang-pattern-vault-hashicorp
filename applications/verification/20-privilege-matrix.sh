#!/usr/bin/env bash
# Phase B5 — the cross-privilege matrix (Stage B PRD §5 B5 step 10). Read-only
# against Kubernetes; against Vault it logs in, reads, and revokes its own tokens.
#
# All four levels share one namespace, so the ServiceAccount name is the ONLY
# thing standing between Level 1 and the PGP private key. This script tests that
# boundary from both sides:
#
#   Part A — door check (login): every SA tries every role. Its own role must
#            admit it; every other role must refuse it FOR THE RIGHT REASON.
#   Part B — room check (read): every SA logs in through its own role and tries
#            every secret. Four allows, twelve denials.
#
# Background and the two owner decisions this encodes (level1-app has a role;
# there is no `level4-pgp` role): documents/vault-roles-and-policies.md
#
# Required env:  VAULT_ADDR (https://, the MetalLB VIP), VAULT_CACERT
# Optional env:  AUTHZ_DENY_PATTERN, INVALID_ROLE_PATTERN — see below
source "$(dirname "$0")/lib.sh"

# A refusal only counts if Vault refused for the intended reason. These are the
# Kubernetes auth plugin's messages; confirm them against the deployed version
# (the run records Vault's version and every raw message). Override if a Vault
# release rewords them — never loosen them to make a run go green.
AUTHZ_DENY_PATTERN="${AUTHZ_DENY_PATTERN:-service account name not authorized}"
INVALID_ROLE_PATTERN="${INVALID_ROLE_PATTERN:-invalid role name}"

require_cmd kubectl jq curl git
require_vault_env
make_secret_dir
start_results privilege-matrix "Phase B5 — cross-privilege matrix"

VAULT_VERSION="$(vault_version)"
md "- Vault: \`$VAULT_VERSION\` at \`$VAULT_ADDR\`"
md "- Accepted guard refusal: \`$AUTHZ_DENY_PATTERN\`"
md ""
md "**Method.** Each ServiceAccount's identity is a short-lived token minted with"
md "\`kubectl create token\`. Vault validates it through the same TokenReview path"
md "as a pod's projected token, so the identity Vault sees is identical. This"
md "replaces the PRD's throwaway pod per SA; it tests authorization, not the"
md "in-cluster network path (that is 40-networkpolicy's job)."

ROLES=("${SAS[@]}")                 # role names equal SA names
GRID_SAS=("${SAS[@]}" default)      # plus `default`, which no role may admit

# Matrix columns: label | API path | owning SA
COL_LABELS=("level1/app" "level2/app" "database/creds" "level4/pgp")
COL_PATHS=("secret/data/level1/app" "secret/data/level2/app" "database/creds/level3-app" "secret/data/level4/pgp")
COL_OWNERS=(level1-app level2-app level3-app level4-app)

# ---------------------------------------------------------------------------
# Identity and session helpers. Every secret-bearing value stays in a file.
# ---------------------------------------------------------------------------

mint_jwt() { # <sa> -> path of a 0600 file holding its JWT
  local f="$SECRET_DIR/$1.jwt"
  if kubectl -n "$NS" create token "$1" --duration=10m >"$f" 2>/dev/null && [[ -s "$f" ]]; then
    echo "$f"
  else
    return 1
  fi
}

# login <jwt-file> <role> <out-file> -> prints HTTP status
login() {
  local body="$SECRET_DIR/login-body.json"
  jq -n --rawfile jwt "$1" --arg role "$2" '{jwt: ($jwt | rtrimstr("\n")), role: $role}' >"$body"
  local code
  code="$(vault_curl POST auth/kubernetes/login "" "$body" "$3")"
  rm -f "$body"
  echo "$code"
}

# token_header <login-response> <header-file> — the token goes from one file to
# another; it is never held in a shell variable or passed as an argument.
token_header() { jq -r '"X-Vault-Token: " + .auth.client_token' "$1" >"$2"; }

# Revoking the token also revokes every lease it created — including any
# database credential an ALLOWED read produced, so no Postgres role is left behind.
revoke_self() {
  local out="$SECRET_DIR/revoke.json" code
  code="$(vault_curl POST auth/token/revoke-self "$1" "" "$out")"
  rm -f "$out" "$1"
  [[ "$code" == "204" || "$code" == "200" ]]
}

# ---------------------------------------------------------------------------
section "Mint ServiceAccount tokens"
declare -A JWT
for sa in "${GRID_SAS[@]}"; do
  if f="$(mint_jwt "$sa")"; then
    JWT[$sa]="$f"
    pass "token minted for ServiceAccount $sa (10 min)"
  else
    fail "could not mint a token for $sa — does it exist, and may you create serviceaccounts/token?"
  fi
done

# ---------------------------------------------------------------------------
section "Part A — door check: every ServiceAccount against every role"

declare -A GRID
REFUSALS=()

for sa in "${GRID_SAS[@]}"; do
  [[ -n "${JWT[$sa]:-}" ]] || { for role in "${ROLES[@]}"; do GRID[$sa,$role]="— no token"; done; continue; }
  for role in "${ROLES[@]}"; do
    out="$SECRET_DIR/login.json"
    code="$(login "${JWT[$sa]}" "$role" "$out")"

    if [[ "$sa" == "$role" ]]; then
      # Own door: must admit, with exactly the expected key ring.
      if [[ "$code" == "200" ]]; then
        want="$(printf '%s\n' default "${POLICY_FOR_ROLE[$role]}" | sort | paste -sd, -)"
        got="$(jq -r '.auth.token_policies // .auth.policies | sort | join(",")' "$out" 2>/dev/null || echo "<unreadable>")"
        hdr="$SECRET_DIR/$sa-$role.hdr"; token_header "$out" "$hdr"
        if [[ "$got" == "$want" ]]; then
          pass "$sa -> role $role: admitted with exactly [$got]"
          GRID[$sa,$role]="✅ admitted"
        else
          fail "$sa -> role $role: admitted, but policies are [$got], expected [$want]"
          GRID[$sa,$role]="❌ admitted, wrong policies"
        fi
        revoke_self "$hdr" || note "revoke-self failed for $sa/$role — token will expire on its own TTL"
      else
        msg="$(vault_errors "$out")"
        fail "$sa -> role $role: its OWN role refused it (HTTP $code: $msg)"
        GRID[$sa,$role]="❌ refused ($code)"
        REFUSALS+=("| \`$sa\` | \`$role\` | $code | $msg |")
      fi

    else
      # Someone else's door: must refuse — and the GUARD must be the one refusing.
      if [[ "$code" == "200" ]]; then
        hdr="$SECRET_DIR/$sa-$role.hdr"; token_header "$out" "$hdr"; revoke_self "$hdr" || true
        fail "$sa -> role $role: ADMITTED. A ServiceAccount logged in through another level's role — the isolation boundary is broken"
        GRID[$sa,$role]="🚨 ADMITTED"
        continue
      fi
      msg="$(vault_errors "$out")"
      REFUSALS+=("| \`$sa\` | \`$role\` | $code | $msg |")
      if grep -qiF -- "$AUTHZ_DENY_PATTERN" <<<"$msg"; then
        pass "$sa -> role $role: refused by the guard"
        GRID[$sa,$role]="👮 refused"
      elif grep -qiF -- "$INVALID_ROLE_PATTERN" <<<"$msg"; then
        # The broken-test case: refused because the door does not exist. This
        # proves nothing about the binding, so it is a failure, not a pass.
        fail "$sa -> role $role: refused because the ROLE DOES NOT EXIST — the binding was never tested"
        GRID[$sa,$role]="❌ no such role"
      elif grep -qiF -- "namespace not authorized" <<<"$msg"; then
        fail "$sa -> role $role: refused on NAMESPACE — every role should bind $NS; this role is misconfigured"
        GRID[$sa,$role]="❌ wrong namespace"
      else
        fail "$sa -> role $role: refused for an unrecognised reason (HTTP $code). Confirm the wording for Vault $VAULT_VERSION; do not loosen the pattern to pass"
        GRID[$sa,$role]="❓ unrecognised"
      fi
    fi
  done
done

md ""
md "### Login grid"
md ""
md "| ServiceAccount ↓ / Role → | $(printf '`%s` | ' "${ROLES[@]}")"
md "|---|$(printf -- '---|%.0s' "${ROLES[@]}")"
for sa in "${GRID_SAS[@]}"; do
  row="| \`$sa\` |"
  for role in "${ROLES[@]}"; do row+=" ${GRID[$sa,$role]} |"; done
  md "$row"
done
md ""
md "Expected: \`admitted\` on the diagonal, \`refused\` (by the guard) everywhere else, and \`refused\` across the whole \`default\` row."
if ((${#REFUSALS[@]} > 0)); then
  md ""
  md "<details><summary>Raw refusal messages (${#REFUSALS[@]})</summary>"
  md ""
  md "| ServiceAccount | Role | HTTP | Vault's message |"
  md "|---|---|---|---|"
  for r in "${REFUSALS[@]}"; do md "$r"; done
  md ""
  md "</details>"
fi

# ---------------------------------------------------------------------------
section "Part B — room check: every ServiceAccount, own role, every secret"

declare -A MATRIX
ALLOWS=0
DENIALS=0

for sa in "${SAS[@]}"; do
  role="${ROLE_FOR_SA[$sa]}"
  if [[ -z "${JWT[$sa]:-}" ]]; then
    for i in "${!COL_PATHS[@]}"; do MATRIX[$sa,$i]="— no token"; done
    fail "$sa: no token, row not tested"
    continue
  fi

  out="$SECRET_DIR/login.json"
  code="$(login "${JWT[$sa]}" "$role" "$out")"
  if [[ "$code" != "200" ]]; then
    for i in "${!COL_PATHS[@]}"; do MATRIX[$sa,$i]="— login failed"; done
    fail "$sa: could not log in through its own role $role (HTTP $code: $(vault_errors "$out")) — row not tested"
    continue
  fi
  hdr="$SECRET_DIR/$sa.hdr"
  token_header "$out" "$hdr"
  rm -f "$out"

  for i in "${!COL_PATHS[@]}"; do
    path="${COL_PATHS[$i]}" label="${COL_LABELS[$i]}"
    resp="$SECRET_DIR/read.json"
    code="$(vault_curl GET "$path" "$hdr" "" "$resp")"

    if [[ "$sa" == "${COL_OWNERS[$i]}" ]]; then
      # Expected ALLOW. The response holds the secret: discard it unread.
      if [[ "$code" == "200" ]]; then
        rm -f "$resp"
        ALLOWS=$((ALLOWS + 1))
        pass "$sa reads $label: allowed (200)"
        MATRIX[$sa,$i]="✅ allow"
      else
        msg="$(vault_errors "$resp")"; rm -f "$resp"
        case "$code" in
          403) hint="permission denied on its OWN secret — check the policy uses the KV v2 API path (secret/data/...), not the CLI path" ;;
          404) hint="not found — is the secret seeded (Stage A Phase A7)?" ;;
          *)   hint="$msg" ;;
        esac
        fail "$sa reads $label: expected allow, got HTTP $code — $hint"
        MATRIX[$sa,$i]="❌ $code (expected allow)"
      fi
    else
      # Expected DENY, and specifically a permission denial.
      if [[ "$code" == "200" ]]; then
        rm -f "$resp"   # a secret this SA must not have — never inspect it
        fail "$sa reads $label: ALLOWED. This ServiceAccount can read another level's secret"
        MATRIX[$sa,$i]="🚨 ALLOWED"
      else
        msg="$(vault_errors "$resp")"; rm -f "$resp"
        if [[ "$code" == "403" ]] && grep -qi "permission denied" <<<"$msg"; then
          DENIALS=$((DENIALS + 1))
          pass "$sa reads $label: denied (403 permission denied)"
          MATRIX[$sa,$i]="⛔ deny"
        else
          fail "$sa reads $label: refused, but not as a permission denial (HTTP $code: $msg)"
          MATRIX[$sa,$i]="❓ $code"
        fi
      fi
    fi
  done

  if revoke_self "$hdr"; then
    note "$sa: token revoked (and with it any lease it created)"
  else
    note "$sa: revoke-self FAILED — any database lease it created will live until its TTL"
  fi
done

md ""
md "### Read matrix"
md ""
md "| ServiceAccount ↓ / Secret → | $(printf '`%s` | ' "${COL_LABELS[@]}")"
md "|---|$(printf -- '---|%.0s' "${COL_LABELS[@]}")"
for sa in "${SAS[@]}"; do
  row="| \`$sa\` |"
  for i in "${!COL_PATHS[@]}"; do row+=" ${MATRIX[$sa,$i]} |"; done
  md "$row"
done
md ""
md "**Observed: $ALLOWS allows, $DENIALS denials.** Expected: 4 allows, 12 denials."

section "Matrix totals"
[[ $ALLOWS -eq 4 ]] && pass "4 of 4 expected allows observed" || fail "$ALLOWS of 4 expected allows observed"
[[ $DENIALS -eq 12 ]] && pass "12 of 12 expected denials observed" || fail "$DENIALS of 12 expected denials observed"
note "The level3-app row created a real database credential. Revoking its token revoked that lease; confirm with: vault list sys/leases/lookup/database/creds/level3-app"

finish
