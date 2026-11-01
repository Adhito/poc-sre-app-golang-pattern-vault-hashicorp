#!/usr/bin/env bash
# Phase B5 — NetworkPolicy verification (Stage B PRD §5 B5 step 11).
#
# Activation is a GIT change, not something this script does: uncomment
# `- networkpolicy.yaml` in each level's deploy/base/kustomization.yaml, commit,
# and let ArgoCD sync it. Applying policies by hand would be drift outside GitOps.
# Run 10-independence BEFORE activating — its endpoint checks may be refused
# once `ingress: []` is in force.
#
# This script then proves the policies do what they say:
#   1. activated in git, and no selector has been rewritten by kustomize
#   2. present in the cluster
#   3. the live labels they depend on actually exist
#   4. the four apps are still Ready (kubelet probes survive `ingress: []`)
#   5. real connection attempts from each level's network identity:
#      allowed paths connect, everything else — including level-to-level — fails
#
# Required env:  PROBE_IMAGE — a PINNED image with sh, sleep and curl, pullable by
#                the cluster (e.g. a curlimages/curl tag mirrored into the
#                registry recorded in environment.md). No default: guessing an
#                image or a tag is what CLAUDE.md rules 10 and "never hardcode
#                environment values" forbid.
source "$(dirname "$0")/lib.sh"

require_cmd kubectl jq git
start_results networkpolicy "Phase B5 — NetworkPolicy"

PG_SVC="postgres.$NS.svc"
VAULT_SVC="vault.vault.svc"

# ---------------------------------------------------------------------------
section "1a — policies activated in git"
for lvl in "${LEVELS[@]}"; do
  k="$(base_dir "$lvl")/kustomization.yaml"
  if grep -qE '^[[:space:]]*-[[:space:]]+networkpolicy\.yaml' "$k"; then
    pass "$lvl: networkpolicy.yaml is in resources"
  else
    fail "$lvl: networkpolicy.yaml is NOT active — uncomment it in deploy/base/kustomization.yaml and commit"
  fi
done

section "1b — no selector rewritten by kustomize (commonLabels regression guard)"
# commonLabels once injected our labels into the egress selectors, which would
# have denied DNS to every level and Postgres to Level 3 — silently. Any
# app.kubernetes.io/* key inside a selector means that has come back.
for lvl in "${LEVELS[@]}"; do
  if ! rendered="$(render_json "$(base_dir "$lvl")")"; then
    fail "$lvl: base did not render — selectors not audited (an empty render is not a clean one)"
    continue
  fi
  leaks="$(jq -r '
    (.items // [.])[] as $o
    | [ if $o.kind == "Deployment" then {w: "Deployment.spec.selector", m: $o.spec.selector.matchLabels} else empty end,
        if $o.kind == "Service" then {w: "Service.spec.selector", m: ($o.spec.selector // {})} else empty end,
        if $o.kind == "NetworkPolicy" then
          ({w: "NetworkPolicy.podSelector", m: $o.spec.podSelector.matchLabels},
           ($o.spec.egress // [])[].to[]? | select(.podSelector) | {w: "NetworkPolicy.egress.to.podSelector", m: .podSelector.matchLabels})
        else empty end ]
    | .[] | select(.m | keys | any(startswith("app.kubernetes.io/"))) | "\(.w) \(.m | tojson)"' <<<"$rendered")"
  if [[ -z "$leaks" ]]; then
    pass "$lvl: every selector is exactly as written"
  else
    fail "$lvl: kustomize rewrote selectors: $(echo "$leaks" | paste -sd'; ' -)"
  fi
done

# ---------------------------------------------------------------------------
section "2 — policies present in the cluster"
for lvl in "${LEVELS[@]}"; do
  if kubectl -n "$NS" get networkpolicy "$lvl" >/dev/null 2>&1; then
    pass "NetworkPolicy/$lvl exists"
  else
    fail "NetworkPolicy/$lvl not found — activated in git but not synced?"
  fi
done

section "3 — the live labels these policies depend on"
# The egress rules name pods by label. If those labels are not what the
# manifests assume, the rule matches nothing and the traffic is silently denied.
n="$( { kubectl -n kube-system get pods -l k8s-app=kube-dns -o name 2>/dev/null || true; } | wc -l)"
[[ "$n" -gt 0 ]] && pass "$n DNS pod(s) carry k8s-app=kube-dns" ||
  fail "no pod in kube-system carries k8s-app=kube-dns — the DNS egress rule matches nothing"
n="$( { kubectl -n "$NS" get pods -l app=postgres -o name 2>/dev/null || true; } | wc -l)"
[[ "$n" -gt 0 ]] && pass "Postgres pod carries app=postgres" ||
  fail "no pod in $NS carries app=postgres — Level 3's egress rule matches nothing (check Stage A's Postgres labels)"
for ns in kube-system vault; do
  v="$(kubectl get namespace "$ns" -o jsonpath='{.metadata.labels.kubernetes\.io/metadata\.name}' 2>/dev/null || true)"
  [[ "$v" == "$ns" ]] && pass "namespace $ns carries kubernetes.io/metadata.name=$ns" ||
    fail "namespace $ns lacks kubernetes.io/metadata.name — namespaceSelector rules match nothing"
done

section "4 — the apps are still Ready under ingress: []"
# Kubelet probes come from the node. Calico admits host-to-local-pod traffic by
# default, but that is CNI configuration, not a guarantee — so check it.
for lvl in "${LEVELS[@]}"; do
  ready="$( { kubectl -n "$NS" get pods -l "app=$lvl,!b5-probe" \
    -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null || true; } | sort -u)"
  [[ "$ready" == "True" ]] && pass "$lvl: all pods Ready" ||
    fail "$lvl: pods not all Ready ([$ready]) — the policy may be blocking kubelet probes"
done

# ---------------------------------------------------------------------------
section "5 — real connection attempts"
if [[ -z "${PROBE_IMAGE:-}" ]]; then
  skip "PROBE_IMAGE unset — no connection probes run. This is the step the PRD names; the gate is not met without it"
  finish
fi
md "- Probe image: \`$PROBE_IMAGE\`"

# A probe pod borrows a level's `app` label so the NetworkPolicy treats it
# exactly like that level. Two hazards, both handled:
#   * The level's Service selects the same label. The probe's readiness check
#     always fails, so it is never added to the Service's endpoints and never
#     receives the level's traffic.
#   * The level's ReplicaSet will NOT adopt it: a Deployment-managed ReplicaSet
#     also selects on pod-template-hash, which the probe does not carry.
on_exit "kubectl -n '$NS' delete pods -l b5-probe=true --ignore-not-found --wait=false >/dev/null 2>&1"

start_probe() { # <level>
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: b5-probe-$1
  namespace: $NS
  labels:
    app: $1
    b5-probe: "true"
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: probe
      image: $PROBE_IMAGE
      command: ["sleep", "600"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
      readinessProbe:
        exec: { command: ["false"] }
        periodSeconds: 5
      resources:
        requests: { cpu: 10m, memory: 16Mi }
        limits:   { cpu: 100m, memory: 32Mi }
EOF
  kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Running "pod/b5-probe-$1" --timeout=120s >/dev/null 2>&1
}

# probe <level> <host> <port> — classify one TCP connection attempt. Prints one of:
#
#   ALLOW      handshake completed ("Connected to")
#   BLOCK      timed out — the policy dropped the packets
#   REFUSED    the target answered with a reset. The packet GOT THROUGH; nothing
#              was listening. For a BLOCK expectation this is a failure: the
#              policy did not stop it.
#   NORESOLVE  the name did not resolve, so no packet ever met the policy
#   ERROR      the probe itself could not run
#
# Only ALLOW and BLOCK are verdicts. The others mean the test did not test what
# it claims — the same trap as a denial test refused by a role that does not
# exist (documents/vault-roles-and-policies.md). A dead probe pod or a mistyped
# Service name must never read as "blocked".
probe() {
  local out
  if ! out="$(kubectl -n "$NS" exec "b5-probe-$1" -- sh -c \
        "curl -sv --connect-timeout 3 -m 4 telnet://$2:$3 </dev/null 2>&1; true" 2>/dev/null)"; then
    echo ERROR; return
  fi
  # Two spellings: curl has phrased a completed connect both ways across
  # versions. The calibration controls below catch any other drift.
  if   grep -qE "Connected to|Established connection" <<<"$out"; then echo ALLOW
  elif grep -qi "could not resolve" <<<"$out";    then echo NORESOLVE
  elif grep -qi "connection refused" <<<"$out";   then echo REFUSED
  elif grep -q "Trying " <<<"$out";               then echo BLOCK
  else                                                 echo ERROR
  fi
}

expect() { # <level> <ALLOW|BLOCK> <label> <host> <port>
  local lvl="$1" want="$2" label="$3" host="$4" port="$5" got
  got="$(probe "$lvl" "$host" "$port")"
  if [[ "$got" == "$want" ]]; then
    pass "$lvl -> $label ($host:$port): $got as expected"
  else
    case "$got" in
      NORESOLVE) fail "$lvl -> $label: $host did not resolve — the policy was never exercised (wrong name, or DNS blocked)" ;;
      REFUSED)   fail "$lvl -> $label: connection REFUSED — packets reached the target, so the policy did not block them$([[ $want == ALLOW ]] && echo '; and nothing is listening on the port')" ;;
      ERROR)     fail "$lvl -> $label: probe could not run — result unknown, NOT treated as blocked" ;;
      *)         fail "$lvl -> $label ($host:$port): expected $want, observed $got" ;;
    esac
  fi
  PROBE_ROWS+=("| \`$lvl\` | $label | $want | $got | $([[ $got == "$want" ]] && echo ✅ || echo ❌) |")
}

PROBE_ROWS=()
for lvl in "${LEVELS[@]}"; do
  if ! start_probe "$lvl"; then
    fail "$lvl: probe pod did not reach Running (image pull? PSA?) — kubectl -n $NS describe pod b5-probe-$lvl"
    continue
  fi

  # Calibration. The classifier reads curl's verbose text, which is not a stable
  # API. Two controls whose answers are known in advance prove it reads THIS
  # image's curl correctly before any real result is trusted:
  #   * kube-dns TCP/53 — every level's policy allows it      -> must be ALLOW
  #     (and it proves name resolution works, so it doubles as the DNS check)
  #   * API server 443  — no level's policy allows it         -> must be BLOCK
  # If either is wrong, this level's probes would be guesses. Discard them.
  c_allow="$(probe "$lvl" kube-dns.kube-system.svc.cluster.local 53)"
  c_block="$(probe "$lvl" kubernetes.default.svc.cluster.local 443)"
  PROBE_ROWS+=("| \`$lvl\` | *control:* DNS (TCP 53) | ALLOW | $c_allow | $([[ $c_allow == ALLOW ]] && echo ✅ || echo ❌) |")
  PROBE_ROWS+=("| \`$lvl\` | *control:* API server | BLOCK | $c_block | $([[ $c_block == BLOCK ]] && echo ✅ || echo ❌) |")
  if [[ "$c_allow" == ALLOW && "$c_block" == BLOCK ]]; then
    pass "$lvl: calibrated — DNS reachable and resolving; a dropped connection reads as BLOCK"
  else
    case "$c_allow" in
      ALLOW)     ;;
      NORESOLVE) fail "$lvl: DNS does not resolve — the kube-dns egress rule is not matching" ;;
      *)         fail "$lvl: control 'DNS TCP 53' read as $c_allow, expected ALLOW — DNS egress broken, or the classifier misreads this curl" ;;
    esac
    case "$c_block" in
      BLOCK)   ;;
      REFUSED) fail "$lvl: control 'API server' was REFUSED, expected a drop — the CNI may reject rather than drop, which the classifier would misread" ;;
      *)       fail "$lvl: control 'API server' read as $c_block, expected BLOCK — a dropped connection is not being recognised" ;;
    esac
    fail "$lvl: calibration failed — its connection results would be untrustworthy, so none are reported"
    kubectl -n "$NS" delete pod "b5-probe-$lvl" --wait=false >/dev/null 2>&1 || true
    continue
  fi

  case "$lvl" in
    level1-env-secret)
      # Level 1 never talks to Vault — that is the level's whole claim.
      expect "$lvl" BLOCK "Vault"    "$VAULT_SVC" 8200
      expect "$lvl" BLOCK "Postgres" "$PG_SVC" 5432
      expect "$lvl" BLOCK "Level 2"  "level2-k8s-auth.$NS.svc" 8080
      expect "$lvl" BLOCK "Level 3"  "level3-dynamic-db.$NS.svc" 8080   # the test the PRD names
      ;;
    level2-k8s-auth)
      expect "$lvl" ALLOW "Vault"    "$VAULT_SVC" 8200
      expect "$lvl" BLOCK "Postgres" "$PG_SVC" 5432
      expect "$lvl" BLOCK "Level 3"  "level3-dynamic-db.$NS.svc" 8080
      ;;
    level3-dynamic-db)
      expect "$lvl" ALLOW "Vault"    "$VAULT_SVC" 8200
      expect "$lvl" ALLOW "Postgres" "$PG_SVC" 5432
      expect "$lvl" BLOCK "Level 1"  "level1-env-secret.$NS.svc" 8080
      ;;
    level4-pgp-decrypt)
      expect "$lvl" ALLOW "Vault"    "$VAULT_SVC" 8200
      expect "$lvl" BLOCK "Postgres" "$PG_SVC" 5432
      expect "$lvl" BLOCK "Level 3"  "level3-dynamic-db.$NS.svc" 8080
      ;;
  esac

  kubectl -n "$NS" delete pod "b5-probe-$lvl" --wait=false >/dev/null 2>&1 || true
done

md ""
md "### Connection probes"
md ""
md "| From | To | Expected | Observed | |"
md "|---|---|---|---|---|"
for r in "${PROBE_ROWS[@]}"; do md "$r"; done

finish
