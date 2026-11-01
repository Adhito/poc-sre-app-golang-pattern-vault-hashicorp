#!/usr/bin/env bash
# Phase B5 — independence tests (Stage B PRD §5 B5, steps 1–5).
#
#   ./10-independence.sh                 read-only checks only
#   ./10-independence.sh --destructive   also delete / restart / redeploy levels
#
# Read-only:
#   1. all four levels healthy, checked by endpoint
#   5. no cross-module imports
#   +  each overlay renders from a clean clone, alone — proves no manifest reaches
#      outside its own level directory
#
# Destructive (opt-in):
#   2. delete Level 2 entirely      -> 1, 3, 4 healthy AND their pods untouched
#   3. restart Level 3 alone        -> 1, 2, 4 pods untouched
#   4. from a clean checkout, deploy ONLY Level 4 -> it works with nothing else
#
# Run this BEFORE activating the NetworkPolicies. Endpoint checks go through the
# API server's service proxy, which `ingress: []` may refuse.
source "$(dirname "$0")/lib.sh"

DESTRUCTIVE=false
[[ "${1:-}" == "--destructive" ]] && DESTRUCTIVE=true

require_cmd kubectl jq git
start_results independence "Phase B5 — independence"
md "- Mode: \`$([[ $DESTRUCTIVE == true ]] && echo destructive || echo read-only)\`"

# ---------------------------------------------------------------------------
check_all_healthy() { # <label> <levels...> — endpoint check, not assumption
  local label="$1"; shift
  local lvl
  for lvl in "$@"; do
    if deploy_available "$lvl" 120s && endpoint_ok "$lvl" healthz; then
      pass "[$label] $lvl available and /healthz 200"
    else
      fail "[$label] $lvl not healthy (rollout or /healthz)"
    fi
  done
}

declare -A UIDS_BEFORE
snapshot_uids() { local l; for l in "$@"; do UIDS_BEFORE[$l]="$(pod_uids "$l")"; done; }

assert_untouched() { # <label> <levels...> — same pods, not merely healthy pods
  local label="$1"; shift
  local lvl now
  for lvl in "$@"; do
    now="$(pod_uids "$lvl")"
    if [[ -n "$now" && "$now" == "${UIDS_BEFORE[$lvl]}" ]]; then
      pass "[$label] $lvl pods untouched (same pod UIDs)"
    else
      fail "[$label] $lvl pods changed or vanished — the operation was not isolated"
    fi
  done
}

# ---------------------------------------------------------------------------
section "Step 1 — all four levels healthy"
check_all_healthy "step 1" "${LEVELS[@]}"

section "Step 5 — no cross-module imports"
# The module line itself names the level, so exclude it; anything else naming a
# level is a dependency on a sibling module (D2, CLAUDE.md rule 7).
cross="$(grep -nE 'level[0-9]' "$REPO_ROOT"/applications/level*/go.mod | grep -vE ':module ' || true)"
if [[ -z "$cross" ]]; then
  pass "no go.mod references another level"
else
  fail "cross-module reference found: $(echo "$cross" | paste -sd' ' -)"
fi
for f in go.mod go.work; do
  [[ -e "$REPO_ROOT/$f" ]] && fail "root $f exists — the levels must not share a module" ||
    pass "no root $f"
done

section "Each overlay renders alone, from a clean clone"
# Copy ONE level's directory into an empty tree and render it there. If any
# manifest reaches outside its own level (a ../ into a sibling, a shared base),
# this fails. Rendering in place cannot catch that.
CLONE="$(mktemp -d)"
on_exit "rm -rf '$CLONE'"
git clone -q --no-local "$REPO_ROOT" "$CLONE/repo"
for lvl in "${LEVELS[@]}"; do
  iso="$(mktemp -d)"
  on_exit "rm -rf '$iso'"
  mkdir -p "$iso/applications"
  cp -r "$CLONE/repo/applications/$lvl" "$iso/applications/"
  if kubectl kustomize "$iso/applications/$lvl/deploy/overlays/onprem" >/dev/null 2>&1; then
    pass "$lvl renders with no other level present"
  else
    fail "$lvl does not render in isolation — it depends on something outside its directory"
  fi
done

# ---------------------------------------------------------------------------
if [[ $DESTRUCTIVE != true ]]; then
  section "Steps 2–4 — destructive"
  skip "steps 2–4 not run (read-only mode). Re-run with --destructive — see README for the ArgoCD prerequisite"
  finish
fi

section "Destructive prerequisite — ArgoCD self-heal must be off"
# With automated sync + selfHeal, ArgoCD recreates whatever this script deletes
# within seconds. "Level 2 deleted, others fine" would then be testing nothing.
# The root app must be off too: it owns the child Applications and would revert
# any change to their sync policy.
if ! apps_json="$(kubectl -n argocd get applications -o json 2>/dev/null)"; then
  fail "could not read ArgoCD Applications — cannot prove self-heal is off, so refusing destructive steps"
  finish
fi
auto="$(jq -r '.items[] | select(.metadata.name == "root-applications" or (.spec.destination.namespace == "'"$NS"'"))
         | select(.spec.syncPolicy.automated != null) | .metadata.name' <<<"$apps_json" | paste -sd' ' -)"
if [[ -n "$auto" ]]; then
  fail "automated sync is ON for: $auto"
  cat >&2 <<EOF

Refusing to run destructive steps. Disable automated sync first, root app first:

  argocd app set root-applications --sync-policy none
$(for a in $auto; do [[ $a != root-applications ]] && echo "  argocd app set $a --sync-policy none"; done)

Re-enable afterwards, root app LAST, so it does not fight the children:
$(for a in $auto; do [[ $a != root-applications ]] && echo "  argocd app set $a --sync-policy automated --self-heal --auto-prune"; done)
  argocd app set root-applications --sync-policy automated --self-heal --auto-prune

This changes persistent cluster configuration, so it is left to a human.
EOF
  finish
fi
pass "no automated sync on root-applications or the four level Applications"

apply_level() { kubectl apply -k "$CLONE/repo/applications/$1/deploy/overlays/onprem" >/dev/null; }
delete_level() { kubectl delete -k "$CLONE/repo/applications/$1/deploy/overlays/onprem" --wait=true --ignore-not-found >/dev/null; }

# Whatever happens below, put every level back from the committed state.
restore_all() {
  local l
  for l in "${LEVELS[@]}"; do apply_level "$l" || echo "WARNING: failed to restore $l" >&2; done
}
on_exit "restore_all"

# --- Step 2 ---------------------------------------------------------------
section "Step 2 — delete Level 2 entirely"
snapshot_uids level1-env-secret level3-dynamic-db level4-pgp-decrypt
delete_level level2-k8s-auth
if kubectl -n "$NS" get deploy level2-k8s-auth >/dev/null 2>&1; then
  fail "Level 2 still present after delete — something recreated it (ArgoCD?)"
else
  pass "Level 2 deleted"
fi
check_all_healthy "step 2" level1-env-secret level3-dynamic-db level4-pgp-decrypt
assert_untouched "step 2" level1-env-secret level3-dynamic-db level4-pgp-decrypt
apply_level level2-k8s-auth
check_all_healthy "step 2 restore" level2-k8s-auth

# --- Step 3 ---------------------------------------------------------------
section "Step 3 — redeploy Level 3 alone"
# The PRD says "rebuild and redeploy". The rebuild is `make image push` in the
# level directory; this step proves the REDEPLOY is isolated.
snapshot_uids level1-env-secret level2-k8s-auth level4-pgp-decrypt
kubectl -n "$NS" rollout restart deploy/level3-dynamic-db >/dev/null
check_all_healthy "step 3" level3-dynamic-db
assert_untouched "step 3" level1-env-secret level2-k8s-auth level4-pgp-decrypt
note "Level 3 revokes its lease on SIGTERM. Confirm no orphan from the restart: vault list sys/leases/lookup/database/creds/level3-app"

# --- Step 4 ---------------------------------------------------------------
section "Step 4 — only Level 4, from a clean checkout"
for l in level1-env-secret level2-k8s-auth level3-dynamic-db level4-pgp-decrypt; do delete_level "$l"; done
remaining="$(kubectl -n "$NS" get deploy -o name 2>/dev/null | grep -E 'level[0-9]' || true)"
[[ -z "$remaining" ]] && pass "all four levels removed" || fail "levels still present: $remaining"
apply_level level4-pgp-decrypt
check_all_healthy "step 4" level4-pgp-decrypt
others="$(kubectl -n "$NS" get deploy -o name 2>/dev/null | grep -E 'level[123]' || true)"
[[ -z "$others" ]] && pass "Level 4 healthy with no other level present" ||
  fail "other levels reappeared during step 4: $others"
note "Level 4 was healthy alone. Its decrypt result is a B4 concern and is not re-asserted here."

section "Restore"
restore_all
check_all_healthy "restore" "${LEVELS[@]}"
note "Re-enable ArgoCD automated sync now — root-applications LAST."

finish
