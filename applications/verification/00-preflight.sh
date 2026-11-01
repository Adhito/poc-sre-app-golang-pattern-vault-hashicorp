#!/usr/bin/env bash
# Phase B5 preflight. Read-only.
#
# Confirms the environment can produce meaningful B5 results. B5 run against a
# half-working platform produces results that mislead rather than teach — this
# is the "Stage B built on a half-working Vault" warning from the Stage B PRD,
# applied one phase later.
#
# Required env:  VAULT_ADDR (https://, the MetalLB VIP), VAULT_CACERT
source "$(dirname "$0")/lib.sh"

require_cmd kubectl jq curl git
require_lab_cluster
require_vault_env
make_secret_dir
start_results preflight "Phase B5 — preflight"

section "Phase gate reminder"
# This script cannot see whether B1–B4 have been signed off; it can only say so.
note "CLAUDE.md rule 4: B5 results only count once every B1–B4 exit-gate box is ticked. This script cannot verify that — confirm it from the phase commit bodies."

section "Cluster and namespace"
if kubectl version --request-timeout=10s >/dev/null 2>&1; then
  pass "API server reachable (context: $(kubectl config current-context))"
else
  fail "API server unreachable"
fi

if kubectl get namespace "$NS" >/dev/null 2>&1; then
  pass "namespace $NS exists"
else
  fail "namespace $NS does not exist"
fi

if kubectl -n "$NS" get configmap vault-ca >/dev/null 2>&1; then
  pass "vault-ca ConfigMap present in $NS"
else
  fail "vault-ca ConfigMap missing in $NS (Phase B0 step 6)"
fi

section "Vault"
health="$SECRET_DIR/health.json"
code="$(vault_curl GET "sys/health?standbyok=true&perfstandbyok=true" "" "" "$health")"
if [[ "$code" == "000" ]]; then
  fail "Vault unreachable at $VAULT_ADDR with the configured CA — a TLS failure here means a missing SAN or wrong CA, never a reason to skip verification"
else
  ver="$(jq -r '.version // "?"' "$health")"
  init="$(jq -r '.initialized // false' "$health")"
  sealed="$(jq -r '.sealed // true' "$health")"
  note "Vault version: $ver (record this — refusal wording in 20-privilege-matrix is version-sensitive)"
  [[ "$init" == "true" ]] && pass "Vault initialized" || fail "Vault not initialized"
  [[ "$sealed" == "false" ]] && pass "Vault unsealed (the node answering)" || fail "Vault is sealed"
  note "sys/health reports only the node that answered. Confirm all three peers are unsealed per runbooks/seal-unseal.md — a sealed follower passes its readiness probe and there is no automated seal alert (Prometheus Operator absent)."
fi

section "Four levels deployed and available"
for lvl in "${LEVELS[@]}"; do
  if deploy_available "$lvl" 30s; then
    pass "deploy/$lvl available"
  else
    fail "deploy/$lvl not available"
  fi
done

section "ServiceAccounts"
for sa in "${SAS[@]}"; do
  if kubectl -n "$NS" get serviceaccount "$sa" >/dev/null 2>&1; then
    pass "ServiceAccount $sa exists"
  else
    fail "ServiceAccount $sa missing"
  fi
done

section "Overlays carry real values, not placeholders"
for lvl in "${LEVELS[@]}"; do
  f="$(overlay_dir "$lvl")/kustomization.yaml"
  if grep -qE 'REGISTRY_FROM_DOCS_ENVIRONMENT_MD|newTag: GIT_SHA' "$f"; then
    fail "$lvl overlay still has the registry/tag placeholder — destructive restores in 10-independence would deploy an unpullable image"
  else
    pass "$lvl overlay has a concrete image reference"
  fi
done

section "Level 4 fixture"
fx="$REPO_ROOT/applications/level4-pgp-decrypt/fixtures/secret-message.txt.gpg"
if [[ -f "$fx" ]]; then
  pass "Level 4 fixture present (produced by Stage A Phase A7)"
else
  fail "Level 4 fixture missing — see applications/level4-pgp-decrypt/fixtures/README.md"
fi

section "ArgoCD self-heal (informational)"
# Not a failure here: it matters only for 10-independence --destructive, which
# checks again and refuses. Reported now so it is not a surprise later.
if kubectl get crd applications.argoproj.io >/dev/null 2>&1; then
  auto="$(kubectl -n argocd get applications -o json 2>/dev/null |
    jq -r '.items[] | select(.metadata.name == "root-applications" or (.spec.destination.namespace == "'"$NS"'"))
           | select(.spec.syncPolicy.automated != null) | .metadata.name' | paste -sd, - || true)"
  if [[ -n "$auto" ]]; then
    note "automated sync is ON for: $auto — 10-independence --destructive will refuse to run until it is off"
  else
    note "no automated sync on root-applications or the four level Applications"
  fi
else
  note "ArgoCD CRDs not found from this context"
fi

finish
