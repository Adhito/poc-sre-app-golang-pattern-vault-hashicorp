# shellcheck shell=bash
# Shared helpers for the Phase B5 verification scripts. Sourced, never run.
#
# Two rules every script here follows, because B5 is the phase that checks for
# leaks and it would be absurd to cause one:
#
#   1. No secret reaches argv, the terminal, or a results file. Tokens, JWTs and
#      request bodies live in $SECRET_DIR (mode 0700, wiped on exit). Bodies of
#      ALLOWED reads are discarded unread — they contain the secrets.
#   2. No TLS bypass. Every Vault call uses --cacert "$VAULT_CACERT".

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NS="${NS:-poc-hashicorp-vault-application}"

LEVELS=(level1-env-secret level2-k8s-auth level3-dynamic-db level4-pgp-decrypt)
SAS=(level1-app level2-app level3-app level4-app)

# One ServiceAccount, one role, one policy. The role name equals the SA name;
# the policy name does NOT. `level4-pgp` is a policy, never a role — see
# documents/vault-roles-and-policies.md.
declare -A ROLE_FOR_SA=(
  [level1-app]=level1-app [level2-app]=level2-app
  [level3-app]=level3-app [level4-app]=level4-app
)
declare -A POLICY_FOR_ROLE=(
  [level1-app]=level1-reader [level2-app]=level2-reader
  [level3-app]=level3-db     [level4-app]=level4-pgp
)
POLICY_NAMES=(level1-reader level2-reader level3-db level4-pgp eso-reader)

# Results record the commit they ran against, so these scripts must run from a
# git checkout. Fail with a reason — under `set -e` a bare failure here would
# abort the sourcing script with no message at all.
if ! REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)"; then
  echo "ERROR: run these scripts from a git checkout of the repository (results record the commit)." >&2
  exit 2
fi
RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/documents/results/phase-b5}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"

# ---------------------------------------------------------------------------
# Result recording
# ---------------------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULT_FILE=""

# start_results <script-name> <title>
start_results() {
  mkdir -p "$RESULTS_DIR"
  RESULT_FILE="$RESULTS_DIR/${RUN_ID}-$1.md"
  {
    echo "# $2"
    echo
    echo "- Run: \`$RUN_ID\` (UTC)"
    echo "- Commit: \`$(git -C "$REPO_ROOT" rev-parse --short HEAD)\`$(git -C "$REPO_ROOT" diff --quiet || echo ' **(working tree dirty — results are not reproducible from this commit)**')"
    echo "- Cluster context: \`$(kubectl config current-context 2>/dev/null || echo unknown)\` — identity confirmed by node \`${B5_EXPECTED_NODE:-<unchecked>}\`"
    echo "- Namespace: \`$NS\`"
    echo
  } >"$RESULT_FILE"
}

section() {
  echo
  echo "== $* =="
  { echo; echo "## $*"; echo; echo "| Result | Check |"; echo "|---|---|"; } >>"$RESULT_FILE"
}

_record() { echo "| $1 | $2 |" >>"$RESULT_FILE"; }

pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo "  PASS  $*"; _record "✅ PASS" "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo "  FAIL  $*" >&2; _record "❌ FAIL" "$*"; }
# A skip is NOT a pass. A gate that did not run is a failed gate (CLAUDE.md
# rule 5) — skips are reported loudly and make the script exit non-zero.
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); echo "  SKIP  $*" >&2; _record "⚠️ SKIP" "$*"; }
note() { echo "  note  $*"; _record "ℹ️" "$*"; }

# Append free-form markdown (tables etc.) to the results file.
md() { echo "$*" >>"$RESULT_FILE"; }

finish() {
  {
    echo
    echo "## Summary"
    echo
    echo "**$PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped.**"
    if ((SKIP_COUNT > 0)); then
      echo
      echo "Skipped checks are **not** passes. A gate check that did not run is a failed gate."
    fi
  } >>"$RESULT_FILE"

  echo
  echo "Summary: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"
  echo "Results: $RESULT_FILE"
  if ((FAIL_COUNT > 0 || SKIP_COUNT > 0)); then
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 2; }

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
  done
}

require_env() {
  local v
  for v in "$@"; do
    [[ -n "${!v:-}" ]] || die "$v is unset. See applications/verification/README.md."
  done
}

# Refuse to run against the wrong cluster.
#
# The current kubectl context is whatever the shell last used, and the context
# name proves nothing: kubeadm names every cluster `kubernetes-admin@kubernetes`.
# The workstation these scripts were written on defaults to an unrelated EKS
# context — and 10-independence --destructive deletes Deployments. So identity
# is checked by something only the lab cluster has: a node with a known name.
#
# B5_EXPECTED_NODE has no default. Node names are environment values, recorded
# in environment.md in the cluster repo; CLAUDE.md forbids hardcoding them.
require_lab_cluster() {
  require_env B5_EXPECTED_NODE
  local ctx server
  ctx="$(kubectl config current-context 2>/dev/null || echo '<none>')"
  server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo '<unknown>')"
  if ! kubectl get node "$B5_EXPECTED_NODE" --request-timeout=10s >/dev/null 2>&1; then
    die "refusing to run: context '$ctx' ($server) has no node named '$B5_EXPECTED_NODE'.
       This is either the wrong cluster or an unreachable one. Switch context, or
       correct B5_EXPECTED_NODE from environment.md — never just unset the check."
  fi
  echo "cluster: context '$ctx' ($server) — node '$B5_EXPECTED_NODE' present"
  check_clock
}

# Refuse to run when this machine's clock disagrees with the cluster's.
#
# TLS certificate validity is judged against the LOCAL clock. A VM resumed from
# suspend without a time sync can be weeks behind — the dev workspace was found
# ~26 days slow on 2026-10-31 — and then every certificate issued since looks
# "not yet valid". That surfaces as a TLS failure, which is exactly the moment
# someone reaches for `curl -k` (CLAUDE.md rule 3). It would also stamp results
# files with the wrong date.
#
# Cluster time comes from the scheduler's leader-election lease: renewed every
# few seconds by the control plane, readable with a plain `get`, nothing to
# install. Unmeasurable skew is a warning, not a pass and not a block.
CLOCK_SKEW_MAX_S="${CLOCK_SKEW_MAX_S:-120}"
check_clock() {
  local rt srv now skew abs
  rt="$(kubectl -n kube-system get lease kube-scheduler -o jsonpath='{.spec.renewTime}' 2>/dev/null || true)"
  if [[ -z "$rt" ]] || ! srv="$(date -u -d "$rt" +%s 2>/dev/null)"; then
    echo "WARNING: could not read cluster time — clock skew NOT checked. Confirm with: date -u" >&2
    return 0
  fi
  now="$(date -u +%s)"
  skew=$((now - srv)); abs=${skew#-}
  if ((abs > CLOCK_SKEW_MAX_S)); then
    die "this machine's clock is $((skew / 86400))d $(((abs % 86400) / 3600))h off the cluster's (${skew}s; local $(date -u +%FT%TZ), cluster ~$rt).
       TLS certificate checks and results timestamps would both be wrong. Fix the
       clock first — e.g. set it from the cluster's:
         sudo date -u -s \"\$(kubectl -n kube-system get lease kube-scheduler -o jsonpath='{.spec.renewTime}')\"
       ('timedatectl set-ntp true' does not help if NTP is on but has no reachable
       server) — and never work around a TLS failure it causes."
  fi
  echo "clock: within ${abs}s of the cluster"
}

require_vault_env() {
  require_env VAULT_ADDR VAULT_CACERT
  [[ -r "$VAULT_CACERT" ]] || die "VAULT_CACERT=$VAULT_CACERT is not readable"
  # Refuse a plaintext address: this is the human-facing path to Vault and it is
  # TLS-only by design (Stage A D7).
  [[ "$VAULT_ADDR" == https://* ]] || die "VAULT_ADDR must be https:// (got $VAULT_ADDR)"
}

# ---------------------------------------------------------------------------
# Secret-safe scratch space
# ---------------------------------------------------------------------------

SECRET_DIR=""
_cleanup_hooks=()

on_exit() { _cleanup_hooks+=("$1"); }

# Last-in, first-out, like Go's defer: a hook registered later may depend on
# state an earlier hook tears down (10-independence restores levels from a clone
# directory that an earlier hook deletes).
_run_cleanup() {
  local i
  for ((i = ${#_cleanup_hooks[@]} - 1; i >= 0; i--)); do
    eval "${_cleanup_hooks[i]}" || true
  done
  if [[ -n "$SECRET_DIR" && -d "$SECRET_DIR" ]]; then rm -rf -- "$SECRET_DIR"; fi
}
trap _run_cleanup EXIT

make_secret_dir() {
  umask 077
  SECRET_DIR="$(mktemp -d)"
  chmod 700 "$SECRET_DIR"
}

# ---------------------------------------------------------------------------
# Vault over plain curl
# ---------------------------------------------------------------------------

# vault_curl <method> <path> <header-file-or-empty> <body-file-or-empty> <out-file>
# Prints the HTTP status. Never prints the body. The token travels in a header
# FILE (curl -H @file), so it never appears in argv or `ps`.
vault_curl() {
  local method="$1" path="$2" hdr="$3" body="$4" out="$5"
  local args=(-sS --cacert "$VAULT_CACERT" -X "$method" -o "$out" -w '%{http_code}'
              --connect-timeout 5 -m 20)
  [[ -n "$hdr" ]] && args+=(-H "@$hdr")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data-binary "@$body")
  curl "${args[@]}" "$VAULT_ADDR/v1/$path" 2>/dev/null || echo "000"
}

# vault_errors <response-file> — the `errors` array only. Safe to print: Vault
# error messages describe the refusal, they do not echo secret values.
vault_errors() {
  jq -r '(.errors // []) | join("; ")' "$1" 2>/dev/null || echo "<unparseable response>"
}

vault_version() {
  local out="$SECRET_DIR/health.json"
  vault_curl GET "sys/health?standbyok=true&perfstandbyok=true" "" "" "$out" >/dev/null
  jq -r '.version // "unknown"' "$out" 2>/dev/null || echo unknown
}

# ---------------------------------------------------------------------------
# Kubernetes helpers
# ---------------------------------------------------------------------------

# Health through the API server's service proxy: no port-forward, no extra pod.
# NOTE: once the NetworkPolicies are active (ingress: []), this path may be
# refused, because the proxied connection arrives from the control-plane node.
# Run endpoint checks BEFORE activating the policies — 10-independence does.
endpoint_ok() {
  local svc="$1" path="${2:-healthz}"
  kubectl get --raw "/api/v1/namespaces/$NS/services/http:${svc}:http/proxy/${path}" >/dev/null 2>&1
}

deploy_available() {
  kubectl -n "$NS" rollout status "deploy/$1" --timeout="${2:-180s}" >/dev/null 2>&1
}

# Pod UIDs for a level, excluding B5 probe pods. Used to prove "untouched".
pod_uids() {
  { kubectl -n "$NS" get pods -l "app=$1,!b5-probe" -o jsonpath='{range .items[*]}{.metadata.uid}{"\n"}{end}' 2>/dev/null || true; } | sort
}

overlay_dir() { echo "$REPO_ROOT/applications/$1/deploy/overlays/onprem"; }
base_dir() { echo "$REPO_ROOT/applications/$1/deploy/base"; }

# render_json <kustomize-dir> — rendered manifests as JSON. Uses a client dry-run
# so the result is real Kubernetes objects; needs cluster discovery. Returns
# non-zero on failure, and callers must treat that as a FAILURE: an empty render
# reads as "no problems found", which is the worst possible false pass.
render_json() {
  local out
  out="$(kubectl kustomize "$1" 2>/dev/null | kubectl create --dry-run=client -o json -f - 2>/dev/null)" || return 1
  [[ -n "$out" ]] || return 1
  printf '%s\n' "$out"
}
