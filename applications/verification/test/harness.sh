#!/usr/bin/env bash
# Local harness for the pure-bash logic in applications/verification.
#
# Stubs kubectl; needs no cluster and no jq. Covers: result recording and exit
# codes (a SKIP must fail the run), LIFO cleanup, secret-dir permissions, the
# NetworkPolicy probe classifier against realistic curl output, table rendering,
# and that the sweep patterns neither match their own source nor flag the
# levels' real (safe) log lines.
#
# The jq filters are covered separately by test/jq-filters.sh, which needs jq.
# Run both on the dev workspace before the first real B5 run, plus
# `shellcheck -x *.sh` once shellcheck is installed there.
#
#   bash applications/verification/test/harness.sh
set -uo pipefail
V="${1:-$(cd "$(dirname "$0")/.." && pwd)}"   # applications/verification
SCR="$(mktemp -d)"
trap 'rm -rf "$SCR"' EXIT

# lib.sh insists on a git checkout (results record the commit). When the harness
# is run on a plain copy — e.g. shipped to the dev workspace as a tarball — put
# that copy in a throwaway repo first, rather than letting every test that
# sources lib.sh fail for an unrelated reason.
if ! git -C "$V" rev-parse --show-toplevel >/dev/null 2>&1; then
  mkdir -p "$SCR/repo/applications"
  cp -r "$V" "$SCR/repo/applications/verification"
  git -C "$SCR/repo" init -q
  git -C "$SCR/repo" add -A
  git -C "$SCR/repo" -c user.name=harness -c user.email=harness@invalid commit -qm harness
  V="$SCR/repo/applications/verification"
  echo "(not a git checkout — testing a copy in a throwaway repo)"
fi
T_PASS=0 T_FAIL=0
ok()  { T_PASS=$((T_PASS+1)); echo "  ok    $*"; }
bad() { T_FAIL=$((T_FAIL+1)); echo "  FAIL  $*"; }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

# --- stub kubectl ----------------------------------------------------------
mkdir -p "$SCR/bin"
cat >"$SCR/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
sub=""; for a in "$@"; do case "$a" in config|exec|get) sub="$a"; break ;; esac; done
case "$sub" in
  config) echo "stub-context" ;;
  get)
    # `kubectl get lease ...` — cluster time, as the scheduler last renewed it.
    for a in "$@"; do [[ "$a" == lease ]] && { printf '%s' "${STUB_LEASE:-}"; exit 0; }; done
    # `kubectl get node <name> ...` — the node exists only if it is $STUB_NODE.
    args=("$@"); for i in "${!args[@]}"; do
      if [[ "${args[i]}" == node ]]; then [[ "${args[i+1]:-}" == "${STUB_NODE:-}" ]]; exit; fi
    done ;;
  exec)
    case "${STUB_MODE:-}" in
      exec-fails) exit 1 ;;
      connected)  printf '*   Trying 10.96.0.10:53...\n* Connected to kube-dns.kube-system.svc.cluster.local (10.96.0.10) port 53\n' ;;
      established) printf '*   Trying 10.96.0.10:53...\n* Established connection to kube-dns (10.96.0.10 port 53) from 10.0.0.5 port 41234\n' ;;
      timeout)    printf '*   Trying 10.96.0.1:443...\n* ipv4 connect timeout after 2999ms, move on!\n* Failed to connect to kubernetes.default.svc.cluster.local port 443 after 3001 ms: Timeout was reached\n' ;;
      refused)    printf '*   Trying 10.97.1.2:8080...\n* connect to 10.97.1.2 port 8080 from 10.0.0.5 port 50000 failed: Connection refused\n* Failed to connect to level3 port 8080 after 2 ms: Couldn'"'"'t connect to server\n' ;;
      noresolve)  printf '* Could not resolve host: level3-dynamic-db.wrong.svc\n* Closing connection\n' ;;
      garbage)    printf 'sh: curl: not found\n' ;;
    esac ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$SCR/bin/kubectl"
export PATH="$SCR/bin:$PATH"

# ---------------------------------------------------------------------------
echo "== T1: result recording and exit codes =="
run_lib() { # <body> -> exit code; results land in $SCR/results
  ( export RESULTS_DIR="$SCR/results"; source "$V/lib.sh"; start_results t "T"; section S; eval "$1"; finish ) >/dev/null 2>&1
}
run_lib 'pass a; pass b';          check "all passes -> exit 0" [ $? -eq 0 ]
run_lib 'pass a; fail b';          check "any failure -> exit 1" [ $? -eq 1 ]
run_lib 'pass a; skip b';          check "a SKIP alone -> exit 1 (a skip is not a pass)" [ $? -eq 1 ]
f="$(ls -t "$SCR"/results/*-t.md | head -1)"
check "results file records the skip" grep -q "⚠️ SKIP | b" "$f"
check "results file warns that skips are not passes" grep -q "Skipped checks are \*\*not\*\* passes" "$f"
check "results file carries the commit" grep -q "Commit:" "$f"

echo "== T2: cleanup runs last-in-first-out =="
order="$( source "$V/lib.sh" 2>/dev/null
          on_exit "echo first-registered"; on_exit "echo second-registered"; exit 0 )"
check "later hook runs first" [ "$order" == $'second-registered\nfirst-registered' ]

echo "== T2b: secret dir is private and removed on exit =="
d="$( source "$V/lib.sh"; make_secret_dir; stat -c '%a' "$SECRET_DIR" >"$SCR/mode"; echo "$SECRET_DIR" )"
check "secret dir created mode 700" [ "$(cat "$SCR/mode")" == "700" ]
check "secret dir removed on exit" [ ! -e "$d" ]

echo "== T3: probe classifier =="
probe_fn="$(awk '/^probe\(\) \{/,/^\}/' "$V/40-networkpolicy.sh")"
NS=test; eval "$probe_fn"
for case in "connected:ALLOW" "established:ALLOW" "timeout:BLOCK" "refused:REFUSED" \
            "noresolve:NORESOLVE" "exec-fails:ERROR" "garbage:ERROR"; do
  mode="${case%%:*}" want="${case#*:}"
  got="$(STUB_MODE=$mode probe lvl host 1)"
  check "$mode -> $want (got $got)" [ "$got" == "$want" ]
done
echo "   (the cases that matter most: a dead probe and an unresolvable name must"
echo "    NEVER read as BLOCK — that would pass every isolation check untested)"
for mode in exec-fails noresolve garbage refused; do
  got="$(STUB_MODE=$mode probe lvl host 1)"
  check "$mode does not read as BLOCK" [ "$got" != "BLOCK" ]
done

echo "== T4: matrix table header =="
ROLES=(level1-app level2-app)
hdr="| SA | $(printf '`%s` | ' "${ROLES[@]}")"
sep="|---|$(printf -- '---|%.0s' "${ROLES[@]}")"
check "header renders backticked roles" [ "$hdr" == '| SA | `level1-app` | `level2-app` | ' ]
check "separator has one cell per role" [ "$sep" == '|---|---|---|' ]

echo "== T5: composite associative-array keys =="
declare -A G; G[level1-app,level2-app]="refused"; G[default,level4-app]="refused2"
check "sa,role key round-trips" [ "${G[level1-app,level2-app]}" == "refused" ]
check "default row key round-trips" [ "${G[default,level4-app]}" == "refused2" ]

echo "== T6: level -> expected ServiceAccount =="
LEVELS=(level1-env-secret level2-k8s-auth level3-dynamic-db level4-pgp-decrypt)
SAS=(level1-app level2-app level3-app level4-app)
for i in 0 1 2 3; do
  lvl="${LEVELS[$i]}"
  got="${SAS[$(printf '%s\n' "${LEVELS[@]}" | grep -nx "$lvl" | cut -d: -f1) - 1]}"
  check "$lvl -> ${SAS[$i]}" [ "$got" == "${SAS[$i]}" ]
done

echo "== T7: self-match guard — sweep patterns must not match their own source =="
TLS=( "Insecure""SkipVerify[[:space:]]*[:=][[:space:]]*true" "-tls-skip""-verify" "curl[^|]*[[:space:]](-k|--insec""ure)([[:space:]]|$)" )
for p in "${TLS[@]}"; do
  hits="$(grep -nE -e "$p" "$V"/*.sh || true)"
  check "no script matches /$p/" [ -z "$hits" ]
done

echo "== T9: wrong-cluster guard =="
# The guard is the only thing between `10-independence --destructive` and
# whatever cluster the shell happens to point at. It must REFUSE, not warn.
# A refusal only counts if it is THIS refusal. Asserting on exit status alone
# once let these pass because lib.sh failed to load at all.
guard() { ( source "$V/lib.sh"; require_lab_cluster ) >"$SCR/guard.out" 2>&1; }
said() { grep -q -- "$1" "$SCR/guard.out"; }
now_iso="$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)"

STUB_LEASE="$now_iso" STUB_NODE=devnodemaster01 B5_EXPECTED_NODE=devnodemaster01 guard
check "expected node present -> proceeds" [ $? -eq 0 ]
STUB_LEASE="$now_iso" STUB_NODE=ip-10-0-1-23.ec2.internal B5_EXPECTED_NODE=devnodemaster01 guard
rc=$?; check "expected node absent (some other cluster) -> refuses, saying why" \
  bash -c '[ "$1" -ne 0 ] && grep -q "refusing to run" "$2"' _ "$rc" "$SCR/guard.out"
( unset B5_EXPECTED_NODE; STUB_LEASE="$now_iso" STUB_NODE=devnodemaster01 guard ); rc=$?
check "B5_EXPECTED_NODE unset -> refuses, never defaults" \
  bash -c '[ "$1" -ne 0 ] && grep -q "B5_EXPECTED_NODE is unset" "$2"' _ "$rc" "$SCR/guard.out"

echo "== T10: clock-skew check =="
past="$(date -u -d '26 days ago' +%Y-%m-%dT%H:%M:%S.000000Z)"
STUB_LEASE="$past" STUB_NODE=n B5_EXPECTED_NODE=n guard; rc=$?
check "clock 26 days off the cluster -> refuses, saying why" \
  bash -c '[ "$1" -ne 0 ] && grep -q "clock is 26d" "$2"' _ "$rc" "$SCR/guard.out"
STUB_LEASE="$now_iso" STUB_NODE=n B5_EXPECTED_NODE=n guard; rc=$?
check "clock in step -> proceeds and reports it" \
  bash -c '[ "$1" -eq 0 ] && grep -q "clock: within" "$2"' _ "$rc" "$SCR/guard.out"
STUB_LEASE="" STUB_NODE=n B5_EXPECTED_NODE=n guard; rc=$?
check "cluster time unreadable -> proceeds, but WARNS it was not checked" \
  bash -c '[ "$1" -eq 0 ] && grep -q "clock skew NOT checked" "$2"' _ "$rc" "$SCR/guard.out"
for s in "$V"/[0-4]*.sh; do
  check "$(basename "$s") calls the guard before touching the cluster" \
    grep -qx 'require_lab_cluster' "$s"
done

echo "== T8: log patterns fire on secrets, not on safe log lines =="
PGP_RE="BEGIN PGP PRIVATE ""KEY BLOCK"; TOK_RE='hvs\.[A-Za-z0-9_-]{20,}'
DSN_RE='postgres(ql)?://[^:/@[:space:]]+:[^@[:space:]]+@'
check "PGP block detected"   grep -qE "$PGP_RE" <<<'-----BEGIN PGP PRIVATE KEY BLOCK-----'
check "Vault token detected" grep -qE "$TOK_RE" <<<'token=hvs.CAESIJ2kAbCdEfGhIjKlMnOpQrStUv'
check "DSN with password detected" grep -qE "$DSN_RE" <<<'dsn=postgres://v-kube-x:s3cr3tP4ss@postgres:5432/appdb'
safe='{"level":"INFO","msg":"issued dynamic database credential","username":"v-kubernet-level3","lease_id":"database/creds/level3-app/abc","password_len":20}'
for re in "$PGP_RE" "$TOK_RE" "$DSN_RE"; do
  check "Level 3's real (safe) log line is not flagged by /$re/" bash -c '! grep -qE "$1" <<<"$2"' _ "$re" "$safe"
done

echo
echo "harness: $T_PASS passed, $T_FAIL failed"
[ "$T_FAIL" -eq 0 ]
