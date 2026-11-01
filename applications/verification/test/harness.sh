#!/usr/bin/env bash
# Local harness for the pure-bash logic in applications/verification.
#
# Stubs kubectl; needs no cluster and no jq. Covers: result recording and exit
# codes (a SKIP must fail the run), LIFO cleanup, secret-dir permissions, the
# NetworkPolicy probe classifier against realistic curl output, table rendering,
# and that the sweep patterns neither match their own source nor flag the
# levels' real (safe) log lines.
#
# NOT covered: the jq filters. Those first execute on a machine with jq — run
# this harness there, then `shellcheck -x *.sh`, before the first real B5 run.
#
#   bash applications/verification/test/harness.sh
set -uo pipefail
V="${1:-$(cd "$(dirname "$0")/.." && pwd)}"   # applications/verification
SCR="$(mktemp -d)"
trap 'rm -rf "$SCR"' EXIT
T_PASS=0 T_FAIL=0
ok()  { T_PASS=$((T_PASS+1)); echo "  ok    $*"; }
bad() { T_FAIL=$((T_FAIL+1)); echo "  FAIL  $*"; }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

# --- stub kubectl ----------------------------------------------------------
mkdir -p "$SCR/bin"
cat >"$SCR/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
sub=""; for a in "$@"; do case "$a" in config|exec) sub="$a"; break ;; esac; done
case "$sub" in
  config) echo "stub-context" ;;
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
