#!/usr/bin/env bash
# Executes the B5 scripts' real jq filters against synthetic input. Needs jq;
# needs no cluster. Run it on the dev workspace — the workstation has no jq.
#
# The filters are EXTRACTED from the scripts, not copied here, so this tests the
# code that will actually run. If a script's filter is edited, this file tests
# the edit; if the extraction anchor moves, this fails loudly instead of quietly
# testing nothing.
#
#   bash applications/verification/test/jq-filters.sh
set -uo pipefail
V="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
command -v jq >/dev/null || { echo "jq not installed"; exit 2; }
echo "jq: $(jq --version)"

T_PASS=0 T_FAIL=0
ok()  { T_PASS=$((T_PASS+1)); echo "  ok    $*"; }
bad() { T_FAIL=$((T_FAIL+1)); echo "  FAIL  $*"; }

# extract <file> <start-text> — the single-quoted jq program that begins on the
# first line CONTAINING <start-text> (a plain substring, not a regex: awk -v
# would mangle backslash escapes) and ends at the next line containing "' <<<".
extract() {
  awk -v start="$2" '
    !on && index($0, start) { on=1; sub(/^[^'"'"']*'"'"'/, ""); }
    on { if (index($0, "'"'"' <<<")) { sub(/'"'"' <<<.*/, ""); print; exit } print }
  ' "$1"
}

# ---------------------------------------------------------------------------
echo "== 40-networkpolicy: selector guard (commonLabels regression) =="
F="$(extract "$V/40-networkpolicy.sh" 'leaks="$(jq -r')"
[[ -n "$F" ]] || { bad "could not extract the selector-guard filter — anchor moved?"; F='empty'; }

run_guard() { jq -r "$F" <<<"$1"; }

# A clean render, shaped like `kubectl create --dry-run=client -o json` output:
# Level 3, with the CORRECTED Postgres selector.
clean='{"kind":"List","items":[
 {"kind":"Deployment","spec":{"selector":{"matchLabels":{"app":"level3-dynamic-db"}}}},
 {"kind":"Service","spec":{"selector":{"app":"level3-dynamic-db"}}},
 {"kind":"NetworkPolicy","spec":{"podSelector":{"matchLabels":{"app":"level3-dynamic-db"}},
   "egress":[
     {"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},
             "podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}]},
     {"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"vault"}}}]},
     {"to":[{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"postgres"}}}]}]}}]}'
out="$(run_guard "$clean")"
[[ -z "$out" ]] && ok "clean render -> no leaks (app.kubernetes.io/name is NOT flagged)" \
                || bad "clean render flagged: $out"

# The original bug: component + part-of injected into the egress selectors.
leaky='{"kind":"List","items":[
 {"kind":"NetworkPolicy","spec":{"podSelector":{"matchLabels":{"app":"level3-dynamic-db"}},
   "egress":[
     {"to":[{"podSelector":{"matchLabels":{"k8s-app":"kube-dns","app.kubernetes.io/component":"level3-dynamic-db"}}}]},
     {"to":[{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"postgres","app.kubernetes.io/part-of":"vault-poc-applications"}}}]}]}}]}'
out="$(run_guard "$leaky")"
n="$(grep -c . <<<"$out" || true)"
[[ "$n" -eq 2 ]] && ok "the commonLabels bug -> both leaked selectors flagged" \
                 || bad "expected 2 flagged selectors, got $n: $out"

dep='{"kind":"List","items":[{"kind":"Deployment","spec":{"selector":{"matchLabels":{"app":"x","app.kubernetes.io/component":"x"}}}}]}'
[[ -n "$(run_guard "$dep")" ]] && ok "leak into a Deployment selector -> flagged" \
                               || bad "Deployment selector leak not flagged"

# The policy's OWN podSelector — not just its egress targets. This is the case a
# jq precedence bug once hid: `,` binds tighter than `|`, so the podSelector
# entry was piped into the egress filter and dropped.
own='{"kind":"List","items":[{"kind":"NetworkPolicy","spec":{
  "podSelector":{"matchLabels":{"app":"x","app.kubernetes.io/component":"x"}},
  "egress":[{"to":[{"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}]}]}}]}'
out="$(run_guard "$own")"
[[ "$out" == NetworkPolicy.podSelector* ]] && ok "leak into the policy's own podSelector -> flagged" \
                                            || bad "own podSelector leak missed (got: ${out:-nothing})"

single='{"kind":"NetworkPolicy","spec":{"podSelector":{"matchLabels":{"app":"x","app.kubernetes.io/part-of":"vault-poc-applications"}}}}'
[[ -n "$(run_guard "$single")" ]] && ok "single object (not a List) -> still inspected" \
                                  || bad "single object not inspected"

# ---------------------------------------------------------------------------
echo "== 30-hardening-sweep: pod security report =="
F2="$(extract "$V/30-hardening-sweep.sh" 'report="$(jq -r')"
[[ -n "$F2" ]] || { bad "could not extract the security-report filter"; F2='empty'; }

good_pod='{"items":[{"spec":{"serviceAccountName":"level3-app",
  "securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},
  "containers":[{"name":"app","securityContext":{"readOnlyRootFilesystem":true,
     "allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},
     "resources":{"requests":{"cpu":"25m","memory":"32Mi"},"limits":{"cpu":"500m","memory":"128Mi"}}}]}}]}'
rep="$(jq -r "$F2" <<<"$good_pod")"
want="nonroot=true rorootfs=true noescal=true dropall=true seccomp=true requests=true limits=true sas=level3-app"
[[ "$(tr '\n' ' ' <<<"$rep" | sed 's/ $//')" == "$want" ]] && ok "hardened pod -> every check true" \
  || bad "hardened pod report: $(tr '\n' ' ' <<<"$rep")"

weak_pod='{"items":[{"spec":{"containers":[{"name":"app","securityContext":{"capabilities":{"drop":["NET_RAW"]}},
  "resources":{"requests":{"cpu":"10m"}}}]}}]}'
rep="$(jq -r "$F2" <<<"$weak_pod")"
for k in nonroot rorootfs noescal dropall seccomp requests limits; do
  grep -qx "$k=false" <<<"$rep" && ok "unhardened pod -> $k=false" || bad "unhardened pod -> $k not false ($rep)"
done
grep -qx "sas=default" <<<"$rep" && ok "missing serviceAccountName -> reported as 'default'" \
  || bad "missing SA not reported as default: $rep"

mixed='{"items":[
 {"spec":{"serviceAccountName":"level1-app","securityContext":{"runAsNonRoot":true},"containers":[{"name":"a","securityContext":{"readOnlyRootFilesystem":true}}]}},
 {"spec":{"serviceAccountName":"level1-app","containers":[{"name":"b","securityContext":{"readOnlyRootFilesystem":false}}]}}]}'
rep="$(jq -r "$F2" <<<"$mixed")"
grep -qx "rorootfs=false" <<<"$rep" && ok "one weak container among many -> the level fails (all, not any)" \
  || bad "one weak container slipped through: $rep"

# ---------------------------------------------------------------------------
echo "== lib.sh / 20-privilege-matrix: Vault response handling =="
errs="$(jq -r '(.errors // []) | join("; ")' <<<'{"errors":["service account name not authorized"]}')"
[[ "$errs" == "service account name not authorized" ]] && ok "vault_errors extracts the refusal reason" || bad "vault_errors: $errs"
errs="$(jq -r '(.errors // []) | join("; ")' <<<'{"data":{"x":1}}')"
[[ -z "$errs" ]] && ok "vault_errors on a success body -> empty" || bad "vault_errors on success: $errs"

pol="$(jq -r '.auth.token_policies // .auth.policies | sort | join(",")' \
       <<<'{"auth":{"token_policies":["level4-pgp","default"]}}')"
[[ "$pol" == "default,level4-pgp" ]] && ok "policy set extracted and sorted" || bad "policies: $pol"

body="$(mktemp)"; jwt="$(mktemp)"; trap 'rm -f "$body" "$jwt"' EXIT
printf 'eyJhbGciOi.fake.jwt\n' >"$jwt"
jq -n --rawfile jwt "$jwt" --arg role level4-app '{jwt: ($jwt | rtrimstr("\n")), role: $role}' >"$body"
[[ "$(jq -r .jwt "$body")" == "eyJhbGciOi.fake.jwt" && "$(jq -r .role "$body")" == "level4-app" ]] \
  && ok "login body built from a JWT file; trailing newline stripped" || bad "login body: $(cat "$body")"

hdr="$(jq -r '"X-Vault-Token: " + .auth.client_token' <<<'{"auth":{"client_token":"hvs.FAKE"}}')"
[[ "$hdr" == "X-Vault-Token: hvs.FAKE" ]] && ok "token header built file-to-file" || bad "header: $hdr"

echo
echo "jq filters: $T_PASS passed, $T_FAIL failed"
[ "$T_FAIL" -eq 0 ]
