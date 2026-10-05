# Troubleshooting and surprises

Anything non-obvious hit during the build, **including things that contradicted
a PRD**. Newest first within each stage.

---

## Stage B

### Documentation lives in `documents/`, not `docs/` — a deliberate deviation

**Phase B0.** Both PRDs and CLAUDE.md specify a `docs/` directory throughout:
`docs/environment.md`, `docs/key-custody.md`, `docs/runbooks/*`,
`docs/troubleshooting.md`, `docs/pattern-comparison.md`. The repository owner
consolidated on the existing `documents/` folder instead, to keep one home for
all written material rather than two.

**Resolution:** every Stage B reference — both `Makefile`s, both overlay
`kustomization.yaml` files, `applications/README.md` — now points at
`documents/`. The PRDs and playbooks are unedited: they are the specification,
and rewriting a spec to match an implementation gets the direction of authority
backwards.

**Open coordination item — now cross-repo.** Stage A lives in the cluster repo
(see the Stage A section below), so `environment.md` is a Stage A deliverable
produced *outside this repository*. Stage B's `Makefile`s and overlays currently
tell the reader to get `REGISTRY` from `documents/environment.md`, a path that
does not exist here and may never.

**Answered on the Stage A side.** `environment.md` and the three runbooks now
exist, beside the manifests they describe:

```
poc-platform-engineering-iac-vagrant-ansible-k8s-cluster-kubeadm-calico
  └── script-manifest/utility-hashicorp-vault/documents/
        ├── environment.md
        └── runbooks/{seal-unseal,snapshot-restore,upgrade}.md
```

No copy is kept in this repo. A copy drifts, and `environment.md` is precisely
the file whose purpose is to be the one place a value is true.

**Done here.** All four `Makefile`s, all four overlay comments, and
`applications/README.md` now name the cluster repo and path explicitly instead
of implying a local `documents/` file. The `require-registry` guard still fails
the build when `REGISTRY` is unset, and its message points at the Makefile
header where that path is spelled out.

**Note for whoever does that:** `REGISTRY` is still one of six values marked ❌
unverified in `environment.md`. The file is written; several of its answers are
not, and each carries the command that produces it.

`key-custody.md` now exists alongside it, in the same directory.

### A test key that was never actually locked — the quiet kind of false pass

**Phase B4.** Level 4's tests generate their own keypair rather than committing
one. The first version serialised it **without passphrase encryption**, so
`importKeyring` unlocked nothing and the wrong-passphrase injection passed with
any passphrase at all. The test was green and proving nothing.

It was caught only because `importKeyring` logs `keys_unlocked`, which read `0`.
Without that field the suite would have looked fine indefinitely.

**Resolution:** `newTestKey` now calls `PrivateKey.Encrypt` on the primary key
**and every subkey** before serialising with `SerializePrivateWithoutSigning`
(re-signing needs the key decrypted, which is what was just undone). The import
log now reads `keys_unlocked=2`, and the wrong-passphrase test has something
real to fail against.

Generalises: a negative test that has never been *seen* to fail is a hypothesis,
the same way an unrun denial test is. When a test asserts that something is
rejected, confirm it rejects for the reason intended — the CLAUDE.md rule 5
argument applies to unit tests too.

Encrypted **subkeys** matter here beyond the test: a message is usually
encrypted to a subkey rather than the primary, so unlocking only the primary
gives "imported fine, cannot decrypt."

### `0400` and tmpfs cannot be verified on Windows

**Phase B4.** `TestKeyFileIsWrittenReadOnly` asserted no group/other permission
bits. Windows has no POSIX mode model — Go synthesises `0444` for any read-only
file regardless of what `OpenFile` requested — so it failed on a correct
implementation.

**Resolution:** the test asserts the file is non-writable on Windows and skips
the exact-mode check with a message saying where the real check happens. The
`0400` and tmpfs guarantees are verified in-cluster:

```bash
kubectl exec deploy/level4-pgp-decrypt -- ls -l /keys
kubectl exec deploy/level4-pgp-decrypt -- df -h /keys   # must report tmpfs
```

The O_EXCL clobber assertion runs on every platform — it was originally placed
after the skip, where it never executed on this workstation.

Third item now on the "cannot be verified here" list, with `go test -race` and
the live-cluster injections. Worth stating plainly: **the Windows workstation
can prove logic, not deployment behaviour.**

### The Level 3 demo table has no name in either PRD

**Phase B3.** Stage A Phase A7 step 2 says to seed "a demo table so Level 3 has
something real to `SELECT`" and never names it. `/query` needs an identifier.

**Resolution:** the table name is `DEMO_TABLE`, defaulting to `demo`, set in the
Deployment with a TODO. The name is interpolated through
`pgx.Identifier{}.Sanitize()` rather than concatenated raw — it comes from the
environment, which is not a trust boundary worth assuming.

**Confirmed against Stage A — the default is correct, no TODO left.** Stage A's
seed originally created `widgets`; it was renamed to `demo` to match this
default, so Level 3 needs no `DEMO_TABLE` override. Source of truth:
`script-manifest/utility-hashicorp-vault/base/postgres/seed-configmap.yaml` in
the cluster repo. If that seed is ever re-edited, this is the coupling to check.

`/query` also runs `SELECT current_user` independently of the demo table, so a
wrong table name produces a clean `42P01` classified as a *database* fault
rather than looking like a credential problem.

### The lease deadline was a data race, and the race detector cannot run here

**Phase B3.** The lease manager extends `ExpiresAt` on every renewal while
`/readyz` and `/creds-info` read it. As first written these were bare struct
fields — a genuine race, and one that would surface as nonsense TTLs on
`/creds-info` under load long before it surfaced as a crash.

**Resolution:** the mutable lease state is behind a mutex on `dbCredential`,
reached through `lease()` and `extend()`. Fixed by construction rather than by
testing, because `go test -race` **cannot run on the Windows workstation**: the
race detector needs cgo, and there is no C compiler installed. `make race` runs
it on the dev workspace, and that is where the guarantee actually gets checked.

Worth remembering for Levels 1, 2 and 4 too — none of their local test runs
prove anything about concurrency.

### Stage B's `vault-ca` ConfigMap has the same staleness hazard the Stage A store avoided

**Phase B0.** Stage A's `ClusterSecretStore` reads `vault-tls` in the `vault`
namespace directly, specifically to avoid a copied CA going stale when
cert-manager rotates it (see Stage A below). Stage B cannot do the same trick:
a pod may only mount a Secret or ConfigMap from **its own namespace**, and
Levels 2–4 run in `poc-hashicorp-vault-application`. PRD B0 step 6 therefore
calls for a `vault-ca` ConfigMap, which is a copy — with exactly the staleness
failure mode, surfacing as an unexplained TLS error weeks later.

**Not yet resolved.** Options, cheapest first: have ESO sync `vault-tls` into
the app namespace so the copy self-heals; add a renewal hook; or accept it and
write the manual re-copy into the cert-rotation runbook. Worth settling in B0
rather than discovering it after the first cert renewal. Whatever is chosen, the
answer must not be `InsecureSkipVerify`.

### The Level 1 "zero Vault references" grep has two incompatible definitions

**Phase B1.** The PRD (Stage B, Phase B1, step 2) scopes the check to
`grep -ri vault level1-env-secret/main.go go.mod`. The Stage B playbook writes
it as `grep -ri vault applications/level1-env-secret/` — the whole directory.

The broader form **cannot pass**: `deploy/base/externalsecret.yaml` must name
the `vault-backend` ClusterSecretStore, and the README discusses the pattern at
length.

**Resolution:** CLAUDE.md says the PRD wins, so `make verify` implements the
PRD's narrower check against `main.go` and `go.mod`. The claim the level makes
is about the *application module* — its source and its dependencies — not about
the manifests that wire it up. The manifests are the platform's business, which
is the whole point of the level.

### Module paths must not be repository-qualified

**Phase B0.** The PRD's structure comments suggest `module .../level1-env-secret`.
A repository-qualified path would be
`github.com/Adhito/poc-sre-app-golang-pattern-vault-hashicorp/applications/level1-env-secret`
— which contains the string `vault`, in `go.mod`, and **fails Level 1's own
acceptance criterion.**

**Resolution:** bare module paths (`module level1-env-secret`). These modules
are never `go get`-ed; they are built in place by their `Containerfile`, so a
resolvable path buys nothing. It also reinforces D2 — a bare path cannot be
imported by a sibling module even by accident.

### Grepping for `InsecureSkipVerify` flags the test that proves it is unset

**Phase B2.** `vault_login_test.go` asserts
`tr.TLSClientConfig.InsecureSkipVerify == false`. The playbook's B5 sweep is
`grep -rn "InsecureSkipVerify" applications/`, which matches that assertion and
reports a false positive.

**Resolution:** match the assignment, not the identifier:

```bash
grep -rnE "InsecureSkipVerify[[:space:]]*[:=][[:space:]]*true" applications/
```

Apply the same form in Phase B5's sweep. Deleting the test to satisfy a
literal grep would be exactly backwards.

### Prose in `go.mod` trips the "no Vault SDK" grep

**Phase B2.** Level 2's `go.mod` originally carried a comment explaining *why*
the SDK is forbidden — and named its import path to do so. The B5 check is a
plain `grep hashicorp/vault go.mod`, which matched the explanation and reported
a dependency that does not exist.

**Resolution:** the comment no longer names the import path. Same class of
problem as the `InsecureSkipVerify` grep above, and worth a general rule: when a
gate is a literal string match, keep that literal out of the prose it is
checking. Both of these fail *loudly*, which is the good case — a mechanical
gate that reports a false positive costs minutes, while one that silently passes
costs the whole control.

### NetworkPolicies are written in B0 but not activated until B5

**Phase B0.** PRD §3 lists `networkpolicy.yaml` in each level's `base/`, but
NetworkPolicy work — and crucially its *testing* — is a Phase B5 deliverable.
A default-deny applied during B1–B4 would break each level's verification in a
way that reads as an application bug.

**Resolution:** the manifests exist and are commented, but are commented out of
`base/kustomization.yaml` until B5 adds them under its own gate.

One thing to check when they are activated: `kubectl port-forward` is used for
every level's verification. Port-forward traffic originates from the node rather
than from a pod, and whether Calico admits it under `ingress: []` needs
confirming in B5. If it is refused, verification moves to an in-namespace
throwaway pod with an explicit allow, rather than weakening the policy.

### Go and base-image versions differ from the PRD's example

**Phase B0.** The PRD's `Containerfile` shows `golang:1.24`. CLAUDE.md rule 10
and Stage A D16 say the PRDs deliberately omit or stale-date versions and that
current stable must be verified at implementation time.

**Resolution:** pinned to `golang:1.26.5`, matching the toolchain actually
verified on the workstation (`go version` → `go1.26.5`), with `go 1.26` in each
`go.mod`. Both tags — `golang:1.26.5` and
`gcr.io/distroless/static-debian12:nonroot` — still need confirming against the
registry before the first build, and the distroless base should be pinned by
digest once the build host can resolve one.

### ArgoCD cannot use the local git remote

**Phase B0.** The workstation's remote is an SSH host alias
(`github.com-adhito909:Adhito/...`) that exists only in the local SSH config.
ArgoCD cannot resolve it.

**Resolution:** the Application manifests use the HTTPS URL. Before applying
`root-applications` in B0, confirm ArgoCD has a credential for the repository
(it is not public), or switch to a plain SSH URL plus a deploy key.

### Level 3 and 4 ArgoCD children deliberately absent

**Phase B0.** PRD §3 lists four children under
`argocd/applications/applications/`. Only two exist. An Application pointing at
a `deploy/overlays/onprem` path that does not yet exist syncs to a hard error.

**Resolution:** each child lands with its level's code, per the PRD's own
"level code and its manifests commit together."

---

## Stage A

### Vault 2.0 made root recovery authenticated — a break-glass identity was added

**Phase A6, found 2026-09-11 while re-verifying pins.** The pin moved from Vault
1.17 to 2.0.4. The 2.0.0 changelog lists a single "breaking" change — an SDK
change nothing here uses — but two entries filed under routine `CHANGES` break
D10's recovery model: `sys/generate-root` and `sys/rekey` are now
**authenticated by default**. D10 revokes root at the end of A6 and relies on
`operator generate-root` to get one back. On 2.x that command needs a token, so
after revocation there would be nothing to authenticate with: a lockout.

**Resolution (owner's decision):** keep the new authenticated default, rather
than set `enable_unauthenticated_access` to restore the 1.x behaviour. Added a
break-glass `userpass` identity (`bootstrap/95-create-breakglass.sh`, policy
`breakglass-admin`) that can *start* root generation and rekey, can do nothing
else, and still needs three shares to *finish*. `99-revoke-root.sh` now refuses
to revoke root unless a live break-glass login succeeds. It is a userpass
password rather than a stored token because tokens expire — a break-glass token
that silently hit its max TTL would fail exactly when needed, which is the D6
reviewer-JWT footgun again.

**Worth keeping as a lesson:** a changelog's "breaking changes" heading is the
vendor's judgement of what breaks *most* users. It is not a substitute for
reading every entry against your own design.

Also caught here: the first draft of the recovery commands generated the OTP
inline (`-init -otp="$(… -generate-otp)"`), discarding the value the final
`-decode` step needs — the regenerated root token would have been unrecoverable.
Corrected in `95-`, `99-`, and `runbooks/seal-unseal.md`.

### Three Helm values were silently ignored — caught by diffing against the chart

**Phase A2, found 2026-09-11.** Moving the chart from 0.28.1 to 0.34.1, every
key in `values-onprem.yaml` was checked against the 0.34.1 chart's own
`values.yaml`. Two were not chart keys at all and had never done anything:
`server.imagePullPolicy` (the chart reads `server.image.pullPolicy`) and
`ui.enabled_service`. Both fixed.

A third, `server.readinessProbe.path`, was flagged but is correct — the chart
supports it as a commented-out option, and its template renders an `httpGet`
probe when it is set. It matters more than it looks: the chart's **default**
probe is `exec: vault status -tls-skip-verify`, which marks a *sealed* pod **not
ready** and bypasses TLS verification. The explicit
`/v1/sys/health?…sealedcode=204` path is what makes a sealed pod pass readiness —
the premise of the seal-alert design (D15).

Wrong keys in Helm values do not error; they are simply never read. Same failure
class as a ServiceMonitor with the wrong discovery label.

**A worse problem surfaced in the same pass: the liveness probe.** It was set to
`/v1/sys/health?standbyok=true` — without `sealedcode`/`uninitcode`. That
endpoint returns 503 when sealed and 501 when uninitialised, so Kubernetes would
have killed every sealed pod about 70 seconds after start. A restarted peer could
never have been unsealed (restarted mid-unseal, back sealed, loop), and on the
first Phase A2 boot the pod would likely have died before `operator init`
finished. Fixed by giving liveness the same codes as readiness. This one would
not have been silent — it would have looked like a crash-looping chart on day
one, with nothing pointing at the probe.

### Stage A manifests live in the platform repo, not this one

**Phase A0.** D18 places Stage A under `platform/kubernetes/base/…` here, with
ArgoCD children in `argocd/applications/platform/`. The repository owner instead
put them in the cluster repo,
`poc-platform-engineering-iac-vagrant-ansible-k8s-cluster-kubeadm-calico`, under
`script-manifest/utility-hashicorp-vault/` — matching that repo's existing
`utility-*` convention, and matching ownership: Stage A is platform work.

**Resolution:** the platform half moved; Stage B is untouched and still sources
from this repo. `root-platform.yaml` now lives in the cluster repo;
`root-applications.yaml` stays here and is still not applied during Stage A.

**Consequence to be aware of.** D18's "one clone gets you everything" no longer
holds — the cross-stage references are now cross-repo. Anything in Stage B that
assumes a Stage A file is reachable by relative path will not find it.

### Kubernetes 1.29 — a failed A0 gate, proceeded past deliberately

**Phase A0.** P2 requires ≥ 1.32 and says to bump if still on 1.29 (EOL). The
control plane reports **v1.29.15**; the kubelets are **v1.29.0** (the apt pin in
the cluster repo's `settings.yaml`). The owner chose to record the gate as failed
and design around it rather than upgrade a cluster shared with the observability
and tracing-poc teams.

**Resolution:** every component is pinned to the newest release that supports
1.29, verified against upstream on 2026-09-11 — cert-manager `v1.18.6`, Vault
chart `0.34.1` (Vault `2.0.4`), ESO `0.13.0`, local-path-provisioner `v0.0.37`,
PostgreSQL `16.15-alpine`. Rule 4 says phase gates are hard, so this is recorded
as an accepted deviation, not a passed gate. The upgrade remains outstanding.

**ESO is in the same position as cert-manager.** Its support table shows 0.13.x
(`k8s 1.19 → 1.31`, EOL 2025-02-04) as the newest line for 1.29 — every release
from 0.14 needs ≥ 1.32. Two of the five pins are end-of-life *because of* this
gate. Vault itself is unaffected: chart 0.34.1 declares `kubeVersion >= 1.20`.

**The cost is now concrete (verified 2026-09-11).** In cert-manager's support
matrix, 1.18 is the newest line that runs on Kubernetes 1.29 — and 1.18 reached
**end of life on 2026-03-10**. Staying on 1.29 means installing a cert-manager
that no longer receives fixes, for the component that issues Vault's TLS. That is
the strongest single argument for doing the upgrade before Stage A goes live
rather than after.

### ESO `ClusterSecretStore` uses `v1beta1`, not `v1`

**Phase A8.** PRD step 3 writes `apiVersion: external-secrets.io/v1`. That API
only exists in newer ESO releases; the pin above (0.10.7, chosen for 1.29
support) serves `v1beta1`.

**Resolution:** the manifest uses `v1beta1`. If A0 settles on an ESO new enough
to serve `v1`, switch it — `v1beta1` stays served either way. This is a
version-compatibility consequence of the 1.29 decision, not a disagreement with
the PRD.

### The CA is read from the Secret, not copied into a ConfigMap

**Phase A8.** PRD step 3 has `caProvider` read a `vault-ca` ConfigMap in
`external-secrets`, which implies copying `ca.crt` out of the `vault-tls` Secret.

**Resolution:** a `ClusterSecretStore` is cluster-scoped and may reference any
namespace, so it reads `vault-tls` in `vault` directly. This removes a manual
copy step and, more importantly, a failure mode: a copied CA goes stale the
moment cert-manager rotates it, surfacing weeks later as an unexplained TLS
error.

### The `ServiceMonitor` targets the headless Service, not `vault`

**Phase A9.4.** PRD step 17 says to target the `vault` Service. In the chart,
`vault`, `vault-active`, and `vault-standby` all carry the same
`app.kubernetes.io` labels, so a label selector cannot pick out just one — it
matches several and scrapes the same pods repeatedly.

**Resolution:** target `vault-internal` (headless), uniquely identified by
`vault-internal: "true"`. It yields one target per pod, which satisfies the
PRD's actual requirement — per-peer seal status — more directly than the named
Service would.

### Prometheus is not operator-managed — A9.4 cannot be done additively

**Phase A0.5 — resolved 2026-09-11 by `preflight.sh`.** Check 5a:
`servicemonitors.monitoring.coreos.com` and
`prometheusrules.monitoring.coreos.com` are **absent**. The observability stack
(Grafana LGTM, `observability` namespace, owned by another team's ArgoCD app)
does not run the Prometheus Operator.

**Consequence.** D15's additive-object approach is unavailable. Adding a scrape
target would mean editing a scrape config that currently works, which Rule 8
forbids. Per the PRD this is reported, not worked around: the `vault-monitoring`
child has been moved from `argocd/applications/` to `argocd/disabled/`, so
`root-platform` does not sync it. The manifests stay intact for the day the CRDs
exist.

**What this leaves.** There is no automated seal detection. A sealed follower —
which passes its readiness probe — is invisible until someone runs the manual
check in `runbooks/seal-unseal.md`. The PRD names that gap; it is now the actual
state rather than a hypothetical, and should be treated as such.

**Open for the observability team, not this POC:** either install the Prometheus
Operator CRDs, or add a static scrape job for `vault-internal:8200/v1/sys/metrics`
to their own config. Both are their decisions. Checks 5b and 5c are moot until
one happens.
