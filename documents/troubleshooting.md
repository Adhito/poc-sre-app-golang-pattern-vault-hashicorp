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

Needs deciding before Phase B0 runs:

- Does `environment.md` live in the cluster repo next to the Stage A manifests,
  or is a copy kept here for Stage B to read?
- If it stays in the cluster repo, Stage B's references should name the repo and
  path explicitly rather than implying a local file.

Either answer is fine; the current state — a reference to a local path that is
not populated by anything — is the one that is not. Same question applies to
`key-custody.md` and the three runbooks, which Stage B's docs cross-reference.

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
cluster is on v1.29.0. The owner chose to record the gate as failed and design
around it rather than upgrade a cluster shared with the observability and
tracing-poc teams.

**Resolution:** every component is pinned to a version supporting 1.29 —
cert-manager `v1.16.2`, Vault chart `0.28.1` (Vault `1.17.6`), ESO `0.10.7`,
PostgreSQL `16.6-alpine`. Rule 4 says phase gates are hard, so this is recorded
as an accepted deviation, not a passed gate. The upgrade remains outstanding.

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

### Prometheus may not be operator-managed — A9.4 is at risk

**Phase A0.5, unresolved.** The observability stack on this cluster is Grafana
LGTM (`observability` namespace, owned by another team's ArgoCD app). Its
metrics store is Mimir, which does not necessarily run the Prometheus Operator.

**Open.** If check 5a shows `servicemonitors.monitoring.coreos.com` and
`prometheusrules.monitoring.coreos.com` are absent, D15's additive-object
approach is not available, and adding a scrape target would mean editing a
config that currently works — which Rule 8 forbids. The `vault-monitoring` child
is written and ready for the case where the CRDs exist; if they do not, it
should be removed from the applications directory and the finding reported
rather than worked around.

The discovery labels (check 5b) are likewise unknown; both objects carry a
placeholder `release: kube-prometheus-stack` that must be corrected before they
will be scraped. Wrong label = applies cleanly, never scraped, no error.
