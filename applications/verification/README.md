# Phase B5 — verification scripts

Phase B5's goal, from the Stage B PRD: **prove the four levels are genuinely
decoupled, and that nothing leaks.** These scripts turn its twelve steps into
repeatable checks that write their results into `documents/results/phase-b5/`.

All four levels share one namespace, so the ServiceAccount name is the *only*
thing standing between Level 1 and the PGP private key. Most of what follows is
about testing that boundary from every side. For a plain-language explanation
of roles, policies and why one PRD test was broken, read
[`documents/vault-roles-and-policies.md`](../../documents/vault-roles-and-policies.md)
first.

> **Status: written, not yet run against a cluster.** The pure-bash logic is
> tested locally (`test/harness.sh`, 37 checks). The `jq` filters have **not**
> executed anywhere yet — the workstation they were written on has no `jq`. Run
> the harness and `shellcheck` on the dev workspace before the first real run.

---

## Run order

| # | Script | Touches the cluster | Covers (PRD §5 B5) |
|---|---|---|---|
| 0 | `00-preflight.sh` | read-only | Environment can produce meaningful results |
| 1 | `10-independence.sh` | read-only | Steps 1, 5, plus isolated rendering |
| 1′ | `10-independence.sh --destructive` | **deletes and redeploys levels** | Steps 2, 3, 4 |
| 2 | `20-privilege-matrix.sh` | logs in to Vault; reads; revokes its own tokens | Step 10 — the 4×4 matrix and the login grid |
| 3 | `30-hardening-sweep.sh` | read-only | Steps 6, 7, 8, 9, 12 |
| — | *activate the NetworkPolicies (a git change — see below)* | | |
| 4 | `40-networkpolicy.sh` | creates and deletes probe pods | Step 11 |

**`10-independence` must run before the NetworkPolicies are activated.** Its
health checks reach each level through the API server's service proxy, which
`ingress: []` may refuse once it is in force.

Every script exits non-zero if anything failed **or was skipped**. A gate check
that did not run is a failed gate (CLAUDE.md rule 5), so a skip is never quietly
treated as a pass.

---

## Prerequisites

Run on the **Linux dev workspace**, not the Windows workstation.

| Need | For |
|---|---|
| `bash` ≥ 4, `kubectl`, `jq` ≥ 1.6, `curl`, `git` | everything |
| `gitleaks` | step 6. Without it, step 6 is **skipped**, which fails the run |
| `VAULT_ADDR` (https, the MetalLB VIP), `VAULT_CACERT` | 00, 20, and 30's step 9 |
| `VAULT_TOKEN` with `list`+`read` on `auth/kubernetes/role/*` | 30's step 9 only. Without it, step 9 is skipped |
| `PROBE_IMAGE` — a **pinned** image with `sh`, `sleep`, `curl`, pullable by the cluster | 40's connection probes. No default, deliberately: guessing an image or tag is what CLAUDE.md forbids |
| Permission to `create serviceaccounts/token` in the namespace | 20 mints a short-lived token per ServiceAccount |

```bash
export VAULT_ADDR=https://<metallb-vip>:8200
export VAULT_CACERT=/etc/vault-poc/ca.crt
```

**Before the first run:**

```bash
bash applications/verification/test/harness.sh
```

```bash
shellcheck -x applications/verification/*.sh
```

---

## What each script does

### `00-preflight.sh`

Checks the API server, namespace, `vault-ca` ConfigMap, Vault health and
version, that all four Deployments are available, that all four ServiceAccounts
exist, that no overlay still carries the registry placeholder, and that the
Level 4 fixture exists. It also reports ArgoCD's sync policy, so the destructive
prerequisite below is not a surprise.

It **cannot** see whether B1–B4 have been signed off. CLAUDE.md rule 4 says B5
results only count once they have; check the phase commit bodies.

### `10-independence.sh`

**Read-only:** all four levels healthy *by endpoint*; no `go.mod` references a
sibling; no root `go.mod` or `go.work`; and each level's overlay renders from a
clean clone **with no other level present** — proving no manifest reaches
outside its own directory.

**`--destructive`:** delete Level 2 and prove 1, 3 and 4 are healthy **and
untouched** (same pod UIDs, not merely healthy pods); restart Level 3 and prove
the others' pods are untouched; delete everything and deploy **only** Level 4
from a clean checkout. Everything is restored from the committed state on exit,
even if the script fails partway.

**ArgoCD must not be self-healing while this runs.** With automated sync, ArgoCD
recreates whatever the script deletes within seconds, and "delete Level 2, the
others are fine" would then test nothing. The script checks and refuses, and
prints the exact commands. Disable the root app first and re-enable it last:

```bash
argocd app set root-applications --sync-policy none
```

The script does not change this itself. It is persistent cluster configuration,
so that decision stays with a human.

### `20-privilege-matrix.sh`

The core of B5. Each ServiceAccount's identity is a short-lived token from
`kubectl create token`. Vault validates it through the same TokenReview path as
a pod's own token, so the identity Vault sees is identical. This replaces the
PRD's throwaway pod per SA; it tests authorization, while `40-networkpolicy`
tests the network path.

**Part A — login grid (5×4).** Every ServiceAccount, plus `default`, tries every
role. Its own role must admit it **with exactly the expected policies**. Every
other role must refuse it — and **refuse for the right reason**:

| Vault's refusal | Verdict |
|---|---|
| `service account name not authorized` | ✅ pass — the binding was tested |
| `invalid role name` | ❌ fail — the role does not exist, so nothing was tested |
| `namespace not authorized` | ❌ fail — the role binds the wrong namespace |
| anything else | ❌ fail — confirm the wording for this Vault version |

This is the fix for the PRD's broken `level4-pgp` test. The refusal wording is
version-sensitive: every run records Vault's version and every raw message. If a
release rewords it, set `AUTHZ_DENY_PATTERN` — **never loosen it to make a run
go green.**

**Part B — read matrix (4×4).** Each ServiceAccount logs in through its own role
and tries every secret. Expected: **4 allows, 12 denials.** A denial only counts
if it is a `403 permission denied`.

Responses to *allowed* reads contain the secrets, so they are discarded unread.
The `level3-app` row creates a real database credential; revoking the row's
token revokes that lease too, so no Postgres role is left behind.

Owner decisions this encodes: `level1-app` **has** a role (its row expects
`level1/app` → allow), and there is **no** role named `level4-pgp`.

### `30-hardening-sweep.sh`

- **Step 6:** `gitleaks`, with `--redact`.
- **TLS bypass:** none anywhere in `applications/` or `argocd/`.
- **Step 7:** every level's current *and previous* container logs, searched for
  PGP private key blocks, Vault tokens, DSNs carrying a password, and passphrase
  or password assignments. **Matching lines are never printed** — only the pod,
  the pattern's name and a count. Printing the line would put the secret it just
  found into the terminal and the results file. Level 4's decrypted demo message
  on stdout is by design and is not targeted.
- **Steps 8 and 12:** on live pods — non-root, read-only root filesystem, no
  privilege escalation, `drop: [ALL]`, `RuntimeDefault` seccomp, CPU and memory
  requests *and* limits, and the expected ServiceAccount.
- **Explicit `serviceAccountName`:** checked in the **rendered manifests**, not
  live pods. A live pod always shows *some* ServiceAccount, because Kubernetes
  fills in `default`; only the manifest shows whether it was set on purpose.
- **Step 9:** every role's bindings. No wildcard SA or namespace; each level's
  SA bound to exactly one role (its own); `default` bound to none; and no role
  named after a policy.

### `40-networkpolicy.sh`

**Activation is a git change, not something the script does.** In each level's
`deploy/base/kustomization.yaml`, uncomment `- networkpolicy.yaml`, commit, and
let ArgoCD sync. Applying policies by hand would be drift outside GitOps.

The script then checks:

1. **The policies are active in git, and no selector has been rewritten.** This
   guards against a real bug found in B5: `commonLabels` once injected labels
   into the egress selectors, which would have denied DNS to every level.
2. **The policies exist in the cluster.**
3. **The live labels they depend on exist**: `k8s-app=kube-dns` on the DNS pods,
   `app=postgres` on Stage A's Postgres, and `kubernetes.io/metadata.name` on
   the namespaces. If any is missing, its rule silently matches nothing.
4. **The four apps are still Ready.** Kubelet probes have to survive `ingress: []`.
5. **Real connection attempts** from a probe pod wearing each level's label.

The probe pod borrows the level's `app` label so the policy treats it exactly
like that level. Its readiness check always fails, so it never joins the level's
Service endpoints. The level's ReplicaSet will not adopt it either, because a
Deployment's ReplicaSet also selects on `pod-template-hash`.

Each probe classifies an attempt as **ALLOW** (connected), **BLOCK** (dropped),
or one of three non-verdicts: **REFUSED** (packets reached the target, so the
policy did *not* block), **NORESOLVE** (no packet ever met the policy), or
**ERROR** (the probe could not run). Only ALLOW and BLOCK count. A dead probe pod
or a mistyped Service name must never read as "blocked".

Each probe pod also **calibrates itself** before testing anything. It connects to
kube-dns on TCP 53 (allowed for every level, so it must read ALLOW) and to the
API server (allowed for none, so it must read BLOCK). If either control reads
wrong, that level's results are discarded instead of reported.

| From | Vault | Postgres | Another level |
|---|---|---|---|
| Level 1 | **blocked** — it never talks to Vault | blocked | blocked (Level 2, Level 3) |
| Level 2 | allowed | blocked | blocked (Level 3) |
| Level 3 | allowed | **allowed** | blocked (Level 1) |
| Level 4 | allowed | blocked | blocked (Level 3) |

---

## Results

Each run writes `documents/results/phase-b5/<UTC-timestamp>-<script>.md`. Those
files contain the verdicts, the matrix and probe tables, Vault's version and its
raw refusal messages. **They never contain secrets**, and they are meant to be
committed: CLAUDE.md lists the 4×4 matrix results as a deliverable.

Each file records the commit it ran against, and flags a dirty working tree,
because results that cannot be tied to a commit cannot be reproduced.

---

## Deviations from the PRD

All are recorded in `documents/troubleshooting.md`.

| PRD says | These scripts do | Why |
|---|---|---|
| Matrix "from a throwaway pod running as each SA" | Token from `kubectl create token` | The identity Vault validates is identical, with no image or scheduling dependency. The network path is tested separately by `40` |
| SA/role mismatch: request role `level4-pgp` | Request the real `level4-app` role, assert on the reason | `level4-pgp` is a policy. Requesting it tests nothing |
| One mismatch cell | Full 5×4 login grid, including `default` | Costs nothing extra to run |
| `level1-app` row: per the matrix | Same, with a role | Owner decision: Stage A A6.6 over Stage B B1 |
| B2 injection 1, B4 injection 6 | Superseded by the matrix | With one SA per role, "login succeeds, read 403" cannot happen |
