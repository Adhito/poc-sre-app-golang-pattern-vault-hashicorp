# PRD — HashiCorp Vault on On-Prem Kubernetes Cluster

**Document ID:** PRD_HashiCorp_Vault_Kubernetes_Cluster_Onprem
**Version:** 1.4.0
**Stage:** A (Platform / Vault deployment)
**Status:** Design locked — ready for Claude Code handoff
**Owner:** Adhito (SRE)
**Target cluster:** `learning-labs-developer-workspace-type-01`
**Companion document:** `PRD_HashiCorp_Vault_Application_Golang.md` (Stage B)

**Changelog**
- **1.4.0** — Key custody resolved to `~/.credentials/vault-poc/` on the host, outside the repo tree, with a password-manager copy as the durable second (D20). Node-loss data loss recorded as an explicit accepted risk rather than a mitigated one (§3.1, §8). Phase A9.3 reframed as a learning deliverable rather than a DR requirement. Longhorn added to backlog.
- **1.3.0** — Single repository with stage-split folders (D18); ArgoCD app-of-apps with two stage-scoped root Applications and sync waves (D19); unseal-key custody made an explicit Phase A2 gate with `docs/key-custody.md` (D20).
- **1.2.0** — Metrics scraping and seal alerting brought back into scope as **additive-only** objects (D15). Phase A9.4 becomes a build phase. Phase A0 gains Prometheus compatibility checks. Audit remains `stdout` / `kubectl logs` (D14 unchanged).
- **1.1.0** — Confirmed decisions applied: Helm chart as ArgoCD source (D1); worker count fixed at 2 (D4); `local-path-provisioner` confirmed (P8); ingress replaced by MetalLB LoadBalancer + NodePort 30004 (D8); licensing resolved (§5.1); LGTM integration deferred, Phase A9 rescoped to audit + DR (D14, D15).
- **1.0.0** — Initial design.

---

## 1. Purpose

Stand up a production-shaped HashiCorp Vault on the `learning-labs-developer-workspace-type-01` on-prem cluster, and prove out the full operational surface an SRE actually owns: storage, sealing, TLS, identity, policy, secrets engines, audit, backup, and restore.

This is a **learning-grade POC with production-shaped decisions**. Every shortcut taken for POC convenience is named explicitly and paired with the production alternative, so nothing silently graduates into a real environment.

The deliverable is not "Vault is running." The deliverable is a **repeatable, GitOps-managed Vault platform** that Stage B applications can consume through four distinct integration patterns.

---

## 2. Scope

### 2.1 In scope

| Area | Included |
|---|---|
| Deployment | Official `hashicorp/vault` Helm chart, ArgoCD multi-source Application |
| Storage | Integrated Storage (Raft) on `local-path-provisioner` PVCs |
| Seal | Shamir manual unseal; auto-unseal options documented, not built |
| TLS | End-to-end TLS on the Vault listener via cert-manager |
| Exposure | MetalLB `LoadBalancer` (primary) + NodePort `30004` (secondary) |
| Identity | Kubernetes auth method, policies, roles, entity/alias model |
| Secrets engines | KV v2, Database (PostgreSQL), plus a KV-stored PGP key for Stage B Level 4 |
| Consumption plumbing | External Secrets Operator (ESO) install + `ClusterSecretStore` |
| Audit | File audit device to `stdout`, readable via `kubectl logs` |
| Metrics | `ServiceMonitor` + `PrometheusRule` — **additive objects only**, no edits to the existing stack (D15) |
| Operations | Seal/unseal runbook, Raft snapshot backup + restore drill, upgrade path |

### 2.2 Explicit non-goals (v1)

These are named so they don't leak into the implementation.

| Non-goal | Rationale | Disposition |
|---|---|---|
| **Any modification to the existing LGTM stack** | Confirmed boundary: this POC may *add* objects Prometheus discovers on its own (`ServiceMonitor`, `PrometheusRule`, a new dashboard). It may **not** edit existing scrape configs, alert rules, dashboards, Alertmanager routes, or the log collection pipeline. If a step appears to require an edit, it stops and asks (D15) | Boundary, not a deferral |
| **Grafana dashboard (beyond an optional new one)** | Metrics land in Prometheus and are queryable; a dashboard is presentation, and the seal alert is what actually protects you | Optional in A9.4; not gated |
| **Audit logs → Loki** | Would require touching the log collection pipeline, which crosses the boundary above. Audit stays on `stdout` via `kubectl logs` (D14) | Backlog |
| **Ingress for Vault** | MetalLB LoadBalancer + NodePort supersede it (D8). Also sidesteps the ingress-nginx retirement question entirely for this workload | Removed from scope |
| **Cloud KMS auto-unseal** | No cloud dependency on-prem; adds an external trust anchor that changes the DR story entirely | Backlog — Stage A v2 (tied to cloud expansion) |
| **Vault Enterprise features** (namespaces, replication, HSM, control groups) | Licensed; the POC targets Vault Community | Out of scope permanently |
| **Vault Agent Injector sidecar pattern** | A fourth consumption pattern; Stage B already covers three | Backlog — Stage B Level 5 |
| **Multi-cluster / multi-region replication** | Community edition can't do it; DR is snapshot-based here | Out of scope |
| **Vault as a CA (PKI engine)** for workload certs | Large surface area, deserves its own POC | Backlog |
| **Cloud provider expansion (EKS/GKE)** | Explicitly deferred per requirement | Backlog — Stage A v2 |
| **A third worker node** | Confirmed not currently possible. Drives D4 and the accepted quorum risk in §8 | Backlog — revisit on capacity |
| **Auto-unseal via a second "unsealer" Vault** | Implemented as a *documented option only*, not deployed | Documented in Phase A3 |

### 2.3 A distinction worth stating up front

**Vault is a secrets *authority*, not a secrets *distribution mechanism*.** Vault's job is to decide who may hold which secret, for how long, and to record that decision. Getting the secret onto a pod is a separate problem with several valid answers (ESO, Agent Injector, direct API, CSI driver). Stage A builds the authority. Stage B exercises the distribution mechanisms.

Conflating the two is the most common Vault design error — teams treat it as "a nicer etcd" and never enable dynamic secrets, leases, or revocation, which is where the actual security value lives.

---

## 3. Environment

**Cluster:** `learning-labs-developer-workspace-type-01`

| ID | Fact | Verification |
|---|---|---|
| P1 | 1 control plane + 2 workers, `192.168.56.0/24`, Calico CNI, Vagrant/Ansible provisioned | `kubectl get nodes -o wide` |
| P2 | Kubernetes ≥ 1.32 — **bump if still on 1.29 (EOL)** | `kubectl version` |
| P3 | Dev workspace VM has a second NIC on `192.168.56.20` with L3 reachability to the node subnet | `ping` a node IP |
| P4 | MetalLB with an address pool on the node subnet — **required**, it is the primary exposure path (D8) | `kubectl -n metallb-system get ipaddresspool` |
| P5 | **Worker count is fixed at 2.** Not negotiable for v1 | Drives D4 |
| P6 | ArgoCD installed; **Helm-source Applications must be permitted** by the ArgoCD config (D1) | `argocd app list` |
| P7 | Private registry (`registry:2`) reachable and trusted by containerd on all nodes | `crictl pull <registry>/hello` |
| P8 | **Rancher `local-path-provisioner`** is the StorageClass, `volumeBindingMode: WaitForFirstConsumer` | `kubectl get sc` |
| P9 | Podman available on the dev workspace | `podman version` |
| P10 | LGTM stack running in-cluster. **Prometheus is added to, never edited** (D15) | See Phase A0.5 — three compatibility checks |

**Namespaces**

| Namespace | Contents |
|---|---|
| `vault` | Vault StatefulSet, Services, TLS, cert-manager Certificate |
| `external-secrets` | ESO controller and its ServiceAccount |
| `poc-hashicorp-vault-application` | Stage B applications and the POC PostgreSQL |

The `vault` namespace name is deliberately plain — it should read like a platform namespace, not a POC artifact, so that promoting this design later requires no renaming (D17).

### 3.1 `local-path-provisioner` — understand the consequence

`local-path` creates a hostPath-backed PV on whichever node first schedules the pod, and **pins it there**. Implications you are accepting:

- A Raft peer whose node is lost loses its data volume. It cannot simply reschedule — it must be removed from the Raft cluster and re-joined empty, or restored from snapshot.
- PVCs are not portable between nodes. `kubectl delete pod` is safe; node failure is not.
- Combined with D4 (2 workers, soft anti-affinity), this is why **Phase A9's restore drill is the most important phase in this document.**

**There is no storage-layer safety net.** `local-path-provisioner` is a *provisioner*, not a storage system — it creates a directory on a node and hands it over as a PV. It does not implement the CSI snapshot interface, so `VolumeSnapshot` objects do not work against it. Vault's own `operator raft snapshot` is the only backup mechanism in this design. (Rancher's **Longhorn** does provide replicated block storage with real volume snapshots and would remove the node-pinning problem entirely — logged as backlog, out of scope here.)

**Accepted, explicitly:** losing a worker node means losing that peer's data outright, and on this 2-worker topology losing the wrong node means losing quorum and rebuilding. This is a development environment and that trade is deliberate. It is recorded in §8 as an *accepted* risk, not a mitigated one — the mitigation is that the whole cluster is reproducible from Vagrant, Ansible, git, and the bootstrap scripts.

This is the correct choice for the lab. It is not the correct choice for production, and the runbook must say so.

---

## 4. Architecture

### 4.1 Target topology

```
┌─ Dev Workspace VM (192.168.1.10 / 192.168.56.20) ─────────────┐
│  vault CLI  ·  kubectl  ·  argocd  ·  podman  ·  browser      │
│  VAULT_ADDR=https://<metallb-vip>:8200                        │
│  VAULT_CACERT=/etc/vault-poc/ca.crt                           │
└────────────┬──────────────────────────┬───────────────────────┘
             │ primary                  │ secondary / fallback
             │ HTTPS :8200              │ HTTPS :30004
             ▼                          ▼
   ┌─ Service: vault-lb ────┐   ┌─ Service: vault-nodeport ──┐
   │ type: LoadBalancer     │   │ type: NodePort  30004      │
   │ MetalLB VIP            │   │ any node IP                │
   │ → vault-active :8200   │   │ → vault-active :8200       │
   └───────────┬────────────┘   └────────────┬───────────────┘
               └──────────────┬──────────────┘
                              │  TLS terminated by Vault itself
                              │  (no proxy, no re-encryption)
                              ▼
┌─ namespace: vault ─────────────────────────────────────────┐
│                                                             │
│  StatefulSet vault  (3 replicas, Integrated Storage / Raft) │
│    ├─ vault-0   PVC (local-path, pinned to its node)        │
│    ├─ vault-1   PVC (local-path, pinned to its node)        │
│    └─ vault-2   PVC (local-path, pinned to its node)        │
│         each: cert-manager TLS + audit device → stdout      │
│                                                             │
│  Chart-provided Services:                                   │
│    vault           → all pods                               │
│    vault-active    → leader only  ◄── both exposure paths   │
│    vault-standby   → followers                              │
│    vault-internal  → headless, Raft peer discovery          │
│                                                             │
│  ServiceAccount: vault  (+ system:auth-delegator)           │
│  Secret: vault-reviewer-token  (non-expiring, D6)           │
└──────────┬──────────────────────────────────────────────────┘
           │ TokenReview API
           ▼
     Kubernetes API server ── OIDC issuer ── SA token validation
           ▲
           │ auth/kubernetes/login  (SA JWT → Vault token)
           │
┌──────────┴──────────────────┬───────────────────────────────┐
│ namespace: external-secrets │ ns: poc-hashicorp-vault-       │
│   ESO controller            │     application                │
│   SA: external-secrets      │   Stage B Levels 1–4           │
│   ClusterSecretStore ───────┘   PostgreSQL (Level 3)         │
└──────────────────────────────────────────────────────────────┘

  ┌─ Existing LGTM stack (in-cluster, NOT modified) ──────────┐
  │  Prometheus ◄── ServiceMonitor (new object, additive)      │
  │             ◄── PrometheusRule  (new object, additive)     │
  │                     ▲                                      │
  │                     └── scrapes vault:8200/v1/sys/metrics  │
  │  Loki / Tempo / Grafana — untouched                        │
  └────────────────────────────────────────────────────────────┘

  Audit log: `stdout` → `kubectl logs -n vault` only (D14).
  Not shipped to Loki — that would mean editing the log pipeline.
```

### 4.2 Why two exposure paths (D8)

They fail differently, which is the point:

- **MetalLB LoadBalancer** is the documented path. Stable VIP, survives node changes, behaves like a real environment.
- **NodePort 30004** is the break-glass path. If MetalLB's speaker pods are down, its pool is exhausted, or ARP behaves oddly on the host-only network, you can still reach Vault directly on any node IP — including to unseal it. A seal event you cannot reach Vault to fix is the worst possible failure in this design, so a second path that depends on nothing but kube-proxy is worth the small extra surface.

Both point at `vault-active`, so writes always land on the Raft leader and no request-forwarding or redirect behaviour is involved. **TLS is terminated by Vault in both cases** — nothing proxies or re-encrypts, which keeps the trust model trivial to reason about.

### 4.3 The Kubernetes auth handshake (the thing to internalize)

This sequence is the conceptual core of Stage A. Stage B Level 2 reimplements it by hand.

```
 pod                    Vault                  K8s API server
  │                      │                          │
  │ 1. read own SA JWT   │                          │
  │    from projected    │                          │
  │    volume            │                          │
  │                      │                          │
  │ 2. POST auth/kubernetes/login                   │
  │    {role, jwt} ─────►│                          │
  │                      │ 3. TokenReview(jwt)      │
  │                      │    using reviewer JWT ──►│
  │                      │                          │
  │                      │◄── 4. {authenticated,    │
  │                      │        ns, sa name, uid} │
  │                      │                          │
  │                      │ 5. match ns+sa against   │
  │                      │    the Vault role's      │
  │                      │    bound_service_account_*│
  │                      │                          │
  │                      │ 6. mint Vault token with │
  │                      │    the role's policies   │
  │◄─── {client_token, lease_duration, renewable}   │
  │                      │                          │
  │ 7. GET secret with X-Vault-Token header         │
  │ ────────────────────►│                          │
```

**Key insight:** the pod never holds a Vault credential at rest. Its identity *is* its Kubernetes ServiceAccount. Vault trusts the cluster's word about who the caller is, then applies its own authorization on top. This is why the reviewer JWT and issuer configuration (D6) are the trust anchor for the entire scheme.

---

## 5. Decision log

| ID | Decision | Rationale | Rejected alternatives |
|---|---|---|---|
| **D1** | Deploy the **official `hashicorp/vault` Helm chart** as an **ArgoCD multi-source Application**: chart from `https://helm.releases.hashicorp.com`, `values-onprem.yaml` from the git repo | Chart encodes StatefulSet ordering, Raft peer discovery, and the active/standby Services correctly. Multi-source keeps values under git review without vendoring the chart. Upgrades become a pinned-version bump | Kustomize `helmCharts:` inflation (works, but adds a render step and obscures chart upgrades); hand-written manifests (high error rate, no upgrade path); Bank-Vaults operator (a second abstraction to learn simultaneously) |
| **D2** | **Integrated Storage (Raft)**, not Consul | Consul means operating a second distributed system for no POC benefit. Raft is the vendor default and the on-prem norm | Consul backend (deprecated posture); file backend (no HA, no snapshot API) |
| **D3** | **Phased replica count: 1 → 3.** Phase A2 runs single-node Raft; Phase A4 scales to 3 | Getting persistence, TLS, and manual unseal correct on one node isolates those failure modes from quorum and Raft-join failures. Debugging all of it simultaneously costs hours | Starting at 3; staying at 1 (never exercises Raft join or leader election) |
| **D4** | **2 workers, 3 Vault replicas, soft anti-affinity** (`preferredDuringSchedulingIgnoredDuringExecution`), with the resulting fault-tolerance loss documented in the runbook | Confirmed: a third worker is not available. Hard anti-affinity would leave one pod permanently `Pending`. Soft affinity schedules, and the runbook states plainly that two peers share a node and losing it costs quorum. **The honest framing: this cluster runs Raft to exercise Raft, not to achieve availability** | Hard anti-affinity (unschedulable); 2 replicas (a 2-node Raft cluster has *worse* availability than 1 — it needs both for quorum); a third worker (unavailable, §2.2 backlog) |
| **D5** | **Shamir manual unseal** for v1, key shares 5 / threshold 3 | Auto-unseal on-prem requires either a cloud KMS (out of scope) or a second Vault running Transit — a chicken-and-egg the POC shouldn't hide. Manual unseal forces engagement with the seal lifecycle, the single most operationally distinctive thing about Vault | Cloud KMS; Transit auto-unseal (documented Phase A3, built in v2); dev mode as the end state |
| **D6** | Kubernetes auth configured with a **long-lived reviewer JWT** from a `kubernetes.io/service-account-token` Secret, bound to the `vault` SA which holds `system:auth-delegator` | Projected SA tokens rotate hourly; Vault reads `token_reviewer_jwt` once at config time and never re-reads it, so a rotated projected token breaks auth silently, hours after it appeared to work. A Secret-backed token is stable. This is the classic Vault-on-K8s footgun | Omitting `token_reviewer_jwt` (forces every client SA to hold `auth-delegator` — over-privileged); using the projected token directly (breaks after rotation) |
| **D7** | **TLS on the Vault listener from Phase A2 onward**, issued by cert-manager from a self-signed cluster CA | "Add TLS later" reliably fails: SANs, CA distribution, and every client's TLS config change at once. ESO and Stage B Level 2 both need the CA anyway | `tls_disable = 1`; manual OpenSSL certs (no renewal) |
| **D8** | Expose via **MetalLB `LoadBalancer` (primary) and NodePort `30004` (secondary)**, both targeting `vault-active`. **No ingress.** | ssl-passthrough is off on this cluster and would need enabling for an ingress that does nothing but forward bytes — Vault terminates its own TLS regardless. Direct Services remove a hop, remove the passthrough config, and make the ingress-nginx retirement question irrelevant here. The NodePort exists as a break-glass path for seal events (§4.2) | ingress-nginx with `ssl-passthrough` (a proxy with no job); TLS termination at ingress (plaintext on the pod hop, breaks `api_addr` behaviour) |
| **D9** | Vault is configured **imperatively via documented, idempotent bootstrap scripts** — not Terraform, not a config operator | The POC's purpose includes understanding what `vault write auth/kubernetes/config` actually does. Wrapping it in the Terraform `vault` provider on day one hides the API surface. Scripts are written re-runnable so they aren't one-shot | Terraform `vault` provider (backlog — the right production answer); Vault Config Operator |
| **D10** | **Root token and unseal keys written to a gitignored local file**; root token **revoked at the end of Phase A6** | Root tokens are for bootstrap only. Leaving one alive teaches the wrong reflex. Bootstrap completes, root is revoked, and regenerated on demand via `operator generate-root` | Keeping root alive; storing the keys in the cluster (circular dependency) |
| **D11** | **KV v2** (versioned) rather than KV v1 | Versioning, soft delete, and metadata are what make KV usable operationally. The API path difference (`secret/data/x` vs `secret/x`) is a well-known stumbling block worth hitting deliberately | KV v1 |
| **D12** | **PostgreSQL for the database secrets engine** runs in `poc-hashicorp-vault-application` as a single-replica StatefulSet, dedicated to the POC | Stage B Level 3 needs a database whose roles Vault can create and drop, with a privileged admin account. A throwaway instance keeps blast radius at zero. Placing it with the apps rather than with Vault keeps the platform namespace clean | External/shared DB (Vault needs a privileged role — inappropriate against anything shared); Postgres in `vault` (couples app-tier data to the platform namespace) |
| **D13** | The **PGP key for Level 4 is stored as a KV v2 secret**, not in a dedicated engine | Vault has no PGP secrets engine. PGP appears in Vault only as an *output* wrapper (encrypting unseal key shares). A PGP private key is just bytes Vault custodies. Transit is Vault-native crypto and a genuinely *different* pattern | Transit engine (different primitive; doesn't satisfy Level 4's "pull the key out" requirement); external key file |
| **D14** | **Audit device enabled to `stdout`** (`file` device, `file_path=stdout`), read via `kubectl logs`. **Not shipped to Loki in v1** | Audit is a security control, not an observability nicety — it stays enabled regardless of the LGTM decision. `stdout` also removes a real availability hazard: a PVC-backed audit file that fills causes **Vault to block all requests**, because Vault refuses to serve what it cannot audit. Loki shipping is a later one-line change | File on PVC (availability hazard); socket device; no audit (unacceptable) |
| **D15** | **Scrape Vault metrics and alert on seal status, using additive objects only.** Deploy a `ServiceMonitor` and a `PrometheusRule` into the `vault` namespace. Do **not** edit any existing Prometheus config, alert rule, dashboard, Alertmanager route, or log pipeline | A `ServiceMonitor` is a new object that Prometheus discovers by itself — it changes nothing that currently works, which is the actual requirement. And the gap it closes is real: **Vault seals on every restart, and a sealed pod passes its readiness probe** (the chart's health check treats `sealedcode=204` as healthy, deliberately, so Kubernetes won't kill a pod that is waiting to be unsealed). With 3 peers, one sealed node costs nothing visible — quorum holds, apps keep working, nothing reports a problem — while the cluster quietly sits one event away from the Phase A9.3 restore path. That is silent degradation, which is worse than a loud failure because it removes the chance to act. `vault_core_unsealed` is the signal that makes it loud | A CronJob + webhook (more work than a ServiceMonitor, and duplicates a system that already exists); no alerting (the gap above); full LGTM integration including Loki audit shipping (crosses the boundary — requires editing the log pipeline) |
| **D16** | **Pin every version explicitly** — Vault chart, Vault image, ESO, cert-manager, PostgreSQL — in git. Never `latest` | Vault's storage format and seal behaviour are version-sensitive and **downgrades are not supported**. Verify current stable releases at implementation time rather than trusting versions written into this document | Floating tags |
| **D18** | **One repository, split by stage into `platform/` and `applications/` folders** | Cross-references between the stages stay live (Stage B's manifests reference Vault roles Stage A created), and a single clone gets you everything. Folder separation still allows tearing down and rebuilding Stage B without touching platform manifests. The four Go modules keep their own `go.mod` under `applications/` — no root module, so Stage B's D2 independence is untouched | Two repos (clean lifecycle split, but cross-stage references become dangling and bootstrap needs two clones); one flat repo (platform and app concerns interleave) |
| **D19** | **ArgoCD app-of-apps, with two stage-scoped root Applications** (`root-platform.yaml`, `root-applications.yaml`) applied at different times, and `sync-wave` annotations ordering children | A single root app would deploy Stage B the moment it syncs — which breaks the phase gates, because Stage A's bootstrap scripts are imperative steps that must complete between deployments. Two roots preserve the gate: `root-platform` in Phase A1, `root-applications` not until Stage B Phase B0. Sync waves handle ordering *within* a stage (cert-manager → Vault → monitoring → ESO → Postgres) | A single root app (deploys Stage B before Vault is configured, guaranteeing a confusing first failure); no root app, four manual applies (fine, but you asked for app-of-apps and it does make bootstrap one command per stage) |
| **D20** | **Unseal keys live at `~/.credentials/vault-poc/vault-init.json` on the host — outside the repo tree — with a password-manager copy as the durable second. Backup verified readable before Phase A2 closes** | The repo is a Vagrant synced folder on the host, so `vagrant destroy` does not touch it and a gitignored in-repo file would in fact survive. Two things still argue against in-repo: **`git clean -xfd` deletes gitignored files by design** — that is what `-x` means — and it is exactly the command reached for when resetting a working tree, silently; and `git add -f` bypasses `.gitignore` entirely. Moving one directory up removes both failure modes at zero cost while keeping the file on the host, one path away, and scriptable. The password-manager copy covers the remaining single-machine cases: disk failure, OS reinstall, laptop lost. **Proportionality:** nothing in this POC is irreplaceable — KV is re-seeded by script, DB credentials are generated on demand, the PGP keypair is regenerable — so key loss costs hours of rebuild, not data. A second copy is right-sized; a key ceremony is not | In-repo + `.gitignore` (survives `vagrant destroy`, but not `git clean -xfd`, and not `git add -f`); dev VM only (destroyed by routine `vagrant destroy`); in-cluster (circular — the keys are needed to reach the thing holding them); split custody across five holders (the correct production answer, documented in the runbook, disproportionate for a solo lab) |
| **D17** | Namespaces: `vault`, `external-secrets`, `poc-hashicorp-vault-application` | `vault` reads as a platform namespace, so this design promotes without renaming. The POC-scoped name is confined to the application tier, where it belongs. Separation lets Stage B be torn down and rebuilt without touching the platform | Single namespace; `vault-poc` for the server (bakes POC-ness into the platform tier) |

### 5.1 Licensing — resolved

**Decision: proceed with HashiCorp Vault Community under BUSL 1.1. Verify against your organisation's OSS policy in Phase A0.**

Context, since you asked:

<cite index="3-1">In August 2023, HashiCorp changed Vault from the Mozilla Public License 2.0 (MPL 2.0) to the Business Source License 1.1 (BUSL 1.1). BUSL 1.1 is not an OSI-approved open source license, and its key restriction prevents organizations from offering a competing commercial product or hosted service based on the Vault codebase.</cite> <cite index="1-1">The license otherwise permits you to use, copy, modify, and redistribute Vault, including in production, under most circumstances, and after four years from each release date the code converts to MPL 2.0.</cite>

<cite index="7-1">The practical impact is that internal Vault usage is unaffected by the license model; organizations building SaaS platforms or offering secrets management to customers are the ones who face restrictions.</cite> An internal POC and internal production use both fall clearly on the permitted side. <cite index="8-1">Note that HashiCorp is now an IBM company.</cite>

**OpenBao** is the fork that resulted. <cite index="7-1">It was forked from Vault 1.14.0 — the last MPL-2.0 release — before the license change, maintains API compatibility with Vault, and operates under MPL 2.0 with Linux Foundation governance.</cite> <cite index="1-1">As of early 2026 it reached version 2.5.0, is under Linux Foundation governance with IBM engineers among its contributors, and is a credible production-ready alternative rather than an experiment.</cite> <cite index="6-1">It speaks the same API and exposes the same command surface; the reason to choose between them is almost entirely licence and governance rather than features. The trade-off is that there is no first-party commercial vendor for support.</cite>

**Why Vault for this POC:** everything in this document — Raft, Kubernetes auth, KV v2, the database engine, ESO integration — exists in both. But documentation, the Helm chart, and the ecosystem you'll hit when troubleshooting are all Vault-first, and troubleshooting friction is exactly what you don't want in a learning exercise. <cite index="3-1">Worth knowing that because the two are independently maintained with separate release cycles, compatibility may diverge over time in particular areas, so a future migration would need version-specific validation.</cite>

Logged as a backlog evaluation item. If your OSS policy blocks BUSL, the substitution changes chart coordinates and the binary name and essentially nothing else in this PRD.

---

## 6. Phased execution

Ten phases. Each has a single-sentence goal, concrete deliverables, and a binary exit gate. **Do not proceed past a failed gate** — every later phase assumes the earlier ones hold.

---

### Phase A0 — Cluster readiness and repository scaffolding

**Goal:** Remove every prerequisite gap before Vault enters the picture.

**Tasks**
1. Verify P1–P10 against the live cluster. Record actual values into `docs/environment.md`:
   - Node names and IPs
   - MetalLB pool range and an allocatable VIP for Vault
   - `local-path` StorageClass name (confirm it is default, or set `storageClass` explicitly in values)
   - Registry address
   - Cluster OIDC issuer (Phase A6 needs it; look it up now)
2. Bump Kubernetes if still on 1.29 (EOL).
3. Confirm `local-path-provisioner` is installed and healthy. Bind a test PVC and confirm the PV lands on the expected node.
4. Confirm ArgoCD permits Helm-repo sources and multi-source Applications (D1). Add `https://helm.releases.hashicorp.com` to allowed repos if the ArgoCD config restricts them.
5. **Prometheus compatibility checks (D15).** Three questions, all answerable in a minute, all of which determine whether A9.4 is two objects or a conversation. Record answers in `docs/environment.md`:

   **5a — Is Prometheus operator-managed?**
   ```bash
   kubectl get crd servicemonitors.monitoring.coreos.com prometheusrules.monitoring.coreos.com
   ```
   If these CRDs are absent, the stack is plain Prometheus with a static scrape config, and adding a target means **editing a file that currently works** — which crosses the boundary. **Stop and report.** Do not edit it.

   **5b — What selector does Prometheus use to discover ServiceMonitors?**
   ```bash
   kubectl get prometheus -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.spec.serviceMonitorSelector}{"\t"}{.spec.serviceMonitorNamespaceSelector}{"\n"}{end}'
   ```
   This is the step people skip, and it fails silently. Many `kube-prometheus-stack` installs default to `serviceMonitorSelectorNilUsesHelmValues: true`, which means Prometheus only picks up ServiceMonitors carrying the Helm release label — e.g. `release: kube-prometheus-stack`. Get the required labels wrong and your ServiceMonitor deploys cleanly, reports no error, and is **never scraped**. Also check `serviceMonitorNamespaceSelector`: if it's scoped to specific namespaces, `vault` must be among them, and adding it *would* be an edit to their config — report rather than doing it. Write the exact labels needed into `docs/environment.md`.

   **5c — Is Alertmanager wired to a receiver that reaches a human?**
   ```bash
   kubectl get alertmanager -A
   kubectl get secret -n <ns> alertmanager-<name> -o jsonpath='{.data.alertmanager\.yaml}' | base64 -d
   ```
   If there's no receiver, or it routes nowhere, say so plainly. A `PrometheusRule` still fires and is visible in the Prometheus UI, which beats nothing — but **do not describe the alert as "working" if nobody gets paged.** Configuring a receiver is an edit to their stack: report the finding and let the owner decide.

6. Install `cert-manager`, pinned. Create the chain: self-signed `ClusterIssuer` → CA `Certificate` → CA `ClusterIssuer`.
7. Create namespaces: `vault`, `external-secrets`, `poc-hashicorp-vault-application`.
8. Confirm the BUSL position per §5.1 against org policy. **If blocked, stop and report before proceeding** — the substitution is cheap now and expensive at Phase A7.
9. Scaffold the repository:

```
vault-poc/                                  # ONE repo (D18)
├── README.md
├── .gitignore                              # committed FIRST — see step 10
│
├── docs/
│   ├── environment.md                      # verified live values — no guesses
│   ├── architecture.md
│   ├── licensing.md                        # §5.1 outcome + org policy confirmation
│   ├── key-custody.md                      # D20 — method, NOT the location
│   ├── troubleshooting.md
│   └── runbooks/
│       ├── seal-unseal.md
│       ├── snapshot-restore.md
│       └── upgrade.md
│
├── argocd/                                 # app-of-apps (D19)
│   ├── root-platform.yaml                  # applied in Phase A1
│   ├── root-applications.yaml              # applied in Stage B Phase B0 — NOT before
│   └── applications/
│       ├── platform/                       # children of root-platform
│       │   ├── vault.yaml                  # wave 1 · multi-source Helm + values
│       │   ├── vault-extras.yaml           # wave 0 · cert, reviewer Secret, NodePort
│       │   ├── vault-monitoring.yaml       # wave 2 · ServiceMonitor + PrometheusRule
│       │   ├── external-secrets.yaml       # wave 3
│       │   └── postgres.yaml               # wave 3
│       └── applications/                   # children of root-applications (Stage B)
│           ├── level1-env-secret.yaml
│           ├── level2-k8s-auth.yaml
│           ├── level3-dynamic-db.yaml
│           └── level4-pgp-decrypt.yaml
│
├── platform/                               # Stage A
│   ├── bootstrap/
│   │   ├── 00-init-unseal.sh
│   │   ├── 10-enable-kubernetes-auth.sh
│   │   ├── 20-policies/
│   │   ├── 30-enable-kv.sh
│   │   ├── 40-enable-database.sh
│   │   ├── 50-seed-secrets.sh
│   │   ├── 60-enable-audit.sh
│   │   ├── 90-snapshot.sh
│   │   └── 99-revoke-root.sh
│   ├── helm/
│   │   └── vault/values-onprem.yaml        # git side of the multi-source app (D1)
│   └── kubernetes/
│       ├── base/
│       │   ├── vault-extras/               # Certificate, reviewer Secret,
│       │   │                               #   NodePort svc, auth-delegator CRB
│       │   ├── monitoring/                 # ServiceMonitor + PrometheusRule (A9.4)
│       │   ├── external-secrets/
│       │   └── postgres/
│       └── overlays/onprem/
│
└── applications/                           # Stage B — see the companion PRD
    ├── level1-env-secret/                  # own go.mod, no root module
    ├── level2-k8s-auth/
    ├── level3-dynamic-db/
    └── level4-pgp-decrypt/
```

**On the two root Applications (D19).** `root-platform` points ArgoCD at `argocd/applications/platform/`; `root-applications` points at `argocd/applications/applications/`. Only the first is applied during Stage A. Applying both up front would deploy Stage B pods before Kubernetes auth exists, producing a confusing crash-loop that looks like an app bug and is actually a sequencing error.

Within a stage, order with sync waves:

```yaml
metadata:
  annotations:
    argocd.argoproj.io/sync-wave: "1"
```

Wave 0 must complete before Vault starts — the cert-manager `Certificate` and the reviewer-token Secret are mounted by the StatefulSet. Set `Retry` with backoff on the root app; the monitoring child will fail its first sync if the Prometheus CRDs are checked before they're cached, and that's expected rather than alarming.

10. Commit `.gitignore` **first**, before any secret material can exist:
   ```
   vault-init.json
   *.key
   *.asc
   *.snap
   .env
   ```
   Add a `gitleaks` pre-commit hook if convenient.

**Exit gate**
- [ ] `docs/environment.md` populated with verified live values, including the OIDC issuer
- [ ] Test PVC binds on `local-path`; PV location confirmed on a node
- [ ] cert-manager issues a test Certificate
- [ ] **Prometheus checks 5a/5b/5c answered and recorded**, including the exact labels a ServiceMonitor needs to be discovered
- [ ] ArgoCD can reach the repo and the HashiCorp Helm repo
- [ ] Single repo scaffolded with `platform/` and `applications/` split; both root Applications written but **only `root-platform` applied**
- [ ] `docs/key-custody.md` drafted (the method, not the location) — D20
- [ ] Three namespaces created
- [ ] Licensing position confirmed and recorded
- [ ] `.gitignore` committed as the first commit containing it

---

### Phase A1 — Dev-mode smoke deploy (throwaway)

**Goal:** Prove the delivery path (Helm repo → ArgoCD → scheduling → networking) with a Vault that has zero persistence, then delete it.

**Tasks**
1. Apply `argocd/root-platform.yaml` only (D19). Deploy the chart with `server.dev.enabled=true`, 1 replica, via its child Application. This validates D1's multi-source wiring and D19's app-of-apps nesting together.
2. `kubectl exec` in; `vault status`, `vault kv put secret/smoke hello=world`, `vault kv get secret/smoke`.
3. Port-forward the UI; confirm it loads.
4. **Delete the release entirely.** Nothing from this phase survives.

**Why this phase exists:** it separates "my ArgoCD/Helm/registry path is broken" from "my Vault configuration is wrong." Debugging both at once in Phase A2 is where days go.

**Exit gate**
- [ ] `root-platform` syncs and creates its children in wave order
- [ ] The Vault child Application syncs from the Helm repo with git-sourced values
- [ ] `root-applications` is **not** applied
- [ ] Pod Running; `vault status` shows Initialized/Unsealed (dev mode does both)
- [ ] KV write/read round-trips
- [ ] Release deleted; `vault` namespace empty

---

### Phase A2 — Single-node Raft with TLS and manual unseal

**Goal:** A real, persistent, TLS-terminated Vault that survives a pod restart and requires deliberate unsealing.

**Tasks**

1. **cert-manager `Certificate` in `vault`.** SANs must cover every name and IP Vault will ever be addressed by. Missing one here surfaces as an unexplained Raft-join failure in Phase A4 — get it right once:
   ```
   DNS:
     vault
     vault.vault
     vault.vault.svc
     vault.vault.svc.cluster.local
     vault-active
     vault-active.vault.svc.cluster.local
     vault-lb
     vault-lb.vault.svc.cluster.local
     *.vault-internal
     *.vault-internal.vault.svc.cluster.local
     localhost
   IP:
     127.0.0.1
     <MetalLB VIP for Vault>        ← D8 primary path
     <control-plane node IP>        ← D8 NodePort path
     <worker-1 node IP>             ← D8 NodePort path
     <worker-2 node IP>             ← D8 NodePort path
   ```
   **The node IPs are the easily-forgotten ones.** Without them the NodePort break-glass path fails TLS verification — precisely when you need it, during a seal event.

2. **Helm values** (`helm/vault/values-onprem.yaml`): `ha.enabled=true`, `ha.raft.enabled=true`, `ha.replicas=1`, TLS enabled, PVC 10Gi on `local-path`, resource requests/limits set, image and chart pinned.

3. **Vault HCL config:**
   ```hcl
   listener "tcp" {
     address            = "[::]:8200"
     cluster_address    = "[::]:8201"
     tls_cert_file      = "/vault/userconfig/vault-tls/tls.crt"
     tls_key_file       = "/vault/userconfig/vault-tls/tls.key"
     tls_client_ca_file = "/vault/userconfig/vault-tls/ca.crt"
     telemetry {
       unauthenticated_metrics_access = true    # D15 — scraped in A9.4
     }
   }

   storage "raft" {
     path    = "/vault/data"
     node_id = "${HOSTNAME}"
   }

   service_registration "kubernetes" {}

   telemetry {
     prometheus_retention_time = "30s"
     disable_hostname          = true
   }

   api_addr     = "https://$(POD_IP):8200"
   cluster_addr = "https://$(HOSTNAME).vault-internal:8201"
   ui           = true
   ```

4. **Run `bootstrap/00-init-unseal.sh`:**
   - Assert `.gitignore` covers `vault-init.json` and **abort if not**, before writing anything
   - `vault operator init -key-shares=5 -key-threshold=3 -format=json > vault-init.json`
   - Unseal with 3 distinct shares
   - **Write to `~/.credentials/vault-poc/vault-init.json` on the host — never inside the repo tree (D20).** The script should read its target from `${VAULT_POC_KEYS:-$HOME/.credentials/vault-poc}` and `mkdir -p` it with mode `0700`. Assert the resolved path is outside the repo and **abort if it is not** — an in-repo file survives `vagrant destroy` but not `git clean -xfd`, which deletes gitignored files by design and is exactly what gets run when resetting a working tree.
   - **Add a durable second copy**: paste the full JSON into a password-manager secure note. This covers host disk failure, OS reinstall, and a lost laptop — the cases `~/.credentials/` alone does not.
   - **Verify at least one copy is readable**: seal a node, retrieve a share from the backup rather than the working file, and confirm it unseals. A backup you have never read from is a hypothesis.
   - Write `docs/key-custody.md` recording the *method* and *who holds it* — never the location or the shares themselves. Include the production alternative you are deliberately not doing: five shares to five separate holders, threshold three, no single person able to unseal alone. The 5/3 split otherwise implies a ceremony that is not happening.
   - Note for later: after Phase A6 revokes the root token (D10), this file's remaining value is purely the five unseal shares.

5. **Expose it (D8).** Both paths, now, so they're proven before HA complicates things:
   - `vault-lb`: `type: LoadBalancer`, MetalLB annotation/pool, selector matching `vault-active`, port 8200 → 8200
   - `vault-nodeport`: `type: NodePort`, `nodePort: 30004`, port 8200 → 8200, same selector

   Note: the chart's `vault-active` Service uses `vault-active: "true"` in its selector, set by `service_registration "kubernetes"`. Reuse that selector rather than inventing one.

6. **Trust the CA** on the dev workspace: `VAULT_ADDR`, `VAULT_CACERT`. Then verify **both** paths:
   ```bash
   VAULT_ADDR=https://<metallb-vip>:8200 vault status     # primary
   VAULT_ADDR=https://<any-node-ip>:30004 vault status    # break-glass
   ```
   Neither may use `-tls-skip-verify`. If either fails, a SAN is missing — go back to step 1.

7. **Restart test:** `kubectl delete pod vault-0`. Confirm it returns **sealed**. Unseal manually. Confirm pre-restart KV data is intact.

**Exit gate**
- [ ] `vault status`: Initialized `true`, Sealed `false`, Storage `raft`, HA Mode `active`
- [ ] TLS verifies over **both** the MetalLB VIP and NodePort 30004, without bypass flags
- [ ] Data survives pod deletion; pod returns sealed and requires manual unseal
- [ ] `vault-init.json` absent from `git status`
- [ ] Keys at `~/.credentials/vault-poc/`, confirmed **outside** the repo tree (D20)
- [ ] Durable second copy in a password manager
- [ ] Backup verified by unsealing from a retrieved share, not the working file
- [ ] `docs/key-custody.md` written, recording method and holder — not location, not shares

---

### Phase A3 — Seal strategy documentation (no deployment)

**Goal:** Write down the seal decision and its DR consequences while the manual unseal experience is fresh.

**Tasks**
1. Author `docs/runbooks/seal-unseal.md`:
   - What sealing actually is — the master key is not in memory, and storage is encrypted at rest and unreadable
   - When Vault seals: restart, `operator seal`, quorum loss, seal-wrapping errors
   - The unseal procedure, **including via the NodePort path**, since a seal event may coincide with whatever broke MetalLB
   - Key share custody for the POC, and what a real one requires: separate holders, offline storage, split custody
   - `operator rekey` and `operator generate-root` procedures
   - **Detection:** the `VaultNodeSealed` alert from Phase A9.4 is the primary signal. Record the manual check (`vault status` per peer, or `curl /v1/sys/health`) as the fallback for when you don't trust the alert yet — and note that until A9.4's fire test passes, manual *is* the only detection.
2. Document the **Transit auto-unseal option** as a design note, not an implementation:
   - Requires a second, separately-sealed Vault whose only job is Transit
   - Moves the problem rather than eliminating it — the unsealer still needs unsealing
   - The genuine win is at scale (N Vaults, 1 unsealer), which does not apply here
3. Document the **cloud KMS option** as backlog, tied to future cloud expansion.

**Exit gate**
- [ ] Runbook exists; a second person could unseal from it cold, via either network path
- [ ] Both auto-unseal options documented with honest tradeoffs
- [ ] Manual seal-detection gap explicitly recorded

---

### Phase A4 — Scale to 3-node Raft HA

**Goal:** Exercise Raft join, leader election, and quorum behaviour — with clear eyes about what this topology can and cannot survive.

**Tasks**
1. Add `retry_join` stanzas for all three peers:
   ```hcl
   storage "raft" {
     path    = "/vault/data"
     node_id = "${HOSTNAME}"
     retry_join {
       leader_api_addr     = "https://vault-0.vault-internal:8200"
       leader_ca_cert_file = "/vault/userconfig/vault-tls/ca.crt"
     }
     retry_join { leader_api_addr = "https://vault-1.vault-internal:8200" ... }
     retry_join { leader_api_addr = "https://vault-2.vault-internal:8200" ... }
   }
   ```
2. Set `ha.replicas=3` with **soft** anti-affinity (D4):
   ```yaml
   affinity:
     podAntiAffinity:
       preferredDuringSchedulingIgnoredDuringExecution:
         - weight: 100
           podAffinityTerm:
             topologyKey: kubernetes.io/hostname
             labelSelector:
               matchLabels: { app.kubernetes.io/name: vault }
   ```
3. Scale up. **Unseal `vault-1` and `vault-2` individually** with the same key shares. Every peer seals independently — this surprises people; it belongs in the runbook.
4. `vault operator raft list-peers` → 3 peers, one leader.
5. Record actual pod-to-node placement: `kubectl get pods -n vault -o wide`. With 2 workers, two peers share a node. **Write down which node holds two peers** — that is your single point of failure, by name.
6. **Failover drill:** delete the leader pod. Observe and record:
   - Leader election time
   - `vault-active` Service endpoint follows the new leader (and therefore both exposure paths follow it too)
   - The restarted pod returns **sealed** and does not rejoin until unsealed
   - Measured unavailability window
7. **Write the honest assessment into the runbook.** Suggested wording:

   > This cluster runs 3-node Raft to exercise Raft, not to achieve availability. Two of three peers share worker node `<name>`. Losing that node drops quorum, and Vault becomes unavailable until either the node returns or the cluster is rebuilt from snapshot (see `snapshot-restore.md`). A third worker node is the fix; it is a capacity item, not a configuration one.

**Exit gate**
- [ ] 3 peers healthy, one leader
- [ ] Failover completes; `vault-active` re-points; both exposure paths follow
- [ ] Unavailability window measured and recorded
- [ ] The node hosting two peers is named in the runbook
- [ ] Quorum-loss consequence documented without euphemism

---

### Phase A5 — Access paths and UI

**Goal:** Both exposure paths are stable, documented, and proven against the HA cluster.

**Tasks**
1. Re-verify both paths now that the leader can move:
   ```bash
   VAULT_ADDR=https://<metallb-vip>:8200  vault status
   VAULT_ADDR=https://<node-ip>:30004     vault status
   ```
   Confirm both reach the **active** node by comparing `HA Mode: active` and the reported node.
2. Trigger a failover and re-run both immediately. Both must follow the new leader without intervention.
3. Add a hosts entry (or DNS record) on the dev workspace mapping a friendly name to the MetalLB VIP, e.g. `vault.learning-labs.local`. Ensure that name is in the cert SANs — **if it isn't, add it and reissue now**, not later.
4. Trust the CA in the dev workspace OS store and browser. Load the UI over the MetalLB VIP; confirm a valid padlock. Log in with a token.
5. Confirm the NodePort path serves the UI too (it will) and note it as break-glass only.
6. Write `docs/environment.md` access section: both URLs, when to use which, and the exact `VAULT_ADDR`/`VAULT_CACERT` exports.
7. **Sanity check the security posture of NodePort 30004:** it is reachable on every node IP from anywhere that can route to `192.168.56.0/24`. On this lab network that's acceptable. Record it as a deliberate acceptance, and note that in a real environment this port would be firewalled to an admin subnet.

**Exit gate**
- [ ] Both paths verified against the HA cluster with CA verification, no bypass flags
- [ ] Both paths follow a leader failover automatically
- [ ] UI loads with a trusted certificate over the primary path
- [ ] Access documented; NodePort exposure explicitly accepted in writing

---

### Phase A6 — Kubernetes auth, policies, and roles

**Goal:** Workload identity works, and it is least-privilege from the first role.

**Tasks**
1. `ClusterRoleBinding`: `system:auth-delegator` → `vault` ServiceAccount in `vault`.
2. Create the long-lived reviewer token (D6):
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: vault-reviewer-token
     namespace: vault
     annotations:
       kubernetes.io/service-account.name: vault
   type: kubernetes.io/service-account-token
   ```
3. Get the cluster's **real** OIDC issuer — do not guess:
   ```bash
   kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
   ```
4. `bootstrap/10-enable-kubernetes-auth.sh` (idempotent — guard the `auth enable`):
   ```bash
   vault auth enable kubernetes
   vault write auth/kubernetes/config \
     kubernetes_host="https://kubernetes.default.svc:443" \
     kubernetes_ca_cert=@ca.crt \
     token_reviewer_jwt="$REVIEWER_JWT" \
     issuer="$OIDC_ISSUER"
   ```
5. Write policies (least privilege, `bootstrap/20-policies/`):

   | Policy | Grants |
   |---|---|
   | `level1-reader` | `read` on `secret/data/level1/*` |
   | `level2-reader` | `read` on `secret/data/level2/*`; `update` on `auth/token/renew-self` and `auth/token/lookup-self` |
   | `level3-db` | `read` on `database/creds/level3-app`; `update` on `sys/leases/renew` and `sys/leases/lookup` |
   | `level4-pgp` | `read` on `secret/data/level4/pgp` |
   | `eso-reader` | `read` on `secret/data/level1/*`; `list` on `secret/metadata/*` |

   **KV v2 path trap:** the API path is `secret/data/<path>` for reads and `secret/metadata/<path>` for list/delete — even though the CLI displays `secret/<path>`. Policies written against the CLI-visible path silently deny everything. Hit this deliberately here so you recognise it in Stage B.

6. Bind roles to SA + namespace pairs. **All Stage B roles bind to `poc-hashicorp-vault-application`**, distinguished by ServiceAccount:
   ```bash
   vault write auth/kubernetes/role/level2-app \
     bound_service_account_names=level2-app \
     bound_service_account_namespaces=poc-hashicorp-vault-application \
     policies=level2-reader \
     ttl=1h
   ```
   Repeat for `level1-app`, `level3-app`, `level4-app`, and `eso` (bound to `external-secrets`/`external-secrets`).

   Never use `bound_service_account_names="*"`. Since all four app roles share a namespace, **the ServiceAccount name is the entire isolation boundary** — which makes the negative tests below load-bearing, not ceremonial.

7. **Verify from a throwaway pod:**
   ```bash
   kubectl -n poc-hashicorp-vault-application run probe --rm -it \
     --image=curlimages/curl \
     --overrides='{"spec":{"serviceAccountName":"level2-app"}}' -- sh
   # inside:
   JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
   curl -s --cacert /vault-ca/ca.crt \
     --request POST --data "{\"jwt\":\"$JWT\",\"role\":\"level2-app\"}" \
     https://vault.vault.svc:8200/v1/auth/kubernetes/login
   ```
8. **Negative tests — the phase's real deliverable:**
   - Same role, different SA (`default`) → login **denied**
   - `level1-app` SA requesting role `level4-pgp` → **denied** (SA/role mismatch)
   - A `level1-reader` token reading `secret/data/level4/pgp` → **403**

   An auth method that has never said no has not been tested.
9. Run `bootstrap/99-revoke-root.sh` — revoke the initial root token (D10). Document `operator generate-root` in the runbook for when it's needed again.

**Exit gate**
- [ ] Login from each bound SA returns a token with exactly the expected policies
- [ ] All three negative tests deny as specified
- [ ] Root token revoked; regeneration procedure documented and tested once
- [ ] Reviewer token confirmed non-expiring (`kubectl get secret vault-reviewer-token -o jsonpath='{.data.token}'` decodes to a JWT with no short `exp`)

---

### Phase A7 — Secrets engines and seeding

**Goal:** Every secret Stage B needs exists, including the dynamic ones.

**Tasks**

1. **KV v2** at `secret/`:
   ```bash
   vault secrets enable -path=secret -version=2 kv
   vault kv put secret/level1/app greeting="hello from vault" api_key="static-poc-key-001"
   vault kv put secret/level2/app message="fetched via direct k8s auth" tier="gold"
   ```

2. **PostgreSQL** in `poc-hashicorp-vault-application` (D12): single-replica StatefulSet on `local-path`, with:
   - A `vaultadmin` superuser role for Vault's own connection
   - Database `appdb`, schema `public`, and a seeded demo table so Level 3 has something real to `SELECT`

3. **Database secrets engine:**
   ```bash
   vault secrets enable database

   vault write database/config/poc-postgres \
     plugin_name=postgresql-database-plugin \
     allowed_roles="level3-app" \
     connection_url="postgresql://{{username}}:{{password}}@postgres.poc-hashicorp-vault-application.svc:5432/appdb?sslmode=disable" \
     username="vaultadmin" password="$PGADMIN_PW"

   vault write database/roles/level3-app \
     db_name=poc-postgres \
     creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
                          GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
     revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
     default_ttl="1h" max_ttl="24h"
   ```
   Then rotate the admin password so no human knows it:
   ```bash
   vault write -f database/rotate-root/poc-postgres
   ```
   This is the moment the value of dynamic secrets becomes concrete: **after this command, the credential Vault uses is known to no person.**

4. **Prove the engine and prove revocation is real:**
   ```bash
   vault read database/creds/level3-app        # note username + lease_id
   psql -U <generated-user> ...                # succeeds
   vault lease revoke <lease_id>
   psql -U <generated-user> ...                # must now FAIL
   ```
   Confirm in Postgres that the role is actually dropped: `\du`.

5. **PGP key material for Level 4** (D13), scripted in `bootstrap/50-seed-secrets.sh`:
   - Generate an RSA-4096 PGP keypair with a passphrase
   - Encrypt a fixture file to that key — this fixture ships with Stage B
   - Upload to Vault:
     ```bash
     vault kv put secret/level4/pgp \
       private_key=@poc-key-private.asc \
       public_key=@poc-key-public.asc \
       passphrase="$PGP_PASSPHRASE"
     ```
   - **Delete the local private key after upload.** Verify with `ls`.

6. Document `default_lease_ttl` and `max_lease_ttl` at both the mount and system level — Level 3's renewal behaviour depends on them, and Stage B Phase B3 temporarily shortens them.

**Exit gate**
- [ ] All KV paths readable by their intended policy and no other
- [ ] `vault read database/creds/level3-app` returns working, ephemeral credentials
- [ ] Revoked credentials dropped in Postgres, verified with `\du`
- [ ] Postgres admin password rotated; no human holds it
- [ ] PGP key + passphrase in Vault; encrypted fixture produced; local private key destroyed

---

### Phase A8 — External Secrets Operator

**Goal:** The Level 1 consumption path, and a working example of the "app doesn't know Vault exists" model.

**Tasks**
1. Install ESO (pinned) into `external-secrets`.
2. SA `external-secrets` + Vault role `eso` bound to it with `eso-reader`.
3. `ClusterSecretStore`:
   ```yaml
   apiVersion: external-secrets.io/v1
   kind: ClusterSecretStore
   metadata:
     name: vault-backend
   spec:
     provider:
       vault:
         server: "https://vault.vault.svc:8200"
         path: "secret"
         version: "v2"
         caProvider:
           type: ConfigMap
           name: vault-ca
           namespace: external-secrets
           key: ca.crt
         auth:
           kubernetes:
             mountPath: "kubernetes"
             role: "eso"
             serviceAccountRef:
               name: external-secrets
               namespace: external-secrets
   ```
   Note ESO reaches Vault over the **in-cluster** Service, not the MetalLB VIP — the external paths are for humans.
4. Verify `status.conditions` shows `Ready=True`. A store that cannot authenticate fails quietly; check it explicitly.
5. Test `ExternalSecret` in `poc-hashicorp-vault-application` targeting `secret/level1/app`. Confirm a Kubernetes Secret materialises with the right keys.
6. **Rotation test:** change the value in Vault, wait for `refreshInterval`, confirm the Kubernetes Secret updates.
   Then note the gap that matters: **the Secret updated, but a running pod's environment variable did not.** Env vars are read at process start. This limitation is the entire subject of Stage B Level 1.

**Exit gate**
- [ ] `ClusterSecretStore` Ready
- [ ] `ExternalSecret` produces a correct Kubernetes Secret
- [ ] Vault-side change propagates within `refreshInterval`
- [ ] Env-var staleness reproduced and documented

---

### Phase A9 — Audit, backup, and operational validation

**Goal:** Vault is auditable and *proven* recoverable — not assumed to be.

**Tasks**

**A9.1 — Audit device (D14)**
1. Enable **before Stage B begins**, so every Stage B request is captured:
   ```bash
   vault audit enable file file_path=stdout
   ```
2. Verify audit lines appear in `kubectl logs -n vault vault-0`.
3. Confirm secret values are HMAC'd, not plaintext — read a KV secret and inspect the corresponding audit line.
4. Document in the runbook: audit is read via `kubectl logs` for v1; Loki shipping is backlog (A9.4). Note that the pods' log rotation determines audit retention, and that this is **not** adequate retention for a real environment.

**A9.2 — Snapshot**
5. `bootstrap/90-snapshot.sh`:
   ```bash
   vault operator raft snapshot save vault-$(date +%F-%H%M).snap
   ```
6. Document where snapshots live, and state prominently: **a snapshot is encrypted with the same seal — it is useless without the unseal keys.** This is the most commonly misunderstood point in Vault DR. `vault-init.json` and the snapshots are a matched pair; losing either loses both.

**A9.3 — Full restore drill (the phase's real deliverable)**

**Framing matters here.** Node loss and the resulting rebuild are an accepted outcome for this dev environment (§3.1), so this drill is **not** a disaster-recovery requirement — you have already decided you can afford to rebuild. It is kept as a *learning deliverable*, because three things about Vault's restore model cannot be learned any other way and all three surprise people:

1. A snapshot is encrypted under the **seal of the cluster it came from**. It is not a portable export. Without the original key shares it is an unopenable blob.
2. `snapshot restore -force` **overwrites the target's entire dataset**. It is not a merge and there is no partial restore.
3. After restoring, you unseal with the **original** shares. The keys produced by the fresh `operator init` in step 10 are discarded — the restore brings the old seal back with it.

Run it once, deliberately, so none of that is a discovery during an incident. It is also where the RTO number comes from.

7. Take a snapshot.
8. Write a canary secret **after** the snapshot: `vault kv put secret/canary v=post-snapshot`.
9. Destroy Vault completely — delete the StatefulSet **and the PVCs**. Confirm the `local-path` directories are gone from the nodes.
10. Redeploy. `vault operator init` a fresh instance.
11. `vault operator raft snapshot restore -force vault-<ts>.snap`
12. Unseal with the **original** key shares. The restore brings back the original seal; the keys from step 10's init are discarded. Understanding this is the whole point of the drill.
13. Confirm: pre-snapshot data present, canary **absent**.
14. **Record wall-clock time for steps 9–13. That number is your actual RTO.** Put it in the runbook, not in a chat message.

**A9.4 — Metrics and seal alerting (D15)**

Two objects. Both additive. **If any step here would require editing something that already works, stop and report it instead.**

16. Confirm the telemetry endpoint responds before wiring anything to it:
    ```bash
    kubectl -n vault exec vault-0 -- \
      curl -sk https://127.0.0.1:8200/v1/sys/metrics?format=prometheus | head
    ```
    Expect `vault_core_unsealed` among the output. If this is empty, the listener telemetry stanza from Phase A2 is missing — fix that first, not the ServiceMonitor.

17. **`ServiceMonitor`** in `vault`, targeting the `vault` Service (all pods, not `vault-active` — you need per-peer seal status, so scraping only the leader defeats the purpose):
    ```yaml
    apiVersion: monitoring.coreos.com/v1
    kind: ServiceMonitor
    metadata:
      name: vault
      namespace: vault
      labels:
        release: <VALUE FROM PHASE A0.5b>   # ← discovery depends on this
    spec:
      selector:
        matchLabels:
          app.kubernetes.io/name: vault
      endpoints:
        - port: https
          scheme: https
          path: /v1/sys/metrics
          params:
            format: ["prometheus"]
          interval: 30s
          tlsConfig:
            ca:
              secret: { name: vault-tls, key: ca.crt }
            serverName: vault.vault.svc
    ```
    Note the label comes from A0.5b, not from a guess.

18. **Prove it is actually being scraped.** This is the step that separates a working alert from a believed one:
    ```bash
    # Prometheus should list the targets as UP — three of them
    kubectl port-forward -n <prom-ns> svc/<prometheus> 9090:9090
    # then: http://localhost:9090/targets  → search "vault"
    # and query:  vault_core_unsealed
    ```
    Three series, one per peer, all reporting `1`. **If the target list is empty, the ServiceMonitor label is wrong** — go back to A0.5b. Deploying cleanly is not evidence of anything.

19. **`PrometheusRule`** — seal alert first, since it is the reason this phase exists:
    ```yaml
    apiVersion: monitoring.coreos.com/v1
    kind: PrometheusRule
    metadata:
      name: vault
      namespace: vault
      labels:
        release: <VALUE FROM PHASE A0.5b>
    spec:
      groups:
        - name: vault
          rules:
            - alert: VaultNodeSealed
              expr: vault_core_unsealed == 0
              for: 2m
              labels: { severity: critical }
              annotations:
                summary: "Vault peer {{ $labels.pod }} is sealed"
                description: "Quorum is degraded and will not self-heal. Unseal per docs/runbooks/seal-unseal.md."

            - alert: VaultNoRaftLeader
              expr: sum(vault_core_active) == 0
              for: 1m
              labels: { severity: critical }

            - alert: VaultTargetDown
              expr: up{job=~".*vault.*"} == 0
              for: 5m
              labels: { severity: warning }
              annotations:
                summary: "Vault metrics target down — seal status is now unobservable"

            - alert: VaultAuditFailures
              expr: increase(vault_audit_log_request_failure[5m]) > 0
              labels: { severity: critical }
              annotations:
                summary: "Vault cannot write audit — it will block all requests"
    ```
    `VaultTargetDown` matters more than it looks: it is the alert that tells you the *other* alerts have stopped working. Verify the exact metric names against your Vault version's `/v1/sys/metrics` output rather than trusting this document — telemetry names shift between releases.

20. **Fire test — the exit gate for this phase.** An untested alert is a belief, not a control:
    - `kubectl -n vault exec vault-1 -- vault operator seal` (a follower, so quorum holds and you can observe calmly)
    - Watch `vault_core_unsealed{pod="vault-1"}` drop to 0
    - Confirm `VaultNodeSealed` moves Pending → Firing after 2m in the Prometheus UI
    - Confirm whether it reached a human, per the A0.5c finding. **If Alertmanager has no receiver, record that the alert fires but notifies nobody** — do not tick this as done
    - Unseal `vault-1`; confirm the alert resolves
    - Note in the runbook: this is also a rehearsal of the single most likely real incident

21. *Optional, not gated:* a **new** Grafana dashboard (never an edit to an existing one) with seal status per peer, Raft leader, request rate and latency by mount, token/lease counts, and Raft storage growth. Metrics are queryable in Prometheus regardless; this is presentation.

22. Record in `docs/environment.md`: which alerts exist, where they route (or that they don't), and the A0.5c finding verbatim.

**A9.5 — Upgrade runbook**
15. Write `docs/runbooks/upgrade.md`: standbys first, leader last via `operator step-down`, each node unsealed after restart, chart and image versions bumped together in git. **Downgrades are unsupported** — state it plainly.

**Exit gate**
- [ ] Audit enabled; lines visible via `kubectl logs`; values HMAC'd
- [ ] Snapshot script works; snapshot/key pairing documented
- [ ] **Restore drill completed end-to-end with a measured, recorded RTO**
- [ ] Telemetry endpoint returns `vault_core_unsealed` on a manual `curl`
- [ ] ServiceMonitor deployed **and confirmed as an UP target in Prometheus** — three series, one per peer
- [ ] PrometheusRule deployed; metric names verified against this Vault version
- [ ] **`VaultNodeSealed` fire test passed**: sealed a follower, watched the alert fire, unsealed, watched it resolve
- [ ] Alert routing status recorded honestly — including "fires but notifies nobody" if that is the case
- [ ] No existing Prometheus config, alert rule, dashboard, Alertmanager route, or log pipeline was modified
- [ ] All three runbooks written and cold-tested by following them literally

---

## 7. Acceptance criteria (Stage A complete)

**Availability**
- [ ] 3-node Raft cluster, healthy, one leader, all unsealed
- [ ] Leader failover recovers automatically within a measured window
- [ ] Both exposure paths follow failover without intervention
- [ ] Data survives full pod recreation

**Security**
- [ ] TLS end-to-end, verified without bypass flags, over MetalLB VIP, NodePort 30004, and in-cluster Service
- [ ] Initial root token revoked; regeneration documented and tested
- [ ] Unseal keys at `~/.credentials/vault-poc/` (outside the repo tree) plus a password-manager copy, **verified by unsealing from a retrieved share**; repo scans clean
- [ ] `docs/key-custody.md` records method and holder, and names the production alternative not taken
- [ ] Every Vault role bound to a specific SA + namespace; no wildcards
- [ ] Least privilege proven by three negative tests, not assumed
- [ ] Postgres admin credential rotated to a value no human knows
- [ ] NodePort exposure explicitly accepted in writing

**Functionality**
- [ ] KV v2 serving all Stage B static secrets
- [ ] Database engine issuing 1h-TTL Postgres credentials, genuinely revoked on lease expiry
- [ ] PGP key and passphrase custodied; encrypted fixture available
- [ ] ESO producing Kubernetes Secrets from Vault

**Operations**
- [ ] Audit enabled and readable
- [ ] Vault scraped by Prometheus; targets UP; `VaultNodeSealed` fire-tested end to end
- [ ] Existing observability stack verifiably unmodified
- [ ] Snapshot/restore drill completed with a recorded RTO
- [ ] Seal/unseal, snapshot/restore, and upgrade runbooks written and cold-tested
- [ ] The worker node hosting two Raft peers is named in the runbook

**GitOps**
- [ ] Entire platform reconciled by ArgoCD from git via `root-platform` app-of-apps, children ordered by sync wave
- [ ] `root-applications` exists but is applied only at Stage B Phase B0
- [ ] All versions pinned (chart, image, ESO, cert-manager, PostgreSQL)
- [ ] Bootstrap scripts idempotent — re-running produces no errors and no drift

---

## 8. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Unseal keys deleted by `git clean -xfd`** if kept in-repo | Medium | Vault unrecoverable including from snapshots; rebuild from scratch | D20 — keys live at `~/.credentials/vault-poc/`, outside the repo tree. The init script asserts this and aborts otherwise |
| Host disk failure / OS reinstall / lost laptop | Low | Same as above | D20 — password-manager copy as the durable second; verified readable in Phase A2 |
| Keys and snapshots on the same machine | Medium | One event takes out both halves of the recovery pair | Keys have a second copy off-machine; snapshots remain single-copy on the host for v1 (accepted — regenerable, and rebuild is acceptable per §3.1) |
| Reviewer JWT expiry breaks k8s auth hours after it appeared to work | **High** | All workload auth fails | D6 — Secret-backed non-expiring token; Phase A6 exit gate verifies it |
| Cert SAN gap — especially **node IPs** — surfaces only when the break-glass path is needed | **High** | NodePort unusable during a seal event, when you need it most | Exhaustive SAN list in Phase A2; both paths verified before HA |
| **Node loss takes 2 of 3 peers → quorum loss and peer data loss** | Medium | Vault unavailable; rebuild required | **Accepted, not mitigated** (§3.1). This is a dev environment and the whole cluster is reproducible from Vagrant, Ansible, git, and the bootstrap scripts. `local-path` offers no CSI snapshot fallback. The node hosting two peers is named in the runbook so the exposure is at least known. Longhorn would remove this — backlog |
| **Sealed node goes unnoticed** | Low (mitigated) | Degraded quorum discovered late; potential outage | D15 — `VaultNodeSealed` alert, fire-tested in A9.4. Note the mechanism being defended against: a sealed pod **passes its readiness probe by design**, so `kubectl get pods` shows it as healthy |
| **ServiceMonitor silently not discovered** (wrong selector label) | **High if A0.5b is skipped** | You believe you have seal alerting and do not — strictly worse than knowing you have none | A0.5b records the required labels; A9.4 step 18 requires confirming the target is UP in Prometheus, not merely that the object applied |
| Alert fires but routes to no receiver | Medium | Same as above — false confidence | A0.5c records the finding; A9.4's gate forbids ticking the box if nobody is notified |
| Metric names differ from those in this document | Medium | Alert never fires | A9.4 step 19 requires verifying names against the deployed version's `/v1/sys/metrics` |
| Audit device backpressure blocks Vault | Low | Total outage | D14 stdout device removes the disk-full mode |
| Audit retention limited to pod log rotation | Medium | Audit history lost | Accepted for v1. Shipping audit to Loki would require editing the log collection pipeline, which crosses the D15 boundary — backlog. Recorded as inadequate for real use |
| KV v2 policy path mistake denies everything | High | Confusing debugging | Called out in Phase A6; hit deliberately during verification |
| NodePort 30004 reachable from the whole lab subnet | Medium | Broader admin surface than ideal | Accepted in writing (Phase A5.7); would be firewalled in a real environment |
| Secret material committed to git | Medium | Credential exposure | `.gitignore` committed first; `gitleaks`; scripts assert before writing |
| Version/license drift from this document | Certain | Rework | D16 — verify current stable at implementation time; §5.1 confirmed in Phase A0 |

---

## 9. Backlog (post-v1)

Ordered roughly by value for this environment.

| Item | Trigger | Notes |
|---|---|---|
| **Third worker node** | Cluster capacity | Converts D4 to hard anti-affinity and makes Raft actually fault-tolerant. Now the top operational gap |
| **Longhorn** (or any CSI provisioner with real volume snapshots) | If node-loss rebuilds become tedious | Replicated block storage removes `local-path` node pinning and the accepted data-loss trade in §3.1 entirely. The largest single upgrade available to this lab |
| **Off-host snapshot storage + retention policy** | Before any real use | Snapshots currently live on the dev VM — the same machine that would be gone in the scenario needing them. Lower priority than keys, since snapshots are regenerable |
| **Audit logs → Loki** | When the log pipeline is next touched | Crosses the D15 boundary today. Worth checking first whether an existing node-level collector already picks up all namespaces — if so it may be free |
| **Grafana dashboard for Vault** | Any time | A new dashboard, never an edit. Optional in A9.4 |
| **Alertmanager receiver**, if A0.5c found none | Owner decision | Not this POC's call to make — but without it, alerts fire into an empty room |
| Cloud KMS auto-unseal | Cloud expansion | Removes manual unseal; changes the DR model |
| EKS/GKE deployment (Stage A v2) | Cloud expansion | IRSA / Workload Identity replaces part of the k8s auth story |
| Vault Agent Injector (Stage B Level 5) | After Stage B | Fourth consumption pattern; completes the comparison |
| Secrets Store CSI Driver | After Stage B | Fifth pattern; mount-based |
| Terraform `vault` provider for config-as-code | After bootstrap scripts are understood | The correct production answer (D9) |
| PKI secrets engine + cert-manager `vault-issuer` | Independent | Own POC |
| OpenBao evaluation | If OSS policy changes | API-compatible; low switching cost (§5.1) |
| Transit auto-unseal via a dedicated unsealer Vault | If Vault count grows | Documented in Phase A3 |

---

## 10. Claude Code handoff notes

**Working assumption:** the executing session has admin on `learning-labs-developer-workspace-type-01`, repo write access, and **no prior context from this design conversation**. This document must stand alone.

**Rules of engagement**

1. **Phase gates are hard.** Do not begin phase N+1 until every checkbox in phase N is ticked. Report a failed gate rather than working around it.
2. **Keys go to `~/.credentials/vault-poc/vault-init.json` on the host, never inside the repo tree** (D20). `00-init-unseal.sh` must resolve the path from `${VAULT_POC_KEYS:-$HOME/.credentials/vault-poc}`, `mkdir -p` it `0700`, and **assert the target is outside the repo, aborting if not.** In-repo plus `.gitignore` is not sufficient: `git clean -xfd` deletes gitignored files by design. Phase A2 cannot close until a second copy exists off-machine and has been read from successfully. `docs/key-custody.md` records method and holder only — never the location or the shares.
2b. **Apply `root-platform` only during Stage A** (D19). `root-applications` waits for Stage B Phase B0. Applying both early deploys app pods before Kubernetes auth exists, which fails in a way that looks like an app bug.
3. **Never commit secret material.** `vault-init.json`, `*.key`, `*.asc`, `*.snap`, and PGP passphrases stay local. Scripts must assert `.gitignore` coverage before writing any file containing key material, and abort if the assertion fails.
3. **Verify, don't assume, environment values.** MetalLB pool and the chosen VIP, `local-path` StorageClass name, node IPs, registry address, and the OIDC issuer are all read from the live cluster in Phase A0 and written into `docs/environment.md`. Never hardcode a value this document guessed at.
4. **Pin versions; verify current stable first.** Before Phase A1, check current stable releases for the Vault chart, Vault image, ESO, cert-manager, and PostgreSQL. Versions are deliberately absent from this document (D16).
5. **Node IPs go in the cert SANs.** This is the most likely single omission in the whole build, and it fails silently until the break-glass path is needed.
6. **Bootstrap scripts must be idempotent.** Guard every `vault secrets enable` / `auth enable` with an existence check. They will be re-run.
7. **Negative tests are deliverables.** Phase A6's three denial tests are load-bearing, because all four Stage B roles share one namespace and the ServiceAccount name is the only isolation boundary. An unrun denial test is a failed gate.
8. **Additive-only against the observability stack (D15).** You may create new objects Prometheus discovers by itself: `ServiceMonitor`, `PrometheusRule`, and optionally a new dashboard. You may **not** edit an existing scrape config, alert rule, dashboard, Alertmanager route, recording rule, or log pipeline. If a step appears to need one — a namespace missing from `serviceMonitorNamespaceSelector`, an absent Alertmanager receiver, a non-operator Prometheus — **stop and report the finding.** Do not fix it.
8b. **"Applied cleanly" is not "working."** A ServiceMonitor with the wrong discovery label deploys without error and is never scraped. Phase A9.4 requires confirming the target is UP in Prometheus and fire-testing `VaultNodeSealed` by sealing a follower. Neither box may be ticked from a successful `kubectl apply`.
9. **Report the numbers.** Failover window (A4), lease revocation behaviour (A7), and restore RTO (A9.3) are results. Record them in `docs/`, not in conversation.
10. **Stop and ask** if: the BUSL check in Phase A0 is blocked by org policy; the cluster has fewer than 2 workers; the OIDC issuer lookup returns something unexpected; MetalLB has no allocatable address; or a gate fails twice for the same reason.

**Suggested commit granularity:** one commit per phase, prefixed `phase-a{N}:`, with the exit-gate checklist in the commit body.
