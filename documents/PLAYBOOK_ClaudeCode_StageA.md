# Claude Code Playbook — Stage A (Vault Platform)

**Companion to:** `PRD_HashiCorp_Vault_Kubernetes_Cluster_Onprem.md` v1.4.0
**Read first:** `CLAUDE.md`
**Cluster:** `learning-labs-developer-workspace-type-01`

The PRD is the specification — what to build and why. This playbook is the execution order — what to do in a session, what to verify before moving, and where things go wrong.

---

## Session model

Ten phases. Do not attempt them in one session.

| Session | Phases | Rough shape |
|---|---|---|
| 1 | A0 | Discovery and scaffolding. Mostly reading the cluster. Ends with a repo and `docs/environment.md` |
| 2 | A1 → A2 | Dev-mode smoke, then the real single-node Vault. The longest session |
| 3 | A3 → A4 | Seal runbook, then scale to 3 peers and fail one over |
| 4 | A5 → A6 | Access paths, then Kubernetes auth and policies |
| 5 | A7 → A8 | Secrets engines, Postgres, PGP seeding, ESO |
| 6 | A9 | Audit, metrics, alerting, and the restore drill |

**Start every session** by reading `docs/environment.md` and the previous phase's commit body. **End every session** by committing with the exit-gate checklist filled in, so the next session knows exactly where it is.

---

## Phase A0 — Readiness and scaffolding

**Goal:** eliminate every unknown before Vault exists.

This phase is almost entirely reading. Resist the urge to deploy something.

### Discovery — write every answer into `docs/environment.md`

```bash
kubectl get nodes -o wide                      # names, IPs, roles
kubectl version                                # bump if 1.29 (EOL)
kubectl get sc                                 # local-path present? default?
kubectl -n metallb-system get ipaddresspool -o yaml
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
argocd version
```

**Pick and record a MetalLB VIP for Vault.** Confirm it is inside the pool and not already allocated.

**Confirm ArgoCD multi-source support.** `spec.sources` (plural) must be accepted. If your ArgoCD predates it, fall back to Kustomize `helmCharts:` inflation and record the deviation from D1 in `docs/environment.md`. Do not silently switch.

### The three Prometheus checks (A0.5)

These determine whether A9.4 is two objects or a stop-and-report. **Do not skip 5b.**

```bash
# 5a — operator-managed?
kubectl get crd servicemonitors.monitoring.coreos.com prometheusrules.monitoring.coreos.com
# absent → static scrape config → adding a target means editing a working file → STOP

# 5b — what label does Prometheus require for discovery?
kubectl get prometheus -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.spec.serviceMonitorSelector}{"\t"}{.spec.serviceMonitorNamespaceSelector}{"\n"}{end}'
# record the EXACT labels. also check whether `vault` is inside the namespace selector

# 5c — does Alertmanager reach a human?
kubectl get alertmanager -A
```

**5b is the only silent failure in this entire build.** Wrong label → the ServiceMonitor applies cleanly, reports nothing, and is never scraped. You will believe you have seal alerting and you will not. Everything else in Stage A fails loudly.

If `vault` is outside `serviceMonitorNamespaceSelector`, adding it *is* an edit to their config. Report; do not fix.

### Scaffolding

Install cert-manager (pinned). Build the issuer chain: self-signed `ClusterIssuer` → CA `Certificate` → CA `ClusterIssuer`.

Create the three namespaces.

Create the repo per PRD §6 A0.9. **Commit `.gitignore` first** — before any file it covers can exist.

Write both root Applications. **Apply neither yet.**

### Gate

- [ ] `docs/environment.md` complete, including OIDC issuer and Prometheus labels
- [ ] Test PVC binds; PV location confirmed on a node
- [ ] cert-manager issues a test Certificate
- [ ] Multi-source support confirmed, or the fallback recorded
- [ ] BUSL position confirmed against org policy
- [ ] Repo scaffolded, `.gitignore` committed first
- [ ] `docs/key-custody.md` drafted

---

## Phase A1 — Dev-mode smoke

**Goal:** prove the delivery path in isolation, then throw it away.

Apply `root-platform.yaml` only. Deploy the chart with `server.dev.enabled=true`, 1 replica.

```bash
kubectl -n vault exec vault-0 -- vault status
kubectl -n vault exec vault-0 -- vault kv put secret/smoke hello=world
kubectl -n vault exec vault-0 -- vault kv get secret/smoke
```

**Then delete the release entirely.** Nothing survives.

This phase exists to separate "my ArgoCD/Helm path is broken" from "my Vault config is wrong." Debugging both simultaneously in A2 is where days disappear.

### Gate

- [ ] `root-platform` syncs; children created in wave order
- [ ] Vault child syncs from the Helm repo with git-sourced values
- [ ] KV round-trips
- [ ] Release deleted; namespace empty
- [ ] `root-applications` **not** applied

---

## Phase A2 — Single-node Raft, TLS, manual unseal

**The longest and highest-risk phase.** Budget a full session.

### Order matters here

**1. Certificate first, and get the SANs exactly right.**

```
DNS: vault, vault.vault, vault.vault.svc, vault.vault.svc.cluster.local,
     vault-active, vault-active.vault.svc.cluster.local,
     vault-lb, vault-lb.vault.svc.cluster.local,
     *.vault-internal, *.vault-internal.vault.svc.cluster.local,
     localhost
IP:  127.0.0.1, <MetalLB VIP>,
     <control-plane IP>, <worker-1 IP>, <worker-2 IP>
```

**The node IPs are the ones everyone forgets.** Without them the NodePort break-glass path fails TLS — discovered during a seal event, which is the only time you need it. Verify before moving on:

```bash
openssl s_client -connect <node-ip>:30004 -servername vault 2>/dev/null \
  | openssl x509 -noout -text | grep -A3 "Subject Alternative Name"
```

**2. Deploy** with `ha.enabled=true`, `ha.raft.enabled=true`, `ha.replicas=1`, TLS on, PVC on `local-path`, versions pinned. HCL config per PRD §6 A2.3 — including the telemetry stanza, which A9.4 depends on.

**3. Initialize and secure the keys.**

`00-init-unseal.sh` must:
- Resolve `${VAULT_POC_KEYS:-$HOME/.credentials/vault-poc}`
- `mkdir -p` it `0700`
- **Assert the path is outside the repo tree, and abort if not**
- `vault operator init -key-shares=5 -key-threshold=3 -format=json` into it
- Unseal with 3 shares

Then paste the JSON into a password manager. Then **verify by reading from the backup** — seal, retrieve a share from the password manager rather than the working file, unseal with it.

A backup you have never read from is a hypothesis.

**4. Expose both paths.** `vault-lb` (LoadBalancer, MetalLB VIP) and `vault-nodeport` (NodePort 30004), both selecting `vault-active`. Reuse the chart's existing active-node selector rather than inventing one.

**5. Verify both, without bypass flags:**

```bash
VAULT_ADDR=https://<metallb-vip>:8200 VAULT_CACERT=... vault status
VAULT_ADDR=https://<node-ip>:30004   VAULT_CACERT=... vault status
```

Either failing means a missing SAN. Go back to step 1. Do not add `-tls-skip-verify`.

**6. Restart test.** `kubectl delete pod vault-0`. It must come back **sealed**. Unseal. Confirm the KV data written earlier survived.

### Gate

- [ ] Initialized, unsealed, storage `raft`, HA mode active
- [ ] TLS verifies over both paths, no bypass
- [ ] Data survives pod deletion; returns sealed
- [ ] Keys at `~/.credentials/vault-poc/`, **outside the repo**
- [ ] Password-manager copy exists and has been **read from successfully**
- [ ] `vault-init.json` absent from `git status`
- [ ] `docs/key-custody.md` written — method and holder, never location

---

## Phase A3 — Seal runbook

No deployment. Write `docs/runbooks/seal-unseal.md` while the manual unseal is fresh.

Must cover: what sealing is; when Vault seals (restart, `operator seal`, quorum loss); the unseal procedure **including via NodePort**, since a seal event may coincide with whatever broke MetalLB; key custody as practised and as it would be in production (five holders, threshold three, nobody able to unseal alone — state plainly that you are not doing this and why); `operator rekey` and `operator generate-root`.

Also document Transit auto-unseal and cloud KMS as options **not taken**, with honest tradeoffs. Transit moves the problem rather than solving it — the unsealer still needs unsealing.

**Gate:** a second person could unseal from this document, cold, over either network path.

---

## Phase A4 — Scale to 3 peers

Add `retry_join` for all three peers. Set `ha.replicas=3` with **soft** anti-affinity (2 workers make hard anti-affinity unschedulable).

**Each new peer must be unsealed individually** with the same shares. This surprises people — put it in the runbook.

```bash
kubectl -n vault exec vault-0 -- vault operator raft list-peers
kubectl -n vault get pods -o wide     # ← record which node has TWO peers
```

**Failover drill.** Delete the leader. Record: election time, that `vault-active` re-points, that the restarted pod returns sealed, and the measured unavailability window.

Then write the honest paragraph into the runbook — the PRD supplies suggested wording. The short version: this cluster runs Raft to *exercise* Raft, not to achieve availability. Two peers share one node. Losing it costs quorum.

### Gate

- [ ] 3 peers, one leader
- [ ] Failover completes; both exposure paths follow
- [ ] Window measured and recorded
- [ ] The double-peer node named in the runbook

---

## Phase A5 — Access paths

Re-verify both paths against the HA cluster. Trigger a failover, re-run both immediately — both must follow the new leader with no intervention.

Add a hosts entry for the VIP. **If the friendly name is not in the cert SANs, reissue now** — not later.

Trust the CA in the OS store and browser. Load the UI over the VIP; confirm a valid padlock.

Record in `docs/environment.md`: both URLs, when to use which, exact env exports. Record the NodePort exposure as a deliberate acceptance — 30004 is reachable from anything routing to `192.168.56.0/24`, which is fine here and would be firewalled in production.

---

## Phase A6 — Kubernetes auth and policies

**The trickiest configuration phase.** Two footguns, both known.

**Footgun 1 — the reviewer JWT.** Projected SA tokens rotate hourly; Vault reads `token_reviewer_jwt` once at config time and never again. Configure it from a projected token and auth works fine, then breaks silently hours later.

Use a Secret-backed non-expiring token:

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

Grant `system:auth-delegator` to the `vault` SA. Use the **real** OIDC issuer from A0 — never a guess.

**Footgun 2 — KV v2 paths.** The API path is `secret/data/<path>` for reads and `secret/metadata/<path>` for list and delete, even though the CLI shows `secret/<path>`. A policy written against the CLI-visible path denies everything, silently.

Hit this deliberately here so you recognise it in Stage B.

Write five policies and five roles per PRD §6 A6.5–6. All four app roles bind to `poc-hashicorp-vault-application` and differ only by ServiceAccount name — **which makes the SA the entire isolation boundary.**

### Three negative tests — these are the deliverable

1. Same role, SA `default` → login **denied**
2. `level1-app` SA requesting role `level4-pgp` → **denied**
3. `level1-reader` token reading `secret/data/level4/pgp` → **403**

An auth method that has never said no has not been tested.

Then revoke the root token. Document `operator generate-root`, and test it once so you know it works.

---

## Phase A7 — Secrets engines

KV v2 at `secret/`, seeded for Levels 1 and 2.

PostgreSQL into `poc-hashicorp-vault-application` — single replica, `vaultadmin` superuser, `appdb`, and a **seeded demo table** so Level 3 has something real to query.

Database secrets engine per PRD §6 A7.3, then:

```bash
vault write -f database/rotate-root/poc-postgres
```

After this the credential Vault uses is known to no human. That is the moment dynamic secrets stop being abstract.

**Prove revocation is real** — generate credentials, connect, revoke the lease, confirm the connection fails and the role is gone from `\du`. Not "confirm the API returned 204."

PGP: generate an RSA-4096 keypair with passphrase, encrypt the fixture, upload key + passphrase + public key to `secret/level4/pgp`, **delete the local private key**, verify with `ls`.

---

## Phase A8 — ESO

Install ESO. Create the `eso` Vault role. Create the `ClusterSecretStore` pointing at the **in-cluster** Service — the external paths are for humans.

**Check `status.conditions` shows `Ready=True`.** A store that cannot authenticate fails quietly.

Rotation test: change the value in Vault, wait for `refreshInterval`, confirm the Kubernetes Secret updates — **and confirm a running pod's env var does not.** That gap is the entire subject of Stage B Level 1.

---

## Phase A9 — Audit, metrics, backup

### A9.1 Audit

```bash
vault audit enable file file_path=stdout
```

Enable this **before Stage B begins** so every Stage B request is captured. Verify lines appear in `kubectl logs`. Confirm values are HMAC'd, not plaintext.

Not shipped to Loki — that would require editing the log pipeline (CLAUDE.md rule 8). Note in the runbook that pod log rotation determines audit retention and that this is inadequate for real use.

### A9.4 Metrics and alerting — additive only

**Verify the endpoint first**, before wiring anything to it:

```bash
kubectl -n vault exec vault-0 -- \
  curl -sk https://127.0.0.1:8200/v1/sys/metrics?format=prometheus | grep vault_core_unsealed
```

Empty means the A2 telemetry stanza is missing. Fix that, not the ServiceMonitor.

**ServiceMonitor** targets the `vault` Service — **not** `vault-active`. You need per-peer seal status; scraping only the leader defeats the purpose. The discovery label comes from **A0.5b**, not from a guess.

**Then prove it is scraped:**

```bash
kubectl port-forward -n <prom-ns> svc/<prometheus> 9090:9090
# http://localhost:9090/targets → three vault targets, all UP
# query: vault_core_unsealed → three series, all 1
```

Empty target list means the label is wrong. Go back to A0.5b. **Deploying cleanly is not evidence.**

**PrometheusRule** with `VaultNodeSealed`, `VaultNoRaftLeader`, `VaultTargetDown`, `VaultAuditFailures`. Verify metric names against your Vault version's actual output — telemetry names shift between releases.

**Fire test — this is the gate:**

```bash
kubectl -n vault exec vault-1 -- vault operator seal   # a follower; quorum holds
```

Watch the metric drop, the alert move Pending → Firing after 2m, then unseal and watch it resolve. If Alertmanager has no receiver per A0.5c, **record that it fires but notifies nobody** and do not tick the box.

Why this matters: **a sealed Vault pod passes its readiness probe by design** — the chart treats `sealedcode=204` as healthy so Kubernetes won't kill a pod waiting to be unsealed. With 3 peers, one sealed node is invisible. Quorum holds, apps keep working, and you are one event from a rebuild.

### A9.3 Restore drill

**Framing:** node loss and rebuild are accepted for this dev environment. This is **not** disaster recovery. It is a learning deliverable, because three things cannot be learned any other way:

1. A snapshot is encrypted under its originating cluster's seal. Without the original shares it is an unopenable blob.
2. `restore -force` overwrites the entire dataset. No merge, no partial.
3. You unseal with the **original** shares — the fresh init's keys are discarded.

Procedure: snapshot → write a canary *after* it → delete the StatefulSet **and PVCs** → redeploy → `operator init` → `snapshot restore -force` → unseal with **original** shares → confirm pre-snapshot data present and canary absent.

**Record wall-clock time for the destroy-through-verify span. That is your RTO.** Into the runbook, not a chat message.

### Gate

- [ ] Audit enabled, HMAC'd, visible in logs
- [ ] Telemetry endpoint returns `vault_core_unsealed`
- [ ] ServiceMonitor **confirmed UP** in Prometheus — three series
- [ ] Metric names verified against this Vault version
- [ ] **`VaultNodeSealed` fire test passed** end to end
- [ ] Alert routing status recorded honestly
- [ ] Restore drill complete with measured RTO
- [ ] **Nothing in the existing observability stack was modified**
- [ ] Three runbooks written and cold-tested

---

## Failure quick reference

| Symptom | Likely cause |
|---|---|
| Raft peers won't join | Missing `*.vault-internal` SAN, or `retry_join` CA path wrong |
| `vault status` fails over NodePort but works over VIP | Node IPs missing from cert SANs |
| K8s auth worked, broke ~1h later | Reviewer JWT is a projected token — use the Secret-backed one |
| Policy denies a path that looks correct | KV v2 — needs `secret/data/<path>`, not `secret/<path>` |
| ServiceMonitor applied, no metrics | Discovery label wrong — recheck A0.5b |
| Pod `Pending` after scaling to 3 | Hard anti-affinity on 2 workers — must be soft |
| Vault stopped serving all requests | Audit device cannot write. Should not happen with stdout |
| Restored snapshot won't unseal | Using the new init's keys. Use the **original** shares |

---

## Stage A is done when

All of §7 in the PRD passes. The short version: 3 peers healthy and unsealed; TLS verified over three paths with no bypass; root revoked; three negative tests denying; dynamic Postgres credentials genuinely revoked at the database; ESO producing Secrets; audit on; seal alert fire-tested; restore drill done with a recorded RTO; everything reconciled by ArgoCD with pinned versions; and the existing observability stack provably untouched.

Then hand off to `PLAYBOOK_ClaudeCode_StageB.md`.
