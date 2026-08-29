# Claude Code Playbook — Stage B (Go Applications)

**Companion to:** `PRD_HashiCorp_Vault_Application_Golang.md` v1.2.0
**Read first:** `CLAUDE.md`
**Prerequisite:** every Stage A acceptance criterion passes

The PRD is the specification. This playbook is the execution order, plus the traps.

---

## What you are building and why the order matters

Four Go applications. Each demonstrates a different relationship between an application and Vault, and **each one exposes the limitation the next one solves.**

| Level | Pattern | Teaches | Its limitation → next level |
|---|---|---|---|
| 1 | ESO → Secret → env var | The app has no idea Vault exists | Can't rotate without a restart |
| 2 | Direct Kubernetes auth | The handshake, written by hand | Secrets are still static |
| 3 | Dynamic DB credentials | Leases, renewal, revocation | Only works for creds Vault can *generate* |
| 4 | Key custody via tmpfs | Material Vault stores but can't use | The key is exposed to the app |

Level 1 is deliberately unimpressive. Understanding *why* the ten-line version is what most teams ship, and exactly what it costs them, is worth more than skipping to the sophisticated pattern.

**Build in order.** Each level's README ends with what it doesn't solve, which motivates the next.

---

## Session model

| Session | Phases |
|---|---|
| 1 | B0 → B1 — scaffolding, pipeline, Level 1 |
| 2 | B2 — Level 2 (the handshake) |
| 3 | B3 — Level 3 (the big one; may need two sessions) |
| 4 | B4 — Level 4 |
| 5 | B5 → B6 — hardening, matrix, synthesis |

Commit per phase, prefixed `phase-b{N}:`, exit-gate checklist in the body.

---

## Phase B0 — Scaffolding

### Verify Stage A first — all seven

```bash
VAULT_ADDR=https://<metallb-vip>:8200 vault status          # unsealed, 3 peers, active
VAULT_ADDR=https://<node-ip>:30004    vault status          # break-glass alive
kubectl get clustersecretstore vault-backend -o jsonpath='{.status.conditions}'
vault read database/creds/level3-app
vault kv get secret/level4/pgp
kubectl logs -n vault -l app.kubernetes.io/name=vault | tail
vault list auth/kubernetes/role                             # five roles
```

**If any fail, stop and report.** Stage B built on a half-working Vault produces results that mislead rather than teach.

### Build the subtree

Create `applications/` per PRD §3. **Four separate `go.mod` files. No root module. No `go.work`.**

If you find yourself wanting a shared package, re-read CLAUDE.md rule 7. The duplication is the mechanism.

Write `argocd/root-applications.yaml` and its four children — **apply only after the Stage A verification above passes.**

Uniform `Containerfile` (multi-stage, distroless static, non-root) and per-level `Makefile` with `build`, `image`, `push`, `deploy`, `logs`, `verify`, `destroy`.

Uniform pod security context on all four:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
```

`readOnlyRootFilesystem` is load-bearing for Level 4 — it makes the tmpfs mount a real constraint rather than decoration, and forces the correct answer.

Create the `vault-ca` ConfigMap in `poc-hashicorp-vault-application`.

**Smoke test the pipeline** with a hello-world binary: build → SHA-tagged push → ArgoCD → Running → `/healthz` 200. Then delete it.

---

## Phase B1 — Level 1: env var via ESO

**The code is trivial. The verification is the point.**

~40 lines: read two env vars, fail loudly if unset, serve `/healthz` and `/secret`. Never log the API key value — length and prefix only.

`ServiceAccount: level1-app` is created but **granted no Vault role at all**. That is the demonstration.

### Verification

```bash
curl .../secret                                    # Vault-sourced values
grep -ri vault applications/level1-env-secret/     # ← ZERO matches. The deliverable.
kubectl get secret level1-app-secret -o yaml       # base64, not encrypted. In etcd.
```

### Failure injection — the important part

1. `vault kv put secret/level1/app greeting="CHANGED"`
2. Wait past `refreshInterval` → **the Kubernetes Secret updates**
3. `curl /secret` → **still the old value**
4. `kubectl rollout restart` → now it's new

### README must say

No Vault dependency, no Vault credential, no Vault code. Secret at rest in etcd, base64, readable by anyone with `get secret` in the namespace. **Rotation requires a restart** — the process environment is fixed at exec time. This is the right choice for legacy apps, third-party images, and anything you can't modify, which is most things.

**Doesn't solve:** rotation without restart; credential lifetime; revocation; audit attribution (the audit log shows *ESO* read it, not your app).

---

## Phase B2 — Level 2: the handshake, by hand

**Raw `net/http` only. No `vault/api` in this module's `go.mod`.** This is checked mechanically in B5.

`auth.NewKubernetesAuth()` collapses the entire handshake into one line, which is exactly why it's forbidden here. Once you've written it by hand, using the SDK afterwards is an informed choice.

### The five steps

1. Read the SA JWT from `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. TLS config trusting the mounted Vault CA — **never `InsecureSkipVerify`**
3. `POST /v1/auth/kubernetes/login` with `{jwt, role}` → `client_token`, `lease_duration`
4. `GET /v1/secret/data/level2/app` with `X-Vault-Token`
5. Goroutine renewing at 2/3 of `lease_duration` via `auth/token/renew-self`, **falling back to full re-login on failure**

**KV v2 response shape:** `{"data": {"data": {...}, "metadata": {...}}}`. Double nesting. KV v1 has one level. Everyone hits this once.

Manifests contain **no Vault credential of any kind**. The ServiceAccount is the credential.

Endpoints: `/healthz`, `/secret`, `/token-info` (from `auth/token/lookup-self` — useful for watching the TTL count down).

### Failure injection

| Test | Expected |
|---|---|
| `VAULT_ROLE=level4-pgp` | Login succeeds, secret read **403** |
| `serviceAccountName: default` | Login **fails at step 3** |
| Token revoked by accessor | 403, then the app **re-authenticates** rather than staying broken |
| Vault scaled to 0 briefly | Logs failures, recovers on return, **does not crash-loop** |

### Audit correlation — do this once, properly

```bash
# terminal 1
kubectl logs -n vault -l app.kubernetes.io/name=vault -f | jq 'select(.type=="response")'
# terminal 2
kubectl logs -n poc-hashicorp-vault-application -l app=level2-app -f
```

Trigger each injection and line up the pair. In the audit entry, find `auth.metadata.service_account_name`, the attached policies, and confirm the secret value is HMAC'd.

**This is the closing of the loop between the two PRDs** — your app's claim about who it is, and Vault's independent record of who it decided you were.

### README

The handshake step by step. That ESO does exactly this with `role=eso` on your behalf. **Doesn't solve:** the secret is still static. Read it a thousand times, same value. Nothing expires. A leaked value stays valid forever.

---

## Phase B3 — Level 3: dynamic credentials

**The substantial one.** Budget accordingly; two sessions is normal.

### Structure

- `vault_creds.go` — auth + `database/creds` read + lease renewal (SDK is fine here)
- `db.go` — pool construction, atomic swap, graceful drain
- `lease.go` — renewal loop, jittered backoff, re-auth trigger
- `main.go` — wiring + HTTP

### Build `/creds-info` early

Current username, lease ID, TTL remaining, renewal count, rotation count. It is the observation window for everything below. Building it last means debugging blind.

Also `/query` returning Postgres's `current_user` — so you can *watch the username change* across a rotation.

### The lifecycle

```
renew at 2/3 of lease_duration
  ├─ success → new lease_duration, same pool
  └─ failure → jittered backoff, retry
       └─ exhausted OR max_ttl reached (renewal refused)
            → re-authenticate
            → request fresh credentials
            → build a NEW pool
            → serve new traffic from it
            → drain the old pool gracefully, then close
```

2/3 leaves a third of the TTL for retries — enough headroom for transient Vault unavailability without renewing so aggressively it masks problems.

### Failure injection — this is the phase

| # | Test | What it proves |
|---|---|---|
| 4 | `vault lease revoke <id>` | Detects, re-auths, rebuilds pool. `/creds-info` shows a **different username**, rotation count 1 |
| 5 | **Temporarily set `default_ttl=2m max_ttl=6m`** | Two renewals succeed, third is **refused**, forced re-auth path runs |
| 6 | Vault scaled to 0 during a renewal window | Backs off, **keeps serving** on the still-valid credential, recovers |
| 7 | Postgres down | Distinguishes "DB down" from "creds invalid" — does not uselessly re-auth against Vault |
| 8 | Slow query, rotate mid-flight | In-flight query **completes** rather than erroring |

**Test 5 is the one that matters most.** `max_ttl` exhaustion is not a choice — it is guaranteed to happen in production, and it is almost never tested. Shortening the TTL forces it in minutes instead of a day. Restore the original TTLs afterwards.

**Target: zero request errors during rotation.** If callers can see a rotation, the drain logic is wrong.

Record: renewal count over an hour, rotation latency, errors during rotation.

### On `SIGTERM`

Revoke the lease. Then confirm no orphans:

```bash
vault list sys/leases/lookup/database/creds/level3-app
```

### README

Why a 1-hour credential is categorically different: bounded leak windows, instant central revocation, every credential attributable to a specific pod's identity. The lease as a **contract** — Vault revokes on schedule whether or not you're ready. `max_ttl` is not optional; the re-auth path is mandatory, not defensive.

**Doesn't solve:** works only for credentials Vault can *generate*. Key material it merely stores — a PGP key, a signing key, a licence file — needs a different pattern.

---

## Phase B4 — Level 4: key custody

### Flow

```
1. k8s auth login
2. read secret/data/level4/pgp
3. write private_key → /keys/private.asc   [tmpfs, mode 0400]
4. decrypt with passphrase, import to in-memory keyring
5. os.Remove("/keys/private.asc")          ← immediately
6. decrypt fixtures/secret-message.txt.gpg
7. write plaintext → /output/decrypted.txt [tmpfs]
8. print to stdout
9. serve /result
```

**`emptyDir: {medium: Memory}` — not a plain emptyDir.** A normal emptyDir puts the PGP private key on the node's disk, where it is recoverable and may survive in backups. Verify it is real tmpfs:

```bash
kubectl exec ... -- df -h /keys     # filesystem type must be tmpfs
```

Use `github.com/ProtonMail/go-crypto/openpgp`. **Not** `golang.org/x/crypto/openpgp` — frozen and deprecated.

**Why write the file at all?** You could decrypt straight from memory. The requirement specifies tmpfs, and there's a real reason: it makes the key's on-disk lifetime *observable*. You can `kubectl exec` during the window and see it, then see it gone. `/key-status` reports whether it currently exists and how long it did.

### Failure injection

| Test | Expected |
|---|---|
| Wrong passphrase | Clear failure at import. Not silent garbage. Passphrase not logged |
| Role lacking `level4-pgp` | Clean 403, clear error |
| Truncated `.gpg` fixture | Decryption error, **no partial plaintext written or printed** |
| Pod restart | Full flow re-runs; tmpfs empty on the new pod |

### README

Vault **custodies** this key; it does not **use** it. Contrast with Transit, where the key never leaves Vault and Vault does the crypto — backlog.

**Honest limitation, do not overclaim:** once the key is in the Go process it is in Go's heap. Strings are immutable and the GC may copy them. Reliable zeroization needs `[]byte` throughout plus `mlock`, which is out of scope. Use `[]byte` where practical and **state that this is mitigation, not a guarantee.** That honesty is worth more than a false claim of secure erasure.

**Doesn't solve:** the key is exposed to the application. Compromise the app while the key is in memory and the key is compromised.

---

## Phase B5 — Independence and hardening

### Independence

1. Deploy all four. All healthy.
2. Delete Level 2 entirely → 1, 3, 4 unaffected. **Verify by endpoint, not assumption.**
3. Rebuild Level 3 alone → others untouched.
4. From a clean checkout, deploy **only** Level 4. Must work alone.
5. `grep -r "level[0-9]" applications/*/go.mod` → no matches.

### The 4×4 matrix — mandatory, not sampled

All four apps share one namespace. The ServiceAccount name is the **only** thing between Level 1 and the PGP private key.

| Acting as ↓ / Reading → | `level1/app` | `level2/app` | `database/creds` | `level4/pgp` |
|---|---|---|---|---|
| `level1-app` | allow | **deny** | **deny** | **deny** |
| `level2-app` | **deny** | allow | **deny** | **deny** |
| `level3-app` | **deny** | **deny** | allow | **deny** |
| `level4-app` | **deny** | **deny** | **deny** | allow |

Twelve denials, four allows. Plus the SA/role mismatch dimension: `level1-app`'s SA requesting role `level4-pgp` must fail at **login**, not at read.

Record actual results. A matrix that has never been run is a hypothesis.

### Sweep

```bash
gitleaks detect                                    # clean
kubectl logs ... | grep -i "passphrase\|BEGIN PGP\|hvs\."   # nothing
grep -rn "InsecureSkipVerify" applications/        # nothing
```

Confirm all four pods: non-root, read-only rootfs, dropped caps, `RuntimeDefault`.

Confirm every Deployment sets `serviceAccountName` **explicitly**. A missing one silently uses `default` — a security defect, not a typo. Confirm `default` is bound to no Vault role at all.

### NetworkPolicy

Intra-namespace via `podSelector` (shared namespace). Default-deny both directions, then per level: DNS to kube-dns, egress to `vault.vault.svc:8200`, and Level 3 only to `postgres:5432`.

**Levels must not reach each other.** Verify by attempting a connection from Level 1 to Level 3's Service and confirming refusal.

---

## Phase B6 — Synthesis

**The phase that makes the POC worth having done.** Write `docs/pattern-comparison.md`.

Fill the comparison table from PRD §6 B6 with **measured numbers, not estimates** — rotation latency, renewal counts, errors during rotation, key-on-disk window.

Also write:
- A decision tree: which pattern for which situation, and why
- The three most surprising findings. Candidates: the double-nested KV v2 JSON; that Level 1's Secret updates while the running pod doesn't; that Level 3's `max_ttl` path is guaranteed to execute and almost never tested
- What **Level 5 (Vault Agent Injector)** would change: Level 1's "app knows nothing" property *with* Level 3's rotation, at the cost of a sidecar per pod. That's the trade the backlog item exists to explore

Every level README needs its "what this doesn't solve" section. Without them the progression is four unrelated demos rather than an argument.

---

## Failure quick reference

| Symptom | Likely cause |
|---|---|
| Secret read 403, login fine | KV v2 path — policy needs `secret/data/x` |
| Login fails outright | SA/role binding mismatch, or `serviceAccountName` missing |
| TLS error reaching Vault | `vault-ca` ConfigMap not mounted. **Do not add `InsecureSkipVerify`** |
| Level 3 works an hour, then dies | `max_ttl` reached, no re-auth path — test 5 |
| Errors during rotation | Pool swapped without draining |
| Level 4 key still on disk | Plain `emptyDir` — needs `medium: Memory` |
| Level 1 shows a stale value | Working as designed. That's the lesson |

---

## Stage B is done when

All of PRD §6 passes. The short version: four levels deploy and tear down independently; Level 1 has zero Vault references; Level 2 uses `net/http` only; Level 3 survives revocation and `max_ttl` with **zero request errors during rotation**; Level 4 decrypts and demonstrably removes the key; the 4×4 matrix is run and recorded; no secrets in git, images, logs, or manifests; no `InsecureSkipVerify` anywhere; and `pattern-comparison.md` contains real measurements.
