# PRD — Go Applications Consuming HashiCorp Vault

**Document ID:** PRD_HashiCorp_Vault_Application_Golang
**Version:** 1.2.0
**Stage:** B (Application / consumption patterns)
**Status:** Design locked — ready for Claude Code handoff
**Owner:** Adhito (SRE)
**Target cluster:** `learning-labs-developer-workspace-type-01`
**Target namespace:** `poc-hashicorp-vault-application` (single namespace, all four levels)
**Depends on:** `PRD_HashiCorp_Vault_Kubernetes_Cluster_Onprem.md` (Stage A) — **all Stage A acceptance criteria must pass before Stage B begins**

**Changelog**
- **1.2.0** — Folded into the single `vault-poc/` repository under `applications/` (Stage A D18); ArgoCD app-of-apps via `root-applications`, applied at Phase B0 and not before (Stage A D19).
- **1.1.1** — Aligned with Stage A v1.2.0: metrics/alerting are now additive-only rather than out of scope. Audit correlation stays on `kubectl logs` (D14 unchanged).
- **1.1.0** — Namespace fixed to `poc-hashicorp-vault-application` for all levels (D15); audit correlation moved from Loki to `kubectl logs` per the Stage A observability decision (D14); cluster named.
- **1.0.0** — Initial design.

---

## 1. Purpose

Four Go applications, each demonstrating a distinct way an application relates to Vault, deployed independently, ordered so that each level exposes the limitation the next one solves.

The progression is the point:

| Level | Pattern | What it teaches | What it can't do |
|---|---|---|---|
| **1** | ESO → Kubernetes Secret → env var | The app has no idea Vault exists. This is what most production apps actually do | Cannot rotate without a restart; secret sits at rest in etcd |
| **2** | App authenticates to Vault directly | The Kubernetes auth handshake, implemented by hand | Static secrets still — nothing is time-bound |
| **3** | Dynamic database credentials with leases | Credentials that expire, renew, and get revoked. The actual reason Vault exists | Requires the app to manage a lease lifecycle correctly |
| **4** | Fetch key material to tmpfs, use, discard | Custody of material Vault can't natively operate on | Key transits the app's memory and a tmpfs mount |

Level 1 exists precisely because it is unimpressive. Understanding *why* the ten-line version is what most teams ship — and exactly what it costs them — is more useful than skipping to the sophisticated pattern.

---

## 2. Scope

### 2.1 In scope

- Four independent Go modules, one per level, in separate folders
- Per-level container images, Kustomize manifests, and ArgoCD Applications
- Per-level `README.md` with the concept, the code walkthrough, and a "what this doesn't solve" section
- Verification procedures per level, including failure-injection where relevant
- A PostgreSQL instance for Level 3 (deployed in Stage A Phase A7, consumed here)
- A closing comparison document across all four patterns

### 2.2 Explicit non-goals

| Non-goal | Rationale | Disposition |
|---|---|---|
| **A shared Go module across levels** | Independence is a hard requirement. A shared `internal/vault` package would make Level 2's handshake invisible to Level 3 — the duplication *is* the teaching mechanism | Deliberate (D2) |
| **Vault Agent Injector sidecar** | Fifth pattern; Stage A backlog | Backlog — Level 5 |
| **Secrets Store CSI Driver** | Sixth pattern | Backlog |
| **Production-grade HTTP service concerns** (graceful shutdown beyond what Level 3 needs, rate limiting, tracing, structured request logging) | Would obscure the Vault interaction under boilerplate | Out of scope |
| **Transit engine encryption-as-a-service** | A genuinely different primitive from Level 4's key-custody model. Worth its own exercise | Backlog |
| **AppRole, JWT, or userpass auth methods** | Kubernetes auth is the correct method for in-cluster workloads; the others are for the cases this POC doesn't cover | Out of scope |
| **Multi-level integration** (e.g. Level 3's app also doing Level 4's decryption) | Directly contradicts the independence requirement | Out of scope |
| **Secret zeroization guarantees in Go memory** | Go's GC and string immutability make this genuinely hard; Level 4 documents the limitation honestly rather than pretending to solve it | Documented as a known limitation |

### 2.3 The distinction that runs through all four levels

**Where the secret lives at rest, and for how long, is the design question.** Not "how do I get the secret." Every level answers the first question differently:

- Level 1: at rest in etcd indefinitely, and in the process environment for the process lifetime
- Level 2: at rest in Vault only; in process memory for the process lifetime
- Level 3: at rest in Vault only; in process memory for **one hour**, then replaced
- Level 4: at rest in Vault only; in tmpfs and memory for **seconds**, then deleted

The trend line is the lesson.

---

## 3. Repository structure

Stage B lives under `applications/` in the single `vault-poc/` repository (Stage A D18). Independence is still enforced structurally: **four separate Go modules, no parent `go.mod`, no shared packages.** The shared repo does not create a shared module.

```
vault-poc/
├── docs/
│   ├── pattern-comparison.md               # written in Phase B6
│   └── troubleshooting.md
│
├── argocd/
│   ├── root-applications.yaml              # applied in Phase B0 — NOT before
│   └── applications/applications/
│       ├── level1-env-secret.yaml
│       ├── level2-k8s-auth.yaml
│       ├── level3-dynamic-db.yaml
│       └── level4-pgp-decrypt.yaml
│
├── platform/                               # Stage A — see companion PRD
│
└── applications/
    ├── README.md                           # index + four-pattern comparison
    │
    ├── level1-env-secret/
    │   ├── go.mod                          # module .../level1-env-secret
    │   ├── main.go
    │   ├── Containerfile
    │   ├── README.md
    │   ├── Makefile
    │   └── deploy/
    │       ├── base/
    │       │   ├── serviceaccount.yaml
    │       │   ├── externalsecret.yaml
    │       │   ├── deployment.yaml
    │       │   ├── service.yaml
    │       │   ├── networkpolicy.yaml
    │       │   └── kustomization.yaml
    │       └── overlays/onprem/
    │
    ├── level2-k8s-auth/
    │   ├── go.mod
    │   ├── main.go
    │   ├── vault_login.go                  # raw net/http — deliberately not the SDK
    │   ├── Containerfile
    │   ├── README.md
    │   ├── Makefile
    │   └── deploy/                         # + vault-ca ConfigMap ref
    │
    ├── level3-dynamic-db/
    │   ├── go.mod
    │   ├── main.go
    │   ├── vault_creds.go                  # official SDK
    │   ├── db.go                           # pgx pool + rebuild-on-rotate
    │   ├── lease.go                        # renewal loop + re-auth fallback
    │   ├── Containerfile
    │   ├── README.md
    │   ├── Makefile
    │   └── deploy/
    │
    └── level4-pgp-decrypt/
        ├── go.mod
        ├── main.go
        ├── pgp.go
        ├── fixtures/
        │   └── secret-message.txt.gpg      # produced by Stage A Phase A7
        ├── Containerfile
        ├── README.md
        ├── Makefile
        └── deploy/                         # + tmpfs emptyDir
```

Each level directory is independently buildable, deployable, and deletable. `kubectl delete -k applications/level3-dynamic-db/deploy/overlays/onprem` must not affect any other level. Sharing a repository with Stage A does not weaken this — the test is module and manifest independence, not directory distance.

**Why one repo (Stage A D18):** Stage B's manifests reference Vault roles and policies that Stage A created. In two repos those references dangle and drift silently. Here, a change to a policy name in `platform/bootstrap/20-policies/` and the corresponding `serviceAccountName` in `applications/` land in one reviewable commit.

---

## 4. Decision log

| ID | Decision | Rationale | Rejected alternatives |
|---|---|---|---|
| **D1** | Go 1.24+, standard library first | Go's stdlib covers HTTP, JSON, and TLS well enough that Level 2 needs no dependencies at all | Frameworks |
| **D2** | **Four separate `go.mod` files, zero shared code, duplication accepted** | Independence is a stated requirement, but the stronger reason is pedagogical: if Level 2's handshake is extracted into a shared helper, Level 3 imports it and the handshake becomes invisible. Writing it twice is the point | Monorepo with `internal/vault` (couples the levels, hides the learning); Go workspace (`go.work`) — same coupling with extra indirection |
| **D3** | **Level 2 uses raw `net/http`; Levels 3 and 4 use `hashicorp/vault/api`** | Level 2's stated goal is "implement by hand the exact handshake ESO does." The SDK's `auth.NewKubernetesAuth()` collapses that into one line and teaches nothing. Once it's been written by hand, using the SDK afterwards is an informed choice rather than a shortcut — and the contrast between the two is itself a deliverable | SDK everywhere (Level 2 loses its purpose); raw HTTP everywhere (Level 3's lease lifecycle via raw HTTP is busywork, not insight) |
| **D4** | Each level is an **HTTP service with `/healthz` and a level-specific endpoint**, not a one-shot Job | A long-running process is required to demonstrate Level 1's env-var staleness and Level 3's lease renewal. Uniform shape also makes the levels comparable | Jobs (can't show staleness or renewal); CLI binaries (no in-cluster demonstration) |
| **D5** | **Multi-stage `Containerfile`, distroless/static base, non-root, read-only root filesystem** | Read-only rootfs makes Level 4's tmpfs mount a real constraint rather than a decoration, and forces the correct answer | Alpine + shell (larger surface, and a writable rootfs would let Level 4 cheat) |
| **D6** | Build with **Podman + the existing `registry:2`**; tag with git SHA | Matches the established daemonless, SHA-tagged workflow. `ko` is a reasonable Go-native alternative but adds a tool for no gain here | `ko` (fine, but new tooling); Docker daemon (not in use) |
| **D7** | **Level 3 renews at 2/3 of lease TTL**, with jittered backoff on failure, and falls back to full re-authentication + pool rebuild | 2/3 leaves a full third of the TTL for retries before expiry — enough headroom for transient Vault unavailability without renewing so aggressively that it masks problems. The re-auth fallback is the part most implementations skip, and it's the part that breaks in production | Renew at 50% (unnecessarily chatty); renew at 90% (no retry headroom); no renewal (defeats the exercise); renew without a re-auth path (fails permanently once `max_ttl` is hit — which is *guaranteed* to happen) |
| **D8** | Level 3 **rebuilds the connection pool on credential rotation, draining the old pool gracefully** | New credentials mean a new Postgres role; existing connections authenticated as the old role keep working until it's dropped, then fail mid-query. Draining rather than dropping is the difference between a rotation being invisible and being an incident | Hard swap (in-flight queries fail); never rebuild (connections die when `max_ttl` revokes the role) |
| **D9** | Level 4 writes the PGP key to an **`emptyDir` with `medium: Memory`**, and deletes it immediately after import | Requirement states tmpfs. The reason it matters: a normal `emptyDir` is on the node's disk, so the private key would be recoverable from the node filesystem and could survive in backups. `medium: Memory` never touches disk | Normal emptyDir (key lands on node disk); decrypt from memory without a file (defensible, but the requirement specifies tmpfs — and it makes the key's lifetime *visible*, which has teaching value) |
| **D10** | Level 4 uses `github.com/ProtonMail/go-crypto/openpgp` | `golang.org/x/crypto/openpgp` is frozen and deprecated. ProtonMail's fork is the maintained successor and API-compatible | `x/crypto/openpgp` (deprecated); shelling out to `gpg` (adds a binary, a keyring, and disk state to a read-only container) |
| **D11** | **No secret values in logs, ever** — including at debug level. Log lengths, hashes, prefixes, and lease IDs instead | A debug log line is the most common way a secret escapes. Establishing the discipline in a POC is the point of the POC | Debug-only logging of values (debug gets enabled in production, always) |
| **D12** | **Every level has an explicit failure-injection test** | "It works" proves nothing about a resilience pattern. Level 3 in particular is only interesting under revocation and Vault-unavailability | Happy-path only |
| **D13** | Each level's `README.md` ends with a **"what this pattern does not solve"** section | The limitation is what motivates the next level. Without it the progression is four unrelated demos | Feature-only docs |
| **D14** | Structured JSON logging to stdout. Correlate with Stage A's audit device via `kubectl logs -n vault`, **not** via Loki | Stage A ships audit to `stdout` and does not touch the log collection pipeline (Stage A D14/D15), so correlation is a manual two-terminal exercise. That is fine, and arguably better for learning — you read the raw audit JSON rather than a pre-parsed view. Worth checking once whether an existing node-level log collector already picks up all namespaces; if it does, audit is in Loki for free and nothing needed changing | Editing the log pipeline (crosses Stage A's additive-only boundary); no correlation (loses the strongest link between the two documents) |
| **D15** | **All four levels share the `poc-hashicorp-vault-application` namespace**, isolated by ServiceAccount rather than by namespace | Owner decision. The consequence is important and must be stated in every level README: **the ServiceAccount name is the entire isolation boundary.** Stage A's Vault roles all bind `bound_service_account_namespaces=poc-hashicorp-vault-application` and differ only in `bound_service_account_names`. This makes Phase B5's cross-privilege matrix load-bearing rather than ceremonial, and makes NetworkPolicy work intra-namespace (podSelector-based, not namespaceSelector-based) | Namespace per level (stronger isolation, but diverges from the agreed layout); default namespace (no isolation at all) |
| **D16** | PostgreSQL for Level 3 lives in `poc-hashicorp-vault-application` alongside the apps | Deployed in Stage A Phase A7 but belongs to the app tier, not the platform tier. Keeps the `vault` namespace clean enough to resemble a real platform namespace | Postgres in `vault` (couples app data to the platform namespace) |

---

## 5. Phased execution

Seven phases: scaffolding, four levels, hardening, and synthesis.

---

### Phase B0 — Scaffolding and build pipeline

**Goal:** One level builds, ships, and runs end-to-end before any Vault logic is written.

**Tasks**
1. Confirm **all** Stage A acceptance criteria pass. Specifically re-verify:
   - `vault status` over the MetalLB VIP — unsealed, 3 peers healthy, `HA Mode: active`
   - `vault status` over NodePort `30004` — the break-glass path still works
   - `ClusterSecretStore` Ready
   - `vault read database/creds/level3-app` returns credentials
   - `secret/level4/pgp` readable
   - Audit device enabled and visible: `kubectl logs -n vault -l app.kubernetes.io/name=vault | tail`
   - All five Vault roles exist and bind to `poc-hashicorp-vault-application`: `vault list auth/kubernetes/role`
2. Create the `applications/` subtree from §3 in the existing `vault-poc/` repo. Four `go.mod` files, no root module. Do **not** add a `go.work` — it would couple the modules (D2).
2b. Write `argocd/root-applications.yaml` and its four children. **Apply the root app only after step 1's verification passes** (Stage A D19) — deploying app pods before Kubernetes auth exists produces a crash-loop that reads as an app bug and is actually a sequencing error.
3. Write the shared-by-convention (not by code) `Containerfile` template:
   ```dockerfile
   FROM golang:1.24 AS build
   WORKDIR /src
   COPY go.mod go.sum* ./
   RUN go mod download
   COPY . .
   RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app .

   FROM gcr.io/distroless/static-debian12:nonroot
   COPY --from=build /app /app
   USER nonroot:nonroot
   ENTRYPOINT ["/app"]
   ```
4. Per-level `Makefile`: `build`, `image`, `push`, `deploy`, `logs`, `verify`, `destroy`. Uniform targets across levels.
5. Kustomize base + `overlays/onprem` per level, each with its own ArgoCD child Application. Pod security context standard across all four:
   ```yaml
   securityContext:
     runAsNonRoot: true
     runAsUser: 65532
     readOnlyRootFilesystem: true
     allowPrivilegeEscalation: false
     capabilities: { drop: ["ALL"] }
     seccompProfile: { type: RuntimeDefault }
   ```
6. Create the `vault-ca` ConfigMap in `poc-hashicorp-vault-application` (needed by Levels 2, 3, 4).
7. **Pipeline smoke test:** a hello-world binary, built, pushed with a git-SHA tag, deployed via ArgoCD, serving `/healthz`. Then delete it.

**Exit gate**
- [ ] Stage A re-verified green (all seven checks in step 1)
- [ ] `applications/` subtree created; four modules initialise and build; no `go.work`, no root `go.mod`
- [ ] `root-applications` applied and syncing its four children
- [ ] Smoke image builds → registry → ArgoCD → Running → `/healthz` 200
- [ ] `vault-ca` ConfigMap present

---

### Phase B1 — Level 1: env var via ESO

**Goal:** The app doesn't know Vault exists. Prove it, then prove what that costs.

**The code is genuinely trivial** (~40 lines with the HTTP server):

```go
package main

import (
    "encoding/json"; "log/slog"; "net/http"; "os"
)

func main() {
    greeting := os.Getenv("APP_GREETING")
    apiKey   := os.Getenv("APP_API_KEY")

    if greeting == "" || apiKey == "" {
        slog.Error("required secret env vars are unset")
        os.Exit(1)
    }
    // D11: never log apiKey. Length and prefix only.
    slog.Info("secrets loaded from environment",
        "greeting", greeting,
        "api_key_len", len(apiKey),
        "api_key_prefix", apiKey[:min(4, len(apiKey))])

    http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    http.HandleFunc("/secret", func(w http.ResponseWriter, _ *http.Request) {
        json.NewEncoder(w).Encode(map[string]any{
            "greeting":       greeting,
            "api_key_masked": mask(apiKey),
            "read_at":        "process start",   // the whole point
            "source":         "os.Getenv",
        })
    })
    slog.Info("listening", "addr", ":8080")
    http.ListenAndServe(":8080", nil)
}
```

**Manifests**
- `ServiceAccount: level1-app` (created but **never granted a Vault role** — demonstrating that it needs none)
- `ExternalSecret` → `secret/level1/app`, `refreshInterval: 30s`, target Secret `level1-app-secret`
- Deployment consuming it via `envFrom.secretRef`

**Verification**
1. `curl /secret` → returns the Vault-sourced values
2. `grep -ri vault level1-env-secret/main.go go.mod` → **zero matches.** This is the deliverable.
3. `kubectl get secret level1-app-secret -o yaml` → base64, not encrypted. Note where it lives: etcd.

**Failure injection (D12) — the important part**
4. `vault kv put secret/level1/app greeting="CHANGED"` in Vault
5. Wait past `refreshInterval`; confirm the **Kubernetes Secret updated**
6. `curl /secret` again → **still returns the old value**
7. `kubectl rollout restart deploy/level1-app` → now it's new

**README must state plainly:**
- The app has no Vault dependency, no Vault credential, and no Vault code
- The secret is at rest in etcd, base64-encoded, readable by anyone with `get secret` in the namespace
- **Rotation requires a restart.** The pod's environment is fixed at exec time and cannot be changed
- This is the correct choice for legacy apps, third-party images, and anything you can't modify — which is most things
- **What it doesn't solve:** rotation without restart, credential lifetime, revocation, per-request authorization, audit attribution to the app (audit shows *ESO* read it, not the app)

**Exit gate**
- [ ] Endpoint serves Vault-sourced values
- [ ] No occurrence of "vault" in the module's source or dependencies
- [ ] Staleness reproduced: Secret updated, running pod did not
- [ ] Restart picks up the new value
- [ ] README includes the limitations section (D13)

---

### Phase B2 — Level 2: direct Kubernetes auth, by hand

**Goal:** Implement the handshake from Stage A §4.2 with `net/http` and nothing else.

**Implementation — `vault_login.go`, no SDK (D3)**

```go
// 1. Read the projected ServiceAccount token
const saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// 2. Build a TLS config trusting the Vault CA (mounted ConfigMap)
//    NEVER InsecureSkipVerify. If TLS fails, fix the SANs — Stage A Phase A2.

// 3. POST {VAULT_ADDR}/v1/auth/kubernetes/login
//    body: {"jwt": "<sa token>", "role": "level2-app"}
//    → 200 {"auth":{"client_token":"hvs...","lease_duration":3600,
//                   "renewable":true,"policies":["default","level2-reader"]}}

// 4. GET {VAULT_ADDR}/v1/secret/data/level2/app
//    header: X-Vault-Token: <client_token>
//    → KV v2 shape: {"data":{"data":{...},"metadata":{...}}}
//      NOTE the double nesting. KV v1 has one level. This trips everyone once.

// 5. Background goroutine: renew at 2/3 of lease_duration via
//    POST /v1/auth/token/renew-self
//    On failure → re-login from step 3. A token that can't renew is not fatal;
//    a token that can't renew AND has no re-login path is.
```

**Explicitly do not use** `vault/api` or `auth.NewKubernetesAuth()` here. Note in the README what those would have replaced — that comparison is a deliverable.

**Manifests**
- `ServiceAccount: level2-app` — matching the Vault role's `bound_service_account_names` from Stage A Phase A6
- Mount `vault-ca` ConfigMap at `/vault/tls/ca.crt`
- Env: `VAULT_ADDR=https://vault.vault.svc:8200`, `VAULT_ROLE=level2-app`
- **Note what is absent:** no Vault token, no credential of any kind in the manifest. The SA *is* the credential

**Endpoints**
- `/healthz`
- `/secret` → the KV value plus `authenticated_at`, `token_ttl_remaining`, `policies`
- `/token-info` → result of `auth/token/lookup-self`, useful for watching TTL count down

**Failure injection (D12)**
1. **Wrong role:** set `VAULT_ROLE=level4-pgp` → login succeeds, secret read returns **403**. Least privilege, observed rather than assumed
2. **Wrong SA:** deploy with `serviceAccountName: default` → login **fails at step 3**
3. **Token revoked:** find the accessor via `vault list auth/token/accessors`, `vault token revoke -accessor <a>`, then curl `/secret` → 403, and the app must re-authenticate rather than staying broken
4. **Vault unreachable:** scale Vault to 0 briefly. App should log failures and recover when Vault returns — not crash-loop

**Cross-reference the audit log (D14):** every one of the above appears in Vault's audit device. Two terminals:
```bash
# terminal 1 — Vault audit stream
kubectl logs -n vault -l app.kubernetes.io/name=vault -f | jq 'select(.type=="response")'
# terminal 2 — the app
kubectl logs -n poc-hashicorp-vault-application -l app=level2-app -f
```
Trigger each failure injection and line up the pair. Note in the audit entry: the resolved `auth.metadata.service_account_name`, the policies attached, and that the secret value is HMAC'd rather than plaintext. **This correlation is the closing of the loop between the two PRDs** — the app's claim of who it is, and Vault's independent record of who it decided the app was.

**README must state:**
- The handshake, step by step, matching the Stage A diagram
- That ESO does exactly this, with `role=eso`, on the app's behalf
- **What it doesn't solve:** the secret is still static. Reading `secret/level2/app` a thousand times returns the same value. Nothing expires, nothing rotates, and a leaked value stays valid forever

**Exit gate**
- [ ] Login succeeds; secret retrieved; TLS verified with no bypass
- [ ] Token renewal observable via `/token-info` (TTL resets)
- [ ] All four failure injections behave as specified
- [ ] Zero Vault SDK imports in `go.mod`
- [ ] App log ↔ audit log correlation demonstrated

---

### Phase B3 — Level 3: dynamic database credentials

**Goal:** Credentials with a lifetime. The lease lifecycle, including the paths that break.

This is the most substantial level. Budget accordingly.

**Flow**
```
startup:
  k8s auth login (SDK: vault/api + auth/kubernetes)
  read database/creds/level3-app
    → {username: "v-kubernet-level3-a-xxxx", password: "...",
       lease_id: "database/creds/level3-app/...", lease_duration: 3600}
  build pgx pool with those credentials
  start lease manager goroutine

steady state:
  serve /query → SELECT from the demo table
  at 2/3 of lease_duration → renew lease (D7)

renewal succeeds → new lease_duration, continue with the same pool
renewal fails    → jittered backoff, retry
retries exhausted OR max_ttl reached (renewal refused):
  → re-authenticate to Vault
  → request fresh credentials
  → build a NEW pool
  → serve new traffic from it
  → drain the old pool gracefully (D8), then close
```

**File split**
- `vault_creds.go` — auth + `database/creds` read + lease renewal via `vault/api`
- `db.go` — pool construction, atomic pool swap, graceful drain
- `lease.go` — the renewal loop, backoff, re-auth trigger
- `main.go` — wiring + HTTP

**Endpoints**
- `/healthz` — liveness
- `/readyz` — **ready only if the pool has a valid, non-expired credential**
- `/query` — runs a real SELECT; returns rows plus `current_user` from Postgres, so you can *watch the username change* across a rotation
- `/creds-info` — current username, lease ID, lease TTL remaining, renewal count, rotation count

`/creds-info` is the observability window into the whole exercise. Build it early; it makes every subsequent test legible.

**Verification**
1. Deploy. `/creds-info` shows a generated username with ~3600s TTL
2. In Postgres: `\du` shows the Vault-generated role
3. `/query` returns rows; `current_user` matches `/creds-info`

**Failure injection (D12) — the substance of this phase**
4. **Manual revocation:** `vault lease revoke <lease_id>`. The app must detect the failure, re-authenticate, get new credentials, rebuild the pool. `/query` recovers. `/creds-info` shows a **different username** and rotation count 1
5. **Accelerated `max_ttl`:** temporarily set the Vault role to `default_ttl=2m max_ttl=6m`. Watch two successful renewals, then a refused renewal, then the forced re-auth path. **This is the path that is guaranteed to execute in production and is almost always untested**
6. **Vault unavailable during renewal:** scale Vault to 0 during a renewal window. Confirm backoff, confirm the app keeps serving on its still-valid credential (the credential doesn't expire because Vault is down), and confirm recovery when Vault returns
7. **Postgres unavailable:** confirm the app distinguishes "database down" from "credentials invalid" and doesn't uselessly re-authenticate against Vault for a Postgres outage
8. **Drain correctness:** issue a slow query, trigger a rotation mid-query, confirm the in-flight query completes rather than erroring

Record: renewal count over an hour, rotation latency, and any request errors observed during rotation. **Zero request errors during rotation is the target** — if rotation is visible to callers, the drain logic (D8) is wrong.

**README must state:**
- Why a 1-hour credential is categorically different from a static one: leak windows are bounded, revocation is instant and centrally auditable, and every credential is attributable to a specific pod's identity
- The lease as a *contract*: Vault will revoke on schedule whether or not the app is ready
- That `max_ttl` is not optional — every dynamic credential dies eventually, so the re-auth path is mandatory, not defensive
- **What it doesn't solve:** works for credentials Vault knows how to generate. Key material Vault merely stores — a PGP key, a signing key, a licence file — needs a different pattern

**Exit gate**
- [ ] Dynamic credentials issued; role visible in Postgres
- [ ] Renewal observed extending TTL (renewal count increments)
- [ ] Revocation triggers re-auth and pool rebuild; username changes
- [ ] `max_ttl` exhaustion handled through the same path
- [ ] Vault-outage and Postgres-outage distinguished correctly
- [ ] **Zero request errors during rotation**
- [ ] Lease revoked cleanly on `SIGTERM` (no orphaned leases — check `vault list sys/leases/lookup/database/creds/level3-app`)

---

### Phase B4 — Level 4: PGP key from Vault to tmpfs

**Goal:** Custody of key material Vault stores but cannot operate on.

**Flow**
```
1. k8s auth login (vault/api)
2. read secret/data/level4/pgp → {private_key, public_key, passphrase}
3. write private_key to /keys/private.asc   [tmpfs, emptyDir medium: Memory]
   file mode 0400
4. read the key back, decrypt it with the passphrase, import into an
   in-memory openpgp keyring
5. os.Remove("/keys/private.asc")           ← immediately after import
6. decrypt fixtures/secret-message.txt.gpg
7. write plaintext to /output/decrypted.txt [also tmpfs]
8. print the plaintext to stdout            ← per requirement
9. serve /result with the decrypted content
```

**Why the file at all?** Steps 3–5 could be skipped by decrypting straight from memory. The requirement specifies tmpfs, and there's a real reason it's worth doing: it makes the key's on-disk lifetime **observable**. You can `kubectl exec` during the window and see the file, then see it gone. That visibility is the exercise. Document that a memory-only path exists and is marginally better.

**Manifests**
```yaml
volumes:
  - name: keys
    emptyDir:
      medium: Memory        # D9 — tmpfs, never node disk
      sizeLimit: 1Mi
  - name: output
    emptyDir:
      medium: Memory
      sizeLimit: 10Mi
volumeMounts:
  - { name: keys,   mountPath: /keys }
  - { name: output, mountPath: /output }
```
`readOnlyRootFilesystem: true` from Phase B0 means these mounts are the *only* writable paths. That's deliberate — it makes it impossible to accidentally write the key elsewhere.

**Fixture:** `secret-message.txt.gpg`, produced in Stage A Phase A7, encrypted to the POC public key. It ships in the repo — **it's ciphertext, and the private key is only in Vault**, which is itself a small demonstration worth noting in the README.

**Endpoints**
- `/healthz`
- `/result` → decrypted plaintext + timing metadata
- `/key-status` → whether the key file currently exists on disk (should be `false` after startup) and how long it existed in milliseconds

**Verification**
1. Pod logs show the decrypted plaintext
2. `kubectl exec -- ls -la /keys` → **empty**
3. `/key-status` reports the key file existed for a short, measured window
4. Confirm the tmpfs mount is real: `kubectl exec -- df -h /keys` → filesystem type `tmpfs`

**Failure injection (D12)**
5. **Wrong passphrase:** patch the Vault secret with a bad passphrase. App must fail clearly at import — not silently produce garbage, and not log the passphrase
6. **Missing Vault permission:** point the deployment at a role lacking `level4-pgp`. Confirm a clean 403 and a clear error
7. **Corrupt fixture:** truncate the `.gpg`. Confirm a decryption error, and that **no partial plaintext is written or printed**
8. **Restart:** confirm the whole flow re-runs from scratch. Nothing persists; tmpfs is empty on a new pod

**README must state:**
- The distinction: Vault *custodies* this key, it does not *use* it. Contrast with the Transit engine, where the key never leaves Vault and Vault performs the crypto — logged as backlog
- Why `medium: Memory` and not a plain `emptyDir` (D9)
- **Honest limitation (§2.2):** once the key is in the Go process, it's in Go's heap. Go strings are immutable and the GC may copy them; reliable zeroization would require `[]byte` throughout plus `mlock`, which is out of scope. Use `[]byte` where practical and **state clearly that this is mitigation, not a guarantee** — that honesty is more valuable than a false claim of secure erasure
- **What it doesn't solve:** the key is exposed to the application. If the app is compromised while the key is in memory, the key is compromised. Transit avoids that entirely by never releasing the key

**Exit gate**
- [ ] Fixture decrypts; plaintext printed to stdout and served at `/result`
- [ ] Key file demonstrably deleted post-import; window measured
- [ ] `/keys` confirmed as a real tmpfs mount
- [ ] All four failure injections behave correctly
- [ ] No key, passphrase, or plaintext in logs
- [ ] Memory-zeroization limitation documented honestly, not overclaimed

---

### Phase B5 — Independence verification and hardening

**Goal:** Prove the four levels are genuinely decoupled, and that nothing leaks.

**Independence tests**
1. Deploy all four. All healthy.
2. Delete Level 2 entirely. Levels 1, 3, 4 unaffected — verify by endpoint, not by assumption.
3. Rebuild and redeploy Level 3 alone. Others untouched.
4. From a clean checkout, deploy **only** Level 4. It must work with no other level present.
5. Confirm no cross-imports: `grep -r "level[0-9]" */go.mod` → no matches.

**Security hardening sweep**
6. `gitleaks detect` across the repo → clean
7. Search all pod logs for secret values, passphrases, plaintext, and tokens → none
8. Confirm all four pods: non-root, read-only rootfs, dropped capabilities, `RuntimeDefault` seccomp
9. Confirm each ServiceAccount maps to exactly one Vault role, and no role uses wildcards
10. **Cross-privilege matrix — mandatory, not sampled (D15).** Because all four levels share one namespace, the ServiceAccount name is the *only* thing standing between Level 1 and the PGP private key. Test the full 4×4 grid from a throwaway pod running as each SA in turn:

    | Acting as ↓ / Reading → | `level1/app` | `level2/app` | `database/creds` | `level4/pgp` |
    |---|---|---|---|---|
    | `level1-app` | allow | **deny** | **deny** | **deny** |
    | `level2-app` | **deny** | allow | **deny** | **deny** |
    | `level3-app` | **deny** | **deny** | allow | **deny** |
    | `level4-app` | **deny** | **deny** | **deny** | allow |

    Also test the SA/role mismatch dimension: `level1-app`'s SA requesting Vault role `level4-pgp` must fail at *login*, not at read. Twelve denials and four allows. Record the actual results — a privilege matrix that has never been run is a hypothesis.
11. `NetworkPolicy` per level, **intra-namespace via `podSelector`** since all levels share a namespace (D15): default-deny ingress and egress, then allow per level — DNS to kube-dns, egress to `vault.vault.svc:8200`, and for Level 3 only, egress to `postgres:5432`. Levels must not be able to reach each other. Verify by attempting a connection from a Level 1 pod to the Level 3 Service and confirming it is refused.
12. Resource requests and limits on all four

**Exit gate**
- [ ] Levels independently deployable, deletable, and buildable
- [ ] No cross-module dependencies
- [ ] Secret scan clean; logs clean
- [ ] Pod security context uniform and enforced
- [ ] Full 4×4 cross-privilege matrix run and recorded — twelve denials, four allows
- [ ] SA/role mismatch denied at login
- [ ] Level-to-level pod traffic refused by NetworkPolicy
- [ ] NetworkPolicies in place and tested

---

### Phase B6 — Synthesis

**Goal:** Turn four working demos into one usable decision framework. This is the phase that makes the POC worth having done.

**Deliverable: `docs/pattern-comparison.md`**

| Dimension | L1 (ESO env) | L2 (direct static) | L3 (dynamic DB) | L4 (key custody) |
|---|---|---|---|---|
| App knows about Vault | No | Yes | Yes | Yes |
| Secret at rest in etcd | **Yes** | No | No | No |
| Credential lifetime | Unbounded | Unbounded | **1 hour** | Seconds |
| Rotation without restart | **No** | Yes | Yes | N/A |
| Revocation effective immediately | No | Token only | **Yes, at the DB** | No |
| Audit attributes to the app | No (attributes to ESO) | Yes | Yes | Yes |
| App code complexity | ~40 lines | ~200 lines | ~600 lines | ~250 lines |
| Failure modes to handle | None | Auth, network | Auth, network, lease, pool, DB | Auth, network, crypto |
| Works with unmodifiable apps | **Yes** | No | No | No |
| Blast radius if pod compromised | Secret leaked, permanently valid | Same | Bounded to lease TTL | **Key leaked, permanently valid** |

**Also write:**
- A decision tree: *which pattern for which situation, and why*
- The three most surprising findings from the build (candidates: the double-nested KV v2 JSON; that Level 1's Secret updates while the running pod doesn't; that Level 3's `max_ttl` path is guaranteed to execute and almost never tested)
- Measured numbers: rotation latency, renewal counts, errors during rotation, key-on-disk window
- A short section on **what Level 5 (Vault Agent Injector) would change** — it gives Level 1's "app knows nothing" property *with* Level 3's rotation, at the cost of a sidecar per pod. That's the trade the backlog item exists to explore

**Exit gate**
- [ ] Comparison document complete with real measured numbers, not estimates
- [ ] Decision tree written
- [ ] All four level READMEs include their limitations section (D13)
- [ ] Root `README.md` indexes the levels and links the comparison

---

## 6. Acceptance criteria (Stage B complete)

**Functional**
- [ ] All four levels deploy independently and serve their endpoints
- [ ] Level 1 contains no Vault reference in source or dependencies
- [ ] Level 2's handshake implemented with `net/http` only
- [ ] Level 3 renews leases, rotates on revocation and `max_ttl`, with zero request errors during rotation
- [ ] Level 4 decrypts the fixture and demonstrably removes the key from tmpfs

**Security**
- [ ] No secret material in git, images, logs, or manifests
- [ ] Every level runs non-root with a read-only root filesystem
- [ ] TLS verified everywhere; no `InsecureSkipVerify` anywhere in the codebase
- [ ] Cross-level privilege denials verified for every pair
- [ ] NetworkPolicies default-deny with explicit allows

**Operational**
- [ ] All failure injections executed and behaviour recorded
- [ ] Level 3 revokes its lease on `SIGTERM`; no orphaned leases remain
- [ ] App logs correlate with Vault's audit device via `kubectl logs -n vault` (D14)
- [ ] Teardown of any single level leaves the others healthy

**Documentation**
- [ ] Four level READMEs, each with a limitations section
- [ ] `pattern-comparison.md` with measured data
- [ ] `troubleshooting.md` capturing every non-obvious problem hit during the build

---

## 7. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| KV v2's double-nested JSON (`data.data`) misread | **High** | Confusing failures in L2/L3/L4 | Called out in D3/Phase B2; check `/v1/secret/data/x` response shape first |
| Level 3's `max_ttl` path never actually exercised | **High** | The one path guaranteed to run in production stays untested | Phase B3 test 5 uses a temporarily shortened `max_ttl` — mandatory gate |
| Pool rebuild drops in-flight queries | Medium | Visible errors during rotation | D8 graceful drain; Phase B3 test 8 |
| PGP passphrase logged during debugging | Medium | Key compromise | D11; Phase B5 log sweep |
| `emptyDir` used without `medium: Memory` | Medium | Private key written to node disk | D9; verify with `df -h /keys` |
| Shared code creeps in "just for DRY" | Medium | Levels become coupled; teaching value lost | D2; Phase B5 cross-import grep |
| `InsecureSkipVerify` added to unblock a TLS error | Medium | Silently defeats the trust model | Explicit acceptance criterion; grep for it in review |
| Level 3 re-authenticates against Vault for a Postgres outage | Medium | Noise, and masks the real fault | Phase B3 test 7 distinguishes the two |
| Deprecated `x/crypto/openpgp` used | Medium | Unmaintained crypto | D10 |
| **Shared namespace means a single wrong SA reference grants a level the wrong secrets** | Medium | Level 1 could reach the PGP private key | D15; the full 4×4 matrix in Phase B5 is the control. Also review every `serviceAccountName:` field against its Vault role before deploying |
| A level deployed without `serviceAccountName` silently uses `default` | Medium | Login fails confusingly, or worse, succeeds against an over-broad role | Explicit `serviceAccountName` in every base manifest; confirm `default` SA is bound to no Vault role at all |

---

## 8. Backlog (post-v1)

| Item | Notes |
|---|---|
| **Level 5 — Vault Agent Injector** | Level 1's transparency plus Level 3's rotation; sidecar cost. The most interesting remaining pattern |
| **Level 6 — Secrets Store CSI Driver** | Mount-based delivery; compare against ESO |
| **Level 7 — Transit engine** | Key never leaves Vault; directly answers Level 4's stated limitation |
| Prometheus metrics per level | Renewal counts, rotation counts, auth latency as first-class metrics. Would follow Stage A's additive pattern: a new `ServiceMonitor` per level, no edits to the existing stack. Level 3's renewal and rotation counters are the ones actually worth graphing |
| OpenTelemetry tracing across app → Vault → Postgres | Connects to the existing tracing POC — a Vault call inside a traced request would be a strong demonstration |
| Dynamic credentials for other engines | RabbitMQ, Redis, cloud IAM |
| Response wrapping | Secure secret handoff between processes |
| Load test under continuous rotation | k6 against Level 3 across several `max_ttl` cycles — measures whether rotation is truly invisible under real traffic |

---

## 9. Claude Code handoff notes

**Working assumption:** the executing session has the Stage A platform running and verified on `learning-labs-developer-workspace-type-01`, plus cluster and repo access, and **no prior context from this design conversation**. This document must stand alone.

**Repo model:** Stage B lives under `applications/` in the single `vault-poc/` repo (Stage A D18). ArgoCD manages it through `argocd/root-applications.yaml`, which is applied at Phase B0 and not before (Stage A D19).

**Namespace model:** everything in Stage B deploys to `poc-hashicorp-vault-application`. Vault itself lives in `vault` and is reached in-cluster at `https://vault.vault.svc:8200`. The MetalLB VIP and NodePort 30004 are for human CLI access, not for pods.

**Rules of engagement**

1. **Verify Stage A first.** If any Phase B0 step 1 check fails, stop and report. Stage B built on a half-working Vault produces misleading results.
2. **Do not refactor across levels.** Duplication between `level2-k8s-auth` and `level3-dynamic-db` is deliberate (D2). A shared package is a **failed** acceptance criterion, not a cleanup.
3. **Level 2 uses `net/http` only.** No `hashicorp/vault/api` in `level2-k8s-auth/go.mod`. This is checked mechanically.
4. **Never `InsecureSkipVerify`.** If TLS fails, the cause is a SAN gap or a missing CA mount — fix that. Reaching for the bypass flag invalidates the level.
5. **Never log secret values.** Not at debug level, not temporarily, not "just to check." Log lengths, prefixes, hashes, lease IDs (D11).
5b. **Every Deployment sets `serviceAccountName` explicitly.** All four levels share a namespace, so the SA is the only isolation boundary (D15). A missing `serviceAccountName` is a security defect, not a typo.
5c. **Additive-only against the observability stack**, same boundary as Stage A D15. Stage B builds no ServiceMonitor and no alert rules — per-level app metrics are backlog. Audit correlation is done with `kubectl logs` (D14). Never edit an existing scrape config, dashboard, alert rule, or log pipeline.
6. **Failure injections are deliverables, not extras.** An unrun injection is a failed gate. Record actual observed behaviour, including anything that differed from what this document predicts — those surprises belong in `troubleshooting.md`.
7. **Record measurements.** Rotation latency, renewal counts, errors during rotation, key-on-disk window. Phase B6 needs real numbers.
8. **Build `/creds-info` and `/key-status` early.** They're the observation windows that make Levels 3 and 4 debuggable. Building them last means debugging blind.
9. **Stop and ask** if: Stage A verification fails; a Vault policy denies something this document says it should allow (likely a KV v2 path issue — check before changing the policy); or Level 3's rotation cannot be made error-free after two attempts.

**Suggested commit granularity:** one commit per phase, prefixed `phase-b{N}:`, with the exit-gate checklist in the commit body. Level code and its manifests commit together.
