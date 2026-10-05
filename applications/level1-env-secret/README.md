# Level 1 — environment variable via External Secrets Operator

**Pattern:** Vault → ESO → Kubernetes Secret → `envFrom` → `os.Getenv`

The application has no idea Vault exists. It reads two environment variables and
serves them. That is the whole integration.

This level is deliberately unimpressive. It is also what most production
applications actually do, and understanding *why* — and exactly what it costs —
is worth more than skipping ahead to the sophisticated pattern.

---

## How the secret arrives

```
Vault  secret/level1/app
  │
  │  ESO authenticates as the `eso` Vault role, using the
  │  external-secrets ServiceAccount (Stage A Phase A8)
  ▼
ExternalSecret ──► Kubernetes Secret `level1-app-secret`   [at rest in etcd]
  │
  │  envFrom.secretRef, resolved by the kubelet at container start
  ▼
process environment ──► os.Getenv("APP_GREETING"), os.Getenv("APP_API_KEY")
```

Note who authenticates: **ESO does, not the app.** `ServiceAccount: level1-app`
exists and is bound to no Vault role at all. It doesn't need one, and the
Deployment sets `automountServiceAccountToken: false` to make that concrete.

## Code walkthrough

All of `main.go` that matters:

```go
greeting := os.Getenv("APP_GREETING")
apiKey   := os.Getenv("APP_API_KEY")
```

Read once, at process start, into an immutable `config`. There is no refresh
path because **there cannot be one** — a process cannot change its own
environment after `exec`. `read_at` on `/secret` never changes for the life of
the process, which is the field to watch during the rotation test below.

The API key is never logged and never served raw: `mask()` returns a four-character
prefix and padding, and the startup log line carries length and prefix only.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /healthz` | 200 |
| `GET /secret` | greeting, masked API key, `source`, `read_at`, uptime |

## Verification

```bash
# 1. the values came from Vault, via a path the app knows nothing about
kubectl -n poc-hashicorp-vault-application port-forward deploy/level1-env-secret 8080:8080
curl -s localhost:8080/secret

# 2. THE DELIVERABLE: no backend reference in the module
grep -ri vault main.go go.mod        # → zero matches

# 3. where the secret actually lives
kubectl -n poc-hashicorp-vault-application get secret level1-app-secret -o yaml
#    base64, not encrypted. This is etcd.
```

## Failure injection — the important part

```bash
vault kv put secret/level1/app greeting="CHANGED" api_key="static-poc-key-001"
# wait past refreshInterval (30s)
kubectl -n poc-hashicorp-vault-application get secret level1-app-secret \
  -o jsonpath='{.data.APP_GREETING}' | base64 -d      # → CHANGED
curl -s localhost:8080/secret                         # → still the OLD value
kubectl -n poc-hashicorp-vault-application rollout restart deploy/level1-env-secret
curl -s localhost:8080/secret                         # → now CHANGED
```

The Secret updated. The running pod did not. Nothing is broken — this is the
pattern working exactly as designed, and it is the reason Level 2 exists.

> **Status: not yet executed.** Requires Stage A Phases A7 and A8. Results and
> measured timings go here when the platform is available.

## What this pattern does not solve

- **Rotation without a restart.** The process environment is fixed at `exec`
  time. Every rotation is a rollout, whether or not you planned one.
- **Credential lifetime.** The value is static and valid until someone changes
  it. Nothing expires.
- **Revocation.** Revoking in Vault does not reach into a running process. The
  leaked value stays usable until the next restart, and longer if it was copied.
- **At-rest exposure.** The secret sits in etcd, base64-encoded — which is
  encoding, not encryption. Anyone with `get secret` in this namespace can read
  it, and so can anyone with an etcd backup.
- **Audit attribution.** Vault's audit log records that *ESO* read the secret.
  It has no idea this application consumed it, or when, or how often.

## When this is nonetheless the right choice

Legacy applications, third-party images, anything you cannot modify — which is
most things. The app needs no client library, no Vault credential, no network
path to Vault, and no code change. That is a real advantage, not a consolation
prize. Level 5 (Vault Agent Injector, backlog) is the pattern that keeps this
property while fixing the rotation problem.

---

## A discrepancy worth knowing about

The PRD (Phase B1, step 2) scopes the "zero Vault references" check to
`main.go` and `go.mod`. The Stage B playbook writes it as
`grep -ri vault applications/level1-env-secret/`, across the whole directory.

**The broader form cannot pass, and should not.** `deploy/base/externalsecret.yaml`
must name the `vault-backend` ClusterSecretStore, and this README discusses the
pattern at length. Per CLAUDE.md the PRD wins, so `make verify` implements the
PRD's narrower check. The claim being made is about the *application module* —
its source and its dependencies — not about the manifests that wire it up. The
manifests are the platform's business, which is precisely the point of the level.
