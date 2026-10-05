# Level 2 — direct Kubernetes auth, written by hand

**Pattern:** the application authenticates to Vault itself, using its
ServiceAccount as its identity, and reads the secret over the API.

Level 1's secret arrived without the app's involvement, and could not be
rotated without a restart. Here the app fetches it per request, so a change in
Vault is visible on the next call. Getting there costs an authentication
handshake — and this level implements that handshake with `net/http` and
nothing else, deliberately.

---

## Why no SDK

`hashicorp/vault/api` has `auth.NewKubernetesAuth()`, which collapses everything
in `vault_login.go` into one line. That is the right choice in production and
the wrong one here: the point of this level is that the handshake is *visible*
(Stage B D3). Levels 3 and 4 use the SDK, and the contrast between them is
itself a deliverable.

`go.mod` has zero dependencies and there is no `go.sum`. `make verify` checks
both, and Phase B5 re-checks across all modules.

## The handshake

```
 pod                    Vault                  K8s API server
  │ 1. read own SA JWT   │                          │
  │    /var/run/secrets/kubernetes.io/serviceaccount/token
  │ 2. POST /v1/auth/kubernetes/login {role, jwt} ──►│
  │                      │ 3. TokenReview(jwt),     │
  │                      │    using the reviewer JWT│
  │                      │◄── 4. {ns, sa name, uid} │
  │                      │ 5. match ns+sa against the role's
  │                      │    bound_service_account_*
  │◄─ 6. {client_token, lease_duration, renewable}  │
  │ 7. GET /v1/secret/data/level2/app               │
  │    header: X-Vault-Token ───────────────────────►
```

**The pod never holds a Vault credential at rest.** Its identity is its
Kubernetes ServiceAccount; the manifest contains no token, no password, nothing.
Vault trusts the cluster's word about who is calling, then applies its own
authorization on top.

This is exactly what ESO did on Level 1's behalf, with `role=eso`.

### Two things that trip everyone

**The KV v2 double nesting.** The read returns:

```json
{"data": {"data": {"message": "...", "tier": "gold"}, "metadata": {"version": 3}}}
```

Two levels of `data`. KV v1 has one. See `kvV2Response` in `vault_login.go`.

**The API path is not the CLI path.** Reads go to `secret/data/level2/app`, not
`secret/level2/app`, even though `vault kv get` displays the latter. A policy or
client written against the CLI-visible path is denied, and the denial does not
explain itself.

## Token lifecycle

Renewal runs at **2/3 of `lease_duration`** — a third of the TTL left for
retries is enough headroom for a transient Vault outage without renewing so
aggressively that it masks a problem.

On renewal failure the app re-authenticates from scratch, with jittered backoff
if Vault is unreachable. **A token that cannot renew is not fatal; a token that
cannot renew and has no re-login path is** — and that is the state every
implementation reaches the first time it meets `max_ttl`. Level 3 exercises
that path deliberately.

A read that returns 403 triggers one re-authentication and one retry
(`ReadKVReauth`). That recovers from a token revoked out from under the app. It
does *not* recover from a role that lacks the policy — re-authenticating cannot
change a policy decision — so the retry happens exactly once, never in a loop.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /healthz` | 200, unconditionally. Deliberately independent of Vault — see below |
| `GET /secret` | the KV value, `authenticated_at`, `token_ttl_remaining_s`, `policies`, login/renewal counts |
| `GET /token-info` | `auth/token/lookup-self`, for watching the TTL count down |

`/healthz` does not check Vault on purpose. If it did, a Vault outage would
fail the liveness probe, and Kubernetes would restart the pod into the same
condition — turning a recoverable degradation into a crash-loop.

## Verification

```bash
kubectl -n poc-hashicorp-vault-application port-forward deploy/level2-k8s-auth 8080:8080
curl -s localhost:8080/secret     | jq
curl -s localhost:8080/token-info | jq '.lookup_self.ttl'   # watch it count down
```

## Failure injection

| Test | Expected |
|---|---|
| `VAULT_ROLE=level4-pgp` | Login **succeeds**, secret read **403**. Least privilege observed, not assumed |
| `serviceAccountName: default` | Login **fails at step 3** — the SA/role binding does not match |
| `vault token revoke -accessor <a>` | 403, then the app re-authenticates and recovers on the next call |
| Vault scaled to 0 | Logs failures, backs off, recovers when Vault returns. **No crash-loop** |

The first three are unit-tested against a stub Vault in `vault_login_test.go`
(`TestReadKVReauthGivesUpOnPersistentDenial`,
`TestReadKVReauthRecoversFromRevokedToken`). The stub proves the client logic;
it does not prove the Vault role bindings, which is what the in-cluster run is for.

> **Status: not yet executed against a live cluster.** Requires Stage A.

### Audit correlation — do this once, properly

```bash
# terminal 1 — Vault's own record
kubectl logs -n vault -l app.kubernetes.io/name=vault -f | jq 'select(.type=="response")'
# terminal 2 — the app's claim
kubectl logs -n poc-hashicorp-vault-application -l app=level2-k8s-auth -f
```

Trigger each injection and line the two up. In the audit entry find
`auth.metadata.service_account_name`, the policies attached, and confirm the
secret value is HMAC'd rather than plaintext.

This is the closing of the loop between the two PRDs: the app's claim about who
it is, and Vault's independent record of who it decided the app was.

## What this pattern does not solve

- **The secret is still static.** Read `secret/level2/app` a thousand times and
  it returns the same value. Nothing expires and nothing rotates.
- **A leaked value stays valid forever.** Revoking the app's *token* stops the
  app; it does nothing about a secret value already copied somewhere else.
- **No blast-radius bound.** Compromise the pod and you have the secret, with no
  time limit on its usefulness.
- **The app now carries the failure modes** Level 1 avoided entirely: auth,
  network, TLS trust, token lifecycle. That complexity is the price of rotation,
  and it is only worth paying if the credential actually rotates — which is
  Level 3.
