# Level 3 — dynamic database credentials

**Pattern:** Vault generates a Postgres role on demand, hands it over under a
lease, and drops it when the lease ends. The application manages that lifecycle.

Levels 1 and 2 both ended in the same place: the secret is static. Read it a
thousand times and it is the same value, valid forever, with no bound on the
damage a leak does. This level is where that changes — and it is the reason
Vault exists at all, as opposed to a nicer etcd.

The credential this process uses **did not exist before it started** and will
not outlive its lease.

---

## Flow

```
startup
  k8s auth login (SDK) ─► read database/creds/level3-app
     → {username: "v-kubernet-level3-a-xxxx", password, lease_id, lease_duration: 3600}
  build pgx pool ─► start lease manager

steady state
  serve /query   → SELECT from the demo table
  at 2/3 of lease_duration → renew

  renew ok      → new lease_duration, same pool
  renew fails   → jittered backoff, up to 3 attempts
  terminal      → max_ttl reached, lease gone, or policy denied
      ↓
  re-authenticate ─► fresh credentials ─► NEW pool
      ─► swap (new traffic goes here immediately)
      ─► drain old pool gracefully, then revoke its lease
```

## Files

| File | Holds |
|---|---|
| `vault_creds.go` | login, `database/creds` read, renew, revoke, and Vault error classification |
| `db.go` | DSN construction, pool build, atomic swap, graceful drain, query error classification |
| `lease.go` | the renewal loop, backoff, and the rotation path |
| `main.go` | wiring and HTTP |

`vault_creds.go` uses `hashicorp/vault/api` — the SDK Level 2 was forbidden
from touching. The contrast is deliberate: Level 2's ~200 lines of `net/http`
become

```go
auth, _ := kubernetes.NewKubernetesAuth(role)
client.Auth().Login(ctx, auth)
```

Having written the handshake by hand once, using the SDK here is an informed
choice. **This module does not import Level 2** — the duplication is the
teaching mechanism (D2).

## The three things that are easy to get wrong

**Renew at 2/3, not 90%.** Two thirds leaves a full third of the TTL for
retries. Renewing at 90% leaves no headroom for a transient Vault outage;
renewing at 50% is chatty enough to mask a problem.

**Swap before draining, never the reverse.** New credentials mean a new Postgres
role. Connections authenticated as the old role keep working right up until it
is dropped, then fail mid-query. `pgxpool.Close` blocks until every checked-out
connection is returned, so swapping first and closing second lets in-flight
queries finish on the old pool while new traffic goes to the new one. That is
the whole of the graceful drain (D8).

**"Database down" is not "credentials invalid."** They look identical from a
handler and demand opposite responses. `classifyQueryError` reads the Postgres
SQLSTATE: `28P01`/`28000` mean the role was rejected — rotate. Everything else,
including a refused connection, means Postgres has a problem that
re-authenticating against Vault cannot fix. Rotating anyway burns a credential,
generates noise, and hides the real fault.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness. Independent of Vault and Postgres, deliberately |
| `GET /readyz` | Ready only if the pool exists **and** its credential has not expired |
| `GET /query` | Real SELECT; returns `current_user` from Postgres alongside our own `vault_username` — watch these change together across a rotation |
| `GET /creds-info` | username, lease ID, TTL remaining, renewal count, rotation count, login count, pool stats |

`/creds-info` is the observation window for the entire level. It was built
first, on purpose — building it last means debugging every test below blind.

## Verification

```bash
kubectl -n poc-hashicorp-vault-application port-forward deploy/level3-dynamic-db 8080:8080
curl -s localhost:8080/creds-info | jq   # generated username, ~3600s TTL
curl -s localhost:8080/query | jq '{current_user, vault_username}'   # must agree

# and in Postgres, the role Vault created:
psql -c '\du'
```

## Failure injection — the substance of this phase

| # | Test | Expected |
|---|---|---|
| 4 | `vault lease revoke <lease_id>` | `/query` fails on `28P01`, app re-auths and rebuilds the pool, `/creds-info` shows a **different username** and `rotation_count: 1` |
| 5 | Temporarily set `default_ttl=2m max_ttl=6m` | Two renewals succeed, the third is **refused**, the forced re-auth path runs |
| 6 | Vault scaled to 0 during a renewal window | Backs off, **keeps serving** on the still-valid credential, recovers when Vault returns |
| 7 | Postgres down | Reports `fault: database`, does **not** contact Vault |
| 8 | Slow query, rotate mid-flight | The in-flight query **completes** rather than erroring |

**Test 5 is the one that matters most.** `max_ttl` exhaustion is not a choice —
it is guaranteed to happen in production, and it is almost never tested.
Shortening the TTL forces it in minutes instead of a day. Restore the original
TTLs afterwards.

**Target: zero request errors during rotation.** If a caller can see a rotation
happen, the drain logic is wrong.

To record: renewal count over an hour, rotation latency (logged as
`rotation_latency_ms`), and any request errors observed during rotation.

On `SIGTERM` the lease is revoked. Confirm no orphans:

```bash
vault list sys/leases/lookup/database/creds/level3-app
```

> **Status: not yet executed against a live cluster.** Requires Stage A Phases
> A6 and A7. Locally, `go test` covers the pure logic: DSN escaping and
> round-trip, that the password cannot be serialised by `encoding/json`, both
> error classifiers, the 2/3 arithmetic, rotation-request coalescing, and
> backoff bounds. **Run `make race` on the dev workspace** — the race detector
> needs cgo and a C compiler, which the Windows workstation lacks.

## What this pattern does not solve

- **It works only for credentials Vault can *generate*.** Key material Vault
  merely stores — a PGP key, a signing key, a licence file — has no
  `creds/` endpoint and needs a different pattern. That is Level 4.
- **The app must get the lifecycle right.** ~600 lines of it, and the
  interesting half only runs during failures. An implementation without the
  re-auth path works perfectly for exactly one `max_ttl` and then dies.
- **The credential is still plaintext in process memory** for its lifetime.
  Bounded to an hour rather than forever, which is the improvement, but not zero.
- **Revocation is only as fast as detection.** Vault drops the role instantly;
  this app notices on its next query or renewal, not before.

## Why one hour is categorically different from forever

- **Leak windows are bounded.** A credential scraped from memory is useless
  after its lease.
- **Revocation is instant and central.** `vault lease revoke` drops the Postgres
  role — no coordination with the app, no restart, no config change.
- **Every credential is attributable.** The username maps to one lease, which
  maps to one pod's ServiceAccount identity, recorded in Vault's audit log.
- **The lease is a contract.** Vault revokes on schedule whether or not the
  application is ready. `max_ttl` is not optional and the re-auth path is
  mandatory, not defensive.
