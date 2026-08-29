# Stage B — four ways an application can relate to Vault

Four independent Go applications. Each demonstrates a different relationship
between an app and Vault, and **each one exposes the limitation the next one
solves.** Read them in order; the progression is the argument.

| Level | Pattern | Teaches | Its limitation → next level |
|---|---|---|---|
| [1](level1-env-secret/) | ESO → Secret → env var | The app has no idea Vault exists | Can't rotate without a restart |
| [2](level2-k8s-auth/) | Direct Kubernetes auth, by hand | The handshake, made visible | Secrets are still static |
| [3](level3-dynamic-db/) | Dynamic DB credentials | Leases, renewal, revocation | Only for credentials Vault can *generate* |
| [4](level4-pgp-decrypt/) | Key custody via tmpfs | Material Vault stores but can't use | The key is exposed to the app |

The closing comparison lands in `documents/pattern-comparison.md` at Phase B6.

## The question that runs through all four

**Where does the secret live at rest, and for how long?** Not "how do I get the
secret." Each level answers the first question differently:

- **Level 1** — in etcd indefinitely, and in the process environment for the process lifetime
- **Level 2** — in Vault only; in process memory for the process lifetime
- **Level 3** — in Vault only; in process memory for **one hour**, then replaced
- **Level 4** — in Vault only; in tmpfs and memory for **seconds**, then deleted

The trend line is the lesson.

## Independence is structural

Four separate `go.mod` files. **No root module. No `go.work`. No shared
packages.** The duplication between Level 2's hand-written handshake and Level
3's SDK usage is deliberate: extracting it into a shared helper would make the
handshake invisible to Level 3, which destroys the reason Level 2 exists.

A shared module is a **failed acceptance criterion**, not a cleanup opportunity
(Stage B D2, CLAUDE.md rule 7).

Module paths are bare (`module level1-env-secret`), not repository-qualified.
See "module naming" in `documents/troubleshooting.md` for why.

## The isolation boundary

All four levels deploy into `poc-hashicorp-vault-application`. Vault's roles all
bind `bound_service_account_namespaces=poc-hashicorp-vault-application` and
differ only in `bound_service_account_names`.

**The ServiceAccount name is therefore the entire isolation boundary.** Every
Deployment sets `serviceAccountName` explicitly; a missing one silently falls
back to `default` and is a security defect, not a typo. This is what makes
Phase B5's 4×4 cross-privilege matrix load-bearing rather than ceremonial.

## Uniform shape

Every level is an HTTP service, not a one-shot Job — a long-running process is
required to demonstrate Level 1's env-var staleness and Level 3's lease renewal
at all. Every level has `/healthz` plus a level-specific endpoint, the same pod
security context, the same multi-stage distroless `Containerfile`, and a
`Makefile` with the same targets:

```
make build test image push deploy logs verify destroy
```

`REGISTRY` has no default. It is read from `documents/environment.md`, which Stage A
Phase A0 populates from the live cluster. `make image` fails loudly if it is
unset rather than guessing.

## Build status

| Level | Code | Manifests | ArgoCD child | Verified against a cluster |
|---|---|---|---|---|
| 1 | done | done | done | **no — Stage A pending** |
| 2 | done | done | done | **no — Stage A pending** |
| 3 | `go.mod` only | — | — | — |
| 4 | `go.mod` only | — | — | — |

Nothing here has run against a real Vault. Every failure injection, the audit
correlation, the 4×4 matrix, and every measured number in Phase B6 are still
outstanding, and no phase gate has been ticked. The per-level READMEs mark the
same thing inline.
