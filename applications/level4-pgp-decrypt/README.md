# Level 4 — PGP key custody, from Vault to tmpfs and gone

**Pattern:** fetch key material Vault stores but cannot operate on, use it, and
destroy it as fast as possible.

Level 3 handled credentials Vault can *generate* — it creates the Postgres role,
it drops the Postgres role, and the app never holds anything for longer than a
lease. That does not work for a PGP private key, a signing key, or a licence
file. Vault has no PGP secrets engine; a private key is just bytes it custodies.
Getting the key out and using it is the application's problem.

**Vault custodies this key. It does not use it.** That distinction is the level.

---

## Flow

```
1. k8s auth login (SDK)
2. read secret/data/level4/pgp → {private_key, public_key, passphrase}
3. write private_key → /keys/private.asc   [tmpfs, mode 0400, O_EXCL]
4. read it back, unlock with the passphrase, import to an in-memory keyring
5. os.Remove("/keys/private.asc")          ← immediately after import
6. decrypt fixtures/secret-message.txt.gpg
7. write plaintext → /output/decrypted.txt [tmpfs]
8. print plaintext to stdout
9. serve /result and /key-status
```

Steps 3–5 are one function, `decryptFlow`, with a deferred cleanup so **the key
file cannot outlive it** — including on a panic or an early error return.

## Why write the file at all?

The key could be imported straight from memory, and that would be marginally
better. Two reasons it lands on disk anyway:

1. The requirement specifies tmpfs.
2. It makes the key's on-disk lifetime **observable**. You can `kubectl exec`
   during the window and see the file, then see it gone; `/key-status` reports
   the measured duration in milliseconds. A window you can watch is a better
   teaching artefact than one you have to take on trust.

It is read back off disk rather than reused from memory on purpose — that proves
the file written is the file used, so the measured window is the window that
actually mattered.

## `medium: Memory` is not optional

```yaml
- name: keys
  emptyDir:
    medium: Memory     # tmpfs — never touches disk
    sizeLimit: 1Mi
```

A **plain `emptyDir` lives on the node's disk.** The PGP private key would be
recoverable from the node filesystem and could survive into node backups —
exactly the outcome this level exists to avoid. Verify it is real:

```bash
kubectl exec deploy/level4-pgp-decrypt -- df -h /keys    # must say tmpfs
```

`readOnlyRootFilesystem: true` is load-bearing rather than decorative here: the
two tmpfs mounts are the *only* writable paths in the container, so the key
cannot be written anywhere else even by mistake.

## Library choice

`github.com/ProtonMail/go-crypto/openpgp` (D10). **Not**
`golang.org/x/crypto/openpgp`, which is frozen and deprecated. `make verify`
checks for both conditions.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /healthz` | 200 |
| `GET /result` | decrypted plaintext, decrypt duration, key-on-disk window |
| `GET /key-status` | whether the key file exists **now** (must be `false`), how long it existed, written/removed timestamps |

## Verification

```bash
kubectl logs -n poc-hashicorp-vault-application deploy/level4-pgp-decrypt   # plaintext on stdout
kubectl exec deploy/level4-pgp-decrypt -- ls -la /keys                      # empty
kubectl exec deploy/level4-pgp-decrypt -- df -h /keys                       # tmpfs
curl -s localhost:8080/key-status | jq                                      # exists:false, on_disk_ms:N
```

## Failure injection

| Test | Expected |
|---|---|
| Wrong passphrase | Clear failure at import. No garbage plaintext, passphrase never logged or returned |
| Role lacking `level4-pgp` | Clean 403 with a clear error |
| Truncated `.gpg` fixture | Decryption error and **no partial plaintext written or printed** |
| Pod restart | Whole flow re-runs; tmpfs empty on the new pod |

Three of these are covered by `go test` against a keypair generated at runtime:
`TestWrongPassphraseFailsClearlyAndDoesNotLeak` also asserts the key file is
removed *even when import fails*, and
`TestCorruptFixtureWritesNoPartialPlaintext` asserts the output directory is
left completely empty.

That last one drove a design decision: `decryptMessage` reads the body to
completion **before** anything is written or printed. OpenPGP integrity failures
surface at the *end* of the stream, so streaming straight to a file or to stdout
would emit unverified plaintext and only then discover it was corrupt.

> **Status: not yet executed against a live cluster.** Requires Stage A Phases
> A6 and A7, and `fixtures/secret-message.txt.gpg`, which A7 produces —
> see `fixtures/README.md`. The tmpfs and `0400` assertions can only be made on
> Linux; the mode test skips on Windows, which has no POSIX mode bits.

## The honest limitation

**Once the key is in the Go process, it is in Go's heap.** The code uses
`[]byte` rather than `string` throughout for key material and overwrites those
buffers when done — but Go strings are immutable, the garbage collector may
have copied the bytes, and nothing here is `mlock`ed, so the pages can be
swapped. Reliable zeroization would need `[]byte` end to end plus `mlock`,
which is out of scope.

**This is mitigation, not a guarantee.** Saying so plainly is worth more than a
false claim of secure erasure.

## What this pattern does not solve

- **The key is exposed to the application.** Compromise the app while the key
  is in memory and the key is compromised — and unlike Level 3's credential,
  there is no lease bounding how long that matters.
- **Revocation does not exist here.** Vault can stop *handing out* the key, but
  a copy already extracted stays valid until the key is rotated everywhere it
  is trusted. Compare Level 3, where `vault lease revoke` ends the credential's
  usefulness instantly and centrally.
- **Blast radius is unbounded in time.** This is the one place where Level 4 is
  *worse* than Level 3, and the comparison table in Phase B6 should say so.

**The alternative:** Vault's Transit engine, where the key never leaves Vault
and Vault performs the crypto on your behalf. That answers this limitation
completely — the app sends ciphertext and receives plaintext, never holding key
material at all. It is a genuinely different primitive, it does not satisfy this
level's "pull the key out" requirement, and it is logged as backlog (Level 7).
