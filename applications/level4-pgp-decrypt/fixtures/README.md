# fixtures/

`secret-message.txt.gpg` belongs here. **It is not in the repository yet** —
it is produced by Stage A Phase A7 step 5, which has not run.

That phase generates an RSA-4096 keypair with a passphrase, encrypts a fixture
file to it, uploads the private key, public key, and passphrase to
`secret/level4/pgp`, and then **deletes the local private key**.

## What goes here, and what must not

Commit **only the ciphertext**. It is safe: the private key that opens it lives
in Vault and nowhere else. That asymmetry is worth noticing — the encrypted
fixture can sit in git precisely because the custody model works.

Never commit the keypair or the passphrase. `.gitignore` covers `*.asc` and
`*.key`, and `.gitattributes` marks `*.gpg` as binary so git will not mangle it
with line-ending conversion.

## Either encoding works

`gpg --encrypt` produces binary; `gpg --armor --encrypt` produces text. Phase A7
does not specify which, so `decryptMessage` accepts both — it attempts
`armor.Decode` and falls back to raw bytes. Both paths are covered by
`TestDecryptAcceptsArmouredAndBinary`.

## Tests do not need this file

`pgp_test.go` generates its own passphrase-protected keypair and ciphertext at
runtime, in memory. Nothing key-shaped is ever written into the repository —
a "test-only" private key committed here is exactly how CLAUDE.md rule 1 erodes.
