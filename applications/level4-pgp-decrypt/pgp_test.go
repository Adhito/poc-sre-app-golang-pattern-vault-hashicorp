package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const testPassphrase = "correct-horse-battery-staple"

// newTestKey generates a passphrase-protected keypair at test time.
//
// Nothing is committed: CLAUDE.md rule 1 forbids key material in the repo in
// any form, and a "test-only" private key checked in is exactly how that rule
// erodes. The real fixture comes from Stage A Phase A7.
func newTestKey(t *testing.T) (armoredPrivate []byte, entity *openpgp.Entity) {
	t.Helper()

	e, err := openpgp.NewEntity("POC Level 4", "test key", "level4@example.invalid", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	// Lock the primary key AND every subkey with the passphrase, mirroring
	// what `gpg --gen-key` with a passphrase produces in Phase A7.
	//
	// Getting this wrong is quiet: an unencrypted key imports fine with any
	// passphrase, so the wrong-passphrase test has nothing to fail against and
	// passes for the wrong reason. Watch `keys_unlocked` in the import log —
	// it must be non-zero.
	pass := []byte(testPassphrase)
	if err := e.PrivateKey.Encrypt(pass); err != nil {
		t.Fatalf("encrypt primary key: %v", err)
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey == nil {
			continue
		}
		if err := sub.PrivateKey.Encrypt(pass); err != nil {
			t.Fatalf("encrypt subkey: %v", err)
		}
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	// WithoutSigning: re-signing the identities would need the private key
	// decrypted, which is precisely what we just undid.
	if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatalf("SerializePrivateWithoutSigning: %v", err)
	}
	w.Close()

	return buf.Bytes(), e
}

func encryptTo(t *testing.T, e *openpgp.Entity, plaintext string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{e}, nil, nil, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	w.Close()
	return buf.Bytes()
}

func dirs(t *testing.T) (keyDir, outDir string) {
	t.Helper()
	base := t.TempDir()
	keyDir, outDir = filepath.Join(base, "keys"), filepath.Join(base, "output")
	for _, d := range []string{keyDir, outDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return
}

// The happy path, end to end: key lands on disk, is imported, is deleted, and
// the fixture decrypts.
func TestDecryptFlowRemovesKeyAndDecrypts(t *testing.T) {
	const message = "the fixture decrypted successfully"
	priv, entity := newTestKey(t)
	ciphertext := encryptTo(t, entity, message)
	keyDir, outDir := dirs(t)

	mat := &keyMaterial{privateKey: priv, passphrase: []byte(testPassphrase)}

	plaintext, window, err := decryptFlow(mat, ciphertext, keyDir, outDir)
	if err != nil {
		t.Fatalf("decryptFlow: %v", err)
	}
	if string(plaintext) != message {
		t.Errorf("plaintext = %q, want %q", plaintext, message)
	}

	// The deliverable: the key is gone.
	if keyFileExists(window.Path) {
		t.Fatalf("private key still on disk at %s", window.Path)
	}
	if window.durationMs() < 0 {
		t.Error("on-disk window was not measured")
	}

	// And /keys is empty, not merely missing that one file.
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("key directory is not empty: %v", entries)
	}

	out, err := os.ReadFile(filepath.Join(outDir, "decrypted.txt"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(out) != message {
		t.Errorf("output file = %q, want %q", out, message)
	}
}

// Injection 5: a wrong passphrase must fail clearly at import — not silently
// produce garbage — and must not leak the passphrase into the error.
func TestWrongPassphraseFailsClearlyAndDoesNotLeak(t *testing.T) {
	priv, entity := newTestKey(t)
	ciphertext := encryptTo(t, entity, "never seen")
	keyDir, outDir := dirs(t)

	const wrong = "definitely-not-the-passphrase"
	mat := &keyMaterial{privateKey: priv, passphrase: []byte(wrong)}

	plaintext, window, err := decryptFlow(mat, ciphertext, keyDir, outDir)
	if err == nil {
		t.Fatal("expected an error for a wrong passphrase")
	}
	if plaintext != nil {
		t.Error("plaintext returned despite failure")
	}
	if strings.Contains(err.Error(), wrong) {
		t.Fatalf("error leaked the passphrase: %v", err)
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error should name the cause, got: %v", err)
	}

	// Even on failure the key must not be left behind.
	if keyFileExists(window.Path) {
		t.Fatalf("private key left on disk after a failed import: %s", window.Path)
	}
}

// Injection 7: a truncated fixture must produce a decryption error and NO
// partial plaintext — nothing written, nothing printed.
func TestCorruptFixtureWritesNoPartialPlaintext(t *testing.T) {
	priv, entity := newTestKey(t)
	full := encryptTo(t, entity, strings.Repeat("sensitive payload. ", 500))
	truncated := full[:len(full)/2]
	keyDir, outDir := dirs(t)

	mat := &keyMaterial{privateKey: priv, passphrase: []byte(testPassphrase)}

	plaintext, window, err := decryptFlow(mat, truncated, keyDir, outDir)
	if err == nil {
		t.Fatal("expected an error for a truncated fixture")
	}
	if plaintext != nil {
		t.Error("plaintext returned for a corrupt message")
	}
	if keyFileExists(window.Path) {
		t.Error("key left on disk")
	}

	// The critical assertion: no output file at all. Streaming the body
	// straight to disk would have written unverified bytes before the
	// integrity check failed.
	if _, err := os.Stat(filepath.Join(outDir, "decrypted.txt")); !os.IsNotExist(err) {
		t.Fatal("a partial plaintext file was written for a corrupt message")
	}
	entries, _ := os.ReadDir(outDir)
	if len(entries) != 0 {
		t.Errorf("output directory is not empty: %v", entries)
	}
}

func TestKeyFileIsWrittenReadOnly(t *testing.T) {
	priv, _ := newTestKey(t)
	keyDir, _ := dirs(t)

	path, _, err := writeKeyToTmpfs(keyDir, priv)
	if err != nil {
		t.Fatalf("writeKeyToTmpfs: %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()

	// A second write must not silently clobber the first. Asserted before the
	// platform check below so it runs everywhere — it has nothing to do with
	// mode bits.
	if _, _, err := writeKeyToTmpfs(keyDir, priv); err == nil {
		t.Error("writing over an existing key file should fail loudly")
	}

	// Windows has no POSIX mode bits: Go synthesises 0444 for any read-only
	// file regardless of what was requested, so the exact mode can only be
	// asserted where the OS actually models it. The 0400 guarantee is verified
	// on Linux — in the pod, with `kubectl exec -- ls -l /keys`.
	if runtime.GOOS == "windows" {
		if perm&0o200 != 0 {
			t.Errorf("key file is writable: mode %o", perm)
		}
		t.Skip("POSIX mode bits are not modelled on Windows — verify 0400 in-cluster")
	}

	if perm != 0o400 {
		t.Errorf("key file mode = %o, want 400", perm)
	}
}

func TestZeroOverwritesBuffers(t *testing.T) {
	mat := &keyMaterial{
		privateKey: []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
		passphrase: []byte(testPassphrase),
	}
	priv := mat.privateKey // same backing array
	pass := mat.passphrase

	mat.destroy()

	if !bytes.Equal(priv, make([]byte, len(priv))) {
		t.Error("private key buffer was not zeroed")
	}
	if !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Error("passphrase buffer was not zeroed")
	}
}

func TestDecryptAcceptsArmouredAndBinary(t *testing.T) {
	const message = "either encoding is fine"
	priv, entity := newTestKey(t)

	binary := encryptTo(t, entity, message)

	var armoured bytes.Buffer
	w, err := armor.Encode(&armoured, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(binary)
	w.Close()

	keyring, err := unlockForTest(t, priv)
	if err != nil {
		t.Fatal(err)
	}

	for name, ct := range map[string][]byte{"binary": binary, "armoured": armoured.Bytes()} {
		t.Run(name, func(t *testing.T) {
			got, err := decryptMessage(keyring, ct)
			if err != nil {
				t.Fatalf("decryptMessage: %v", err)
			}
			if string(got) != message {
				t.Errorf("got %q, want %q", got, message)
			}
		})
	}
}

func unlockForTest(t *testing.T, armoredPrivate []byte) (openpgp.EntityList, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "private.asc")
	if err := os.WriteFile(path, armoredPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	return importKeyring(path, []byte(testPassphrase))
}
