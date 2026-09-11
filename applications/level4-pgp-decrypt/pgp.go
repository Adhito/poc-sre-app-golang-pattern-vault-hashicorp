// PGP key custody: fetch, land on tmpfs, import, delete, decrypt.
//
// Vault *custodies* this key; it does not *use* it. There is no PGP secrets
// engine — a private key is just bytes Vault stores, so unlike Level 3's
// database credentials there is nothing Vault can generate or revoke here.
// Getting the key out and using it is the application's problem, which is the
// whole subject of this level (Stage B D13).
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// keyMaterial is what Vault hands back from secret/data/level4/pgp.
//
// All three fields are []byte rather than string. Go strings are immutable and
// the garbage collector may copy them, so a []byte can at least be overwritten
// in place. Read the README before believing that amounts to secure erasure —
// it is mitigation, not a guarantee.
type keyMaterial struct {
	privateKey []byte
	publicKey  []byte
	passphrase []byte
}

// zero overwrites a buffer. Best-effort: it cannot reach copies the runtime
// may already have made.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (m *keyMaterial) destroy() {
	zero(m.privateKey)
	zero(m.passphrase)
	m.privateKey = nil
	m.passphrase = nil
}

// keyFileWindow records how long the private key existed on disk. This is the
// measurement Phase B4 asks for, and the reason the file is written at all.
type keyFileWindow struct {
	Path      string
	WrittenAt time.Time
	RemovedAt time.Time
}

func (w keyFileWindow) durationMs() int64 {
	if w.WrittenAt.IsZero() || w.RemovedAt.IsZero() {
		return -1
	}
	return w.RemovedAt.Sub(w.WrittenAt).Milliseconds()
}

// writeKeyToTmpfs lands the private key on the mounted tmpfs at mode 0400.
//
// This step is skippable — the key could be imported straight from memory, and
// that would be marginally better. It is here because the requirement specifies
// tmpfs and because it makes the key's on-disk lifetime *observable*: you can
// `kubectl exec` during the window and see the file, then see it gone.
func writeKeyToTmpfs(dir string, privateKey []byte) (string, time.Time, error) {
	path := filepath.Join(dir, "private.asc")

	// O_EXCL: never silently overwrite a key file that is somehow already
	// there. If one is, something is wrong and it should be loud.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create key file: %w", err)
	}

	if _, err := f.Write(privateKey); err != nil {
		f.Close()
		os.Remove(path)
		return "", time.Time{}, fmt.Errorf("write key file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", time.Time{}, fmt.Errorf("close key file: %w", err)
	}

	return path, time.Now().UTC(), nil
}

// importKeyring reads the key back off disk and unlocks it with the passphrase.
//
// Reading it back rather than using the in-memory copy is deliberate: it proves
// the file that was written is the file that gets used, so the window measured
// below is the window that actually mattered.
func importKeyring(path string, passphrase []byte) (openpgp.EntityList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer f.Close()

	entities, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, fmt.Errorf("parse armored key: %w", err)
	}
	if len(entities) == 0 {
		return nil, errors.New("key file contained no entities")
	}

	// Unlock the primary key and every subkey. Encrypted subkeys are the usual
	// cause of "imported fine, cannot decrypt" — the message is almost always
	// encrypted to a subkey, not to the primary.
	var unlocked int
	for _, e := range entities {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Decrypt(passphrase); err != nil {
				// The passphrase must not appear in this error. It is the most
				// likely thing to be logged during debugging (D11).
				return nil, errors.New("could not unlock private key: wrong passphrase, or the key is not encrypted as expected")
			}
			unlocked++
		}
		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Decrypt(passphrase); err != nil {
					return nil, errors.New("could not unlock a subkey: wrong passphrase")
				}
				unlocked++
			}
		}
	}

	slog.Info("keyring imported",
		"entities", len(entities),
		"keys_unlocked", unlocked,
		"key_id", entities[0].PrimaryKey.KeyIdShortString())
	return entities, nil
}

// decryptMessage decrypts the fixture. It accepts both ASCII-armoured and
// binary OpenPGP data, because which one Stage A Phase A7 produced is not
// specified — `gpg --encrypt` yields binary, `--armor` yields text.
func decryptMessage(keyring openpgp.EntityList, ciphertext []byte) ([]byte, error) {
	reader := io.Reader(bytes.NewReader(ciphertext))

	// armor.Decode fails cleanly on binary input, so try it and fall back.
	if block, err := armor.Decode(bytes.NewReader(ciphertext)); err == nil {
		reader = block.Body
	}

	md, err := openpgp.ReadMessage(reader, keyring, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("read pgp message: %w", err)
	}

	// Read the body fully BEFORE treating any of it as output. OpenPGP
	// integrity failures surface at the end of the stream, so streaming
	// straight to a file or to stdout would emit unverified plaintext and only
	// then discover it was corrupt (Phase B4 injection 7).
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed — no plaintext produced: %w", err)
	}
	if md.SignatureError != nil {
		return nil, fmt.Errorf("signature verification failed: %w", md.SignatureError)
	}

	slog.Info("message decrypted",
		"plaintext_len", len(plaintext),
		"was_encrypted", md.IsEncrypted,
		"was_signed", md.IsSigned)
	return plaintext, nil
}

// decryptFlow is the whole of steps 3–7, in order, as one testable unit.
//
//  3. write the private key to tmpfs, 0400
//  4. read it back, unlock it, import into an in-memory keyring
//  5. delete the file IMMEDIATELY after import
//  6. decrypt the fixture
//  7. write the plaintext to tmpfs
func decryptFlow(mat *keyMaterial, ciphertext []byte, keyDir, outDir string) (plaintext []byte, window keyFileWindow, err error) {
	path, writtenAt, err := writeKeyToTmpfs(keyDir, mat.privateKey)
	if err != nil {
		return nil, window, err
	}
	window.Path = path
	window.WrittenAt = writtenAt

	// Whatever happens next, the key file does not outlive this function.
	defer func() {
		if window.RemovedAt.IsZero() {
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				slog.Error("FAILED TO REMOVE KEY FILE — it is still on tmpfs", "path", path, "err", rmErr)
				if err == nil {
					err = fmt.Errorf("remove key file: %w", rmErr)
				}
				return
			}
			window.RemovedAt = time.Now().UTC()
		}
	}()

	keyring, err := importKeyring(path, mat.passphrase)
	if err != nil {
		return nil, window, err
	}

	// Step 5, immediately after import and before any decryption work.
	if err := os.Remove(path); err != nil {
		return nil, window, fmt.Errorf("remove key file: %w", err)
	}
	window.RemovedAt = time.Now().UTC()
	slog.Info("private key removed from disk",
		"path", path, "on_disk_ms", window.durationMs())

	plaintext, err = decryptMessage(keyring, ciphertext)
	if err != nil {
		return nil, window, err
	}

	// Only now, with the whole plaintext verified, does anything get written.
	outPath := filepath.Join(outDir, "decrypted.txt")
	if err := os.WriteFile(outPath, plaintext, 0o600); err != nil {
		return nil, window, fmt.Errorf("write plaintext: %w", err)
	}

	return plaintext, window, nil
}

// keyFileExists backs /key-status. After startup this must report false.
func keyFileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
