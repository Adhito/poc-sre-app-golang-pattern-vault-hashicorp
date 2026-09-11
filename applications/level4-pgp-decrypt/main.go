// Level 4 — custody of key material Vault stores but cannot operate on.
//
// The key is fetched, lands on tmpfs for a measured handful of milliseconds,
// is imported, and is deleted. Everything after that happens in memory.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

const listenAddr = ":8080"

type result struct {
	Plaintext   string
	DecryptedAt time.Time
	Window      keyFileWindow
	DecryptMs   int64
}

type app struct {
	mu        sync.RWMutex
	res       *result
	startErr  error
	startedAt time.Time
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var is unset", "key", key)
		os.Exit(1)
	}
	return v
}

// fetchKeyMaterial performs the Kubernetes auth login and reads the KV v2
// secret. Note the API path: `secret/data/level4/pgp`, not the CLI-visible
// `secret/level4/pgp` — a policy or client written against the latter is denied
// silently.
func fetchKeyMaterial(ctx context.Context, addr, caPath, role, secretPath string) (*keyMaterial, error) {
	cfg := api.DefaultConfig()
	cfg.Address = addr
	if err := cfg.ConfigureTLS(&api.TLSConfig{CACert: caPath}); err != nil {
		return nil, fmt.Errorf("configure TLS from %s: %w", caPath, err)
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}

	k8s, err := auth.NewKubernetesAuth(role)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes auth for role %q: %w", role, err)
	}
	authSecret, err := client.Auth().Login(ctx, k8s)
	if err != nil {
		return nil, fmt.Errorf("login as role %q: %w", role, err)
	}
	if authSecret == nil || authSecret.Auth == nil {
		return nil, errors.New("login returned no auth data")
	}
	slog.Info("authenticated to vault",
		"role", role, "policies", authSecret.Auth.Policies, "accessor", authSecret.Auth.Accessor)

	secret, err := client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", secretPath, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("read %s: no data (wrong path, or the policy denies it)", secretPath)
	}

	// KV v2 nests twice: {"data": {"data": {...}, "metadata": {...}}}.
	inner, ok := secret.Data["data"].(map[string]any)
	if !ok {
		return nil, errors.New("unexpected KV shape — expected KV v2 double nesting under data.data")
	}

	get := func(key string) ([]byte, error) {
		v, ok := inner[key].(string)
		if !ok || v == "" {
			return nil, fmt.Errorf("secret is missing %q", key)
		}
		return []byte(v), nil
	}

	priv, err := get("private_key")
	if err != nil {
		return nil, err
	}
	pass, err := get("passphrase")
	if err != nil {
		return nil, err
	}
	pub, _ := get("public_key") // optional — not needed to decrypt

	// Lengths only. Never the key, never the passphrase (D11).
	slog.Info("fetched key material from vault",
		"private_key_len", len(priv),
		"public_key_len", len(pub),
		"passphrase_len", len(pass))

	return &keyMaterial{privateKey: priv, publicKey: pub, passphrase: pass}, nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	var (
		vaultAddr  = mustEnv("VAULT_ADDR")
		vaultRole  = envOr("VAULT_ROLE", "level4-app")
		caPath     = envOr("VAULT_CACERT", "/vault/tls/ca.crt")
		secretPath = envOr("SECRET_PATH", "secret/data/level4/pgp")
		keyDir     = envOr("KEY_DIR", "/keys")
		outDir     = envOr("OUTPUT_DIR", "/output")
		fixture    = envOr("FIXTURE", "/fixtures/secret-message.txt.gpg")
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := &app{startedAt: time.Now().UTC()}

	// The flow runs once at startup. Everything it touches is ephemeral: a
	// restart re-runs the whole thing from scratch, and tmpfs is empty on the
	// new pod.
	go func() {
		if err := a.run(ctx, vaultAddr, caPath, vaultRole, secretPath, keyDir, outDir, fixture); err != nil {
			slog.Error("decrypt flow failed", "err", err)
			a.mu.Lock()
			a.startErr = err
			a.mu.Unlock()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /result", a.handleResult)
	mux.HandleFunc("GET /key-status", a.handleKeyStatus)

	srv := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	slog.Info("listening", "addr", listenAddr, "role", vaultRole, "fixture", fixture)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func (a *app) run(ctx context.Context, addr, caPath, role, secretPath, keyDir, outDir, fixture string) error {
	mat, err := fetchKeyMaterial(ctx, addr, caPath, role, secretPath)
	if err != nil {
		return err
	}
	// The private key and passphrase do not outlive this function, as far as
	// this code can control that. See the README on what that is worth.
	defer mat.destroy()

	ciphertext, err := os.ReadFile(fixture)
	if err != nil {
		return fmt.Errorf("read fixture %s: %w", fixture, err)
	}

	start := time.Now()
	plaintext, window, err := decryptFlow(mat, ciphertext, keyDir, outDir)
	if err != nil {
		// The window is still worth recording on failure — it says whether the
		// key was cleaned up despite the error.
		a.mu.Lock()
		a.res = &result{Window: window}
		a.mu.Unlock()
		return err
	}

	a.mu.Lock()
	a.res = &result{
		Plaintext:   string(plaintext),
		DecryptedAt: time.Now().UTC(),
		Window:      window,
		DecryptMs:   time.Since(start).Milliseconds(),
	}
	a.mu.Unlock()

	// Per the requirement, the decrypted content goes to stdout. This is the
	// one place a secret value is printed deliberately — the fixture is a demo
	// message, not a credential, and printing it is the level's visible output.
	fmt.Println(string(plaintext))

	slog.Info("flow complete",
		"key_on_disk_ms", window.durationMs(),
		"total_ms", time.Since(start).Milliseconds())
	return nil
}

func (a *app) handleResult(w http.ResponseWriter, _ *http.Request) {
	a.mu.RLock()
	res, startErr := a.res, a.startErr
	a.mu.RUnlock()

	switch {
	case startErr != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": startErr.Error(),
			"note":  "no plaintext was produced — see /key-status for whether the key was cleaned up",
		})
	case res == nil || res.DecryptedAt.IsZero():
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "decryption has not completed yet"})
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"plaintext":      res.Plaintext,
			"decrypted_at":   res.DecryptedAt.Format(time.RFC3339),
			"decrypt_ms":     res.DecryptMs,
			"key_on_disk_ms": res.Window.durationMs(),
		})
	}
}

// handleKeyStatus is the level's evidence. `exists` must be false after
// startup, and `on_disk_ms` is the measured window Phase B4 asks for.
func (a *app) handleKeyStatus(w http.ResponseWriter, _ *http.Request) {
	a.mu.RLock()
	res := a.res
	a.mu.RUnlock()

	if res == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "flow has not run yet"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"key_path":   res.Window.Path,
		"exists":     keyFileExists(res.Window.Path),
		"on_disk_ms": res.Window.durationMs(),
		"written_at": timeOrNull(res.Window.WrittenAt),
		"removed_at": timeOrNull(res.Window.RemovedAt),
		"uptime":     time.Since(a.startedAt).Truncate(time.Second).String(),
	})
}

func timeOrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Format(time.RFC3339Nano)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}
