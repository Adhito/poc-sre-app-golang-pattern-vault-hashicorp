// Level 2 — the application authenticates to Vault itself.
//
// No Vault credential appears in the manifests. The ServiceAccount is the
// credential. See vault_login.go for the handshake, and the README for what
// this pattern still does not solve.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const listenAddr = ":8080"

type app struct {
	vc         *Client
	secretPath string
	startedAt  time.Time
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

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	var (
		addr       = mustEnv("VAULT_ADDR")
		role       = mustEnv("VAULT_ROLE")
		caPath     = envOr("VAULT_CACERT", "/vault/tls/ca.crt")
		secretPath = envOr("SECRET_PATH", "secret/data/level2/app")
	)

	vc, err := NewClient(addr, role, caPath)
	if err != nil {
		// A CA that will not load is a deployment fault, not a runtime one.
		// Fail immediately rather than retrying something that cannot improve.
		slog.Error("client construction failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := &app{vc: vc, secretPath: secretPath, startedAt: time.Now().UTC()}

	// Authenticate in the background rather than blocking startup. If Vault is
	// unreachable when this pod starts, the app must log and recover — not
	// crash-loop (Phase B2 injection 4).
	go func() {
		if err := vc.Login(ctx); err != nil {
			slog.Warn("initial login failed, maintenance loop will retry", "err", err)
		}
		vc.Maintain(ctx)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /secret", a.handleSecret)
	mux.HandleFunc("GET /token-info", a.handleTokenInfo)

	srv := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	slog.Info("listening", "addr", listenAddr, "role", role, "secret_path", secretPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func (a *app) handleSecret(w http.ResponseWriter, r *http.Request) {
	if !a.vc.Authenticated() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "not yet authenticated to vault",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	data, version, err := a.vc.ReadKVReauth(ctx, a.secretPath)
	if err != nil {
		status := http.StatusBadGateway
		var ae *apiError
		if errors.As(err, &ae) {
			status = ae.status
		}
		slog.Error("secret read failed", "err", err, "path", a.secretPath)
		writeJSON(w, status, map[string]any{"error": err.Error(), "path": a.secretPath})
		return
	}

	st := a.vc.State()
	writeJSON(w, http.StatusOK, map[string]any{
		"data":                  data,
		"kv_version":            version,
		"path":                  a.secretPath,
		"authenticated_at":      st.authenticatedAt.Format(time.RFC3339),
		"token_ttl_remaining_s": int(time.Until(st.expiresAt).Seconds()),
		"policies":              st.policies,
		"login_count":           st.logins,
		"renewal_count":         st.renewals,
		// Unlike Level 1, this value is fetched per request. Change it in Vault
		// and the next call reflects it — no restart involved.
		"read_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *app) handleTokenInfo(w http.ResponseWriter, r *http.Request) {
	if !a.vc.Authenticated() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "not yet authenticated to vault",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	info, err := a.vc.LookupSelf(ctx)
	if err != nil {
		slog.Error("token lookup failed", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	st := a.vc.State()
	writeJSON(w, http.StatusOK, map[string]any{
		"lookup_self":           info,
		"accessor":              st.accessor,
		"renewable":             st.renewable,
		"login_count":           st.logins,
		"renewal_count":         st.renewals,
		"local_ttl_remaining_s": int(time.Until(st.expiresAt).Seconds()),
		"uptime":                time.Since(a.startedAt).Truncate(time.Second).String(),
	})
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
