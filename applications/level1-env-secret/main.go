// Level 1 — the application reads its secrets from the process environment.
//
// There is deliberately no client library here, no authentication, and no
// network call to fetch a secret. The environment is populated by the platform
// before this process starts, and this process cannot tell where the values
// came from. That opacity is the entire point of the level.
//
// Read the package README for what this costs.
package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	greetingEnv = "APP_GREETING"
	apiKeyEnv   = "APP_API_KEY"
	listenAddr  = ":8080"
)

// config holds the values read once, at process start. They are never re-read:
// a process cannot change its own environment after exec, which is the
// limitation this level exists to demonstrate.
type config struct {
	greeting string
	apiKey   string
	readAt   time.Time
}

func loadConfig() (config, error) {
	greeting := os.Getenv(greetingEnv)
	apiKey := os.Getenv(apiKeyEnv)

	var missing []string
	if greeting == "" {
		missing = append(missing, greetingEnv)
	}
	if apiKey == "" {
		missing = append(missing, apiKeyEnv)
	}
	if len(missing) > 0 {
		return config{}, errors.New("required secret env vars are unset: " + strings.Join(missing, ", "))
	}

	return config{greeting: greeting, apiKey: apiKey, readAt: time.Now().UTC()}, nil
}

// mask renders a secret safe to serve or log: a short prefix and the length,
// never the value. Four characters is enough to correlate a rotation without
// being enough to use.
func mask(s string) string {
	const keep = 4
	if len(s) <= keep {
		return strings.Repeat("*", len(s))
	}
	return s[:keep] + strings.Repeat("*", len(s)-keep)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := loadConfig()
	if err != nil {
		// Fail loudly and immediately. A pod that starts without its secrets
		// and serves errors later is harder to diagnose than one that never
		// becomes ready.
		slog.Error("startup failed", "err", err)
		os.Exit(1)
	}

	// Never log the API key itself — not here, not at debug level, not
	// temporarily. Length and prefix are enough to confirm it parsed.
	slog.Info("secrets loaded from environment",
		"greeting", cfg.greeting,
		"api_key_len", len(cfg.apiKey),
		"api_key_prefix", cfg.apiKey[:min(4, len(cfg.apiKey))],
		"read_at", cfg.readAt.Format(time.RFC3339))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /secret", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"greeting":       cfg.greeting,
			"api_key_masked": mask(cfg.apiKey),
			"api_key_len":    len(cfg.apiKey),
			"source":         "os.Getenv",
			// read_at never changes for the life of the process. Watch this
			// field across a rotation: the backing Secret updates, this does not.
			"read_at":        cfg.readAt.Format(time.RFC3339),
			"process_uptime": time.Since(cfg.readAt).Truncate(time.Second).String(),
		})
	})

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	slog.Info("listening", "addr", listenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}
