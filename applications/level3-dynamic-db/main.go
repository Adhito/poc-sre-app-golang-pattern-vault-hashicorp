// Level 3 — dynamic database credentials with a lease lifecycle.
//
// The credential this process uses did not exist before it started and will not
// outlive its lease. Watch /creds-info across a rotation: the Postgres username
// changes, and /query keeps answering throughout.
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

	"github.com/jackc/pgx/v5"
)

const listenAddr = ":8080"

type app struct {
	vc     *vaultCreds
	pools  *poolManager
	leases *leaseManager

	demoTable string
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

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	var (
		vaultAddr = mustEnv("VAULT_ADDR")
		vaultRole = envOr("VAULT_ROLE", "level3-app")
		caPath    = envOr("VAULT_CACERT", "/vault/tls/ca.crt")
		credsPath = envOr("VAULT_DB_CREDS_PATH", "database/creds/level3-app")

		target = dbTarget{
			host:     mustEnv("PGHOST"),
			port:     envOr("PGPORT", "5432"),
			database: envOr("PGDATABASE", "appdb"),
			sslmode:  envOr("PGSSLMODE", "disable"),
		}
		demoTable = envOr("DEMO_TABLE", "demo")
	)

	vc, err := newVaultCreds(vaultAddr, caPath, vaultRole, credsPath)
	if err != nil {
		slog.Error("vault client construction failed", "err", err)
		os.Exit(1)
	}

	pools := newPoolManager(target, 30*time.Second)
	leases := newLeaseManager(vc, pools)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := &app{vc: vc, pools: pools, leases: leases, demoTable: demoTable, startedAt: time.Now().UTC()}

	go leases.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		// Liveness only. Deliberately independent of Vault and Postgres — a
		// dependency outage must not get the pod killed and restarted into the
		// same outage.
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", a.handleReady)
	mux.HandleFunc("GET /query", a.handleQuery)
	mux.HandleFunc("GET /creds-info", a.handleCredsInfo)

	srv := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")

		sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)

		// Order matters: stop serving, revoke the lease, then close the pool.
		// Revoking first would break in-flight queries; closing first would
		// leave the lease alive until Vault expires it.
		leases.Shutdown()
		pools.closeAll()
	}()

	slog.Info("listening",
		"addr", listenAddr, "role", vaultRole, "creds_path", credsPath,
		"pg_host", target.host, "pg_database", target.database, "demo_table", demoTable)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// handleReady is ready only when a pool exists and its credential has not
// expired — the distinction the PRD asks for. A pod whose lease has lapsed
// should stop taking traffic even though the process is perfectly alive.
func (a *app) handleReady(w http.ResponseWriter, _ *http.Request) {
	h := a.pools.current()
	switch {
	case h == nil:
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "reason": "no pool yet"})
	case h.cred.expired():
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "reason": "credential expired"})
	default:
		_, expiresAt := h.cred.lease()
		writeJSON(w, http.StatusOK, map[string]any{
			"ready":                 true,
			"username":              h.cred.Username,
			"lease_ttl_remaining_s": int(time.Until(expiresAt).Seconds()),
		})
	}
}

func (a *app) handleQuery(w http.ResponseWriter, r *http.Request) {
	h := a.pools.current()
	if h == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no database pool yet"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// current_user comes from Postgres itself, not from our own bookkeeping.
	// That is the point: it is independent evidence of which role is in use,
	// and it changes visibly across a rotation.
	var currentUser string
	var now time.Time
	if err := h.pool.QueryRow(ctx, "SELECT current_user, now()").Scan(&currentUser, &now); err != nil {
		a.failQuery(w, err, "identity query")
		return
	}

	rows, err := h.pool.Query(ctx,
		"SELECT * FROM "+pgx.Identifier{a.demoTable}.Sanitize()+" LIMIT 20")
	if err != nil {
		a.failQuery(w, err, "demo table select")
		return
	}
	defer rows.Close()

	out, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		a.failQuery(w, err, "row collection")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"current_user":   currentUser,     // Postgres's answer
		"vault_username": h.cred.Username, // ours — these must agree
		"server_time":    now.UTC().Format(time.RFC3339),
		"table":          a.demoTable,
		"row_count":      len(out),
		"rows":           out,
	})
}

// failQuery is where the two outage modes are told apart. Rotating because
// Postgres is down would burn a credential, produce noise, and mask the real
// fault (Phase B3 test 7).
func (a *app) failQuery(w http.ResponseWriter, err error, stage string) {
	switch classifyQueryError(err) {
	case faultCredentials:
		slog.Warn("query failed on credentials — requesting rotation", "stage", stage, "err", err)
		a.leases.requestRotation()
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "database credentials rejected; rotation requested",
			"stage": stage,
			"fault": "credentials",
		})
	default:
		slog.Error("query failed on the database — not rotating", "stage", stage, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": err.Error(),
			"stage": stage,
			"fault": "database",
			"note":  "Postgres fault, not a credential fault — Vault was not contacted",
		})
	}
}

// handleCredsInfo is the observation window for the whole level. Built early
// on purpose: without it, every test below is debugged blind.
func (a *app) handleCredsInfo(w http.ResponseWriter, _ *http.Request) {
	h := a.pools.current()
	if h == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no credential yet"})
		return
	}

	stat := h.pool.Stat()
	leaseDuration, expiresAt := h.cred.lease()
	writeJSON(w, http.StatusOK, map[string]any{
		"username":              h.cred.Username,
		"lease_id":              h.cred.LeaseID,
		"lease_duration_s":      int(leaseDuration.Seconds()),
		"lease_ttl_remaining_s": int(time.Until(expiresAt).Seconds()),
		"issued_at":             h.cred.IssuedAt.Format(time.RFC3339),
		"expires_at":            expiresAt.Format(time.RFC3339),
		"renewal_count":         a.leases.renewalCount(),
		"rotation_count":        a.pools.rotationCount(),
		"login_count":           a.vc.loginCount(),
		"pool": map[string]any{
			"total_conns":    stat.TotalConns(),
			"idle_conns":     stat.IdleConns(),
			"acquired_conns": stat.AcquiredConns(),
		},
		"uptime": time.Since(a.startedAt).Truncate(time.Second).String(),
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
