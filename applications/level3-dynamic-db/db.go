// Connection pool construction, atomic swap, and graceful drain.
//
// The hard part of dynamic credentials is not getting them — it is replacing
// them without anyone noticing. New credentials mean a new Postgres role;
// connections authenticated as the old role keep working until that role is
// dropped, then fail mid-query. Draining rather than dropping is the difference
// between a rotation being invisible and being an incident (Stage B D8).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type dbTarget struct {
	host     string
	port     string
	database string
	sslmode  string
}

// dsn builds the connection string. The returned value contains the password —
// it must never be logged, and no error wrapping it may be returned to a
// handler. pgx does not log it either; connection errors carry the host, not
// the credential.
func (t dbTarget) dsn(cred *dbCredential) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cred.Username, cred.password),
		Host:   net.JoinHostPort(t.host, t.port),
		Path:   "/" + t.database,
	}
	q := u.Query()
	q.Set("sslmode", t.sslmode)
	u.RawQuery = q.Encode()
	return u.String()
}

// poolHandle pairs a pool with the credential it was built from, so that
// /creds-info can report what the *currently serving* pool is actually using
// rather than what was most recently fetched.
type poolHandle struct {
	pool *pgxpool.Pool
	cred *dbCredential
}

type poolManager struct {
	target       dbTarget
	drainTimeout time.Duration

	mu        sync.RWMutex
	cur       *poolHandle
	rotations int
}

func newPoolManager(target dbTarget, drainTimeout time.Duration) *poolManager {
	return &poolManager{target: target, drainTimeout: drainTimeout}
}

func (m *poolManager) current() *poolHandle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur
}

func (m *poolManager) rotationCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rotations
}

// build opens a new pool and verifies it before returning. Verifying here means
// a failed rotation leaves the *old* pool serving rather than swapping in a
// pool that cannot connect.
func (m *poolManager) build(ctx context.Context, cred *dbCredential) (*poolHandle, error) {
	cfg, err := pgxpool.ParseConfig(m.target.dsn(cred))
	if err != nil {
		// Deliberately not wrapping err with the DSN — it holds the password.
		return nil, errors.New("parse connection config: invalid target or credential")
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 55 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool as %s: %w", cred.Username, err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping as %s: %w", cred.Username, err)
	}

	return &poolHandle{pool: pool, cred: cred}, nil
}

// swap installs next as the pool serving new traffic and drains the previous
// one in the background.
//
// pgxpool.Close blocks until every checked-out connection is returned, so an
// in-flight query completes on the old pool rather than being cut off. That is
// the whole of the graceful drain: swap first, close second, never the reverse.
func (m *poolManager) swap(next *poolHandle) *poolHandle {
	m.mu.Lock()
	prev := m.cur
	m.cur = next
	if prev != nil {
		m.rotations++
	}
	rotations := m.rotations
	m.mu.Unlock()

	if prev == nil {
		return nil
	}

	slog.Info("pool swapped",
		"from_username", prev.cred.Username,
		"to_username", next.cred.Username,
		"rotation_count", rotations)

	go m.drain(prev)
	return prev
}

func (m *poolManager) drain(old *poolHandle) {
	start := time.Now()
	done := make(chan struct{})

	go func() {
		old.pool.Close() // blocks until in-flight queries return their conns
		close(done)
	}()

	select {
	case <-done:
		slog.Info("old pool drained",
			"username", old.cred.Username,
			"drain_ms", time.Since(start).Milliseconds())
	case <-time.After(m.drainTimeout):
		// The pool is still closing; we simply stop waiting to report on it.
		// A query outliving the drain timeout is worth knowing about — it means
		// the timeout is shorter than the slowest query, and a rotation could
		// become visible to a caller.
		slog.Warn("drain exceeded timeout — a query outlived it",
			"username", old.cred.Username,
			"timeout", m.drainTimeout.String())
	}
}

// closeAll shuts the current pool down on exit.
func (m *poolManager) closeAll() {
	m.mu.Lock()
	cur := m.cur
	m.cur = nil
	m.mu.Unlock()

	if cur != nil {
		cur.pool.Close()
	}
}

// queryFault distinguishes the two failure modes that look identical from a
// handler but demand opposite responses.
//
// Re-authenticating against Vault because Postgres is down is noise that masks
// the real fault, and it is the mistake Phase B3 test 7 exists to catch.
type queryFault int

const (
	faultNone        queryFault = iota
	faultCredentials            // the role is gone or rejected — rotate
	faultDatabase               // Postgres is unreachable or erroring — do NOT rotate
)

func classifyQueryError(err error) queryFault {
	if err == nil {
		return faultNone
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		// 28P01 invalid_password, 28000 invalid_authorization_specification:
		// the role was dropped out from under us, or never existed. This is
		// what a revoked lease looks like from the database side.
		case "28P01", "28000":
			return faultCredentials
		// 3D000 invalid_catalog_name, 57P03 cannot_connect_now, and anything
		// else Postgres reports is the database's problem, not the credential's.
		default:
			return faultDatabase
		}
	}

	// Dial failures, timeouts, resets: Postgres is unreachable. Rotating would
	// burn a Vault credential and change nothing.
	return faultDatabase
}
