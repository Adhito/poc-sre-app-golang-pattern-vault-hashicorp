// The lease lifecycle: renew, back off, and when renewal is no longer possible,
// rotate.
//
// The lease is a contract. Vault revokes on schedule whether or not the
// application is ready, and max_ttl guarantees that every dynamic credential
// eventually stops being renewable. The re-authentication path below is
// therefore mandatory, not defensive — it is the path that runs in production,
// and it is almost never tested (Stage B D7).
package main

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

const (
	// Renew at 2/3 of the lease. A full third of the TTL remains for retries —
	// enough headroom to sit out a transient Vault outage, without renewing so
	// aggressively that it masks a problem (D7).
	renewFraction = 2.0 / 3.0

	minRenewWait   = 5 * time.Second
	renewAttempts  = 3
	backoffBase    = 2 * time.Second
	backoffCeiling = 30 * time.Second
)

type leaseManager struct {
	vc    *vaultCreds
	pools *poolManager

	renewals atomic.Int64
	// rotateNow lets a query handler that saw a credentials fault ask for an
	// immediate rotation rather than waiting for the next renewal window.
	rotateNow chan struct{}
}

func newLeaseManager(vc *vaultCreds, pools *poolManager) *leaseManager {
	return &leaseManager{vc: vc, pools: pools, rotateNow: make(chan struct{}, 1)}
}

func (l *leaseManager) renewalCount() int64 { return l.renewals.Load() }

// requestRotation is non-blocking and coalescing: several failing queries
// produce one rotation, not several.
func (l *leaseManager) requestRotation() {
	select {
	case l.rotateNow <- struct{}{}:
	default:
	}
}

// bootstrap performs the initial login, credential fetch, and pool build. It is
// retried by Run rather than being fatal, so that a pod starting while Vault or
// Postgres is down backs off and recovers instead of crash-looping.
func (l *leaseManager) bootstrap(ctx context.Context) error {
	if err := l.vc.Login(ctx); err != nil {
		return err
	}
	cred, err := l.vc.Fetch(ctx)
	if err != nil {
		return err
	}
	handle, err := l.pools.build(ctx, cred)
	if err != nil {
		return err
	}
	l.pools.swap(handle)
	return nil
}

// Run owns the credential for the life of the process.
func (l *leaseManager) Run(ctx context.Context) {
	// Keep trying to get into a serving state.
	delay := backoffBase
	for l.pools.current() == nil {
		if err := l.bootstrap(ctx); err != nil {
			slog.Warn("bootstrap failed, backing off", "err", err, "delay", delay.String())
			if !sleepCtx(ctx, jitter(delay)) {
				return
			}
			delay = nextBackoff(delay)
			continue
		}
		delay = backoffBase
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.rotateNow:
			slog.Info("rotation requested by a failing query")
			l.rotateWithRetry(ctx)
			continue
		case <-time.After(l.timeUntilRenew()):
		}

		if l.tryRenew(ctx) {
			continue
		}
		l.rotateWithRetry(ctx)
	}
}

// timeUntilRenew returns 2/3 of the current lease's remaining life.
func (l *leaseManager) timeUntilRenew() time.Duration {
	h := l.pools.current()
	if h == nil || h.cred == nil {
		return minRenewWait
	}
	_, expiresAt := h.cred.lease()
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return minRenewWait
	}
	if wait := time.Duration(float64(remaining) * renewFraction); wait > minRenewWait {
		return wait
	}
	return minRenewWait
}

// tryRenew reports whether the lease was extended. A terminal error — max_ttl
// reached, lease gone, policy denied — short-circuits the retries: those do not
// improve by being asked again.
func (l *leaseManager) tryRenew(ctx context.Context) bool {
	h := l.pools.current()
	if h == nil || h.cred == nil {
		return false
	}

	delay := backoffBase
	for attempt := 1; attempt <= renewAttempts; attempt++ {
		requested, _ := h.cred.lease()
		ttl, err := l.vc.RenewLease(ctx, h.cred.LeaseID, int(requested.Seconds()))
		if err == nil {
			h.cred.extend(ttl)
			n := l.renewals.Add(1)
			slog.Info("lease renewed",
				"username", h.cred.Username,
				"lease_id", h.cred.LeaseID,
				"new_ttl_s", int(ttl.Seconds()),
				"renewal_count", n)
			return true
		}

		if classifyVaultError(err) == vaultTerminal {
			// The expected end of every dynamic credential's life.
			slog.Info("lease is no longer renewable — rotating",
				"username", h.cred.Username, "lease_id", h.cred.LeaseID, "reason", err.Error())
			return false
		}

		slog.Warn("lease renewal failed, retrying",
			"attempt", attempt, "of", renewAttempts, "err", err, "delay", delay.String())
		if !sleepCtx(ctx, jitter(delay)) {
			return false
		}
		delay = nextBackoff(delay)
	}

	slog.Warn("lease renewal retries exhausted — rotating")
	return false
}

// rotate performs the full re-authentication path: new token, new credential,
// new pool, swap, drain, then revoke the lease the old pool was using.
func (l *leaseManager) rotate(ctx context.Context) error {
	start := time.Now()

	if err := l.vc.Login(ctx); err != nil {
		return err
	}
	cred, err := l.vc.Fetch(ctx)
	if err != nil {
		return err
	}
	handle, err := l.pools.build(ctx, cred)
	if err != nil {
		return err
	}

	// Swap before draining. New traffic goes to the new pool immediately; the
	// old one closes behind it, letting in-flight queries finish (D8).
	old := l.pools.swap(handle)

	slog.Info("rotation complete",
		"new_username", cred.Username,
		"lease_id", cred.LeaseID,
		"rotation_latency_ms", time.Since(start).Milliseconds())

	// Revoke the superseded lease so roles do not accumulate. Best-effort and
	// deliberately not fatal: if rotation was triggered *by* a revocation, the
	// lease is already gone and this returns an error that means nothing.
	if old != nil && old.cred != nil && old.cred.LeaseID != "" {
		go func(leaseID, username string) {
			rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := l.vc.RevokeLease(rctx, leaseID); err != nil {
				slog.Info("superseded lease not revoked (usually already gone)",
					"lease_id", leaseID, "username", username, "err", err)
				return
			}
			slog.Info("superseded lease revoked", "lease_id", leaseID, "username", username)
		}(old.cred.LeaseID, old.cred.Username)
	}
	return nil
}

func (l *leaseManager) rotateWithRetry(ctx context.Context) {
	delay := backoffBase
	for {
		if err := l.rotate(ctx); err == nil {
			return
		} else {
			slog.Error("rotation failed, backing off", "err", err, "delay", delay.String())
		}
		if !sleepCtx(ctx, jitter(delay)) {
			return
		}
		delay = nextBackoff(delay)
	}
}

// Shutdown revokes the current lease so no orphan is left behind. Phase B3's
// exit gate checks for exactly this:
//
//	vault list sys/leases/lookup/database/creds/level3-app
func (l *leaseManager) Shutdown() {
	h := l.pools.current()
	if h == nil || h.cred == nil || h.cred.LeaseID == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := l.vc.RevokeLease(ctx, h.cred.LeaseID); err != nil {
		slog.Error("failed to revoke lease on shutdown — check for an orphan",
			"lease_id", h.cred.LeaseID, "username", h.cred.Username, "err", err)
		return
	}
	slog.Info("lease revoked on shutdown", "lease_id", h.cred.LeaseID, "username", h.cred.Username)
}

func nextBackoff(d time.Duration) time.Duration {
	if next := 2 * d; next < backoffCeiling {
		return next
	}
	return backoffCeiling
}

// jitter spreads retries so several pods do not stampede Vault in lockstep when
// it returns.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Millisecond
	}
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
