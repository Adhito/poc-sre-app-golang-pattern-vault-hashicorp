// Authentication and credential acquisition, using the official SDK.
//
// Contrast with Level 2, which implements this handshake by hand in ~200 lines
// of net/http. Here it is:
//
//	auth, _ := kubernetes.NewKubernetesAuth(role)
//	client.Auth().Login(ctx, auth)
//
// That collapse is exactly why Level 2 forbids the SDK. Having written the
// handshake once, using it here is an informed choice rather than a shortcut
// (Stage B D3). Note that this file does NOT import Level 2 — the duplication
// between the two levels is deliberate (D2, CLAUDE.md rule 7).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

// dbCredential is one dynamically generated Postgres role.
//
// `password` is unexported on purpose: it cannot be reached by encoding/json,
// so no handler can serialise it into a response by accident. Everything else
// here is safe to expose — the username and lease ID are what make a rotation
// observable, and CLAUDE.md explicitly permits logging both.
//
// The lease deadline is mutable: renewal extends it. The lease manager writes
// it while HTTP handlers read it, so it lives behind a mutex rather than as a
// bare field. Accessing it directly would be a data race that shows up as
// nonsense TTLs on /creds-info under load, long before it shows up as a crash.
type dbCredential struct {
	Username string
	password string
	LeaseID  string
	IssuedAt time.Time

	mu            sync.RWMutex
	leaseDuration time.Duration
	expiresAt     time.Time
}

// lease returns the current duration and deadline as a consistent pair.
func (c *dbCredential) lease() (time.Duration, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.leaseDuration, c.expiresAt
}

// extend records a successful renewal.
func (c *dbCredential) extend(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaseDuration = ttl
	c.expiresAt = time.Now().UTC().Add(ttl)
}

func (c *dbCredential) expired() bool {
	if c == nil {
		return true
	}
	_, exp := c.lease()
	return !time.Now().Before(exp)
}

type vaultCreds struct {
	client    *api.Client
	role      string
	credsPath string

	mu     sync.Mutex
	logins int
}

func newVaultCreds(addr, caPath, role, credsPath string) (*vaultCreds, error) {
	cfg := api.DefaultConfig()
	cfg.Address = addr

	// Trust exactly the mounted CA. There is no InsecureSkipVerify path here —
	// a TLS failure means a missing SAN or an unmounted CA (CLAUDE.md rule 3).
	if err := cfg.ConfigureTLS(&api.TLSConfig{CACert: caPath}); err != nil {
		return nil, fmt.Errorf("configure TLS from %s: %w", caPath, err)
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}
	return &vaultCreds{client: client, role: role, credsPath: credsPath}, nil
}

// Login authenticates with the pod's ServiceAccount and stores the resulting
// token on the client. The SA token is read from the standard projected path by
// the auth helper.
func (v *vaultCreds) Login(ctx context.Context) error {
	k8s, err := auth.NewKubernetesAuth(v.role)
	if err != nil {
		return fmt.Errorf("build kubernetes auth for role %q: %w", v.role, err)
	}

	secret, err := v.client.Auth().Login(ctx, k8s)
	if err != nil {
		return fmt.Errorf("login as role %q: %w", v.role, err)
	}
	if secret == nil || secret.Auth == nil {
		return errors.New("login returned no auth data")
	}

	v.mu.Lock()
	v.logins++
	n := v.logins
	v.mu.Unlock()

	slog.Info("authenticated to vault",
		"role", v.role,
		"policies", secret.Auth.Policies,
		"token_ttl_s", secret.Auth.LeaseDuration,
		"accessor", secret.Auth.Accessor,
		"login_count", n)
	return nil
}

func (v *vaultCreds) loginCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.logins
}

// Fetch requests a fresh dynamic credential. Vault creates a new Postgres role
// on the fly and returns it under a lease; the role is dropped when that lease
// is revoked or expires.
func (v *vaultCreds) Fetch(ctx context.Context) (*dbCredential, error) {
	secret, err := v.client.Logical().ReadWithContext(ctx, v.credsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", v.credsPath, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("read %s: no credentials returned", v.credsPath)
	}

	username, _ := secret.Data["username"].(string)
	password, _ := secret.Data["password"].(string)
	if username == "" || password == "" {
		return nil, errors.New("credential response missing username or password")
	}

	now := time.Now().UTC()
	ttl := time.Duration(secret.LeaseDuration) * time.Second
	cred := &dbCredential{
		Username:      username,
		password:      password,
		LeaseID:       secret.LeaseID,
		IssuedAt:      now,
		leaseDuration: ttl,
		expiresAt:     now.Add(ttl),
	}

	// Username and lease ID, never the password. The username is the field that
	// makes a rotation visible from outside.
	slog.Info("issued dynamic database credential",
		"username", cred.Username,
		"lease_id", cred.LeaseID,
		"lease_duration_s", int(ttl.Seconds()),
		"password_len", len(password))
	return cred, nil
}

// RenewLease extends the lease. A refusal is expected and normal once max_ttl
// is reached — it is not a fault, it is the signal to rotate.
func (v *vaultCreds) RenewLease(ctx context.Context, leaseID string, increment int) (time.Duration, error) {
	secret, err := v.client.Sys().RenewWithContext(ctx, leaseID, increment)
	if err != nil {
		return 0, err
	}
	if secret == nil {
		return 0, errors.New("renew returned no lease data")
	}
	return time.Duration(secret.LeaseDuration) * time.Second, nil
}

// RevokeLease drops the Postgres role immediately. Called on SIGTERM and after
// a rotation drains, so no orphaned leases accumulate.
func (v *vaultCreds) RevokeLease(ctx context.Context, leaseID string) error {
	return v.client.Sys().RevokeWithContext(ctx, leaseID)
}

// vaultStatus classifies an error from Vault. A 403 means a policy decision
// that retrying will not change; a 400 on a lease usually means the lease is
// already gone. Both call for rotation rather than another renewal attempt.
// Anything else — a timeout, a refused connection, a 5xx — is Vault being
// unavailable, which is transient and should be backed off, not rotated on.
type vaultStatus int

const (
	vaultTransient vaultStatus = iota // retry with backoff
	vaultTerminal                     // stop renewing, rotate now
)

func classifyVaultError(err error) vaultStatus {
	if err == nil {
		return vaultTransient
	}
	var re *api.ResponseError
	if errors.As(err, &re) {
		switch {
		case re.StatusCode == 403, re.StatusCode == 401:
			return vaultTerminal
		case re.StatusCode == 400:
			// "lease not found" / "lease is not renewable" arrive as 400.
			return vaultTerminal
		}
	}
	return vaultTransient
}
