package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// newTestVault stands up a TLS server with a real certificate and returns a
// Client that trusts it through the same CA-file path the pod uses. No test
// shortcut around TLS — if the production path cannot verify, neither can this.
func newTestVault(t *testing.T, h http.Handler) (*httptest.Server, *Client) {
	t.Helper()

	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	jwtPath := filepath.Join(dir, "token")
	if err := os.WriteFile(jwtPath, []byte("fake.sa.jwt"), 0o600); err != nil {
		t.Fatalf("write SA token: %v", err)
	}

	c, err := NewClient(srv.URL, "level2-app", caPath)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.saTokenSrc = jwtPath
	return srv, c
}

func loginBody(ttl int) string {
	return `{"auth":{"client_token":"hvs.FAKE","accessor":"acc-123","lease_duration":` +
		itoa(ttl) + `,"renewable":true,"policies":["default","level2-reader"],` +
		`"metadata":{"service_account_name":"level2-app"}}}`
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestLoginAndKVv2DoubleNesting(t *testing.T) {
	_, c := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role"] != "level2-app" {
				t.Errorf("role = %q", body["role"])
			}
			if body["jwt"] != "fake.sa.jwt" {
				t.Errorf("jwt = %q", body["jwt"])
			}
			w.Write([]byte(loginBody(3600)))
		case "/v1/secret/data/level2/app":
			if got := r.Header.Get("X-Vault-Token"); got != "hvs.FAKE" {
				t.Errorf("X-Vault-Token = %q", got)
			}
			// The double nesting. KV v1 has one level; v2 has two.
			w.Write([]byte(`{"data":{"data":{"message":"fetched via direct k8s auth","tier":"gold"},` +
				`"metadata":{"version":3,"created_time":"2026-08-29T00:00:00Z"}}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	st := c.State()
	if st.token != "hvs.FAKE" || st.accessor != "acc-123" || !st.renewable {
		t.Fatalf("unexpected token state: %+v", st)
	}
	if len(st.policies) != 2 || st.policies[1] != "level2-reader" {
		t.Errorf("policies = %v", st.policies)
	}
	if ttl := time.Until(st.expiresAt); ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("expiresAt implies TTL %v, want ~1h", ttl)
	}

	data, version, err := c.ReadKV(ctx, "secret/data/level2/app")
	if err != nil {
		t.Fatalf("ReadKV: %v", err)
	}
	if data["message"] != "fetched via direct k8s auth" || data["tier"] != "gold" {
		t.Fatalf("unwrapped the wrong nesting level: %+v", data)
	}
	if version != 3 {
		t.Errorf("version = %d, want 3", version)
	}
}

// Injection 3: a token revoked out from under the app must not leave it
// permanently broken.
func TestReadKVReauthRecoversFromRevokedToken(t *testing.T) {
	var logins, reads atomic.Int32

	_, c := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			logins.Add(1)
			w.Write([]byte(loginBody(3600)))
		case "/v1/secret/data/level2/app":
			// First read fails as if the token had been revoked by accessor.
			if reads.Add(1) == 1 {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
			w.Write([]byte(`{"data":{"data":{"message":"ok"},"metadata":{"version":1}}}`))
		}
	}))

	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	data, _, err := c.ReadKVReauth(ctx, "secret/data/level2/app")
	if err != nil {
		t.Fatalf("ReadKVReauth: %v", err)
	}
	if data["message"] != "ok" {
		t.Errorf("data = %+v", data)
	}
	if got := logins.Load(); got != 2 {
		t.Errorf("login count = %d, want 2 (initial + re-auth)", got)
	}
}

// Injection 1: a role that lacks the policy stays denied. Re-authenticating
// cannot fix a policy decision, and the app must not loop trying.
func TestReadKVReauthGivesUpOnPersistentDenial(t *testing.T) {
	var logins atomic.Int32

	_, c := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == loginPath {
			logins.Add(1)
			w.Write([]byte(loginBody(3600)))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["1 error occurred:\n\t* permission denied\n"]}`))
	}))

	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	_, _, err := c.ReadKVReauth(ctx, "secret/data/level4/pgp")
	var ae *apiError
	if !errors.As(err, &ae) || ae.status != http.StatusForbidden {
		t.Fatalf("err = %v, want a 403 apiError", err)
	}
	if got := logins.Load(); got != 2 {
		t.Errorf("login count = %d, want exactly 2 — one retry, not a loop", got)
	}
}

// A transport-level or 5xx failure is not a permission problem and must not
// trigger re-authentication.
func TestReadKVReauthDoesNotReauthOnServerError(t *testing.T) {
	var logins atomic.Int32

	_, c := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == loginPath {
			logins.Add(1)
			w.Write([]byte(loginBody(3600)))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))

	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, _, err := c.ReadKVReauth(ctx, "secret/data/level2/app"); err == nil {
		t.Fatal("expected an error")
	}
	if got := logins.Load(); got != 1 {
		t.Errorf("login count = %d, want 1 — a 500 is not a credential problem", got)
	}
}

func TestRenewSelfExtendsTTLAndCounts(t *testing.T) {
	_, c := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			w.Write([]byte(loginBody(60)))
		case renewSelfPath:
			w.Write([]byte(loginBody(3600)))
		}
	}))

	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := c.RenewSelf(ctx); err != nil {
		t.Fatalf("RenewSelf: %v", err)
	}

	st := c.State()
	if st.renewals != 1 {
		t.Errorf("renewals = %d, want 1", st.renewals)
	}
	if ttl := time.Until(st.expiresAt); ttl < 59*time.Minute {
		t.Errorf("TTL after renew = %v, want ~1h", ttl)
	}
}

func TestTimeUntilRenewIsTwoThirdsOfTTL(t *testing.T) {
	c := &Client{}
	c.st = tokenState{token: "x", expiresAt: time.Now().Add(90 * time.Minute)}

	got := c.timeUntilRenew()
	if got < 59*time.Minute || got > 61*time.Minute {
		t.Errorf("timeUntilRenew = %v, want ~60m (2/3 of 90m)", got)
	}

	// An already-expired token renews immediately rather than never.
	c.st.expiresAt = time.Now().Add(-time.Minute)
	if got := c.timeUntilRenew(); got != minRenewWait {
		t.Errorf("expired token wait = %v, want %v", got, minRenewWait)
	}
}

// CLAUDE.md rule 3. This is cheap to assert and expensive to discover missing.
func TestTLSVerificationIsNeverDisabled(t *testing.T) {
	_, c := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is set")
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("no RootCAs — the mounted CA was not loaded")
	}
	if tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Errorf("MinVersion = %x, want >= TLS 1.2", tr.TLSClientConfig.MinVersion)
	}
}

func TestNewClientRejectsUnusableCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient("https://vault.vault.svc:8200", "level2-app", bad); err == nil {
		t.Fatal("expected an error for a CA file with no certificate")
	}
}
