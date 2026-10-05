// The Kubernetes auth handshake, implemented with net/http and nothing else.
//
// This is exactly what ESO does on Level 1's behalf with role=eso, and exactly
// what hashicorp/vault/api's auth.NewKubernetesAuth() collapses into one line.
// Writing it out is the point of this level (Stage B D3).
//
//	pod                    Vault                  K8s API server
//	 │ 1. read own SA JWT   │                          │
//	 │ 2. POST auth/kubernetes/login {role, jwt} ─────►│
//	 │                      │ 3. TokenReview(jwt) ────►│
//	 │                      │◄── 4. {ns, sa name, uid} │
//	 │                      │ 5. match against the role's bound_service_account_*
//	 │◄─ 6. {client_token, lease_duration, renewable}  │
//	 │ 7. GET secret with X-Vault-Token ──────────────►│
//
// The pod never holds a Vault credential at rest. Its identity *is* its
// Kubernetes ServiceAccount.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// Step 1: the projected ServiceAccount token. The kubelet rotates this
	// roughly hourly, so it is re-read on every login rather than cached.
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	loginPath      = "/v1/auth/kubernetes/login"
	renewSelfPath  = "/v1/auth/token/renew-self"
	lookupSelfPath = "/v1/auth/token/lookup-self"
	requestTimeout = 10 * time.Second
	minRenewWait   = 5 * time.Second
	backoffBase    = 2 * time.Second
	backoffCeiling = 60 * time.Second
)

// apiError carries the HTTP status so callers can distinguish "you may not do
// this" (403 — a policy decision) from "I could not reach Vault" (a transport
// error). Level 3 makes the same distinction for Postgres, for the same reason.
type apiError struct {
	status int
	path   string
	errs   []string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("vault %s: status %d: %s", e.path, e.status, strings.Join(e.errs, "; "))
}

func (e *apiError) denied() bool {
	return e.status == http.StatusForbidden || e.status == http.StatusUnauthorized
}

// tokenState is everything we know about the current Vault token. The token
// value itself never leaves this struct except as a request header.
type tokenState struct {
	token           string
	renewable       bool
	policies        []string
	accessor        string
	authenticatedAt time.Time
	expiresAt       time.Time
	logins          int
	renewals        int
}

type Client struct {
	addr       string
	role       string
	saTokenSrc string
	hc         *http.Client

	mu sync.RWMutex
	st tokenState
}

// NewClient builds a client that trusts exactly one CA: the one mounted from
// the vault-ca ConfigMap. There is no InsecureSkipVerify path, not even behind
// a flag — a TLS failure here means a missing SAN or an unmounted CA, and the
// fix is upstream in Stage A Phase A2 (CLAUDE.md rule 3).
func NewClient(addr, role, caPath string) (*Client, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA %s contains no usable certificate", caPath)
	}

	return &Client{
		addr:       strings.TrimSuffix(addr, "/"),
		role:       role,
		saTokenSrc: saTokenPath,
		hc: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}, nil
}

func (c *Client) State() tokenState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.st
}

func (c *Client) Authenticated() bool {
	return c.State().token != ""
}

// do issues a request and decodes the JSON body into out. token is sent in the
// X-Vault-Token header when non-empty. Neither the token nor the response body
// is ever logged here.
func (c *Client) do(ctx context.Context, method, path, token string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, rdr)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var errBody struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &errBody)
		return &apiError{status: resp.StatusCode, path: path, errs: errBody.Errors}
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
}

// authResponse is the shape returned by both login and renew-self.
type authResponse struct {
	Auth struct {
		ClientToken   string            `json:"client_token"`
		Accessor      string            `json:"accessor"`
		LeaseDuration int               `json:"lease_duration"`
		Renewable     bool              `json:"renewable"`
		Policies      []string          `json:"policies"`
		Metadata      map[string]string `json:"metadata"`
	} `json:"auth"`
}

// Login performs steps 1–6. It re-reads the ServiceAccount token from disk each
// time: the projected token rotates, and a cached copy would work until it
// silently didn't.
func (c *Client) Login(ctx context.Context) error {
	jwt, err := os.ReadFile(c.saTokenSrc)
	if err != nil {
		return fmt.Errorf("read ServiceAccount token: %w", err)
	}

	var out authResponse
	err = c.do(ctx, http.MethodPost, loginPath, "", map[string]string{
		"jwt":  strings.TrimSpace(string(jwt)),
		"role": c.role,
	}, &out)
	if err != nil {
		return fmt.Errorf("login as role %q: %w", c.role, err)
	}
	if out.Auth.ClientToken == "" {
		return errors.New("login succeeded but returned no client_token")
	}

	now := time.Now().UTC()
	ttl := time.Duration(out.Auth.LeaseDuration) * time.Second

	c.mu.Lock()
	logins := c.st.logins + 1
	c.st = tokenState{
		token:           out.Auth.ClientToken,
		renewable:       out.Auth.Renewable,
		policies:        out.Auth.Policies,
		accessor:        out.Auth.Accessor,
		authenticatedAt: now,
		expiresAt:       now.Add(ttl),
		logins:          logins,
	}
	c.mu.Unlock()

	// Log the shape of the credential, never the credential. The accessor is
	// safe — it identifies the token for revocation but cannot be used as one.
	slog.Info("authenticated to vault",
		"role", c.role,
		"policies", out.Auth.Policies,
		"lease_duration_s", out.Auth.LeaseDuration,
		"renewable", out.Auth.Renewable,
		"accessor", out.Auth.Accessor,
		"service_account_name", out.Auth.Metadata["service_account_name"],
		"login_count", logins)
	return nil
}

// RenewSelf extends the current token's TTL. A refusal here is expected and
// normal once max_ttl is reached — it is not an error condition, it is the
// signal to re-authenticate.
func (c *Client) RenewSelf(ctx context.Context) error {
	st := c.State()
	if st.token == "" {
		return errors.New("no token to renew")
	}

	var out authResponse
	if err := c.do(ctx, http.MethodPost, renewSelfPath, st.token, nil, &out); err != nil {
		return err
	}

	ttl := time.Duration(out.Auth.LeaseDuration) * time.Second

	c.mu.Lock()
	c.st.expiresAt = time.Now().UTC().Add(ttl)
	c.st.renewable = out.Auth.Renewable
	c.st.renewals++
	renewals := c.st.renewals
	c.mu.Unlock()

	slog.Info("token renewed", "lease_duration_s", out.Auth.LeaseDuration, "renewal_count", renewals)
	return nil
}

// kvV2Response is the double-nested KV v2 shape. KV v1 has one level of `data`;
// v2 has two, plus metadata. Everyone hits this exactly once.
//
//	{"data": {"data": {...the secret...}, "metadata": {...}}}
type kvV2Response struct {
	Data struct {
		Data     map[string]any `json:"data"`
		Metadata struct {
			Version     int    `json:"version"`
			CreatedTime string `json:"created_time"`
		} `json:"metadata"`
	} `json:"data"`
}

// ReadKV performs step 7. path is the API path — `secret/data/level2/app`, not
// the CLI-visible `secret/level2/app`. A policy written against the latter
// denies everything, silently (Stage A Phase A6).
func (c *Client) ReadKV(ctx context.Context, path string) (map[string]any, int, error) {
	st := c.State()
	if st.token == "" {
		return nil, 0, errors.New("not authenticated")
	}

	var out kvV2Response
	if err := c.do(ctx, http.MethodGet, "/v1/"+strings.TrimPrefix(path, "/"), st.token, nil, &out); err != nil {
		return nil, 0, err
	}
	return out.Data.Data, out.Data.Metadata.Version, nil
}

// ReadKVReauth retries once through a fresh login when the read is denied. A
// token revoked out from under the app (Phase B2 injection 3) must not leave it
// permanently broken. A read denied because the *role* lacks the policy will
// still fail after re-authentication, which is correct — that is a policy
// decision, not a stale credential.
func (c *Client) ReadKVReauth(ctx context.Context, path string) (map[string]any, int, error) {
	data, version, err := c.ReadKV(ctx, path)
	if err == nil {
		return data, version, nil
	}

	var ae *apiError
	if !errors.As(err, &ae) || !ae.denied() {
		return nil, 0, err
	}

	slog.Warn("read denied, re-authenticating", "status", ae.status, "path", path)
	if lerr := c.Login(ctx); lerr != nil {
		return nil, 0, fmt.Errorf("read denied and re-authentication failed: %w", lerr)
	}
	return c.ReadKV(ctx, path)
}

// LookupSelf backs /token-info — the window for watching a TTL count down.
func (c *Client) LookupSelf(ctx context.Context) (map[string]any, error) {
	st := c.State()
	if st.token == "" {
		return nil, errors.New("not authenticated")
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, lookupSelfPath, st.token, nil, &out); err != nil {
		return nil, err
	}
	// display_name and policies are safe; the token id is not returned by
	// lookup-self, only its accessor.
	return out.Data, nil
}

// timeUntilRenew returns 2/3 of the remaining TTL. Two thirds leaves a full
// third for retries before expiry — enough headroom for a transient Vault
// outage, without renewing so aggressively that it masks a real problem.
func (c *Client) timeUntilRenew() time.Duration {
	st := c.State()
	if st.token == "" {
		return minRenewWait
	}
	remaining := time.Until(st.expiresAt)
	if remaining <= 0 {
		return minRenewWait
	}
	if wait := remaining * 2 / 3; wait > minRenewWait {
		return wait
	}
	return minRenewWait
}

// Maintain keeps the token alive for the life of the process.
//
// A token that cannot renew is not fatal. A token that cannot renew *and has no
// re-login path* is — and that is the state every implementation reaches the
// first time it hits max_ttl.
func (c *Client) Maintain(ctx context.Context) {
	for {
		if !sleepCtx(ctx, c.timeUntilRenew()) {
			return
		}

		if err := c.RenewSelf(ctx); err == nil {
			continue
		} else {
			slog.Warn("renew-self failed, falling back to re-authentication", "err", err)
		}

		delay := backoffBase
		for {
			if err := c.Login(ctx); err == nil {
				break
			} else {
				slog.Warn("re-authentication failed, backing off", "err", err, "delay", delay.String())
			}
			if !sleepCtx(ctx, jitter(delay)) {
				return
			}
			if delay = 2 * delay; delay > backoffCeiling {
				delay = backoffCeiling
			}
		}
	}
}

// sleepCtx reports false if the context ended before the delay elapsed.
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

// jitter spreads retries so that several pods do not stampede Vault in lockstep
// when it comes back up.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}
