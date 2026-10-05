package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDSNEscapesCredentialsAndRoundTrips(t *testing.T) {
	// Vault-generated passwords contain characters that are structural in a
	// URL. Getting this wrong produces an authentication failure that looks
	// like a Vault problem and is actually a string-building problem.
	cred := &dbCredential{
		Username: "v-kubernet-level3-a-Xy7@z",
		password: "p@ss:w/rd?#&=+ ",
	}
	target := dbTarget{host: "postgres.poc-hashicorp-vault-application.svc", port: "5432", database: "appdb", sslmode: "disable"}

	dsn := target.dsn(cred)

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgx could not parse the DSN we built: %v", err)
	}
	if cfg.ConnConfig.User != cred.Username {
		t.Errorf("user = %q, want %q", cfg.ConnConfig.User, cred.Username)
	}
	if cfg.ConnConfig.Password != cred.password {
		t.Errorf("password did not round-trip through URL escaping")
	}
	if cfg.ConnConfig.Database != "appdb" {
		t.Errorf("database = %q", cfg.ConnConfig.Database)
	}
}

// The password must not be reachable by encoding/json, so no handler can
// serialise a credential into a response by accident.
func TestPasswordIsNotSerialisable(t *testing.T) {
	cred := &dbCredential{Username: "v-kubernet-x", password: "super-secret-value", LeaseID: "database/creds/level3-app/abc"}

	b, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "super-secret-value") {
		t.Fatalf("credential serialised its password: %s", b)
	}
	if !strings.Contains(string(b), "v-kubernet-x") {
		t.Errorf("username should be visible — it is how a rotation is observed: %s", b)
	}
}

func TestClassifyQueryErrorSeparatesTheTwoOutages(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want queryFault
	}{
		{"no error", nil, faultNone},
		// The role was dropped out from under us — this is what a revoked
		// lease looks like from the database side. Rotate.
		{"invalid password", &pgconn.PgError{Code: "28P01"}, faultCredentials},
		{"invalid authorization", &pgconn.PgError{Code: "28000"}, faultCredentials},
		// Postgres is up but unhappy. Not a credential problem.
		{"invalid catalog", &pgconn.PgError{Code: "3D000"}, faultDatabase},
		{"cannot connect now", &pgconn.PgError{Code: "57P03"}, faultDatabase},
		{"undefined table", &pgconn.PgError{Code: "42P01"}, faultDatabase},
		// Postgres is unreachable. Re-authenticating against Vault would burn a
		// credential and change nothing — Phase B3 test 7.
		{"dial failure", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, faultDatabase},
		{"plain error", errors.New("context deadline exceeded"), faultDatabase},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyQueryError(c.err); got != c.want {
				t.Errorf("classifyQueryError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestClassifyVaultErrorStopsRetryingTerminalFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want vaultStatus
	}{
		// max_ttl reached, or the lease is gone: asking again cannot help.
		{"400 lease not renewable", &api.ResponseError{StatusCode: http.StatusBadRequest}, vaultTerminal},
		{"403 permission denied", &api.ResponseError{StatusCode: http.StatusForbidden}, vaultTerminal},
		{"401 unauthorized", &api.ResponseError{StatusCode: http.StatusUnauthorized}, vaultTerminal},
		// Vault is unavailable: back off, keep the still-valid credential.
		{"500", &api.ResponseError{StatusCode: http.StatusInternalServerError}, vaultTransient},
		{"503 sealed", &api.ResponseError{StatusCode: http.StatusServiceUnavailable}, vaultTransient},
		{"transport error", errors.New("connection refused"), vaultTransient},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyVaultError(c.err); got != c.want {
				t.Errorf("classifyVaultError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestTimeUntilRenewIsTwoThirdsOfRemaining(t *testing.T) {
	pools := newPoolManager(dbTarget{}, time.Second)
	l := newLeaseManager(nil, pools)

	// No pool yet: renew soon rather than never.
	if got := l.timeUntilRenew(); got != minRenewWait {
		t.Errorf("with no pool = %v, want %v", got, minRenewWait)
	}

	cred := &dbCredential{}
	cred.extend(time.Hour)
	pools.cur = &poolHandle{cred: cred}

	got := l.timeUntilRenew()
	if got < 39*time.Minute || got > 41*time.Minute {
		t.Errorf("timeUntilRenew = %v, want ~40m (2/3 of 1h)", got)
	}

	// An expired lease renews immediately, not never.
	cred.extend(-time.Minute)
	if got := l.timeUntilRenew(); got != minRenewWait {
		t.Errorf("expired = %v, want %v", got, minRenewWait)
	}
}

// The lease deadline is written by the lease manager and read by handlers.
// Run with -race: an unguarded field here produces nonsense TTLs under load
// long before it produces a crash.
func TestLeaseDeadlineIsRaceFree(t *testing.T) {
	cred := &dbCredential{Username: "v-kubernet-x"}
	cred.extend(time.Hour)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			cred.extend(time.Duration(i) * time.Second)
		}
	}()
	for i := 0; i < 2000; i++ {
		_, _ = cred.lease()
		_ = cred.expired()
	}
	<-done
}

func TestCredentialExpiry(t *testing.T) {
	var nilCred *dbCredential
	if !nilCred.expired() {
		t.Error("a nil credential must count as expired — /readyz depends on it")
	}
	live := &dbCredential{}
	live.extend(time.Minute)
	if live.expired() {
		t.Error("a live credential reported expired")
	}

	lapsed := &dbCredential{}
	lapsed.extend(-time.Second)
	if !lapsed.expired() {
		t.Error("a lapsed credential reported live")
	}
}

// Several failing queries during one outage must produce one rotation, not one
// per request.
func TestRequestRotationCoalesces(t *testing.T) {
	l := newLeaseManager(nil, newPoolManager(dbTarget{}, time.Second))

	for i := 0; i < 50; i++ {
		l.requestRotation() // must never block
	}

	select {
	case <-l.rotateNow:
	default:
		t.Fatal("no rotation was queued")
	}
	select {
	case <-l.rotateNow:
		t.Fatal("more than one rotation queued — requests did not coalesce")
	default:
	}
}

func TestBackoffIsBoundedAndJittered(t *testing.T) {
	d := backoffBase
	for i := 0; i < 20; i++ {
		d = nextBackoff(d)
	}
	if d > backoffCeiling {
		t.Errorf("backoff grew past its ceiling: %v > %v", d, backoffCeiling)
	}

	for i := 0; i < 100; i++ {
		j := jitter(10 * time.Second)
		if j < 5*time.Second || j >= 15*time.Second {
			t.Fatalf("jitter(10s) = %v, outside [5s,15s)", j)
		}
	}
	if jitter(0) <= 0 {
		t.Error("jitter(0) must still be positive — a zero timer would spin")
	}
}

func TestPoolManagerCountsRotationsNotFirstInstall(t *testing.T) {
	m := newPoolManager(dbTarget{}, time.Second)

	// The first pool is an install, not a rotation.
	m.swap(&poolHandle{cred: &dbCredential{Username: "v-one"}})
	if got := m.rotationCount(); got != 0 {
		t.Errorf("rotation count after first install = %d, want 0", got)
	}
	if cur := m.current(); cur == nil || cur.cred.Username != "v-one" {
		t.Fatal("first pool not installed")
	}
}
