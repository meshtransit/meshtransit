package oidc

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

func TestPreAuthResponseCookieUsesConfirmedBoundedHostOnlyScope(t *testing.T) {
	t.Parallel()
	result, now := cookieStartResult(t)
	cookie, err := PreAuthResponseCookie(result, now)
	if err != nil {
		t.Fatal(err)
	}
	if cookie.Name != PreAuthCookieName || cookie.Value != result.PreAuthCookie().Encoded() ||
		cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("pre-auth cookie weakened host-only scope")
	}
	if cookie.MaxAge < 1 || cookie.MaxAge > 300 || cookie.Expires.After(result.Created().ExpiresAt()) ||
		now.Add(time.Duration(cookie.MaxAge)*time.Second).After(result.Created().ExpiresAt()) {
		t.Fatal("cookie outlives confirmed transaction")
	}
	if err := cookie.Valid(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		result oidcauth.StartResult
		now    time.Time
	}{
		{name: "unconfirmed creation", now: now},
		{name: "zero clock", result: result},
		{name: "backwards clock", result: result, now: now.Add(-time.Second)},
		{name: "expired", result: result, now: result.Created().ExpiresAt()},
		{name: "insufficient cookie precision", result: result, now: result.Created().ExpiresAt().Add(-time.Millisecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cookie, err := PreAuthResponseCookie(test.result, test.now)
			if !errors.Is(err, ErrPreAuthCookie) || cookie != nil {
				t.Fatal("unsafe start released cookie")
			}
		})
	}
	expired := ExpiredPreAuthCookie()
	if expired.Name != cookie.Name || expired.Domain != "" || expired.Path != cookie.Path ||
		!expired.Secure || !expired.HttpOnly || expired.SameSite != cookie.SameSite || expired.MaxAge != -1 || !expired.Expires.Before(now) {
		t.Fatal("expired cookie differs from host-only scope")
	}
}

func TestReadPreAuthCookieRejectsMissingAmbiguousAndUnboundedEvidence(t *testing.T) {
	t.Parallel()
	result, _ := cookieStartResult(t)
	value := result.PreAuthCookie().Encoded()
	pair := PreAuthCookieName + "=" + value
	for _, test := range []struct {
		name   string
		fields []string
		valid  bool
	}{
		{name: "one cookie", fields: []string{pair}, valid: true},
		{name: "unrelated cookies", fields: []string{"theme=dark; " + pair + "; locale=en"}, valid: true},
		{name: "split headers", fields: []string{"theme=dark", pair}, valid: true},
		{name: "missing", fields: []string{}},
		{name: "wrong name", fields: []string{"mt_pre_auth=" + value}},
		{name: "duplicate same header", fields: []string{pair + "; " + pair}},
		{name: "duplicate headers", fields: []string{pair, pair}},
		{name: "invalid first duplicate", fields: []string{PreAuthCookieName + "=bad", pair}},
		{name: "invalid second duplicate", fields: []string{pair, PreAuthCookieName + "=bad"}},
		{name: "quoted", fields: []string{PreAuthCookieName + `="` + value + `"`}},
		{name: "padding", fields: []string{pair + "="}},
		{name: "zero", fields: []string{PreAuthCookieName + "=" + strings.Repeat("A", 43)}},
		{name: "space before equals", fields: []string{PreAuthCookieName + " =" + value}},
		{name: "missing equals", fields: []string{PreAuthCookieName}},
		{name: "header injection", fields: []string{pair + "\r\nX-Test: bad"}},
		{name: "control character", fields: []string{"\v" + pair}},
		{name: "unicode whitespace", fields: []string{"\u2003" + pair}},
		{name: "oversized target", fields: []string{PreAuthCookieName + "=" + strings.Repeat("A", 8193)}},
		{name: "oversized unrelated", fields: []string{pair, "theme=" + strings.Repeat("A", 8193)}},
		{name: "too many headers", fields: []string{pair, "a=1", "a=2", "a=3", "a=4", "a=5", "a=6", "a=7", "a=8"}},
		{name: "too many pairs", fields: []string{pair + strings.Repeat("; a=1", 64)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ReadPreAuthCookie(http.Header{"Cookie": test.fields})
			if test.valid {
				if err != nil || got.Encoded() != value {
					t.Fatal("canonical cookie lost")
				}
				return
			}
			if !errors.Is(err, ErrPreAuthCookie) || got.IsValid() || strings.Contains(err.Error(), value) {
				t.Fatal("unsafe cookie accepted or disclosed")
			}
		})
	}
}

func FuzzReadPreAuthCookie(f *testing.F) {
	f.Add(PreAuthCookieName + "=" + strings.Repeat("A", 42) + "E")
	f.Add("")
	f.Fuzz(func(t *testing.T, field string) {
		got, err := ReadPreAuthCookie(http.Header{"Cookie": []string{field}})
		if err == nil && (!got.IsValid() || len(field) > maximumCookieHeaderBytes || len(got.Encoded()) != 43) {
			t.Fatal("unbounded or invalid handle accepted")
		}
	})
}

func cookieStartResult(t *testing.T) (oidcauth.StartResult, time.Time) {
	t.Helper()
	fixture := &cookieStartFixture{now: time.Date(2026, 9, 16, 1, 2, 3, 456789000, time.UTC)}
	keyID, err := oidcauth.NewDigestKeyID("cookie-test-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := oidcauth.NewDigestKey(keyID, bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cipherID, err := oidcauth.NewVerifierEncryptionKeyID("cookie-aead-v1")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherID, bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := oidcauth.NewStartService(oidcauth.StartOptions{
		RequestTimeout: time.Second, PendingLifetime: 5 * time.Minute, RollbackTimeout: time.Second, ResolveTimeout: time.Second,
	}, oidcauth.StartDependencies{
		Metadata: fixture, Transactions: fixture, Committed: fixture, CreationClock: fixture, Clock: fixture, Observer: fixture,
		IDs: oidcauth.SystemStartIDs{}, Secrets: oidcauth.SystemSecrets{}, DigestKey: key, VerifierCipher: cipher,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Start(t.Context(), discoveryRoute(t))
	if err != nil {
		t.Fatal(err)
	}
	return result, fixture.now
}

type cookieStartFixture struct{ now time.Time }

func (fixture *cookieStartFixture) CreationTime(ctx context.Context) (time.Time, error) {
	return fixture.now, ctx.Err()
}

func (fixture *cookieStartFixture) Now() time.Time                           { return fixture.now }
func (*cookieStartFixture) StartOpened()                                     {}
func (*cookieStartFixture) StartClosed(oidcauth.StartOutcome, time.Duration) {}
func (fixture *cookieStartFixture) Begin(context.Context, oidcauth.Route) (oidcauth.Transaction, error) {
	return fixture, nil
}
func (*cookieStartFixture) Create(_ context.Context, pending oidcauth.Pending) (oidcauth.Created, error) {
	return oidcauth.NewCreated(pending.TransactionID(), 1, pending.CreatedAt(), pending.ExpiresAt())
}
func (*cookieStartFixture) Commit(context.Context) error   { return nil }
func (*cookieStartFixture) Rollback(context.Context) error { return nil }
func (*cookieStartFixture) ResolveCommitted(context.Context, oidcauth.Pending) (oidcauth.Created, bool, error) {
	return oidcauth.Created{}, false, nil
}
func (*cookieStartFixture) Resolve(_ context.Context, route oidcauth.Route) (oidcauth.Metadata, error) {
	return oidcauth.NewMetadata(oidcauth.MetadataParams{
		Issuer: route.Issuer(), AuthorizationEndpoint: route.AuthorizationEndpoint(), TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(),
		ResponseTypes: []string{"code"}, CodeChallengeMethods: []string{"S256"}, IDTokenSigningAlgorithms: route.AllowedAlgorithms(), TokenAuthMethods: []string{route.ClientAuthMethod()},
	})
}
