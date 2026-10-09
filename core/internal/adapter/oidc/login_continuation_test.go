package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

func continuationGuardFixture(t testing.TB) (*LoginContinuationGuard, http.Header, time.Time) {
	t.Helper()
	params := loginRouteParams(discoveryRoute(t))
	params.RedirectURI = "https://console.example.test/auth/callback"
	route, err := oidcauth.NewRoute(params)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewLoginContinuationGuard(LoginContinuationOptions{
		Origin: "https://console.example.test", Route: route,
		KeyID: "continue-v1", KeyMaterial: bytes.Repeat([]byte{0x51}, 32), Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Guard checks cookie syntax only. AEAD authentication belongs to HTTP admission.
	headers := http.Header{"Cookie": {PreAuthCookieName + "=" +
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32)) + "; " +
		LoginCallbackCookieName + "=" + base64.RawURLEncoding.EncodeToString([]byte("synthetic-encrypted-input"))}}
	return guard, headers, time.Unix(1_800_000_000, 0).UTC()
}

func continuationProofHeaders(
	t testing.TB,
	guard *LoginContinuationGuard,
	headers http.Header,
	now time.Time,
) http.Header {
	t.Helper()
	proof, err := guard.Prepare(context.Background(), headers, now)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := proof.Token(now)
	if err != nil {
		t.Fatal(err)
	}
	result := headers.Clone()
	result.Set(LoginCSRFHeader, token)
	return result
}

func TestLoginContinuationGuardRejectsUnsafeConstruction(t *testing.T) {
	t.Parallel()
	guard, _, _ := continuationGuardFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*LoginContinuationOptions)
	}{
		{name: "missing key", mutate: func(o *LoginContinuationOptions) { o.KeyMaterial = nil }},
		{name: "zero key", mutate: func(o *LoginContinuationOptions) { o.KeyMaterial = make([]byte, 32) }},
		{name: "long key", mutate: func(o *LoginContinuationOptions) { o.KeyMaterial = make([]byte, 33) }},
		{name: "bad key id", mutate: func(o *LoginContinuationOptions) { o.KeyID = "bad key" }},
		{name: "insecure origin", mutate: func(o *LoginContinuationOptions) { o.Origin = "http://console.example.test" }},
		{name: "other origin", mutate: func(o *LoginContinuationOptions) { o.Origin = "https://other.example.test" }},
		{name: "query origin", mutate: func(o *LoginContinuationOptions) { o.Origin += "?x=y" }},
		{name: "short ttl", mutate: func(o *LoginContinuationOptions) { o.Lifetime = 29 * time.Second }},
		{name: "long ttl", mutate: func(o *LoginContinuationOptions) { o.Lifetime = 121 * time.Second }},
		{name: "fractional ttl", mutate: func(o *LoginContinuationOptions) { o.Lifetime += time.Nanosecond }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := LoginContinuationOptions{Origin: guard.Origin(), Route: guard.Route(),
				KeyID: "continue-v1", KeyMaterial: bytes.Repeat([]byte{0x51}, 32), Lifetime: time.Minute}
			test.mutate(&options)
			if result, err := NewLoginContinuationGuard(options); result != nil || !errors.Is(err, ErrLoginContinuation) {
				t.Fatal("unsafe continuation configuration accepted")
			}
		})
	}
}

func TestLoginContinuationGuardBindsCookiesTimeAndPurpose(t *testing.T) {
	t.Parallel()
	guard, headers, now := continuationGuardFixture(t)
	proof, err := guard.Prepare(t.Context(), headers, now.Add(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	token, remaining, err := proof.Token(now)
	if err != nil || remaining != 60 {
		t.Fatal("live proof was not released")
	}
	headers.Set(LoginCSRFHeader, token)
	if err := guard.Verify(headers, now); err != nil {
		t.Fatal("valid current continuation rejected")
	}
	// Repeated admission remains no-grant; durable claim must provide single use.
	if err := guard.Verify(headers, now.Add(time.Second)); err != nil {
		t.Fatal("no-grant repeated proof rejected")
	}
	clocks := []time.Time{{}, now.Add(-time.Second), now.Add(time.Minute), now.Add(59_500 * time.Millisecond)}
	for _, clock := range clocks {
		if _, _, err := proof.Token(clock); !errors.Is(err, ErrLoginContinuation) {
			t.Fatal("invalid response time released proof")
		}
	}
	if err := guard.Verify(headers, now.Add(time.Minute)); !errors.Is(err, ErrLoginContinuation) {
		t.Fatal("expiry equality admitted")
	}
	initiation, err := NewLoginInitiationGuard(LoginInitiationOptions{Origin: guard.Origin(), Route: guard.Route(),
		KeyID: "continue-v1", KeyMaterial: bytes.Repeat([]byte{0x51}, 32), Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	start, err := initiation.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	headers.Set(LoginCSRFHeader, start.Proof())
	if err := guard.Verify(headers, now); !errors.Is(err, ErrLoginContinuation) {
		t.Fatal("Start proof crossed continuation purpose")
	}
	if fmt.Sprint(proof) != "[REDACTED]" || fmt.Sprint(guard) != "[REDACTED]" ||
		strings.Contains(fmt.Sprintf("%#v", proof), token) {
		t.Fatal("proof/key formatting disclosed material")
	}
	if _, err := json.Marshal(proof); !errors.Is(err, ErrLoginContinuation) {
		t.Fatal("implicit proof serialization accepted")
	}
}

func TestLoginContinuationGuardRejectsAmbiguousAndChangedInput(t *testing.T) {
	t.Parallel()
	guard, original, now := continuationGuardFixture(t)
	headers := continuationProofHeaders(
		t,
		guard,
		original,
		now,
	)
	for _, test := range []struct {
		name   string
		mutate func(http.Header)
	}{
		{name: "missing proof", mutate: func(h http.Header) { h.Del(LoginCSRFHeader) }},
		{name: "duplicate proof", mutate: func(h http.Header) { h.Add(LoginCSRFHeader, h.Get(LoginCSRFHeader)) }},
		{name: "aliased proof", mutate: func(h http.Header) { h["x-meshtransit-csrf"] = []string{h.Get(LoginCSRFHeader)} }},
		{name: "aliased cookie", mutate: func(h http.Header) { h["cookie"] = []string{h.Get("Cookie")} }},
		{name: "duplicate cookie", mutate: func(h http.Header) { h.Add("Cookie", h.Get("Cookie")) }},
		{name: "missing cookie", mutate: func(h http.Header) { h.Del("Cookie") }},
		{name: "padded proof", mutate: func(h http.Header) { h.Set(LoginCSRFHeader, h.Get(LoginCSRFHeader)+"=") }},
		{name: "control proof", mutate: func(h http.Header) { h.Set(LoginCSRFHeader, "\r\n"+h.Get(LoginCSRFHeader)) }},
		{name: "oversized proof", mutate: func(h http.Header) { h.Set(LoginCSRFHeader, strings.Repeat("x", 8192)) }},
		{name: "changed capsule", mutate: func(h http.Header) { h.Set("Cookie", h.Get("Cookie")+"A") }},
		{name: "changed preauth", mutate: func(h http.Header) {
			h.Set("Cookie", strings.Replace(
				h.Get("Cookie"),
				base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32)),
				base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32)),
				1,
			))
		}},
		{name: "many pairs", mutate: func(h http.Header) { h.Add("Cookie", strings.Repeat("x=y;", 65)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := headers.Clone()
			test.mutate(input)
			if err := guard.Verify(input, now); !errors.Is(err, ErrLoginContinuation) {
				t.Fatal("ambiguous/substituted proof accepted")
			}
		})
	}
	decoded, err := base64.RawURLEncoding.DecodeString(headers.Get(LoginCSRFHeader))
	if err != nil {
		t.Fatal(err)
	}
	for index := range decoded {
		t.Run(fmt.Sprintf("tamper_%d", index), func(t *testing.T) {
			t.Parallel()
			mutated := bytes.Clone(decoded)
			mutated[index] ^= 1
			input := headers.Clone()
			input.Set(LoginCSRFHeader, base64.RawURLEncoding.EncodeToString(mutated))
			if err := guard.Verify(input, now); !errors.Is(err, ErrLoginContinuation) {
				t.Fatal("tampered proof accepted")
			}
		})
	}
}

func TestLoginContinuationGuardRejectsEntropyAndCancellation(t *testing.T) {
	t.Parallel()
	guard, headers, now := continuationGuardFixture(t)
	for _, entropy := range [][]byte{make([]byte, 32), bytes.Repeat([]byte{1}, 31)} {
		proof, err := guard.prepare(
			t.Context(),
			headers,
			now,
			bytes.NewReader(entropy),
		)
		if !errors.Is(err, ErrLoginContinuation) || proof != (LoginContinuationProof{}) {
			t.Fatal("bad entropy released proof")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if proof, err := guard.Prepare(ctx, headers, now); proof != (LoginContinuationProof{}) ||
		!errors.Is(err, ErrLoginContinuation) {
		t.Fatal("canceled preparation released proof")
	}
	var absent *LoginContinuationGuard
	if absent.IsValid() || absent.Verify(headers, now) == nil {
		t.Fatal("nil guard admitted")
	}
	if proof, err := absent.Prepare(t.Context(), headers, now); err == nil || proof != (LoginContinuationProof{}) {
		t.Fatal("nil guard generated proof")
	}
}

func TestLoginContinuationGuardOwnsKeysAndRejectsChangedRoute(t *testing.T) {
	t.Parallel()
	guard, headers, now := continuationGuardFixture(t)
	valid := continuationProofHeaders(
		t,
		guard,
		headers,
		now,
	)
	for _, test := range []struct {
		name   string
		mutate func(*oidcauth.RouteParams)
	}{
		{name: "generation", mutate: func(p *oidcauth.RouteParams) { p.ProviderGeneration++ }},
		{name: "epoch", mutate: func(p *oidcauth.RouteParams) { p.RecoveryEpoch++ }},
		{name: "issuer", mutate: func(p *oidcauth.RouteParams) { p.Issuer += "/other" }},
		{name: "discovery", mutate: func(p *oidcauth.RouteParams) { p.DiscoveryURI += "/other" }},
		{name: "authorization", mutate: func(p *oidcauth.RouteParams) { p.AuthorizationEndpoint += "/other" }},
		{name: "token", mutate: func(p *oidcauth.RouteParams) { p.TokenEndpoint += "/other" }},
		{name: "jwks", mutate: func(p *oidcauth.RouteParams) { p.JWKSURI += "/other" }},
		{name: "client", mutate: func(p *oidcauth.RouteParams) { p.OIDCClientID += "-other" }},
		{name: "connector", mutate: func(p *oidcauth.RouteParams) {
			p.ConnectorID = "other-connector"
			p.Scopes = append(p.Scopes, "federated:id")
		}},
		{name: "scopes", mutate: func(p *oidcauth.RouteParams) { p.Scopes = []string{"openid", "profile"} }},
		{name: "algorithms", mutate: func(p *oidcauth.RouteParams) { p.AllowedAlgorithms = []string{"RS256", "ES256"} }},
		{name: "redirect", mutate: func(p *oidcauth.RouteParams) { p.RedirectID += ".other" }},
		{name: "callback", mutate: func(p *oidcauth.RouteParams) { p.RedirectURI += "/other" }},
		{name: "return", mutate: func(p *oidcauth.RouteParams) { p.ReturnRouteID += ".other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := loginRouteParams(guard.Route())
			test.mutate(&params)
			route, err := oidcauth.NewRoute(params)
			if err != nil {
				t.Fatal(err)
			}
			other, err := NewLoginContinuationGuard(LoginContinuationOptions{Origin: guard.Origin(), Route: route,
				KeyID: "continue-v1", KeyMaterial: bytes.Repeat([]byte{0x51}, 32), Lifetime: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Verify(valid, now); !errors.Is(err, ErrLoginContinuation) {
				t.Fatal("changed full route accepted old proof")
			}
		})
	}
	for _, test := range []struct {
		name     string
		keyID    string
		material byte
		lifetime time.Duration
	}{
		{name: "id", keyID: "continue-v2", material: 0x51, lifetime: time.Minute},
		{name: "key", keyID: "continue-v1", material: 0x61, lifetime: time.Minute},
		{name: "ttl", keyID: "continue-v1", material: 0x51, lifetime: 30 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			other, err := NewLoginContinuationGuard(LoginContinuationOptions{Origin: guard.Origin(), Route: guard.Route(),
				KeyID: test.keyID, KeyMaterial: bytes.Repeat([]byte{test.material}, 32), Lifetime: test.lifetime})
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Verify(valid, now); !errors.Is(err, ErrLoginContinuation) {
				t.Fatal("changed key/ttl accepted old proof")
			}
		})
	}
	material := bytes.Repeat([]byte{0x51}, 32)
	copyGuard, err := NewLoginContinuationGuard(LoginContinuationOptions{Origin: guard.Origin(), Route: guard.Route(),
		KeyID: "continue-v1", KeyMaterial: material, Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clear(material)
	if err := copyGuard.Verify(valid, now); err != nil {
		t.Fatal("caller mutation changed resident key")
	}
	other := continuationProofHeaders(
		t,
		copyGuard,
		headers,
		now,
	)
	if other.Get(LoginCSRFHeader) == valid.Get(LoginCSRFHeader) {
		t.Fatal("independent preparations reused entropy")
	}
}

func TestLoginContinuationGuardRejectsAuthenticatedMalformedPayload(t *testing.T) {
	t.Parallel()
	guard, headers, now := continuationGuardFixture(t)
	valid := continuationProofHeaders(
		t,
		guard,
		headers,
		now,
	)
	payload, err := base64.RawURLEncoding.DecodeString(valid.Get(LoginCSRFHeader))
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := continuationCookies(headers)
	if err != nil {
		t.Fatal(err)
	}
	offset := 2 + len(guard.keyID)
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "zero issue", mutate: func(p []byte) { binary.BigEndian.PutUint64(p[offset:], 0) }},
		{name: "unsigned issue", mutate: func(p []byte) { binary.BigEndian.PutUint64(p[offset:], ^uint64(0)) }},
		{name: "unsigned expiry", mutate: func(p []byte) { binary.BigEndian.PutUint64(p[offset+8:], ^uint64(0)) }},
		{name: "wrong ttl", mutate: func(p []byte) { p[offset+15] ^= 1 }},
		{name: "zero challenge", mutate: func(p []byte) { clear(p[offset+16 : offset+48]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			mutated := bytes.Clone(payload)
			test.mutate(mutated)
			prefix := mutated[:len(mutated)-32]
			copy(mutated[len(prefix):], guard.mac(cookies, prefix))
			input := headers.Clone()
			input.Set(LoginCSRFHeader, base64.RawURLEncoding.EncodeToString(mutated))
			if err := guard.Verify(input, now); !errors.Is(err, ErrLoginContinuation) {
				t.Fatal("authenticated malformed payload accepted")
			}
		})
	}
}

func FuzzLoginContinuationProof(f *testing.F) {
	guard, headers, now := continuationGuardFixture(f)
	// Each fuzz subprocess rebuilds this fixture. Its seed must be identical to
	// the coordinator's; production Prepare and freshness tests still use OS entropy.
	proof, err := guard.prepare(
		f.Context(),
		headers,
		now,
		bytes.NewReader(bytes.Repeat([]byte{0x77}, 32)),
	)
	if err != nil {
		f.Fatal(err)
	}
	valid, _, err := proof.Token(now)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid, int64(0))
	f.Add("", int64(60))
	f.Add("AAAA", int64(-1))
	f.Fuzz(func(t *testing.T, token string, offset int64) {
		input := headers.Clone()
		input.Set(LoginCSRFHeader, token)
		clock := now.Add(time.Duration(offset%1_000_000) * time.Second)
		err := guard.Verify(input, clock)
		if err != nil && !errors.Is(err, ErrLoginContinuation) {
			t.Fatal("proof parser returned input-derived error")
		}
		if err == nil && (token != valid || clock.Before(now) || !clock.Before(now.Add(time.Minute))) {
			t.Fatal("fuzzed proof widened canonical live evidence")
		}
	})
}
