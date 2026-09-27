package oidc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func initiationFixture(t testing.TB) (*LoginInitiationGuard, time.Time) {
	t.Helper()
	guard, err := NewLoginInitiationGuard(LoginInitiationOptions{
		Origin: "https://console.example.test", Route: discoveryRoute(t),
		KeyID: "login-init-v1", KeyMaterial: bytes.Repeat([]byte{0x31}, 32), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return guard, time.Date(2026, time.September, 16, 5, 0, 0, 0, time.UTC)
}

func initiationHeaders(t *testing.T, result LoginInitiation, now time.Time) http.Header {
	t.Helper()
	cookie, err := result.ResponseCookie(now)
	if err != nil {
		t.Fatal(err)
	}
	return http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}, LoginCSRFHeader: {result.Proof()}}
}

func TestLoginInitiationBindsPrivateCookieAndExpiry(t *testing.T) {
	t.Parallel()
	guard, now := initiationFixture(t)
	result, err := guard.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	headers := initiationHeaders(t, result, now)
	if err := guard.Verify(headers, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	cookie, err := result.ResponseCookie(now)
	if err != nil {
		t.Fatal(err)
	}
	if cookie.Name != LoginInitiationCookieName || cookie.Path != "/" || cookie.Domain != "" ||
		!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 300 {
		t.Fatal("unsafe initiation cookie attributes")
	}
	if strings.Contains(result.Proof(), cookie.Value) {
		t.Fatal("private pre-session handle entered JavaScript proof")
	}
	for _, clock := range []time.Time{{}, now.Add(-time.Second), now.Add(5 * time.Minute)} {
		if err := guard.Verify(headers, clock); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("invalid clock admitted proof")
		}
		if _, err := result.ResponseCookie(clock); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("invalid clock released cookie")
		}
	}
	if fmt.Sprint(result) != "[REDACTED]" || fmt.Sprint(guard) != "[REDACTED]" ||
		strings.Contains(fmt.Sprintf("%#v", result), cookie.Value) {
		t.Fatal("default formatting disclosed browser proof")
	}
}

func TestLoginInitiationRejectsMissingAmbiguousAndSubstitutedEvidence(t *testing.T) {
	t.Parallel()
	guard, now := initiationFixture(t)
	result, err := guard.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := guard.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(http.Header)
	}{
		{name: "missing cookie", mutate: func(h http.Header) { h.Del("Cookie") }},
		{name: "missing proof", mutate: func(h http.Header) { h.Del(LoginCSRFHeader) }},
		{name: "duplicate cookie", mutate: func(h http.Header) { h.Add("Cookie", h.Get("Cookie")) }},
		{name: "duplicate proof", mutate: func(h http.Header) { h.Add(LoginCSRFHeader, h.Get(LoginCSRFHeader)) }},
		{name: "quoted cookie", mutate: func(h http.Header) { h.Set("Cookie", LoginInitiationCookieName+"=\"invalid\"") }},
		{name: "padded proof", mutate: func(h http.Header) { h.Set(LoginCSRFHeader, result.Proof()+"=") }},
		{name: "other browser proof", mutate: func(h http.Header) { h.Set(LoginCSRFHeader, other.Proof()) }},
		{name: "oversized unrelated cookie", mutate: func(h http.Header) { h.Add("Cookie", "tracking="+strings.Repeat("x", 8192)) }},
		{name: "too many cookie pairs", mutate: func(h http.Header) { h.Add("Cookie", strings.Repeat("x=y;", 65)) }},
		{name: "control byte", mutate: func(h http.Header) { h.Add("Cookie", "x=\x00") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			headers := initiationHeaders(t, result, now)
			test.mutate(headers)
			if err := guard.Verify(headers, now); !errors.Is(err, ErrLoginInitiation) ||
				strings.Contains(err.Error(), result.Proof()) {
				t.Fatal("invalid browser evidence admitted or echoed")
			}
		})
	}
}

func TestLoginInitiationRejectsWrongOriginRouteAndKey(t *testing.T) {
	t.Parallel()
	guard, now := initiationFixture(t)
	result, err := guard.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*LoginInitiationOptions){
		func(o *LoginInitiationOptions) { o.Origin = "https://other.example.test" },
		func(o *LoginInitiationOptions) { o.KeyID = "login-init-v2" },
		func(o *LoginInitiationOptions) { o.KeyMaterial = bytes.Repeat([]byte{0x32}, 32) },
		func(o *LoginInitiationOptions) {
			params := loginRouteParams(o.Route)
			params.RecoveryEpoch++
			o.Route, err = oidcauth.NewRoute(params)
		},
		func(o *LoginInitiationOptions) {
			params := loginRouteParams(o.Route)
			params.ProviderGeneration++
			o.Route, err = oidcauth.NewRoute(params)
		},
		func(o *LoginInitiationOptions) {
			params := loginRouteParams(o.Route)
			params.ReturnRouteID = "workspace.other"
			o.Route, err = oidcauth.NewRoute(params)
		},
	} {
		options := LoginInitiationOptions{Origin: guard.Origin(), Route: guard.Route(),
			KeyID: "login-init-v1", KeyMaterial: bytes.Repeat([]byte{0x31}, 32), Lifetime: 5 * time.Minute}
		mutate(&options)
		if err != nil {
			t.Fatal(err)
		}
		other, err := NewLoginInitiationGuard(options)
		if err != nil {
			t.Fatal(err)
		}
		if err := other.Verify(initiationHeaders(t, result, now), now); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("substituted trust binding admitted proof")
		}
	}
}

func TestLoginInitiationRejectsBadEntropyAndAuthenticatedMalformedPayload(t *testing.T) {
	t.Parallel()
	guard, now := initiationFixture(t)
	for _, entropy := range [][]byte{make([]byte, 64), bytes.Repeat([]byte{1}, 63), bytes.Repeat([]byte{1}, 64)} {
		if _, err := guard.prepare(now, bytes.NewReader(entropy)); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("short, zero, or aliased entropy admitted")
		}
	}
	result, err := guard.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1, 2, len(result.payload) - 1} {
		payload := bytes.Clone(result.payload)
		payload[index] ^= 0xff
		headers := initiationHeaders(t, result, now)
		headers.Set(LoginCSRFHeader, base64.RawURLEncoding.EncodeToString(payload))
		if err := guard.Verify(headers, now); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("tampered payload admitted")
		}
	}
	for _, mutate := range []func([]byte){
		func(payload []byte) { payload[0] = 2 },
		func(payload []byte) { payload[1] = 0 },
		func(payload []byte) { clear(payload[2+len(guard.keyID)+16 : len(payload)-32]) },
		func(payload []byte) { copy(payload[2+len(guard.keyID)+16:], result.cookie[:]) },
		func(payload []byte) { payload[2+len(guard.keyID)] = 0xff },
	} {
		payload := bytes.Clone(result.payload)
		mutate(payload)
		prefix := payload[:len(payload)-32]
		copy(payload[len(prefix):], guard.mac(result.cookie, prefix))
		headers := initiationHeaders(t, result, now)
		headers.Set(LoginCSRFHeader, base64.RawURLEncoding.EncodeToString(payload))
		if err := guard.Verify(headers, now); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("authenticated malformed payload admitted")
		}
	}
}

func TestNewLoginInitiationRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	guard, _ := initiationFixture(t)
	for _, origin := range []string{"http://console.example.test", "https://console.example.test/", "https://console.example.test#",
		"https://console.example.test?", "https://user@console.example.test", "https://CONSOLE.example.test",
		"https://console.example.test:0", "https://console.example.test:65536", "https://console.example.test:",
		"https://console.example.test:0443", "https://console..example.test", "https://*.example.test"} {
		if _, err := NewLoginInitiationGuard(LoginInitiationOptions{Origin: origin, Route: guard.Route(),
			KeyID: "v1", KeyMaterial: bytes.Repeat([]byte{1}, 32), Lifetime: time.Minute}); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("unsafe origin admitted")
		}
	}
	for _, mutate := range []func(*LoginInitiationOptions){
		func(o *LoginInitiationOptions) { o.Route = oidcauth.Route{} },
		func(o *LoginInitiationOptions) { o.KeyID = "" },
		func(o *LoginInitiationOptions) { o.KeyMaterial = make([]byte, 32) },
		func(o *LoginInitiationOptions) { o.KeyMaterial = make([]byte, 31) },
		func(o *LoginInitiationOptions) { o.Lifetime = 59 * time.Second },
		func(o *LoginInitiationOptions) { o.Lifetime = 301 * time.Second },
		func(o *LoginInitiationOptions) { o.Lifetime = time.Minute + time.Nanosecond },
	} {
		options := LoginInitiationOptions{Origin: guard.Origin(), Route: guard.Route(), KeyID: "v1",
			KeyMaterial: bytes.Repeat([]byte{1}, 32), Lifetime: time.Minute}
		mutate(&options)
		if _, err := NewLoginInitiationGuard(options); !errors.Is(err, ErrLoginInitiation) {
			t.Fatal("unsafe proof configuration admitted")
		}
	}
	var absent *LoginInitiationGuard
	if err := absent.Verify(http.Header{}, time.Now()); !errors.Is(err, ErrLoginInitiation) {
		t.Fatal("nil guard admitted")
	}
}

func FuzzLoginInitiationVerify(f *testing.F) {
	f.Add("", "")
	f.Add("invalid", "x=y")
	guard, now := initiationFixture(f)
	prepared, err := guard.Prepare(now)
	if err != nil {
		f.Fatal(err)
	}
	cookie, err := prepared.ResponseCookie(now)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(prepared.Proof(), cookie.Name+"="+cookie.Value)
	f.Fuzz(func(t *testing.T, proof, cookie string) {
		err := guard.Verify(http.Header{LoginCSRFHeader: {proof}, "Cookie": {cookie}}, now)
		if err != nil && err.Error() != ErrLoginInitiation.Error() {
			t.Fatal("parser exposed input-derived failure")
		}
		if err == nil && !errors.Is(guard.Verify(http.Header{LoginCSRFHeader: {proof}, "Cookie": {cookie}}, now.Add(5*time.Minute)), ErrLoginInitiation) {
			t.Fatal("accepted proof outlived authenticated pre-session window")
		}
	})
}

func TestLoginInitiationFixesEveryConfiguredTrustDimension(t *testing.T) {
	t.Parallel()
	guard, now := initiationFixture(t)
	result, err := guard.Prepare(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*oidcauth.RouteParams)
	}{
		{name: "deployment", mutate: func(p *oidcauth.RouteParams) {
			value, err := deployment.ParseID("01890f00-0000-7000-8000-000000000009")
			if err != nil {
				t.Fatal(err)
			}
			p.DeploymentID = value
		}},
		{name: "workspace", mutate: func(p *oidcauth.RouteParams) {
			value, err := workspace.ParseID("01890f00-0000-7000-8000-000000000009")
			if err != nil {
				t.Fatal(err)
			}
			p.WorkspaceID = value
		}},
		{name: "provider", mutate: func(p *oidcauth.RouteParams) {
			value, err := oidcauth.ParseProviderID("01890f00-0000-7000-8000-000000000009")
			if err != nil {
				t.Fatal(err)
			}
			p.ProviderID = value
		}},
		{name: "client identity", mutate: func(p *oidcauth.RouteParams) {
			value, err := oidcauth.ParseClientID("01890f00-0000-7000-8000-000000000009")
			if err != nil {
				t.Fatal(err)
			}
			p.ClientID = value
		}},
		{name: "issuer", mutate: func(p *oidcauth.RouteParams) { p.Issuer = "https://other.example.test/issuer" }},
		{name: "discovery", mutate: func(p *oidcauth.RouteParams) { p.DiscoveryURI = "https://other.example.test/discovery" }},
		{name: "authorization endpoint", mutate: func(p *oidcauth.RouteParams) { p.AuthorizationEndpoint = "https://other.example.test/auth" }},
		{name: "token endpoint", mutate: func(p *oidcauth.RouteParams) { p.TokenEndpoint = "https://other.example.test/token" }},
		{name: "jwks", mutate: func(p *oidcauth.RouteParams) { p.JWKSURI = "https://other.example.test/certs" }},
		{name: "client id", mutate: func(p *oidcauth.RouteParams) { p.OIDCClientID = "other-console" }},
		{name: "connector", mutate: func(p *oidcauth.RouteParams) {
			p.ConnectorID = "other-connector"
			p.Scopes = append(p.Scopes, "federated:id")
		}},
		{name: "client authentication", mutate: func(p *oidcauth.RouteParams) { p.ClientAuthMethod = "private_key_jwt" }},
		{name: "scopes", mutate: func(p *oidcauth.RouteParams) { p.Scopes = []string{"openid", "email"} }},
		{name: "algorithms", mutate: func(p *oidcauth.RouteParams) { p.AllowedAlgorithms = []string{"ES256"} }},
		{name: "redirect id", mutate: func(p *oidcauth.RouteParams) { p.RedirectID = "other.callback" }},
		{name: "redirect uri", mutate: func(p *oidcauth.RouteParams) { p.RedirectURI = "https://other.example.test/callback" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := loginRouteParams(guard.Route())
			test.mutate(&params)
			route, err := oidcauth.NewRoute(params)
			if err != nil {
				t.Fatal(err)
			}
			other, err := NewLoginInitiationGuard(LoginInitiationOptions{Origin: guard.Origin(), Route: route,
				KeyID: "login-init-v1", KeyMaterial: bytes.Repeat([]byte{0x31}, 32), Lifetime: 5 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Verify(initiationHeaders(t, result, now), now); !errors.Is(err, ErrLoginInitiation) {
				t.Fatal("changed trust dimension admitted")
			}
		})
	}
	key := bytes.Repeat([]byte{0x31}, 32)
	replica, err := NewLoginInitiationGuard(LoginInitiationOptions{Origin: guard.Origin(), Route: guard.Route(),
		KeyID: "login-init-v1", KeyMaterial: key, Lifetime: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if err := replica.Verify(initiationHeaders(t, result, now), now); err != nil {
		t.Fatal("independent replica lost resident key or binding")
	}
}
