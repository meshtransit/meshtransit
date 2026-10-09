package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/adapter/oidc"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestLoginCallbackCapsuleRejectsUnsafeConstruction(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	var absent *noopCallbackCapsuleObserver
	for _, test := range []struct {
		name   string
		mutate func(*LoginCallbackCapsuleOptions)
	}{
		{name: "route", mutate: func(o *LoginCallbackCapsuleOptions) { o.Route = oidcauth.Route{} }},
		{name: "key ID", mutate: func(o *LoginCallbackCapsuleOptions) { o.KeyID = "" }},
		{name: "zero key", mutate: func(o *LoginCallbackCapsuleOptions) { o.KeyMaterial = make([]byte, 32) }},
		{name: "short key", mutate: func(o *LoginCallbackCapsuleOptions) { o.KeyMaterial = make([]byte, 31) }},
		{name: "missing observer", mutate: func(o *LoginCallbackCapsuleOptions) { o.Observer = nil }},
		{name: "typed nil observer", mutate: func(o *LoginCallbackCapsuleOptions) { o.Observer = absent }},
		{name: "short lifetime", mutate: func(o *LoginCallbackCapsuleOptions) { o.Lifetime = 29 * time.Second }},
		{name: "long lifetime", mutate: func(o *LoginCallbackCapsuleOptions) { o.Lifetime = 121 * time.Second }},
		{name: "fractional lifetime", mutate: func(o *LoginCallbackCapsuleOptions) { o.Lifetime = 60*time.Second + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := capsuleTestOptions(fixture.input.Route())
			test.mutate(&options)
			codec, err := NewLoginCallbackCapsuleCodec(options)
			if !errors.Is(err, ErrInvalidLoginCapsule) || codec != nil {
				t.Fatal("unsafe codec accepted")
			}
		})
	}
	var missing *LoginCallbackCapsuleCodec
	for _, codec := range []*LoginCallbackCapsuleCodec{missing, {}, {observer: noopCallbackCapsuleObserver{}}} {
		if capture, err := codec.Capture(t.Context(), fixture.input, fixture.now); err == nil || capture.value != "" {
			t.Fatal("zero codec released capture")
		}
		if input, err := codec.Open(t.Context(), fixture.headers, fixture.now); err == nil || input.IsValid() {
			t.Fatal("zero codec released input")
		}
	}
}

func TestLoginCallbackCapsuleRoundTripAndCleanRedirect(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	capture, err := fixture.codec.Capture(t.Context(), fixture.input, fixture.now)
	if err != nil {
		t.Fatal("capture rejected valid syntax", err)
	}
	response := httptest.NewRecorder()
	if err := capture.WriteRedirect(t.Context(), response, fixture.now); err != nil {
		t.Fatal("live capture did not redirect", err)
	}
	if response.Code != http.StatusSeeOther || response.Body.Len() != 0 ||
		response.Header().Get("Location") != LoginCallbackContinuePath {
		t.Fatal("capture did not release a fixed clean zero-body 303")
	}
	for name, want := range map[string]string{
		"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
		"X-Frame-Options": "DENY", "Content-Length": "0",
	} {
		if response.Header().Get(name) != want {
			t.Fatal("capture lost security header", name)
		}
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("capture permits active content")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != oidc.LoginCallbackCookieName || !cookies[0].HttpOnly ||
		!cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" ||
		cookies[0].Domain != "" || cookies[0].MaxAge != 60 || len(response.Header().Get("Set-Cookie")) >= 4096 {
		t.Fatal("capture cookie scope or size widened")
	}
	headers := fixture.headers.Clone()
	headers.Add("Cookie", cookies[0].Name+"="+cookies[0].Value)
	for range 2 {
		opened, err := fixture.codec.Open(t.Context(), headers, fixture.now)
		if err != nil || !opened.IsValid() || opened.Kind() != fixture.input.Kind() ||
			opened.State().Encoded() != fixture.input.State().Encoded() ||
			opened.Code().Encoded() != fixture.input.Code().Encoded() {
			t.Fatal("capsule did not recover exact untrusted input", err)
		}
	}
}

func TestLoginCallbackCapsuleProviderErrorAndCodeBudget(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	for _, test := range []struct {
		name          string
		code          string
		providerError bool
		accepted      bool
	}{
		{name: "generic error", providerError: true, accepted: true},
		{name: "code maximum", code: strings.Repeat("c", 2048), accepted: true},
		{name: "code too long", code: strings.Repeat("c", 2049)},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := callbackReaderRequest(t.Context(), fixture.input.Route())
			query, err := url.ParseQuery(request.URL.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			query.Set("code", test.code)
			if test.providerError {
				query.Del("code")
				query.Set("error", "access_denied")
				query.Set("error_description", "private-upstream-diagnostic")
			}
			setCallbackQuery(request, query.Encode())
			input, err := mustCallbackReader(t, fixture.input.Route(), &callbackReaderObserver{}).Read(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			capture, err := fixture.codec.Capture(t.Context(), input, fixture.now)
			if !test.accepted {
				if !errors.Is(err, ErrInvalidLoginCapsule) || capture.value != "" {
					t.Fatal("oversized code captured")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			headers := capsuleHeaders(fixture.headers, capture.value)
			opened, err := fixture.codec.Open(t.Context(), headers, fixture.now)
			if err != nil || opened.Kind() != input.Kind() || opened.Code().Encoded() != input.Code().Encoded() {
				t.Fatal("variant changed", err)
			}
			assertCapsuleRedacted(t, fixture.codec, capture)
		})
	}
}

func TestLoginCallbackCapsuleRejectsEveryByteTamperAndCookieAmbiguity(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	capture, err := fixture.codec.Capture(t.Context(), fixture.input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(capture.value)
	if err != nil {
		t.Fatal(err)
	}
	for index := range envelope {
		t.Run(fmt.Sprintf("tamper byte %d", index), func(t *testing.T) {
			t.Parallel()
			changed := bytes.Clone(envelope)
			changed[index] ^= 1
			input, err := fixture.codec.Open(t.Context(), capsuleHeaders(fixture.headers,
				base64.RawURLEncoding.EncodeToString(changed)), fixture.now)
			if !errors.Is(err, ErrInvalidLoginCapsule) || input.IsValid() {
				t.Fatal("tampered envelope released input")
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(http.Header)
	}{
		{name: "missing capture", mutate: func(h http.Header) { h["Cookie"] = fixture.headers["Cookie"] }},
		{name: "duplicate capture", mutate: func(h http.Header) {
			h.Add("Cookie", oidc.LoginCallbackCookieName+"="+capture.value)
		}},
		{name: "quoted capture", mutate: func(h http.Header) {
			h["Cookie"][1] = oidc.LoginCallbackCookieName + "=\"" + capture.value + "\""
		}},
		{name: "missing binding cookie", mutate: func(h http.Header) { h["Cookie"] = h["Cookie"][1:] }},
		{name: "replaced binding cookie", mutate: func(h http.Header) {
			h["Cookie"][0] = oidc.PreAuthCookieName + "=" + callbackReaderHandle(0x67)
		}},
		{name: "header alias", mutate: func(h http.Header) { h["cookie"] = h["Cookie"] }},
		{name: "padded base64", mutate: func(h http.Header) { h["Cookie"][1] += "=" }},
		{name: "trailing newline", mutate: func(h http.Header) { h["Cookie"][1] += "\n" }},
		{name: "value overflow", mutate: func(h http.Header) {
			h["Cookie"][1] = oidc.LoginCallbackCookieName + "=" + strings.Repeat("A", 3801)
		}},
		{name: "pair overflow", mutate: func(h http.Header) { h.Add("Cookie", strings.Repeat("a=b;", 65)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			headers := capsuleHeaders(fixture.headers, capture.value)
			test.mutate(headers)
			input, err := fixture.codec.Open(t.Context(), headers, fixture.now)
			if !errors.Is(err, ErrInvalidLoginCapsule) || input.IsValid() {
				t.Fatal("ambiguous cookie released input")
			}
		})
	}
}

func TestLoginCallbackCapsuleBindsEveryRouteDimensionAndKey(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	did, err := deployment.ParseID("01890f00-0000-7000-8000-000000000041")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := oidcauth.ParseProviderID("01890f00-0000-7000-8000-000000000043")
	if err != nil {
		t.Fatal(err)
	}
	cid, err := oidcauth.ParseClientID("01890f00-0000-7000-8000-000000000044")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := fixture.codec.Capture(t.Context(), fixture.input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*oidcauth.RouteParams)
	}{
		{name: "Deployment", mutate: func(p *oidcauth.RouteParams) { p.DeploymentID = did }},
		{name: "provider", mutate: func(p *oidcauth.RouteParams) { p.ProviderID = pid }},
		{name: "client", mutate: func(p *oidcauth.RouteParams) { p.ClientID = cid }},
		{name: "provider generation", mutate: func(p *oidcauth.RouteParams) { p.ProviderGeneration++ }},
		{name: "recovery epoch", mutate: func(p *oidcauth.RouteParams) { p.RecoveryEpoch++ }},
		{name: "issuer", mutate: func(p *oidcauth.RouteParams) { p.Issuer += "/new" }},
		{name: "discovery", mutate: func(p *oidcauth.RouteParams) { p.DiscoveryURI += "/new" }},
		{name: "authorization", mutate: func(p *oidcauth.RouteParams) { p.AuthorizationEndpoint += "/new" }},
		{name: "token", mutate: func(p *oidcauth.RouteParams) { p.TokenEndpoint += "/new" }},
		{name: "JWKS", mutate: func(p *oidcauth.RouteParams) { p.JWKSURI += "/new" }},
		{name: "OIDC client", mutate: func(p *oidcauth.RouteParams) { p.OIDCClientID += "-new" }},
		{name: "connector", mutate: func(p *oidcauth.RouteParams) {
			p.ConnectorID = "other-connector"
			p.Scopes = append(p.Scopes, "federated:id")
		}},
		{name: "client auth", mutate: func(p *oidcauth.RouteParams) { p.ClientAuthMethod = "private_key_jwt" }},
		{name: "scopes", mutate: func(p *oidcauth.RouteParams) { p.Scopes = append(p.Scopes, "new-scope") }},
		{name: "algorithms", mutate: func(p *oidcauth.RouteParams) { p.AllowedAlgorithms = []string{"ES256"} }},
		{name: "redirect ID", mutate: func(p *oidcauth.RouteParams) { p.RedirectID += ".new" }},
		{name: "redirect URI", mutate: func(p *oidcauth.RouteParams) { p.RedirectURI += "/new" }},
		{name: "return route", mutate: func(p *oidcauth.RouteParams) { p.ReturnRouteID += ".new" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := capsuleTestRouteParams(fixture.input.Route())
			test.mutate(&params)
			route, err := oidcauth.NewRoute(params)
			if err != nil {
				t.Fatal(err)
			}
			codec, err := NewLoginCallbackCapsuleCodec(capsuleTestOptions(route))
			if err != nil {
				t.Fatal(err)
			}
			input, err := codec.Open(t.Context(), capsuleHeaders(fixture.headers, capture.value), fixture.now)
			if err == nil || input.IsValid() {
				t.Fatal("changed route opened input")
			}
			if got, err := codec.Capture(t.Context(), fixture.input, fixture.now); err == nil || got.value != "" {
				t.Fatal("foreign route captured")
			}
		})
	}
	for _, change := range []string{"key ID", "key material", "lifetime"} {
		t.Run(change, func(t *testing.T) {
			options := capsuleTestOptions(fixture.input.Route())
			switch change {
			case "key ID":
				options.KeyID += "-next"
			case "key material":
				options.KeyMaterial[0] ^= 1
			case "lifetime":
				options.Lifetime = 30 * time.Second
			}
			codec, err := NewLoginCallbackCapsuleCodec(options)
			if err != nil {
				t.Fatal(err)
			}
			input, err := codec.Open(t.Context(), capsuleHeaders(fixture.headers, capture.value), fixture.now)
			if err == nil || input.IsValid() {
				t.Fatal("changed key/lifetime opened capture")
			}
		})
	}
}

func TestLoginCallbackCapsuleRejectsAuthenticatedMalformedPayload(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	codeLength := len(fixture.input.Code().Encoded())
	if codeLength > maximumCapsuleCodeBytes {
		t.Fatal("invalid fixture bounds")
		return
	}
	issuedSeconds, expiresSeconds := fixture.now.Unix(), fixture.now.Add(time.Minute).Unix()
	if issuedSeconds <= 0 || expiresSeconds <= 0 {
		t.Fatal("invalid fixture time")
		return
	}
	payload := make([]byte, callbackCapsuleFixedBytes+codeLength)
	binary.BigEndian.PutUint64(payload, uint64(issuedSeconds))
	binary.BigEndian.PutUint64(payload[8:], uint64(expiresSeconds))
	payload[16] = byte(LoginCallbackCodeReceived)
	copy(payload[17:60], fixture.input.State().Encoded())
	binary.BigEndian.PutUint16(payload[60:], uint16(codeLength))
	copy(payload[62:], fixture.input.Code().Encoded())
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "truncated", mutate: func(p []byte) []byte { return p[:61] }},
		{name: "trailing", mutate: func(p []byte) []byte { return append(p, 0) }},
		{name: "unknown kind", mutate: func(p []byte) []byte { p[16] = 255; return p }},
		{name: "zero issued", mutate: func(p []byte) []byte { clear(p[:8]); return p }},
		{name: "overflow expiry", mutate: func(p []byte) []byte { binary.BigEndian.PutUint64(p[8:], ^uint64(0)); return p }},
		{name: "wrong TTL", mutate: func(p []byte) []byte { p[15] ^= 1; return p }},
		{name: "invalid state", mutate: func(p []byte) []byte { p[17] = '!'; return p }},
		{name: "invalid code", mutate: func(p []byte) []byte { p[62] = 0; return p }},
		{name: "empty code", mutate: func(p []byte) []byte { clear(p[60:62]); return p[:62] }},
		{name: "error with code", mutate: func(p []byte) []byte {
			p[16] = byte(LoginCallbackProviderErrorReceived)
			return p
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyLength := len(fixture.codec.keyID)
			if keyLength < 1 || keyLength > 128 {
				t.Fatal("invalid fixture key ID")
				return
			}
			prefix := append([]byte{1, byte(keyLength)}, fixture.codec.keyID...)
			nonce := bytes.Repeat([]byte{0x33}, 12) // synthetic test-only entropy, never production
			envelope := append(bytes.Clone(prefix), nonce...)
			sealed := fixture.codec.aead.Seal(
				envelope,
				nonce,
				test.mutate(bytes.Clone(payload)),
				fixture.codec.additionalData(prefix, fixture.input.PreAuthCookie()),
			)
			input, err := fixture.codec.Open(t.Context(), capsuleHeaders(fixture.headers,
				base64.RawURLEncoding.EncodeToString(sealed)), fixture.now)
			if !errors.Is(err, ErrInvalidLoginCapsule) || input.IsValid() {
				t.Fatal("malformed authenticated payload released input")
			}
		})
	}
}

func TestLoginCallbackCapsuleEntropyCancellationAndOwnership(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	for _, entropy := range []io.Reader{bytes.NewReader([]byte{1}), capsuleFailingEntropy{}, nil} {
		capture, err := fixture.codec.capture(
			t.Context(),
			fixture.input,
			fixture.now,
			entropy,
		)
		if err == nil || capture.value != "" || strings.Contains(err.Error(), "private-entropy-detail") {
			t.Fatal("entropy failure disclosed or released capture")
		}
	}
	capture, err := fixture.codec.Capture(callbackReaderBrokenContext{Context: t.Context()}, fixture.input, fixture.now)
	privateText := err != nil && strings.Contains(err.Error(), "private-context-detail")
	if !errors.Is(err, context.Canceled) || capture.value != "" || privateText {
		t.Fatal("arbitrary context text retained")
	}
	options := capsuleTestOptions(fixture.input.Route())
	codec, err := NewLoginCallbackCapsuleCodec(options)
	if err != nil {
		t.Fatal(err)
	}
	clear(options.KeyMaterial)
	first, err := codec.Capture(t.Context(), fixture.input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Capture(t.Context(), fixture.input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.value == second.value {
		t.Fatal("OS entropy did not produce fresh capture")
	}
	opened, err := fixture.codec.Open(t.Context(), capsuleHeaders(fixture.headers, first.value), fixture.now)
	if err != nil || !opened.IsValid() {
		t.Fatal("caller key mutation altered resident key")
	}
	assertCapsuleRedacted(t, codec, first)
}

type capsuleFailingEntropy struct{}

func TestLoginCallbackCapsuleChecksCancellationAtReleaseAndMaximumCookie(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	ctx := &capsuleReleaseContext{Context: t.Context(), cancelAt: 3}
	capture, err := fixture.codec.Capture(ctx, fixture.input, fixture.now)
	if !errors.Is(err, context.Canceled) || capture.value != "" {
		t.Fatal("release-time canceled capture retained material")
	}
	capture, err = fixture.codec.Capture(t.Context(), fixture.input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx = &capsuleReleaseContext{Context: t.Context(), cancelAt: 2}
	opened, err := fixture.codec.Open(ctx, capsuleHeaders(fixture.headers, capture.value), fixture.now)
	if !errors.Is(err, context.Canceled) || opened.IsValid() {
		t.Fatal("release-time canceled open retained input")
	}

	for _, lifetime := range []time.Duration{30 * time.Second, 120 * time.Second} {
		options := capsuleTestOptions(fixture.input.Route())
		options.Lifetime, options.KeyID = lifetime, strings.Repeat("k", 128)
		codec, err := NewLoginCallbackCapsuleCodec(options)
		if err != nil {
			t.Fatal(err)
		}
		input := fixture.input
		input.code, err = oidcauth.ParseCode(strings.Repeat("c", 2048))
		if err != nil {
			t.Fatal(err)
		}
		capture, err := codec.Capture(t.Context(), input, fixture.now.Add(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		if err := capture.WriteRedirect(t.Context(), response, fixture.now.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if len(response.Header().Get("Set-Cookie")) >= 4096 {
			t.Fatal("maximum key/code cookie exceeds budget")
		}
		opened, err := codec.Open(t.Context(), capsuleHeaders(fixture.headers, capture.value), fixture.now)
		if err != nil || !opened.IsValid() || len(opened.Code().Encoded()) != 2048 {
			t.Fatal("maximum cookie or boundary lifetime rejected", err)
		}
	}
}

type capsuleReleaseContext struct {
	context.Context
	checks   int
	cancelAt int
}

func (ctx *capsuleReleaseContext) Err() error {
	ctx.checks++
	if ctx.checks >= ctx.cancelAt {
		return context.Canceled
	}
	return nil
}

func (capsuleFailingEntropy) Read([]byte) (int, error) {
	return 0, errors.New("private-entropy-detail")
}

func capsuleHeaders(headers http.Header, value string) http.Header {
	result := headers.Clone()
	result.Add("Cookie", oidc.LoginCallbackCookieName+"="+value)
	return result
}

func capsuleTestOptions(route oidcauth.Route) LoginCallbackCapsuleOptions {
	return LoginCallbackCapsuleOptions{Route: route, KeyID: "callback-capture-v1",
		KeyMaterial: bytes.Repeat([]byte{0x71}, 32), Lifetime: time.Minute, Observer: noopCallbackCapsuleObserver{}}
}

func capsuleTestRouteParams(route oidcauth.Route) oidcauth.RouteParams {
	return oidcauth.RouteParams{
		DeploymentID: route.DeploymentID(), ProviderID: route.ProviderID(),
		ClientID: route.ClientID(), ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
		Issuer: route.Issuer(), DiscoveryURI: route.DiscoveryURI(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
		TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(), OIDCClientID: route.OIDCClientID(),
		ConnectorID: route.ConnectorID(),
		ClientKind:  "confidential", ClientAuthMethod: route.ClientAuthMethod(), Scopes: route.Scopes(),
		AllowedAlgorithms: route.AllowedAlgorithms(), RedirectID: route.RedirectID(), RedirectURI: route.RedirectURI(),
		ReturnRouteID: route.ReturnRouteID(),
	}
}

func assertCapsuleRedacted(t *testing.T, codec *LoginCallbackCapsuleCodec, capture LoginCallbackCapture) {
	t.Helper()
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	logger.Info("synthetic", "codec", codec, "capture", capture)
	text := fmt.Sprintf(
		"%v %#v %v %#v",
		codec,
		codec,
		capture,
		capture,
	) + output.String()
	if strings.Contains(text, capture.value) || strings.Contains(text, codec.route.RedirectURI()) ||
		strings.Contains(text, codec.keyID) {
		t.Fatal("capture/key/route disclosed")
	}
	if _, err := json.Marshal(capture); !errors.Is(err, ErrInvalidLoginCapsule) {
		t.Fatal("capture serialized")
	}
}

func FuzzLoginCallbackCapsule(f *testing.F) {
	f.Add("", uint16(0))
	f.Add("not-base64", uint16(3))
	f.Add("AAAA\n", uint16(65535))
	f.Fuzz(func(t *testing.T, raw string, flip uint16) {
		fixture := newCallbackCapsuleFixture(t)
		capture, err := fixture.codec.Capture(t.Context(), fixture.input, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		if raw == "" {
			value, err := base64.RawURLEncoding.DecodeString(capture.value)
			if err != nil {
				t.Fatal(err)
			}
			if flip != 0 {
				value[int(flip)%len(value)] ^= 1
			}
			raw = base64.RawURLEncoding.EncodeToString(value)
		}
		input, err := fixture.codec.Open(t.Context(), capsuleHeaders(fixture.headers, raw), fixture.now)
		if err != nil && input.IsValid() {
			t.Fatal("failed open released input")
		}
		if err == nil && (!input.IsValid() || input.Code().Encoded() != fixture.input.Code().Encoded()) {
			t.Fatal("open corrupted exact syntax")
		}
	})
}

func TestLoginCallbackCapsuleSuppressesCanceledAndExpiredRelease(t *testing.T) {
	t.Parallel()
	fixture := newCallbackCapsuleFixture(t)
	capture, err := fixture.codec.Capture(t.Context(), fixture.input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	var absent *httptest.ResponseRecorder
	if err := capture.WriteRedirect(t.Context(), absent, fixture.now); !errors.Is(err, ErrInvalidLoginCapsule) {
		t.Fatal("typed-nil writer accepted")
	}
	for _, now := range []time.Time{{}, time.Unix(0, 0), fixture.now.Add(-time.Second),
		fixture.now.Add(time.Minute), fixture.now.Add(time.Minute + time.Second)} {
		input, err := fixture.codec.Open(t.Context(), capsuleHeaders(fixture.headers, capture.value), now)
		if err == nil || input.IsValid() {
			t.Fatal("invalid/future/expired open released input")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	input, err := fixture.codec.Open(ctx, capsuleHeaders(fixture.headers, capture.value), fixture.now)
	if !errors.Is(err, context.Canceled) || input.IsValid() {
		t.Fatal("canceled open released input")
	}
	for _, test := range []struct {
		name string
		ctx  context.Context
		now  time.Time
	}{
		{name: "canceled", ctx: ctx, now: fixture.now},
		{name: "future issued", ctx: t.Context(), now: fixture.now.Add(-time.Second)},
		{name: "expiry equality", ctx: t.Context(), now: fixture.now.Add(time.Minute)},
		{name: "last fractional second", ctx: t.Context(), now: fixture.now.Add(time.Minute - time.Millisecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			if err := capture.WriteRedirect(test.ctx, response, test.now); err == nil ||
				response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" ||
				response.Body.Len() != 0 {
				t.Fatal("unsafe capture released a cookie or target")
			}
		})
	}
	if got, err := fixture.codec.Capture(ctx, fixture.input, fixture.now); !errors.Is(err, ErrLoginCapsuleUnavailable) ||
		got.value != "" {
		t.Fatal("canceled capture retained input")
	}
}

type callbackCapsuleFixture struct {
	codec   *LoginCallbackCapsuleCodec
	input   LoginCallbackInput
	headers http.Header
	now     time.Time
}

func newCallbackCapsuleFixture(t *testing.T) callbackCapsuleFixture {
	t.Helper()
	route := newLoginHTTPFixture(t).options.Initiation.Route()
	request := callbackReaderRequest(t.Context(), route)
	reader := mustCallbackReader(t, route, &callbackReaderObserver{})
	input, err := reader.Read(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewLoginCallbackCapsuleCodec(LoginCallbackCapsuleOptions{
		Route: route, KeyID: "callback-capture-v1", KeyMaterial: bytes.Repeat([]byte{0x71}, 32),
		Lifetime: time.Minute, Observer: noopCallbackCapsuleObserver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return callbackCapsuleFixture{codec: codec, input: input, headers: request.Header.Clone(),
		now: time.Unix(1800000000, 0)}
}

type noopCallbackCapsuleObserver struct{}

func (noopCallbackCapsuleObserver) ObserveLoginCapsule(LoginCapsuleOperation, LoginCapsuleOutcome, time.Duration) {
}

func FuzzLoginCallbackCapsulePayload(f *testing.F) {
	payload := make([]byte, callbackCapsuleFixedBytes+1)
	binary.BigEndian.PutUint64(payload, 1800000000)
	binary.BigEndian.PutUint64(payload[8:], 1800000060)
	payload[16] = byte(LoginCallbackCodeReceived)
	copy(payload[17:60], callbackReaderHandle(0x61))
	binary.BigEndian.PutUint16(payload[60:], 1)
	payload[62] = 'c'
	f.Add(payload)
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		fixture := newCallbackCapsuleFixture(t)
		input, err := fixture.codec.decode(raw, fixture.input.PreAuthCookie(), fixture.now)
		if err != nil && input.IsValid() {
			t.Fatal("failed payload parse released input")
		}
		if err == nil && !input.IsValid() {
			t.Fatal("successful payload parse released malformed input")
		}
	})
}
