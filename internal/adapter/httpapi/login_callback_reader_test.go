package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestLoginCallbackReaderRejectsMissingConstruction(t *testing.T) {
	t.Parallel()
	route := newLoginHTTPFixture(t).options.Initiation.Route()
	var absent *callbackReaderObserver
	for _, options := range []LoginCallbackReaderOptions{
		{Observer: &callbackReaderObserver{}}, {Route: route}, {Route: route, Observer: absent},
	} {
		if reader, err := NewLoginCallbackReader(options); !errors.Is(err, ErrInvalidLoginCallbackReader) || reader != nil {
			t.Fatal("missing callback ownership accepted")
		}
	}
	var zero LoginCallbackReader
	var missing *LoginCallbackReader
	partial := &LoginCallbackReader{host: "console.example.test", observer: &callbackReaderObserver{}}
	for _, reader := range []*LoginCallbackReader{&zero, missing, partial} {
		input, err := reader.Read(t.Context(), callbackReaderRequest(t.Context(), route))
		if !errors.Is(err, ErrInvalidLoginCallbackReader) || input.IsValid() {
			t.Fatal("uninitialized reader released input")
		}
	}
}

func TestLoginCallbackReaderPreservesCodeOrDiscardsProviderDiagnostics(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"code", "provider error"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			route := newLoginHTTPFixture(t).options.Initiation.Route()
			observer := &callbackReaderObserver{}
			reader := mustCallbackReader(t, route, observer)
			request := callbackReaderRequest(t.Context(), route)
			values, err := url.ParseQuery(request.URL.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			values.Set("session_state", "untrusted-session-hint")
			values.Set("future_extension", "bounded-ignored-data")
			want := LoginCallbackCodeReceived
			if variant == "provider error" {
				values.Del("code")
				values.Set("error", "access_denied")
				values.Set("error_description", "private-upstream-diagnostic")
				values.Set("error_uri", "https://untrusted.example.test/do-not-fetch")
				want = LoginCallbackProviderErrorReceived
			}
			setCallbackQuery(request, values.Encode())
			input, err := reader.Read(t.Context(), request)
			if err != nil || !input.IsValid() || input.Kind() != want || input.Route().Issuer() != route.Issuer() {
				t.Fatal("bounded callback variant rejected", err)
			}
			if input.State().Encoded() != values.Get("state") || !input.PreAuthCookie().IsValid() ||
				input.Code().IsValid() != (variant == "code") {
				t.Fatal("callback input shape changed")
			}
			if variant == "code" && input.Code().Encoded() != "synthetic-code+exact=/value" {
				t.Fatal("code was normalized or form-decoded twice")
			}
			assertCallbackInputRedacted(t, input, request)
			if got := observer.snapshot(); len(got) != 1 || got[0] != want {
				t.Fatal("callback telemetry did not report one closed receive category")
			}
		})
	}
}

func TestLoginCallbackReaderRejectsAmbiguityBeforeRelease(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "POST", mutate: func(r *http.Request) { r.Method = http.MethodPost }},
		{name: "HEAD", mutate: func(r *http.Request) { r.Method = http.MethodHead }},
		{name: "no TLS", mutate: func(r *http.Request) { r.TLS = nil }},
		{name: "old TLS", mutate: func(r *http.Request) { r.TLS.Version = tls.VersionTLS11 }},
		{name: "unfinished TLS", mutate: func(r *http.Request) { r.TLS.HandshakeComplete = false }},
		{name: "wrong Host", mutate: func(r *http.Request) { r.Host = "attacker.example.test" }},
		{name: "wrong path", mutate: func(r *http.Request) {
			r.URL.Path = "/another/callback"
			r.RequestURI = r.URL.RequestURI()
		}},
		{name: "raw path", mutate: func(r *http.Request) {
			r.URL.RawPath = "/auth/%63allback"
			r.RequestURI = r.URL.RequestURI()
		}},
		{name: "absolute form", mutate: func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = r.Host }},
		{name: "request target mismatch", mutate: func(r *http.Request) { r.RequestURI = "/other?code=other" }},
		{name: "fragment", mutate: func(r *http.Request) { r.URL.Fragment = "private" }},
		{name: "body", mutate: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")) }},
		{name: "length", mutate: func(r *http.Request) { r.ContentLength = 1 }},
		{name: "transfer", mutate: func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{name: "trailer", mutate: func(r *http.Request) { r.Trailer = http.Header{"X-Future": []string{"x"}} }},
		{name: "duplicate Host header", mutate: func(r *http.Request) { r.Header.Set("Host", r.Host) }},
		{name: "content type", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{name: "cross Origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example.test") }},
		{name: "duplicate Origin", mutate: func(r *http.Request) { r.Header["Origin"] = []string{"x", "x"} }},
		{name: "AJAX", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "cors") }},
		{name: "iframe", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "iframe") }},
		{name: "partial metadata", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{name: "missing cookie", mutate: func(r *http.Request) { r.Header.Del("Cookie") }},
		{name: "quoted cookie", mutate: func(r *http.Request) {
			r.Header.Set("Cookie", oidc.PreAuthCookieName+"=\""+callbackReaderHandle(0x62)+"\"")
		}},
		{name: "duplicate cookie", mutate: func(r *http.Request) { r.Header.Add("Cookie", r.Header.Get("Cookie")) }},
		{name: "mixed-case alias", mutate: func(r *http.Request) { r.Header["cookie"] = r.Header["Cookie"] }},
		{name: "header overflow", mutate: func(r *http.Request) { r.Header.Set("X-Future", strings.Repeat("x", 16385)) }},
		{name: "query overflow", mutate: func(r *http.Request) { setCallbackQuery(r, strings.Repeat("x", 8193)) }},
		{name: "duplicate state", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+"&state=x") }},
		{name: "encoded alias", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+"&%73tate=x") }},
		{name: "empty pair", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+"&") }},
		{name: "semicolon", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+";extension=x") }},
		{name: "bad escape", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+"&extension=%xx") }},
		{name: "raw space", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+"&extension=raw space") }},
		{name: "implicit token", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+"&access_token=x") }},
		{name: "both variants", mutate: func(r *http.Request) { setCallbackQuery(r, r.URL.RawQuery+"&error=access_denied") }},
		{name: "error diagnostic on code", mutate: func(r *http.Request) {
			setCallbackQuery(r, r.URL.RawQuery+"&error_description=unexpected")
		}},
		{name: "duplicate ignored extension", mutate: func(r *http.Request) {
			setCallbackQuery(r, r.URL.RawQuery+"&future=x&future=y")
		}},
		{name: "too many pairs", mutate: func(r *http.Request) {
			setCallbackQuery(r, r.URL.RawQuery+"&a=&b=&c=&d=&e=&f=")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			route := newLoginHTTPFixture(t).options.Initiation.Route()
			observer := &callbackReaderObserver{}
			reader := mustCallbackReader(t, route, observer)
			request := callbackReaderRequest(t.Context(), route)
			test.mutate(request)
			input, err := reader.Read(t.Context(), request)
			if !errors.Is(err, ErrInvalidLoginCallback) || input.IsValid() || input.Code().IsValid() {
				t.Fatal("ambiguous callback released input")
			}
			if got := observer.snapshot(); len(got) != 1 || got[0] != LoginCallbackInvalid {
				t.Fatal("invalid callback did not have one closed observation")
			}
		})
	}
}

func TestLoginCallbackReaderRejectsCancellationAndRetainsNoRequest(t *testing.T) {
	t.Parallel()
	route := newLoginHTTPFixture(t).options.Initiation.Route()
	observer := &callbackReaderObserver{}
	reader := mustCallbackReader(t, route, observer)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	input, err := reader.Read(ctx, callbackReaderRequest(t.Context(), route))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrLoginCallbackUnavailable) || input.IsValid() {
		t.Fatal("canceled reader released input")
	}
	request := callbackReaderRequest(t.Context(), route)
	input, err = reader.Read(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	setCallbackQuery(request, "state=mutated")
	request.Header.Set("Cookie", "mutated")
	if !input.IsValid() || input.State().Encoded() != callbackReaderHandle(0x61) {
		t.Fatal("returned input retained mutable request")
	}
}

func TestLoginCallbackReaderRejectsFieldSubstitutionAndOverflow(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, key, value string }{
		{name: "missing issuer", key: "iss", value: ""},
		{name: "issuer slash alias", key: "iss", value: "https://login.example.test/realms/meshtransit/"},
		{name: "direct upstream issuer", key: "iss", value: "https://upstream.example.test"},
		{name: "double-encoded issuer", key: "iss", value: "https%3A%2F%2Flogin.example.test%2Frealms%2Fmeshtransit"},
		{name: "zero state", key: "state", value: callbackReaderHandle(0)},
		{name: "padded state", key: "state", value: callbackReaderHandle(0x61) + "="},
		{name: "short state", key: "state", value: "short"},
		{name: "empty code", key: "code", value: ""},
		{name: "long code", key: "code", value: strings.Repeat("x", 4097)},
		{name: "code space", key: "code", value: "untrusted code"},
		{name: "code control", key: "code", value: "untrusted\ncode"},
		{name: "long hint", key: "session_state", value: strings.Repeat("x", 1025)},
		{name: "long extension", key: "extension", value: strings.Repeat("x", 1025)},
		{name: "extension control", key: "extension", value: "x\n"},
		{name: "unknown key too long", key: strings.Repeat("x", 65), value: "x"},
		{name: "JARM", key: "response", value: "untrusted-jwt"},
		{name: "mixed-case implicit", key: "ID_TOKEN", value: "untrusted-jwt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			route := newLoginHTTPFixture(t).options.Initiation.Route()
			reader := mustCallbackReader(t, route, callbackReaderDiscardObserver{})
			request := callbackReaderRequest(t.Context(), route)
			values, err := url.ParseQuery(request.URL.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			values.Set(test.key, test.value)
			setCallbackQuery(request, values.Encode())
			input, err := reader.Read(t.Context(), request)
			if !errors.Is(err, ErrInvalidLoginCallback) || input.IsValid() {
				t.Fatal("substituted/overflow callback accepted")
			}
		})
	}
}

func TestLoginCallbackReaderAcceptsOnlyCoherentDocumentNavigation(t *testing.T) {
	t.Parallel()
	for _, site := range []string{"cross-site", "same-site", "same-origin", "none"} {
		t.Run(site, func(t *testing.T) {
			t.Parallel()
			route := newLoginHTTPFixture(t).options.Initiation.Route()
			reader := mustCallbackReader(t, route, callbackReaderDiscardObserver{})
			request := callbackReaderRequest(t.Context(), route)
			request.Header.Set("Origin", "https://console.example.test")
			request.Header.Set("Sec-Fetch-Mode", "navigate")
			request.Header.Set("Sec-Fetch-Dest", "document")
			request.Header.Set("Sec-Fetch-Site", site)
			request.Header.Set("Sec-Fetch-User", "?1")
			input, err := reader.Read(t.Context(), request)
			if err != nil || !input.IsValid() {
				t.Fatal("top-level navigation rejected", err)
			}
			request.Header.Add("Sec-Fetch-Dest", "document")
			if input, err := reader.Read(t.Context(), request); err == nil || input.IsValid() {
				t.Fatal("duplicate navigation metadata accepted")
			}
		})
	}
}

func TestLoginCallbackReaderProviderErrorBoundsAndNoContextText(t *testing.T) {
	t.Parallel()
	route := newLoginHTTPFixture(t).options.Initiation.Route()
	reader := mustCallbackReader(t, route, callbackReaderDiscardObserver{})
	for _, test := range []struct{ name, key, value string }{
		{name: "empty error", key: "error", value: ""},
		{name: "long error", key: "error", value: strings.Repeat("x", 129)},
		{name: "diagnostic overflow", key: "error_description", value: strings.Repeat("x", 513)},
		{name: "diagnostic quotes", key: "error_description", value: "untrusted\"quote"},
		{name: "error URI overflow", key: "error_uri", value: strings.Repeat("x", 2049)},
		{name: "error URI space", key: "error_uri", value: "https://untrusted.example.test/a b"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := callbackReaderRequest(t.Context(), route)
			values, err := url.ParseQuery(request.URL.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			values.Del("code")
			values.Set("error", "access_denied")
			values.Set(test.key, test.value)
			setCallbackQuery(request, values.Encode())
			if input, err := reader.Read(t.Context(), request); err == nil || input.IsValid() {
				t.Fatal("unbounded provider error accepted")
			}
		})
	}
	ctx := callbackReaderBrokenContext{Context: t.Context()}
	input, err := reader.Read(ctx, callbackReaderRequest(t.Context(), route))
	if !errors.Is(err, context.Canceled) || input.IsValid() || strings.Contains(err.Error(), "private-context-detail") {
		t.Fatal("callback propagated arbitrary context text")
	}
}

type callbackReaderBrokenContext struct{ context.Context }

func (callbackReaderBrokenContext) Err() error {
	return errors.Join(context.Canceled, errors.New("private-context-detail"))
}

func FuzzLoginCallbackReader(f *testing.F) {
	f.Add("state=" + callbackReaderHandle(0x61) +
		"&code=synthetic-code&iss=https%3A%2F%2Flogin.example.test%2Frealms%2Fmeshtransit")
	f.Add("state=x&code=x&iss=%xx")
	f.Add("error=access_denied&state=x&iss=x")
	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 16384 {
			return
		}
		route := newLoginHTTPFixture(t).options.Initiation.Route()
		reader := mustCallbackReader(t, route, callbackReaderDiscardObserver{})
		request := callbackReaderRequest(t.Context(), route)
		setCallbackQuery(request, query)
		input, err := reader.Read(t.Context(), request)
		if err == nil && (!input.IsValid() || input.Route().Issuer() != route.Issuer()) {
			t.Fatal("malformed or substituted route released")
		}
		if err != nil && input.IsValid() {
			t.Fatal("failed parse retained input")
		}
	})
}

func callbackReaderHandle(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func callbackReaderRequest(ctx context.Context, route oidcauth.Route) *http.Request {
	redirect, err := url.Parse(route.RedirectURI())
	if err != nil {
		panic("invalid synthetic callback route fixture")
	}
	request := httptest.NewRequestWithContext(
		ctx,
		http.MethodGet,
		redirect.Path,
		nil,
	)
	request.Host = redirect.Host
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header.Set("Cookie", oidc.PreAuthCookieName+"="+callbackReaderHandle(0x62))
	setCallbackQuery(request, url.Values{
		"state": []string{callbackReaderHandle(0x61)}, "iss": []string{route.Issuer()},
		"code": []string{"synthetic-code+exact=/value"},
	}.Encode())
	return request
}

func setCallbackQuery(request *http.Request, query string) {
	request.URL.RawQuery = query
	request.RequestURI = request.URL.Path + "?" + query
}

func mustCallbackReader(t *testing.T, route oidcauth.Route, observer LoginCallbackObserver) *LoginCallbackReader {
	t.Helper()
	reader, err := NewLoginCallbackReader(LoginCallbackReaderOptions{Route: route, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func assertCallbackInputRedacted(t *testing.T, input LoginCallbackInput, request *http.Request) {
	t.Helper()
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("synthetic callback", "input", input)
	formatted := fmt.Sprintf(
		"%v %+v %#v",
		input,
		input,
		input,
	) + log.String()
	for _, private := range []string{callbackReaderHandle(0x61), callbackReaderHandle(0x62),
		"synthetic-code", "private-upstream", request.Host, input.Route().ProviderID().String()} {
		if strings.Contains(formatted, private) {
			t.Fatal("callback formatting/logging leaked input")
		}
	}
	if encoded, err := json.Marshal(input); err == nil || bytes.Contains(encoded, []byte("synthetic-code")) {
		t.Fatal("secret-bearing callback was JSON serializable")
	}
}

type callbackReaderObserver struct {
	mu       sync.Mutex
	outcomes []LoginCallbackOutcome
}

type callbackReaderDiscardObserver struct{}

func (callbackReaderDiscardObserver) ObserveLoginCallback(LoginCallbackOutcome, time.Duration) {}

func (observer *callbackReaderObserver) ObserveLoginCallback(outcome LoginCallbackOutcome, _ time.Duration) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.outcomes = append(observer.outcomes, outcome)
}

func (observer *callbackReaderObserver) snapshot() []LoginCallbackOutcome {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return append([]LoginCallbackOutcome{}, observer.outcomes...)
}
