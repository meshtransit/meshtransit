package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

type continuationGateFixture struct {
	mu      sync.Mutex
	now     time.Time
	options LoginContinuationGateOptions
	headers http.Header
	input   LoginCallbackInput
	calls   []ratelimit.SubjectKind
	results []LoginContinuationOutcome
	modes   map[ratelimit.SubjectKind]string
	hook    func(context.Context, ratelimit.SubjectKind)
}

func newContinuationGateFixture(t *testing.T) *continuationGateFixture {
	t.Helper()
	capsule := newCallbackCapsuleFixture(t)
	capture, err := capsule.codec.Capture(t.Context(), capsule.input, capsule.now)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := oidc.NewLoginContinuationGuard(oidc.LoginContinuationOptions{
		Origin: "https://console.example.test", Route: capsule.input.Route(),
		KeyID: "continuation-csrf-v1", KeyMaterial: bytes.Repeat([]byte{0x75}, 32), Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := newLoginHTTPFixture(t)
	statePolicy, err := ratelimit.NewPolicy(3, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f := &continuationGateFixture{now: capsule.now, input: capsule.input,
		headers: capsuleHeaders(capsule.headers, capture.value), calls: []ratelimit.SubjectKind{},
		results: []LoginContinuationOutcome{}, modes: map[ratelimit.SubjectKind]string{}}
	f.options = LoginContinuationGateOptions{CSRF: guard, Capsule: capsule.codec,
		RateLimitSubjects: start.options.RateLimitSubjects, RateLimiter: f,
		SourceRateLimit: start.options.SourceRateLimit, StateRateLimit: statePolicy,
		Clock: f, Observer: f, RequestTimeout: time.Second, MaxConcurrentRequests: 2}
	return f
}

func (f *continuationGateFixture) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *continuationGateFixture) advance(elapsed time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(elapsed)
}

func (f *continuationGateFixture) Allow(
	ctx context.Context,
	subject ratelimit.Subject,
	policy ratelimit.Policy,
) (ratelimit.Decision, error) {
	f.mu.Lock()
	f.calls = append(f.calls, subject.Kind())
	mode, hook := f.modes[subject.Kind()], f.hook
	f.mu.Unlock()
	if hook != nil {
		hook(ctx, subject.Kind())
	}
	switch mode {
	case "failure":
		return ratelimit.Decision{}, errors.New("private-redis-detail")
	case "malformed":
		return ratelimit.Decision{}, nil
	case "wrong capacity":
		return ratelimit.NewDecision(
			true,
			policy.Capacity()+1,
			0,
			0,
		)
	case "limited":
		return ratelimit.NewDecision(
			false,
			policy.Capacity(),
			0,
			time.Second,
		)
	case "unsafe retry":
		return ratelimit.NewDecision(
			false,
			policy.Capacity(),
			0,
			25*time.Hour,
		)
	default:
		return ratelimit.NewDecision(
			true,
			policy.Capacity(),
			policy.Capacity()-1,
			0,
		)
	}
}

func (f *continuationGateFixture) ObserveLoginContinuation(
	_ LoginContinuationOperation,
	result LoginContinuationOutcome,
	_ time.Duration,
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, result)
}

func (f *continuationGateFixture) snapshot() ([]ratelimit.SubjectKind, []LoginContinuationOutcome) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls), slices.Clone(f.results)
}

func mustContinuationGate(t testing.TB, options LoginContinuationGateOptions) *LoginContinuationGate {
	t.Helper()
	gate, err := NewLoginContinuationGate(options)
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func continuationGateRequest(ctx context.Context, headers http.Header, path string) *http.Request {
	request := httptest.NewRequestWithContext(
		ctx,
		http.MethodPost,
		path,
		strings.NewReader("{}"),
	)
	request.Host = "console.example.test"
	request.RemoteAddr = "192.0.2.10:12345"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header = headers.Clone()
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Meshtransit-Login", "v1")
	return request
}

func preparedContinuationRequest(t *testing.T, f *continuationGateFixture, gate *LoginContinuationGate) *http.Request {
	t.Helper()
	response := newLoginHTTPRecorder()
	prepareRequest := continuationGateRequest(t.Context(), f.headers, LoginContinuationPreparePath)
	if err := gate.Prepare(response, prepareRequest); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Token     string `json:"csrf_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Token == "" || body.ExpiresIn != 60 {
		t.Fatal("prepare did not return only live intent", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil || len(fields) != 2 {
		t.Fatal("prepare exposed fields beyond CSRF proof/expiry")
	}
	secrets := []string{f.input.State().Encoded(), f.input.PreAuthCookie().Encoded(), f.input.Code().Encoded()}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(response.Body.String(), secret) {
			t.Fatal("prepare exposed callback/browser material")
		}
	}
	if response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("prepare rotated authority/cookies or lost no-store")
	}
	request := continuationGateRequest(t.Context(), f.headers, LoginCallbackContinuePath)
	request.Header.Set(oidc.LoginCSRFHeader, body.Token)
	return request
}

func TestLoginContinuationGateRejectsIncompleteConstruction(t *testing.T) {
	t.Parallel()
	f := newContinuationGateFixture(t)
	var absent *continuationGateFixture
	for _, test := range []struct {
		name   string
		mutate func(*LoginContinuationGateOptions)
	}{
		{name: "csrf", mutate: func(o *LoginContinuationGateOptions) { o.CSRF = nil }},
		{name: "capsule", mutate: func(o *LoginContinuationGateOptions) { o.Capsule = nil }},
		{name: "limiter", mutate: func(o *LoginContinuationGateOptions) { o.RateLimiter = nil }},
		{name: "typed nil limiter", mutate: func(o *LoginContinuationGateOptions) { o.RateLimiter = absent }},
		{name: "subject", mutate: func(o *LoginContinuationGateOptions) { o.RateLimitSubjects = nil }},
		{name: "clock", mutate: func(o *LoginContinuationGateOptions) { o.Clock = nil }},
		{name: "typed nil clock", mutate: func(o *LoginContinuationGateOptions) { o.Clock = absent }},
		{name: "observer", mutate: func(o *LoginContinuationGateOptions) { o.Observer = absent }},
		{name: "state policy", mutate: func(o *LoginContinuationGateOptions) { o.StateRateLimit = ratelimit.Policy{} }},
		{name: "source policy", mutate: func(o *LoginContinuationGateOptions) { o.SourceRateLimit = ratelimit.Policy{} }},
		{name: "zero timeout", mutate: func(o *LoginContinuationGateOptions) { o.RequestTimeout = 0 }},
		{name: "long timeout", mutate: func(o *LoginContinuationGateOptions) { o.RequestTimeout = 31 * time.Second }},
		{name: "zero capacity", mutate: func(o *LoginContinuationGateOptions) { o.MaxConcurrentRequests = 0 }},
		{name: "large capacity", mutate: func(o *LoginContinuationGateOptions) { o.MaxConcurrentRequests = 129 }},
		{name: "invalid proxy", mutate: func(o *LoginContinuationGateOptions) {
			o.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := f.options
			test.mutate(&options)
			if gate, err := NewLoginContinuationGate(options); gate != nil || !errors.Is(err, ErrInvalidLoginContinuation) {
				t.Fatal("invalid continuation construction accepted")
			}
		})
	}
	var absentGate *LoginContinuationGate
	for _, gate := range []*LoginContinuationGate{absentGate, {}} {
		request := continuationGateRequest(t.Context(), f.headers, LoginCallbackContinuePath)
		input, err := gate.Read(newLoginHTTPRecorder(), request)
		if !errors.Is(err, ErrLoginContinuationUnavailable) || input.IsValid() {
			t.Fatal("zero gate released input")
		}
	}
	var absentWriter *httptest.ResponseRecorder
	err := mustContinuationGate(t, f.options).Prepare(absentWriter, nil)
	if !errors.Is(err, ErrLoginContinuationUnavailable) {
		t.Fatal("typed nil writer admitted")
	}
}

func TestLoginContinuationGatePreparesOnlyIntentAndReleasesOnlySyntax(t *testing.T) {
	t.Parallel()
	f := newContinuationGateFixture(t)
	gate := mustContinuationGate(t, f.options)
	request := preparedContinuationRequest(t, f, gate)
	for range 2 {
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		response.Header().Set("Access-Control-Allow-Origin", "*")
		input, err := gate.Read(response, request.Clone(t.Context()))
		// Clone shares Body; provide a fresh bounded body for each independent request.
		if err != nil || !input.IsValid() || input.Code().Encoded() != f.input.Code().Encoded() {
			t.Fatal("valid protected continuation rejected", err)
		}
		if response.statusWrites != 0 || response.Body.Len() != 0 || response.Header().Get("Set-Cookie") != "" ||
			response.Header().Get("Location") != "" || response.Header().Get("Cache-Control") != "no-store" ||
			response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("Read emitted a secret/success response or unsafe headers")
		}
		request.Body = io.NopCloser(strings.NewReader("{}"))
	}
	calls, results := f.snapshot()
	wantCalls := []ratelimit.SubjectKind{ratelimit.SubjectSource, ratelimit.SubjectAuthTransaction,
		ratelimit.SubjectSource, ratelimit.SubjectAuthTransaction, ratelimit.SubjectSource, ratelimit.SubjectAuthTransaction}
	wantResults := []LoginContinuationOutcome{LoginContinuationPrepared,
		LoginContinuationInputReleased, LoginContinuationInputReleased}
	if !slices.Equal(calls, wantCalls) || !slices.Equal(results, wantResults) {
		t.Fatal("shared budgets or closed observations skipped")
	}
}

func TestLoginContinuationGateRejectsMalformedTransportBeforeCrypto(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		mutate      func(*http.Request)
		budgetCalls int
	}{
		{name: "get", mutate: func(r *http.Request) { r.Method = http.MethodGet }},
		{name: "head", mutate: func(r *http.Request) { r.Method = http.MethodHead }},
		{name: "options", mutate: func(r *http.Request) { r.Method = http.MethodOptions }},
		{name: "no tls", mutate: func(r *http.Request) { r.TLS = nil }},
		{name: "old tls", mutate: func(r *http.Request) { r.TLS.Version = tls.VersionTLS11 }},
		{name: "unfinished tls", mutate: func(r *http.Request) { r.TLS.HandshakeComplete = false }},
		{name: "host", mutate: func(r *http.Request) { r.Host = "other.example.test" }},
		{name: "origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://other.example.test") }},
		{name: "null origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{name: "missing origin", mutate: func(r *http.Request) { r.Header.Del("Origin") }},
		{name: "duplicate origin", mutate: func(r *http.Request) { r.Header.Add("Origin", r.Header.Get("Origin")) }},
		{name: "origin alias", mutate: func(r *http.Request) {
			r.Header["origin"] = []string{"https://console.example.test"}
		}},
		{name: "simple form", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{name: "custom header", mutate: func(r *http.Request) { r.Header.Del("X-Meshtransit-Login") }},
		{name: "authorization", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") }},
		{name: "host header", mutate: func(r *http.Request) { r.Header.Set("Host", "console.example.test") }},
		{name: "alternate path", mutate: func(r *http.Request) { r.URL.Path += "/" }},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "code=synthetic" }},
		{name: "force query", mutate: func(r *http.Request) { r.URL.ForceQuery = true }},
		{name: "raw path", mutate: func(r *http.Request) { r.URL.RawPath = r.URL.Path }},
		{name: "request uri", mutate: func(r *http.Request) { r.RequestURI += "?x=y" }},
		{name: "absolute target", mutate: func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = r.Host }},
		{name: "fragment", mutate: func(r *http.Request) { r.URL.Fragment = "private" }},
		{name: "negative length", mutate: func(r *http.Request) { r.ContentLength = -1 }},
		{name: "large length", mutate: func(r *http.Request) { r.ContentLength = 33 }},
		{name: "empty length header", mutate: func(r *http.Request) { r.Header["Content-Length"] = nil }},
		{name: "duplicate length header", mutate: func(r *http.Request) { r.Header["Content-Length"] = []string{"2", "2"} }},
		{name: "mismatched length header", mutate: func(r *http.Request) { r.Header.Set("Content-Length", "3") }},
		{name: "noncanonical length header", mutate: func(r *http.Request) { r.Header.Set("Content-Length", "02") }},
		{name: "no body", mutate: func(r *http.Request) { r.Body = nil }},
		{name: "transfer", mutate: func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{name: "trailer", mutate: func(r *http.Request) { r.Trailer = http.Header{"X-Extra": {"v"}} }},
		{name: "cross site fetch", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{name: "partial metadata", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }},
		{name: "oversized header", mutate: func(r *http.Request) { r.Header.Set("X-Extra", strings.Repeat("x", 16385)) }},
		{name: "body selector", budgetCalls: 1, mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"workspace":"untrusted"}`))
		}},
		{name: "actual body oversize", budgetCalls: 1, mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", 33)))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newContinuationGateFixture(t)
			gate := mustContinuationGate(t, f.options)
			request := continuationGateRequest(t.Context(), f.headers, LoginContinuationPreparePath)
			test.mutate(request)
			response := newLoginHTTPRecorder()
			if err := gate.Prepare(response, request); !errors.Is(err, ErrInvalidLoginContinuation) {
				t.Fatal("malformed HTTP admitted", err)
			}
			calls, _ := f.snapshot()
			if len(calls) != test.budgetCalls || response.Body.Len() != 0 || response.Header().Get("Set-Cookie") != "" {
				t.Fatal("invalid transport released data or bypassed ingress order")
			}
		})
	}
}

func TestLoginContinuationGateRejectsBudgetFailureAndDelay(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		kind   ratelimit.SubjectKind
		mode   string
		delay  time.Duration
		cancel bool
		want   error
	}{
		{name: "source failure", kind: ratelimit.SubjectSource, mode: "failure", want: ErrLoginContinuationUnavailable},
		{name: "state failure", kind: ratelimit.SubjectAuthTransaction, mode: "failure",
			want: ErrLoginContinuationUnavailable},
		{name: "source limited", kind: ratelimit.SubjectSource, mode: "limited", want: ErrLoginContinuationLimited},
		{name: "state limited", kind: ratelimit.SubjectAuthTransaction, mode: "limited", want: ErrLoginContinuationLimited},
		{name: "malformed source", kind: ratelimit.SubjectSource, mode: "malformed", want: ErrLoginContinuationUnavailable},
		{name: "malformed state", kind: ratelimit.SubjectAuthTransaction, mode: "malformed",
			want: ErrLoginContinuationUnavailable},
		{name: "wrong capacity", kind: ratelimit.SubjectSource, mode: "wrong capacity",
			want: ErrLoginContinuationUnavailable},
		{name: "unsafe retry", kind: ratelimit.SubjectSource, mode: "unsafe retry", want: ErrLoginContinuationUnavailable},
		{name: "source expiry", kind: ratelimit.SubjectSource, delay: time.Minute, want: ErrInvalidLoginContinuation},
		{name: "state expiry", kind: ratelimit.SubjectAuthTransaction, delay: time.Minute, want: ErrInvalidLoginContinuation},
		{name: "backward clock", kind: ratelimit.SubjectAuthTransaction, delay: -time.Second,
			want: ErrInvalidLoginContinuation},
		{name: "state canceled", kind: ratelimit.SubjectAuthTransaction, cancel: true, want: ErrLoginContinuationUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newContinuationGateFixture(t)
			gate := mustContinuationGate(t, f.options)
			request := preparedContinuationRequest(t, f, gate)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request = request.WithContext(ctx)
			f.modes[test.kind] = test.mode
			f.hook = func(_ context.Context, kind ratelimit.SubjectKind) {
				if kind == test.kind {
					f.advance(test.delay)
					if test.cancel {
						cancel()
					}
				}
			}
			response := newLoginHTTPRecorder()
			input, err := gate.Read(response, request)
			if !errors.Is(err, test.want) || input.IsValid() || strings.Contains(err.Error(), "private-redis-detail") ||
				response.Body.Len() != 0 || response.Header().Get("Set-Cookie") != "" {
				t.Fatal("budget/delay failure released input or dependency text", err)
			}
			if test.mode == "limited" && response.Header().Get("Retry-After") != "1" {
				t.Fatal("shared exhaustion lost bounded retry metadata")
			}
		})
	}
}

func TestLoginContinuationGateRejectsCSRFAndMissingTransportDeadlines(t *testing.T) {
	t.Parallel()
	f := newContinuationGateFixture(t)
	gate := mustContinuationGate(t, f.options)
	request := continuationGateRequest(t.Context(), f.headers, LoginCallbackContinuePath)
	input, err := gate.Read(newLoginHTTPRecorder(), request)
	if !errors.Is(err, ErrInvalidLoginContinuation) || input.IsValid() {
		t.Fatal("missing CSRF admitted input")
	}
	input, err = gate.Read(httptest.NewRecorder(), request)
	if !errors.Is(err, ErrLoginContinuationUnavailable) || input.IsValid() {
		t.Fatal("unsupported transport deadlines admitted input")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	input, err = gate.Read(newLoginHTTPRecorder(), request.WithContext(ctx))
	if !errors.Is(err, ErrLoginContinuationUnavailable) || input.IsValid() {
		t.Fatal("canceled admission released input")
	}
}

func TestLoginContinuationGateCapacityIsNonQueuingAndJoined(t *testing.T) {
	t.Parallel()
	f := newContinuationGateFixture(t)
	f.options.MaxConcurrentRequests = 1
	gate := mustContinuationGate(t, f.options)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	var joined sync.WaitGroup
	defer func() { cancel(); joined.Wait() }()
	f.hook = func(ctx context.Context, kind ratelimit.SubjectKind) {
		if kind != ratelimit.SubjectSource {
			return
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	completed := make(chan error, 1)
	joined.Go(func() {
		request := continuationGateRequest(ctx, f.headers, LoginContinuationPreparePath)
		completed <- gate.Prepare(newLoginHTTPRecorder(), request)
	})
	<-entered
	response := newLoginHTTPRecorder()
	input, err := gate.Read(response, continuationGateRequest(t.Context(), f.headers, LoginCallbackContinuePath))
	if !errors.Is(err, ErrLoginContinuationSaturated) || input.IsValid() || response.Body.Len() != 0 {
		t.Fatal("capacity rejection queued or released input")
	}
	close(release)
	if err := <-completed; err != nil {
		t.Fatal("owned first admission did not complete", err)
	}
	joined.Wait()
	calls, results := f.snapshot()
	if len(calls) != 2 || !slices.Contains(results, LoginContinuationSaturated) ||
		!slices.Contains(results, LoginContinuationPrepared) {
		t.Fatal("rejected admission touched shared budget or disappeared from telemetry")
	}
}

type continuationStatusRecorder struct {
	*loginHTTPRecorder
	statusWrites int
}

func (r *continuationStatusRecorder) WriteHeader(status int) {
	r.statusWrites++
	r.loginHTTPRecorder.WriteHeader(status)
}

func TestLoginContinuationGateSupportsRealHTTPSAndCoherentMetadata(t *testing.T) {
	t.Parallel()
	f := newContinuationGateFixture(t)
	gate := mustContinuationGate(t, f.options)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Length") != "2" || r.ContentLength != 2 {
			t.Error("real fixed-length HTTPS request lost coherent transport metadata")
		}
		if r.URL.Path == LoginContinuationPreparePath {
			if err := gate.Prepare(w, r); err != nil {
				t.Error("real TLS prepare failed", err)
			}
			return
		}
		input, err := gate.Read(w, r)
		if err != nil || !input.IsValid() {
			t.Error("real TLS POST admission failed", err)
			return
		}
		w.WriteHeader(http.StatusNoContent) // Test caller only; no claim/session is performed.
	}))
	server.Config.ReadTimeout = 2 * time.Second
	server.Config.WriteTimeout = 2 * time.Second
	server.Config.IdleTimeout = 2 * time.Second
	server.StartTLS()
	defer server.Close()
	client := server.Client() // Trust the synthetic test CA; never skip certificate verification.
	client.Timeout = 2 * time.Second
	prepare := continuationGateRequest(t.Context(), f.headers, LoginContinuationPreparePath)
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		server.URL+LoginContinuationPreparePath,
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Host, request.Header = prepare.Host, prepare.Header
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	value, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	var body struct {
		Token string `json:"csrf_token"`
	}
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK ||
		json.Unmarshal(value, &body) != nil || body.Token == "" {
		t.Fatal("real TLS prepare did not deliver intent")
	}
	request, err = http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		server.URL+LoginCallbackContinuePath,
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Host, request.Header = prepare.Host, prepare.Header.Clone()
	request.Header.Set(oidc.LoginCSRFHeader, body.Token)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Sec-Fetch-Mode", "cors")
	request.Header.Set("Sec-Fetch-Dest", "empty")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatal("real TLS continuation did not complete admission", err)
	}
}

func TestLoginContinuationGateRejectsChangedCapsuleAndRoute(t *testing.T) {
	t.Parallel()
	f := newContinuationGateFixture(t)
	gate := mustContinuationGate(t, f.options)
	request := preparedContinuationRequest(t, f, gate)
	request.Header.Set("Cookie", request.Header.Get("Cookie")+"A")
	if input, err := gate.Read(newLoginHTTPRecorder(), request); err == nil || input.IsValid() {
		t.Fatal("changed capsule accepted current proof")
	}
	params := capsuleTestRouteParams(f.input.Route())
	params.RecoveryEpoch++
	route, err := oidcauth.NewRoute(params)
	if err != nil {
		t.Fatal(err)
	}
	options := f.options
	options.Capsule, err = NewLoginCallbackCapsuleCodec(capsuleTestOptions(route))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := NewLoginContinuationGate(options); result != nil || !errors.Is(err, ErrInvalidLoginContinuation) {
		t.Fatal("CSRF/capsule route mismatch accepted")
	}
}

func TestLoginContinuationGatePreservesGenericProviderErrorWithoutGrant(t *testing.T) {
	t.Parallel()
	f := newContinuationGateFixture(t)
	f.input.kind, f.input.code = LoginCallbackProviderErrorReceived, oidcauth.Code{}
	capture, err := f.options.Capsule.Capture(t.Context(), f.input, f.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.headers = http.Header{"Cookie": {oidc.PreAuthCookieName + "=" + f.input.PreAuthCookie().Encoded(),
		oidc.LoginCallbackCookieName + "=" + capture.value}}
	gate := mustContinuationGate(t, f.options)
	request := preparedContinuationRequest(t, f, gate)
	input, err := gate.Read(newLoginHTTPRecorder(), request)
	if err != nil || input.Kind() != LoginCallbackProviderErrorReceived || input.Code().IsValid() {
		t.Fatal("provider error became code/grant evidence", err)
	}
}

func FuzzLoginContinuationHTTP(f *testing.F) {
	f.Add(LoginCallbackContinuePath, "{}", "keep")
	f.Add("/other", `{"code":"untrusted"}`, "bad")
	f.Fuzz(func(t *testing.T, path, body, proof string) {
		fixture := newContinuationGateFixture(t)
		gate := mustContinuationGate(t, fixture.options)
		request := preparedContinuationRequest(t, fixture, gate)
		request.URL.Path, request.RequestURI = path, path
		request.Body = io.NopCloser(strings.NewReader(body))
		request.ContentLength = int64(len(body))
		if proof != "keep" {
			request.Header.Set(oidc.LoginCSRFHeader, proof)
		}
		response := newLoginHTTPRecorder()
		input, err := gate.Read(response, request)
		if err == nil && (path != LoginCallbackContinuePath || strings.Trim(body, " \t\r\n") != "{}" ||
			proof != "keep" || !input.IsValid()) {
			t.Fatal("fuzzed HTTP widened admission")
		}
		if response.Body.Len() != 0 || response.Header().Get("Set-Cookie") != "" {
			t.Fatal("HTTP read exposed a browser response")
		}
	})
}
