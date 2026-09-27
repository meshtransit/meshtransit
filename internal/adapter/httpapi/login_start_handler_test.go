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
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

type loginHTTPFixture struct {
	now          time.Time
	options      LoginStartHandlerOptions
	calls        []string
	commitErr    error
	admissionErr error
	rateErr      error
	decision     ratelimit.Decision
	pending      oidcauth.Pending
	resolveFound bool
	hook         func(context.Context, string)
	outcome      LoginHTTPOutcome
}

type loginHTTPRecorder struct{ *httptest.ResponseRecorder }

func newLoginHTTPRecorder() *loginHTTPRecorder {
	return &loginHTTPRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (*loginHTTPRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*loginHTTPRecorder) SetWriteDeadline(time.Time) error { return nil }

func newLoginHTTPFixture(t *testing.T) *loginHTTPFixture {
	t.Helper()
	did, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	wid, err := workspace.ParseID("01890f00-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := oidcauth.ParseProviderID("01890f00-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	cid, err := oidcauth.ParseClientID("01890f00-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G101 -- synthetic client authentication-method metadata, not a credential.
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: did, WorkspaceID: wid, ProviderID: pid, ClientID: cid,
		ProviderGeneration: 3, RecoveryEpoch: 7,
		Issuer:       "https://login.example.test/realms/meshtransit",
		DiscoveryURI: "https://login.example.test/discovery", AuthorizationEndpoint: "https://login.example.test/auth",
		TokenEndpoint: "https://login.example.test/token", JWKSURI: "https://login.example.test/certs",
		OIDCClientID: "console", ClientKind: "confidential", ClientAuthMethod: "client_secret_basic",
		Scopes: []string{"openid"}, AllowedAlgorithms: []string{"RS256"},
		RedirectID: "console.callback.v1", RedirectURI: "https://console.example.test/auth/callback", ReturnRouteID: "workspace.home",
	})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := oidc.NewLoginInitiationGuard(oidc.LoginInitiationOptions{
		Origin: "https://console.example.test", Route: route,
		KeyID: "init-v1", KeyMaterial: bytes.Repeat([]byte{0x41}, 32), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := ratelimit.NewDigestKeyID("login-source-v1")
	if err != nil {
		t.Fatal(err)
	}
	digester, err := ratelimit.NewDigester(keyID, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ratelimit.NewPolicy(5, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := ratelimit.NewDecision(true, 5, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &loginHTTPFixture{now: time.Date(2026, time.September, 16, 5, 0, 0, 0, time.UTC),
		calls: []string{}, decision: decision}
	digestID, err := oidcauth.NewDigestKeyID("transaction-digest-v1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := oidcauth.NewDigestKey(digestID, bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cipherID, err := oidcauth.NewVerifierEncryptionKeyID("transaction-aead-v1")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherID, bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := oidcauth.NewStartService(oidcauth.StartOptions{
		RequestTimeout: 10 * time.Second, PendingLifetime: 5 * time.Minute, RollbackTimeout: time.Second, ResolveTimeout: time.Second,
	}, oidcauth.StartDependencies{Metadata: fixture, Transactions: fixture, Committed: fixture,
		IDs: oidcauth.SystemStartIDs{}, Secrets: oidcauth.SystemSecrets{}, Clock: fixture, Observer: fixture,
		DigestKey: digest, VerifierCipher: cipher})
	if err != nil {
		t.Fatal(err)
	}
	fixture.options = LoginStartHandlerOptions{Initiation: guard, Admission: fixture, Starter: service,
		RateLimitSubjects: digester, RateLimiter: fixture, SourceRateLimit: policy, Clock: fixture,
		Observer: fixture, RequestTimeout: 10 * time.Second, MaxConcurrentRequests: 2}
	return fixture
}

func (f *loginHTTPFixture) call(ctx context.Context, name string) {
	f.calls = append(f.calls, name)
	if f.hook != nil {
		f.hook(ctx, name)
	}
}
func (f *loginHTTPFixture) Now() time.Time                                 { return f.now }
func (*loginHTTPFixture) StartOpened()                                     {}
func (*loginHTTPFixture) StartClosed(oidcauth.StartOutcome, time.Duration) {}
func (f *loginHTTPFixture) ObserveLoginHTTP(outcome LoginHTTPOutcome, _ time.Duration) {
	f.outcome = outcome
}
func (f *loginHTTPFixture) Admit(ctx context.Context, route oidcauth.Route) error {
	f.call(ctx, "admission")
	if route.WorkspaceID() != f.options.Initiation.Route().WorkspaceID() {
		return errors.New("wrong route")
	}
	return f.admissionErr
}
func (f *loginHTTPFixture) Allow(ctx context.Context, subject ratelimit.Subject, policy ratelimit.Policy) (ratelimit.Decision, error) {
	f.call(ctx, "rate")
	if !subject.IsValid() || policy.Capacity() != 5 {
		return ratelimit.Decision{}, errors.New("invalid budget")
	}
	return f.decision, f.rateErr
}
func (f *loginHTTPFixture) Resolve(ctx context.Context, route oidcauth.Route) (oidcauth.Metadata, error) {
	f.call(ctx, "metadata")
	return oidcauth.NewMetadata(oidcauth.MetadataParams{Issuer: route.Issuer(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
		TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(), ResponseTypes: []string{"code"},
		CodeChallengeMethods: []string{"S256"}, IDTokenSigningAlgorithms: []string{"RS256"}, TokenAuthMethods: []string{"client_secret_basic"}})
}
func (f *loginHTTPFixture) Begin(ctx context.Context, _ oidcauth.Route) (oidcauth.Transaction, error) {
	f.call(ctx, "begin")
	return f, nil
}
func (f *loginHTTPFixture) Create(ctx context.Context, pending oidcauth.Pending) (oidcauth.Created, error) {
	f.call(ctx, "create")
	f.pending = pending
	return oidcauth.NewCreated(pending.TransactionID(), 1, pending.CreatedAt(), pending.ExpiresAt())
}
func (f *loginHTTPFixture) Commit(ctx context.Context) error {
	f.call(ctx, "commit")
	return f.commitErr
}
func (f *loginHTTPFixture) Rollback(ctx context.Context) error { f.call(ctx, "rollback"); return nil }
func (f *loginHTTPFixture) ResolveCommitted(ctx context.Context, pending oidcauth.Pending) (oidcauth.Created, bool, error) {
	f.call(ctx, "resolve")
	if pending.SemanticHash() != f.pending.SemanticHash() {
		return oidcauth.Created{}, false, errors.New("changed evidence")
	}
	created, err := oidcauth.NewCreated(pending.TransactionID(), 1, pending.CreatedAt(), pending.ExpiresAt())
	return created, f.resolveFound, err
}

func loginHTTPRequest(ctx context.Context, path string) *http.Request {
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://console.example.test"+path, strings.NewReader("{}"))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MeshTransit-Login", "v1")
	request.RemoteAddr = "192.0.2.10:12345"
	return request
}

func (f *loginHTTPFixture) startRequest(t *testing.T) *http.Request {
	t.Helper()
	initiation, err := f.options.Initiation.Prepare(f.now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := initiation.ResponseCookie(f.now)
	if err != nil {
		t.Fatal(err)
	}
	request := loginHTTPRequest(t.Context(), LoginStartPath)
	request.AddCookie(cookie)
	request.Header.Set(oidc.LoginCSRFHeader, initiation.Proof())
	return request
}

func TestLoginHTTPPrepareAndConfirmedStart(t *testing.T) {
	t.Parallel()
	f := newLoginHTTPFixture(t)
	handler, err := NewLoginStartHandler(f.options)
	if err != nil {
		t.Fatal(err)
	}
	prepared := newLoginHTTPRecorder()
	handler.ServeHTTP(prepared, loginHTTPRequest(t.Context(), LoginPreparePath))
	if prepared.Code != 200 || !slices.Equal(f.calls, []string{"rate", "admission"}) || f.outcome != LoginHTTPPrepared {
		t.Fatalf("prepare status=%d effects=%v", prepared.Code, f.calls)
	}
	var proof struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(prepared.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	request := loginHTTPRequest(t.Context(), LoginStartPath)
	for _, cookie := range prepared.Result().Cookies() {
		request.AddCookie(cookie)
	}
	request.Header.Set(oidc.LoginCSRFHeader, proof.Token)
	f.calls = []string{}
	started := newLoginHTTPRecorder()
	f.hook = func(_ context.Context, stage string) {
		if stage == "commit" && (started.Header().Get("Set-Cookie") != "" || started.Body.Len() != 0) {
			t.Fatal("HTTP released secrets before commit")
		}
	}
	handler.ServeHTTP(started, request)
	if started.Code != 200 || !slices.Equal(f.calls, []string{"rate", "admission", "metadata", "begin", "create", "commit"}) || f.outcome != LoginHTTPStarted {
		t.Fatalf("start status=%d effects=%v", started.Code, f.calls)
	}
	var body struct {
		URL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(started.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.URL != f.pending.AuthorizationRequest().Location() || strings.Contains(started.Body.String(), "csrf_token") {
		t.Fatal("response lost exact confirmed URL or retained initiation proof")
	}
	cookies := started.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != oidc.PreAuthCookieName || cookies[1].Name != oidc.LoginInitiationCookieName || cookies[1].MaxAge != -1 {
		t.Fatal("start failed independent pre-auth rotation")
	}
	for _, response := range []*loginHTTPRecorder{prepared, started} {
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" ||
			response.Header().Get("X-Frame-Options") != "DENY" || response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("unsafe browser response policy")
		}
	}
}

func TestLoginHTTPRejectsBoundaryInputBeforeDependencies(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "cleartext", mutate: func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") }},
		{name: "wrong host", mutate: func(r *http.Request) { r.Host = "other.example.test" }},
		{name: "missing origin", mutate: func(r *http.Request) {
			r.Header.Del("Origin")
			r.Header.Set("Referer", "https://console.example.test/")
		}},
		{name: "sibling origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://sibling.example.test") }},
		{name: "duplicate origin", mutate: func(r *http.Request) { r.Header.Add("Origin", r.Header.Get("Origin")) }},
		{name: "missing custom header", mutate: func(r *http.Request) { r.Header.Del("X-MeshTransit-Login") }},
		{name: "get login", mutate: func(r *http.Request) { r.Method = http.MethodGet }},
		{name: "head login", mutate: func(r *http.Request) { r.Method = http.MethodHead }},
		{name: "preflight", mutate: func(r *http.Request) { r.Method = http.MethodOptions }},
		{name: "caller scope", mutate: func(r *http.Request) { r.URL.RawQuery = "workspace=other" }},
		{name: "simple content type", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{name: "oversized headers", mutate: func(r *http.Request) { r.Header.Set("Tracking", strings.Repeat("x", 16385)) }},
		{name: "cross site metadata", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newLoginHTTPFixture(t)
			handler, err := NewLoginStartHandler(f.options)
			if err != nil {
				t.Fatal(err)
			}
			request := f.startRequest(t)
			test.mutate(request)
			response := newLoginHTTPRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || len(f.calls) != 0 || response.Header().Get("Set-Cookie") != "" {
				t.Fatalf("invalid request status=%d effects=%v", response.Code, f.calls)
			}
		})
	}
}

func TestLoginHTTPFailureNeverReleasesCookieOrURL(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*loginHTTPFixture, *http.Request)
		status int
		calls  []string
	}{
		{name: "missing csrf", mutate: func(_ *loginHTTPFixture, r *http.Request) { r.Header.Del(oidc.LoginCSRFHeader) }, status: 403, calls: []string{"rate"}},
		{name: "redis unavailable", mutate: func(f *loginHTTPFixture, _ *http.Request) { f.rateErr = errors.New("secret dependency detail") }, status: 503, calls: []string{"rate"}},
		{name: "malformed limiter", mutate: func(f *loginHTTPFixture, _ *http.Request) { f.decision = ratelimit.Decision{} }, status: 503, calls: []string{"rate"}},
		{name: "admission unavailable", mutate: func(f *loginHTTPFixture, _ *http.Request) { f.admissionErr = errors.New("secret dependency detail") }, status: 503, calls: []string{"rate", "admission"}},
		{name: "commit rejected", mutate: func(f *loginHTTPFixture, _ *http.Request) { f.commitErr = errors.New("secret dependency detail") }, status: 503, calls: []string{"rate", "admission", "metadata", "begin", "create", "commit", "rollback"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newLoginHTTPFixture(t)
			handler, err := NewLoginStartHandler(f.options)
			if err != nil {
				t.Fatal(err)
			}
			request := f.startRequest(t)
			test.mutate(f, request)
			response := newLoginHTTPRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !slices.Equal(f.calls, test.calls) || response.Header().Get("Set-Cookie") != "" ||
				strings.Contains(response.Body.String(), "authorization_url") || strings.Contains(response.Body.String(), "secret dependency detail") {
				t.Fatalf("failure status=%d effects=%v", response.Code, f.calls)
			}
		})
	}
}

func TestLoginHTTPRateLimitedAndNonQueuingConcurrency(t *testing.T) {
	t.Parallel()
	f := newLoginHTTPFixture(t)
	handler, err := NewLoginStartHandler(f.options)
	if err != nil {
		t.Fatal(err)
	}
	f.decision, err = ratelimit.NewDecision(false, 5, 0, 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	response := newLoginHTTPRecorder()
	handler.ServeHTTP(response, f.startRequest(t))
	if response.Code != 429 || response.Header().Get("Retry-After") != "2" || !slices.Equal(f.calls, []string{"rate"}) {
		t.Fatal("invalid shared budget denial")
	}
	for range cap(handler.slots) {
		handler.slots <- struct{}{}
	}
	f.calls = []string{}
	response = newLoginHTTPRecorder()
	handler.ServeHTTP(response, f.startRequest(t))
	if response.Code != 503 || len(f.calls) != 0 {
		t.Fatal("concurrency gate queued or started dependencies")
	}
	for range cap(handler.slots) {
		<-handler.slots
	}
}

func TestLoginHTTPPropagatesDeadlineAndCancellationBetweenEffects(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"rate", "admission", "commit"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			f := newLoginHTTPFixture(t)
			handler, err := NewLoginStartHandler(f.options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := f.startRequest(t).WithContext(ctx)
			f.hook = func(ctx context.Context, name string) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("dependency lost HTTP deadline")
				}
				if name == stage {
					cancel()
				}
			}
			response := newLoginHTTPRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 503 || response.Header().Get("Set-Cookie") != "" || strings.Contains(response.Body.String(), "authorization_url") {
				t.Fatal("canceled request released start")
			}
			if stage == "rate" && len(f.calls) != 1 || stage == "admission" && len(f.calls) != 2 {
				t.Fatal("cancellation did not stop next effect")
			}
		})
	}
}

func TestNewLoginHTTPRejectsUnsafeConstruction(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*LoginStartHandlerOptions){
		func(o *LoginStartHandlerOptions) { o.Initiation = nil }, func(o *LoginStartHandlerOptions) { o.Admission = nil },
		func(o *LoginStartHandlerOptions) { o.Starter = nil }, func(o *LoginStartHandlerOptions) { o.RateLimiter = nil },
		func(o *LoginStartHandlerOptions) { o.RateLimitSubjects = nil }, func(o *LoginStartHandlerOptions) { o.Clock = nil },
		func(o *LoginStartHandlerOptions) { o.Observer = nil }, func(o *LoginStartHandlerOptions) { o.RequestTimeout = 0 },
		func(o *LoginStartHandlerOptions) { o.RequestTimeout = 31 * time.Second }, func(o *LoginStartHandlerOptions) { o.MaxConcurrentRequests = 0 },
		func(o *LoginStartHandlerOptions) { o.SourceRateLimit = ratelimit.Policy{} },
		func(o *LoginStartHandlerOptions) { o.TrustedProxyPrefixes = []netip.Prefix{{}} },
	} {
		f := newLoginHTTPFixture(t)
		mutate(&f.options)
		if _, err := NewLoginStartHandler(f.options); !errors.Is(err, ErrInvalidLoginHTTP) || len(f.calls) != 0 {
			t.Fatal("unsafe construction admitted")
		}
	}
}

func TestLoginHTTPUnknownCommitResolvesOnce(t *testing.T) {
	t.Parallel()
	f := newLoginHTTPFixture(t)
	f.commitErr = oidcauth.ErrCommitOutcomeUnknown
	f.resolveFound = true
	handler, err := NewLoginStartHandler(f.options)
	if err != nil {
		t.Fatal(err)
	}
	response := newLoginHTTPRecorder()
	handler.ServeHTTP(response, f.startRequest(t))
	if response.Code != 200 || !slices.Equal(f.calls, []string{"rate", "admission", "metadata", "begin", "create", "commit", "rollback", "resolve"}) {
		t.Fatalf("unknown commit status=%d effects=%v", response.Code, f.calls)
	}
}

func TestLoginHTTPBodyBoundsAndUnsupportedTransport(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"", "null", "[]", `{"workspace":"other"}`, "{}{}", "{}" + strings.Repeat(" ", 31)} {
		f := newLoginHTTPFixture(t)
		handler, err := NewLoginStartHandler(f.options)
		if err != nil {
			t.Fatal(err)
		}
		request := loginHTTPRequest(t.Context(), LoginPreparePath)
		request.Body = io.NopCloser(strings.NewReader(body))
		request.ContentLength = 0
		response := newLoginHTTPRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 400 || len(f.calls) != 0 || response.Header().Get("Set-Cookie") != "" {
			t.Fatal("malformed body admitted effects")
		}
	}
	f := newLoginHTTPFixture(t)
	handler, err := NewLoginStartHandler(f.options)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, loginHTTPRequest(t.Context(), LoginPreparePath))
	if response.Code != 503 || len(f.calls) != 0 {
		t.Fatal("unsupported transport deadline admitted effects")
	}
}

func TestLoginHTTPRejectsProofExpiryAfterAdmissionOrCommit(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"admission", "commit"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			f := newLoginHTTPFixture(t)
			handler, err := NewLoginStartHandler(f.options)
			if err != nil {
				t.Fatal(err)
			}
			request := f.startRequest(t)
			f.hook = func(_ context.Context, name string) {
				if name == stage {
					f.now = f.now.Add(5 * time.Minute)
				}
			}
			response := newLoginHTTPRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || response.Header().Get("Set-Cookie") != "" || strings.Contains(response.Body.String(), "authorization_url") {
				t.Fatal("expired initiation released start")
			}
			if stage == "admission" && slices.Contains(f.calls, "metadata") {
				t.Fatal("expired intent reached provider discovery")
			}
		})
	}
}

func TestLoginHTTPUsesVerifiedTLSAndRealTransportDeadlines(t *testing.T) {
	t.Parallel()
	f := newLoginHTTPFixture(t)
	server := httptest.NewUnstartedServer(nil)
	guard, err := oidc.NewLoginInitiationGuard(oidc.LoginInitiationOptions{Origin: "https://" + server.Listener.Addr().String(),
		Route: f.options.Initiation.Route(), KeyID: "tls-init-v1", KeyMaterial: bytes.Repeat([]byte{0x45}, 32), Lifetime: time.Minute})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	f.options.Initiation = guard
	handler, err := NewLoginStartHandler(f.options)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+LoginPreparePath, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", server.URL)
	request.Header.Set("X-MeshTransit-Login", "v1")
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	if response.StatusCode != 200 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || !strings.Contains(string(body), "csrf_token") {
		t.Fatal("verified TLS prepare failed")
	}
	var prepared struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(body, &prepared); err != nil {
		t.Fatal(err)
	}
	start, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+LoginStartPath, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	start.Header.Set("Origin", server.URL)
	start.Header.Set("X-MeshTransit-Login", "v1")
	start.Header.Set("Content-Type", "application/json")
	start.Header.Set(oidc.LoginCSRFHeader, prepared.Token)
	for _, cookie := range response.Cookies() {
		start.AddCookie(cookie)
	}
	started, err := server.Client().Do(start)
	if err != nil {
		t.Fatal(err)
	}
	startBody, readErr := io.ReadAll(started.Body)
	closeErr = started.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	if started.StatusCode != 200 || !strings.Contains(string(startBody), "authorization_url") || len(started.Cookies()) != 2 {
		t.Fatal("verified TLS confirmed start failed")
	}
}
