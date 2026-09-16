package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/goleak"
)

func browserLoginTestOptions(t *testing.T) (BrowserLoginOptions, *loginHTTPFixture, *completionTestPort) {
	t.Helper()
	fixture := newLoginHTTPFixture(t)
	callback := &completionTestPort{}
	return BrowserLoginOptions{
		Route: fixture.options.Initiation.Route(), Origin: fixture.options.Initiation.Origin(), ReturnPath: "/console",
		InitiationKey:   BrowserLoginKey{ID: "browser-init-v1", Material: bytes.Repeat([]byte{0x51}, 32)},
		CaptureKey:      BrowserLoginKey{ID: "browser-capture-v1", Material: bytes.Repeat([]byte{0x52}, 32)},
		ContinuationKey: BrowserLoginKey{ID: "browser-continue-v1", Material: bytes.Repeat([]byte{0x53}, 32)},
		IntentLifetime:  time.Minute, CaptureLifetime: time.Minute, ContinuationLifetime: time.Minute,
		Admission: fixture.options.Admission, Starter: fixture.options.Starter, Callback: callback,
		RateLimitSubjects: fixture.options.RateLimitSubjects, RateLimiter: fixture,
		SourceRateLimit: fixture.options.SourceRateLimit, StateRateLimit: fixture.options.SourceRateLimit,
		Clock: fixture, RequestTimeout: 2 * time.Second, CompletionTimeout: 3 * time.Second, MaxConcurrent: 2,
	}, fixture, callback
}

func TestBrowserLoginConstructionAndCaptureNeverGrantAuthority(t *testing.T) {
	t.Parallel()
	options, fixture, callback := browserLoginTestOptions(t)
	browser, err := NewBrowserLogin(options)
	invalidConstruction := err != nil || browser == nil
	unexpectedEffects := len(fixture.calls) != 0 || callback.calls != 0
	if invalidConstruction || unexpectedEffects {
		t.Fatal("constructor touched application/budget ports", err)
	}
	request := callbackReaderRequest(t.Context(), options.Route)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Capture(response, request); err != nil {
		t.Fatal(err)
	}
	invalidStatus := response.Code != http.StatusSeeOther || response.statusWrites != 1
	invalidRedirect := response.Body.Len() != 0 || response.Header().Get("Location") != LoginCallbackContinuePath
	unexpectedCaptureEffects := callback.calls != 0 || len(fixture.calls) != 2
	if invalidStatus || invalidRedirect || unexpectedCaptureEffects {
		t.Fatal("GET captured authority, active content or unexpected effects")
	}
	missingAdmission := browser.Initiation() == nil || browser.Continuation() == nil
	missingCompletion := browser.Completion() == nil || browser.Landing() == nil
	if missingAdmission || missingCompletion {
		t.Fatal("private composition incomplete")
	}
}

func TestBrowserLoginRejectsReusedKeyPurposesBeforeEffects(t *testing.T) {
	t.Parallel()
	options, fixture, callback := browserLoginTestOptions(t)
	options.CaptureKey.Material = options.InitiationKey.Material
	browser, err := NewBrowserLogin(options)
	invalidRejection := browser != nil || !errors.Is(err, ErrInvalidBrowserLogin)
	unexpectedEffects := len(fixture.calls) != 0 || callback.calls != 0
	if invalidRejection || unexpectedEffects {
		t.Fatal("key-purpose reuse passed construction")
	}
}

func TestBrowserLoginRejectsIncompleteProfilesBeforeEffects(t *testing.T) {
	t.Parallel()
	var missing *loginHTTPFixture
	var missingCallback *completionTestPort
	for _, test := range []struct {
		name   string
		change func(*BrowserLoginOptions)
	}{
		{name: "nil admission", change: func(o *BrowserLoginOptions) { o.Admission = nil }},
		{name: "typed nil admission", change: func(o *BrowserLoginOptions) { o.Admission = missing }},
		{name: "nil starter", change: func(o *BrowserLoginOptions) { o.Starter = nil }},
		{name: "nil callback", change: func(o *BrowserLoginOptions) { o.Callback = nil }},
		{name: "typed nil callback", change: func(o *BrowserLoginOptions) { o.Callback = missingCallback }},
		{name: "typed nil limiter", change: func(o *BrowserLoginOptions) { o.RateLimiter = missing }},
		{name: "nil digester", change: func(o *BrowserLoginOptions) { o.RateLimitSubjects = nil }},
		{name: "typed nil clock", change: func(o *BrowserLoginOptions) { o.Clock = missing }},
		{name: "zero route", change: func(o *BrowserLoginOptions) { o.Route = oidcauth.Route{} }},
		{name: "foreign origin", change: func(o *BrowserLoginOptions) { o.Origin = "https://foreign.example.test" }},
		{name: "unsafe return", change: func(o *BrowserLoginOptions) { o.ReturnPath = "//foreign.example.test" }},
		{name: "zero timeout", change: func(o *BrowserLoginOptions) { o.RequestTimeout = 0 }},
		{name: "long timeout", change: func(o *BrowserLoginOptions) { o.RequestTimeout = 31 * time.Second }},
		{name: "zero completion timeout", change: func(o *BrowserLoginOptions) { o.CompletionTimeout = 0 }},
		{name: "long completion timeout", change: func(o *BrowserLoginOptions) { o.CompletionTimeout = 31 * time.Second }},
		{name: "zero capacity", change: func(o *BrowserLoginOptions) { o.MaxConcurrent = 0 }},
		{name: "large capacity", change: func(o *BrowserLoginOptions) { o.MaxConcurrent = 129 }},
		{name: "zero source policy", change: func(o *BrowserLoginOptions) { o.SourceRateLimit = ratelimit.Policy{} }},
		{name: "zero state policy", change: func(o *BrowserLoginOptions) { o.StateRateLimit = ratelimit.Policy{} }},
		{name: "init key id", change: func(o *BrowserLoginOptions) { o.InitiationKey.ID = "bad id" }},
		{name: "capture key id", change: func(o *BrowserLoginOptions) { o.CaptureKey.ID = "bad id" }},
		{name: "continue key id", change: func(o *BrowserLoginOptions) { o.ContinuationKey.ID = "bad id" }},
		{name: "equal key id", change: func(o *BrowserLoginOptions) { o.CaptureKey.ID = o.InitiationKey.ID }},
		{name: "equal continue material", change: func(o *BrowserLoginOptions) {
			o.ContinuationKey.Material = o.CaptureKey.Material
		}},
		{name: "short key", change: func(o *BrowserLoginOptions) { o.CaptureKey.Material = []byte{1} }},
		{name: "zero key", change: func(o *BrowserLoginOptions) { o.ContinuationKey.Material = make([]byte, 32) }},
		{name: "init lifetime", change: func(o *BrowserLoginOptions) { o.IntentLifetime = 0 }},
		{name: "capture lifetime", change: func(o *BrowserLoginOptions) { o.CaptureLifetime = 121 * time.Second }},
		{name: "continue lifetime", change: func(o *BrowserLoginOptions) { o.ContinuationLifetime += time.Millisecond }},
		{name: "unsafe proxy", change: func(o *BrowserLoginOptions) {
			o.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		}},
		{name: "too many proxies", change: func(o *BrowserLoginOptions) {
			o.TrustedProxyPrefixes = make([]netip.Prefix, 17)
		}},
		{name: "duplicate proxies", change: func(o *BrowserLoginOptions) {
			prefix := netip.MustParsePrefix("192.0.2.0/24")
			o.TrustedProxyPrefixes = []netip.Prefix{prefix, prefix}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, fixture, callback := browserLoginTestOptions(t)
			test.change(&options)
			browser, err := NewBrowserLogin(options)
			invalidRejection := browser != nil || !errors.Is(err, ErrInvalidBrowserLogin)
			unexpectedEffects := len(fixture.calls) != 0 || callback.calls != 0
			if invalidRejection || unexpectedEffects {
				t.Fatal("invalid profile reached effects", err)
			}
		})
	}
	for _, path := range []string{
		LoginPreparePath, LoginStartPath, LoginCallbackContinuePath, LoginContinuationPreparePath,
	} {
		t.Run("overlapping callback "+path, func(t *testing.T) {
			t.Parallel()
			options, fixture, callback := browserLoginTestOptions(t)
			params := capsuleTestRouteParams(options.Route)
			params.RedirectURI = options.Origin + path
			var err error
			options.Route, err = oidcauth.NewRoute(params)
			if err != nil {
				t.Fatal(err)
			}
			browser, err := NewBrowserLogin(options)
			invalidRejection := browser != nil || !errors.Is(err, ErrInvalidBrowserLogin)
			unexpectedEffects := len(fixture.calls) != 0 || callback.calls != 0
			if invalidRejection || unexpectedEffects {
				t.Fatal("overlapping browser routes constructed")
			}
		})
	}
}

func TestBrowserLoginImmutableProfileAndProtectedContinuation(t *testing.T) {
	t.Parallel()
	options, fixture, callback := browserLoginTestOptions(t)
	subjects := &browserSubjectRecorder{delegate: options.RateLimitSubjects, raw: []string{}}
	options.RateLimitSubjects = subjects
	options.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	clear(options.InitiationKey.Material)
	clear(options.CaptureKey.Material)
	clear(options.ContinuationKey.Material)
	options.TrustedProxyPrefixes[0] = netip.MustParsePrefix("198.51.100.0/24")
	request := callbackReaderRequest(t.Context(), options.Route)
	request.Header.Set("X-Forwarded-For", "198.51.100.23")
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Capture(response, request); err != nil {
		t.Fatal("caller mutation changed capture", err)
	}
	wantSource := "browser-login-capture-source/v1\x00" + options.Route.DeploymentID().String() + "\x00198.51.100.23"
	wantState := "browser-login-capture-state/v1\x00" + options.Route.DeploymentID().String() +
		"\x00" + callbackReaderHandle(0x61)
	invalidSubjects := len(subjects.raw) != 2 || subjects.raw[0] != wantSource || subjects.raw[1] != wantState
	if invalidSubjects {
		t.Fatal("caller proxy mutation changed observable budget subjects or purposes")
	}
	result := response.Result()
	cookies := result.Cookies()
	if err := result.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 {
		t.Fatal("capture cookie scope widened")
	}
	invalidNameAndFlags := cookies[0].Name != oidc.LoginCallbackCookieName || !cookies[0].Secure || !cookies[0].HttpOnly
	invalidScope := cookies[0].Domain != "" || cookies[0].Path != "/"
	if invalidNameAndFlags || invalidScope {
		t.Fatal("capture cookie scope widened")
	}
	headers := request.Header.Clone()
	headers.Del("X-Forwarded-For")
	headers.Set("Cookie", headers.Get("Cookie")+"; "+cookies[0].Name+"="+cookies[0].Value)
	prepare := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	prepareRequest := continuationGateRequest(t.Context(), headers, LoginContinuationPreparePath)
	if err := browser.Continuation().Prepare(prepare, prepareRequest); err != nil {
		t.Fatal("coherent current capsule/CSRF rejected", err)
	}
	var proof struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(prepare.Body.Bytes(), &proof); err != nil || proof.Token == "" {
		t.Fatal("fresh proof missing", err)
	}
	post := continuationGateRequest(t.Context(), headers, LoginCallbackContinuePath)
	post.Header.Set(oidc.LoginCSRFHeader, proof.Token)
	completed := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	completionErr := browser.Completion().Complete(completed, post)
	invalidCompletion := completionErr == nil || callback.calls != 1
	unexpectedResponse := completed.statusWrites != 0 || completed.Body.Len() != 0 ||
		completed.Header().Get("Set-Cookie") != ""
	if invalidCompletion || unexpectedResponse {
		t.Fatal("zero callback result became Session authority")
	}
	for _, call := range fixture.calls {
		if call != "rate" {
			t.Fatal("capture/continuation invoked start/application authority")
		}
	}
	// A landing sees no custody and performs no additional budget/application effect.
	before := len(fixture.calls)
	landing := landingTestRequest().WithContext(t.Context())
	landing.Header = headers.Clone()
	page := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	landingErr := browser.Landing().Present(page, landing)
	unexpectedLandingEffects := len(fixture.calls) != before || callback.calls != 1
	if landingErr != nil || unexpectedLandingEffects {
		t.Fatal("GET landing gained effects", landingErr)
	}
}

type browserSubjectRecorder struct {
	delegate RateLimitSubjectDigester
	raw      []string
}

func (recorder *browserSubjectRecorder) Subject(kind ratelimit.SubjectKind, raw string) (ratelimit.Subject, error) {
	recorder.raw = append(recorder.raw, raw)
	return recorder.delegate.Subject(kind, raw)
}

func TestBrowserLoginInitiationUsesItsOwnCopiedKeyAndTrustedRoute(t *testing.T) {
	t.Parallel()
	options, fixture, callback := browserLoginTestOptions(t)
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	clear(options.InitiationKey.Material)
	prepare := newLoginHTTPRecorder()
	browser.Initiation().ServeHTTP(prepare, loginHTTPRequest(t.Context(), LoginPreparePath))
	var proof struct {
		Token string `json:"csrf_token"`
	}
	proofErr := json.Unmarshal(prepare.Body.Bytes(), &proof)
	invalidPreparation := proof.Token == "" || prepare.Code != http.StatusOK
	if proofErr != nil || invalidPreparation {
		t.Fatal("private initiation prepare rejected copied key", proofErr)
	}
	prepared := prepare.Result()
	cookies := prepared.Cookies()
	if err := prepared.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 || cookies[0].Name != oidc.LoginInitiationCookieName {
		t.Fatal("initiation cookie missing")
	}
	request := loginHTTPRequest(t.Context(), LoginStartPath)
	request.Header.Set("Cookie", cookies[0].Name+"="+cookies[0].Value)
	request.Header.Set(oidc.LoginCSRFHeader, proof.Token)
	response := newLoginHTTPRecorder()
	browser.Initiation().ServeHTTP(response, request)
	var authorization struct {
		URL string `json:"authorization_url"`
	}
	authorizationErr := json.Unmarshal(response.Body.Bytes(), &authorization)
	invalidAuthorization := response.Code != http.StatusOK ||
		!strings.HasPrefix(authorization.URL, options.Route.AuthorizationEndpoint()+"?")
	unexpectedInitiationEffects := !fixture.pending.IsValid() || callback.calls != 0
	if authorizationErr != nil || invalidAuthorization || unexpectedInitiationEffects {
		t.Fatal("private initiation did not use the trusted creation port/route", authorizationErr)
	}
	result := response.Result()
	defer func() {
		if err := result.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, cookie := range result.Cookies() {
		if cookie.Name == AccountSessionCookieName || cookie.Name == oidc.LoginCallbackCookieName {
			t.Fatal("initiation issued Session/callback custody")
		}
	}
}

func TestBrowserLoginCaptureFailClosedAndNoReflection(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"foreign host", "post", "query alias", "missing cookie", "authorization", "empty authorization",
		"preexisting cookie",
		"alternate navigation", "combined header budget", "canceled", "deadline unsupported", "budget error", "source denied",
		"state denied", "malformed decision", "budget cancellation", "release expiry", "backward release"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			options, fixture, callback := browserLoginTestOptions(t)
			browser, err := NewBrowserLogin(options)
			if err != nil {
				t.Fatal(err)
			}
			request := callbackReaderRequest(t.Context(), options.Route)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			var writer http.ResponseWriter = response
			var unsupportedTransport *httptest.ResponseRecorder
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request = request.WithContext(ctx)
			budgetCalls := 0
			fixture.hook = func(_ context.Context, name string) {
				if name != "rate" {
					t.Error("capture called authority")
				}
				budgetCalls++
				if mode == "state denied" && budgetCalls == 2 {
					fixture.decision, _ = ratelimit.NewDecision(
						false,
						5,
						0,
						time.Second,
					)
				}
				if mode == "budget cancellation" {
					cancel()
				}
			}
			switch mode {
			case "foreign host":
				request.Host = "foreign.example.test"
			case "post":
				request.Method = http.MethodPost
			case "query alias":
				setCallbackQuery(request, request.URL.RawQuery+"&%73tate=alias")
			case "missing cookie":
				request.Header.Del("Cookie")
			case "authorization":
				request.Header.Set("Authorization", "Bearer private-token")
			case "empty authorization":
				request.Header.Set("Authorization", "")
			case "preexisting cookie":
				response.Header().Set("Set-Cookie", "private-cookie")
			case "alternate navigation":
				response.Header().Set("Refresh", "0;url=https://foreign.example.test")
			case "combined header budget":
				response.Header().Set("X-Padding", strings.Repeat("x", 16000))
			case "canceled":
				cancel()
			case "deadline unsupported":
				unsupportedTransport = httptest.NewRecorder()
				writer = unsupportedTransport
			case "budget error":
				fixture.rateErr = errors.New("private-dependency-token")
			case "source denied":
				fixture.decision, _ = ratelimit.NewDecision(
					false,
					5,
					0,
					time.Second,
				)
			case "malformed decision":
				fixture.decision = ratelimit.Decision{}
			case "release expiry", "backward release":
				clock := &browserReleaseClock{at: fixture.now, mode: mode}
				browser.gate.options.Clock = clock
			}
			before := response.Header().Clone()
			actualWriterBefore := writer.Header().Clone()
			err = browser.Capture(writer, request)
			if err == nil {
				t.Fatal("capture failure wrote/reflected/granted", err)
			}
			unexpectedEffects := callback.calls != 0 || response.statusWrites != 0 || response.Body.Len() != 0
			reflectedInput := fmt.Sprint(response.Header()) != fmt.Sprint(before) ||
				strings.Contains(err.Error(), "private-dependency-token")
			if unexpectedEffects || reflectedInput {
				t.Fatal("capture failure wrote/reflected/granted", err)
			}
			if unsupportedTransport != nil {
				unexpectedTransportResponse := unsupportedTransport.Code != http.StatusOK ||
					unsupportedTransport.Body.Len() != 0 ||
					fmt.Sprint(unsupportedTransport.Header()) != fmt.Sprint(actualWriterBefore)
				unexpectedBudgetEffects := budgetCalls != 0 || len(fixture.calls) != 0
				if unexpectedTransportResponse || unexpectedBudgetEffects ||
					!errors.Is(err, ErrBrowserCaptureUnavailable) {
					t.Fatal("unsupported actual transport released response or touched shared budgets", err)
				}
			}
			if mode == "source denied" || mode == "state denied" {
				if !errors.Is(err, ErrBrowserCaptureLimited) {
					t.Fatal("shared rejection classification lost")
				}
			}
		})
	}
}

type browserReleaseClock struct {
	at    time.Time
	calls int
	mode  string
}

func (clock *browserReleaseClock) Now() time.Time {
	clock.calls++
	if clock.calls >= 3 {
		if clock.mode == "backward release" {
			return clock.at.Add(-time.Second)
		}
		return clock.at.Add(time.Minute)
	}
	return clock.at
}

func TestBrowserLoginCaptureClampsTransportAndJoinsCancellation(t *testing.T) {
	t.Parallel()
	options, fixture, _ := browserLoginTestOptions(t)
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	defer cancel()
	response := &completionDeadlineRecorder{
		continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
	}
	fixture.hook = func(ctx context.Context, _ string) {
		deadline, ok := ctx.Deadline()
		invalidContext := !ok || ctx.Err() != nil
		invalidTransport := len(response.read) != 1 || len(response.write) != 1
		if invalidContext || invalidTransport || !deadline.Equal(response.read[0]) || !deadline.Equal(response.write[0]) {
			t.Error("lost caller transport/context budget")
		}
	}
	if err := browser.Capture(response, callbackReaderRequest(ctx, options.Route)); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"read", "write"} {
		broken := &browserDeadlineFailure{
			continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
			failure:                    failure,
		}
		before := len(fixture.calls)
		captureErr := browser.Capture(broken, callbackReaderRequest(ctx, options.Route))
		unexpectedEffects := len(fixture.calls) != before || broken.statusWrites != 0
		if !errors.Is(captureErr, ErrBrowserCaptureUnavailable) || unexpectedEffects {
			t.Fatal("unsupported deadlines reached effects")
		}
	}
}

type browserDeadlineFailure struct {
	*continuationStatusRecorder
	failure string
}

func (writer *browserDeadlineFailure) SetReadDeadline(time.Time) error {
	if writer.failure == "read" {
		return errors.New("private transport")
	}
	return nil
}
func (writer *browserDeadlineFailure) SetWriteDeadline(time.Time) error {
	if writer.failure == "write" {
		return errors.New("private transport")
	}
	return nil
}

type browserBlockingSubmission struct {
	*continuationStatusRecorder
	entered chan struct{}
	release chan struct{}
}

func (writer *browserBlockingSubmission) WriteHeader(status int) {
	close(writer.entered)
	<-writer.release
	writer.continuationStatusRecorder.WriteHeader(status)
}

func TestBrowserLoginCaptureCapacityHeldThroughSubmission(t *testing.T) {
	// Process-global leak inspection stays serial and outside synthetic-clock bubbles.
	defer goleak.VerifyNone(t)
	options, fixture, _ := browserLoginTestOptions(t)
	options.MaxConcurrent = 1
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	writer := &browserBlockingSubmission{
		continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
		entered:                    make(chan struct{}), release: make(chan struct{}),
	}
	joined := make(chan error, 1)
	go func() { joined <- browser.Capture(writer, callbackReaderRequest(t.Context(), options.Route)) }()
	<-writer.entered
	rejected := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	captureErr := browser.Capture(rejected, callbackReaderRequest(t.Context(), options.Route))
	unexpectedResponse := rejected.statusWrites != 0 || rejected.Body.Len() != 0
	if !errors.Is(captureErr, ErrBrowserCaptureSaturated) || unexpectedResponse {
		t.Error("capture admission queued or released early")
	}
	close(writer.release)
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	if len(fixture.calls) != 2 {
		t.Fatal("saturated request consumed shared budget")
	}
	if err := browser.Capture(rejected, callbackReaderRequest(t.Context(), options.Route)); err != nil {
		t.Fatal("joined slot not reusable", err)
	}
}

func TestBrowserLoginRejectsMissingCaptureOwnershipAndRedactsProfile(t *testing.T) {
	t.Parallel()
	options, _, _ := browserLoginTestOptions(t)
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	var missing *BrowserLogin
	var writer *continuationStatusRecorder
	for _, call := range []struct {
		name    string
		browser *BrowserLogin
		writer  http.ResponseWriter
		request *http.Request
	}{
		{name: "nil owner", browser: missing, writer: newLoginHTTPRecorder(),
			request: callbackReaderRequest(t.Context(), options.Route)},
		{name: "zero owner", browser: &BrowserLogin{}, writer: newLoginHTTPRecorder(),
			request: callbackReaderRequest(t.Context(), options.Route)},
		{name: "typed nil writer", browser: browser, writer: writer,
			request: callbackReaderRequest(t.Context(), options.Route)},
		{name: "nil request", browser: browser, writer: newLoginHTTPRecorder()},
	} {
		t.Run(call.name, func(t *testing.T) {
			if err := call.browser.Capture(call.writer, call.request); !errors.Is(err, ErrBrowserCaptureUnavailable) {
				t.Fatal("absent capture ownership accepted")
			}
		})
	}
	for _, value := range []any{options, options.CaptureKey, browser} {
		text := fmt.Sprintf("%v %#v", value, value)
		leakedConfiguration := strings.Contains(text, options.Origin) || strings.Contains(text, options.CaptureKey.ID)
		if leakedConfiguration || strings.Contains(text, "Material") {
			t.Fatal("private configuration leaked through formatting")
		}
	}
	for _, value := range []any{options, options.CaptureKey} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("resident profile serialized")
		}
	}
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(browser.MetricsCollector()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Gather(); err != nil {
		t.Fatal("isolated composition collector invalid", err)
	}
}

func TestBrowserLoginCaptureVerifiedHTTPS(t *testing.T) {
	t.Parallel()
	options, _, callback := browserLoginTestOptions(t)
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := browser.Capture(w, r); err != nil {
			http.Error(w, "capture rejected", http.StatusForbidden)
		}
	}))
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.ReadTimeout = 3 * time.Second
	server.Config.WriteTimeout = 3 * time.Second
	server.Config.IdleTimeout = 3 * time.Second
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("HTTPS test lacks verified test-CA trust")
	}
	if transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HTTPS test lacks verified test-CA trust")
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	t.Cleanup(transport.CloseIdleConnections)
	synthetic := callbackReaderRequest(t.Context(), options.Route)
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		server.URL+synthetic.RequestURI,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Host, request.Header = synthetic.Host, synthetic.Header.Clone()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	invalidStatusAndBody := response.StatusCode != http.StatusSeeOther || response.ContentLength != 0
	invalidRedirectAndCookie := response.Header.Get("Location") != LoginCallbackContinuePath ||
		len(response.Cookies()) != 1
	if invalidStatusAndBody || invalidRedirectAndCookie || callback.calls != 0 {
		t.Fatal("verified HTTPS capture changed method/destination/cookie authority")
	}
	parsed, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal("redirect retained callback target")
	}
	unexpectedCallbackTarget := parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != ""
	if unexpectedCallbackTarget {
		t.Fatal("redirect retained callback target")
	}
}

func FuzzBrowserLoginCaptureHTTP(f *testing.F) {
	validQuery := url.Values{
		"state": {callbackReaderHandle(0x61)},
		"iss":   {"https://login.example.test/realms/meshtransit"},
		"code":  {"synthetic-code+exact=/value"},
	}.Encode()
	f.Add(
		validQuery,
		"",
		"GET",
		"console.example.test",
	)
	f.Add(
		"state=a&iss=x&code=z",
		"",
		"GET",
		"console.example.test",
	)
	f.Fuzz(func(t *testing.T, query, rawPath, method, host string) {
		options, fixture, callback := browserLoginTestOptions(t)
		browser, err := NewBrowserLogin(options)
		if err != nil {
			t.Fatal(err)
		}
		request := callbackReaderRequest(t.Context(), options.Route)
		setCallbackQuery(request, query)
		request.URL.RawPath, request.Method, request.Host = rawPath, method, host
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		err = browser.Capture(response, request)
		if callback.calls != 0 || response.Body.Len() != 0 {
			t.Fatal("fuzzed GET created authority/active content")
		}
		for _, call := range fixture.calls {
			if call != "rate" {
				t.Fatal("fuzzed capture invoked authority")
			}
		}
		if err != nil && (response.statusWrites != 0 || len(response.Header()) != 0) {
			t.Fatal("rejected capture released response")
		}
		invalidRedirect := response.Code != http.StatusSeeOther ||
			response.Header().Get("Location") != LoginCallbackContinuePath
		if err == nil && (invalidRedirect || strings.Contains(response.Header().Get("Set-Cookie"), "synthetic-code")) {
			t.Fatal("capture reflected input or changed destination")
		}
	})
}
