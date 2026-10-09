//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/adapter/httpapi"
	adapteroidc "meshtransit.net/core/internal/adapter/oidc"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/platform/ratelimit"
)

type integrationCompletionCallback struct {
	service  *oidcauth.CallbackService
	result   oidcauth.CallbackResult
	err      error
	calls    int
	after    func(oidcauth.CallbackResult)
	override oidcauth.CallbackCommand
}

func (port *integrationCompletionCallback) CompleteBrowser(
	ctx context.Context,
	command oidcauth.CallbackCommand,
) (oidcauth.CallbackResult, error) {
	port.calls++
	if port.override.IsValid() {
		command = port.override
	}
	port.result, port.err = port.service.CompleteBrowser(ctx, command)
	if port.err == nil && port.after != nil {
		port.after(port.result)
	}
	return port.result, port.err
}

type integrationCompletionWriter struct {
	*httptest.ResponseRecorder
	statusWrites int
	writeMode    string
}

func (*integrationCompletionWriter) SetReadDeadline(time.Time) error  { return nil }
func (*integrationCompletionWriter) SetWriteDeadline(time.Time) error { return nil }
func (writer *integrationCompletionWriter) WriteHeader(status int) {
	writer.statusWrites++
	writer.ResponseRecorder.WriteHeader(status)
}
func (writer *integrationCompletionWriter) Write(body []byte) (int, error) {
	if writer.writeMode == "delivery failure" {
		return 0, errors.New("private writer diagnostic")
	}
	if writer.writeMode == "short write" {
		return writer.ResponseRecorder.Write(body[:1])
	}
	return writer.ResponseRecorder.Write(body)
}

// This controlled shared-budget port is not live Redis acceptance; transport/CSRF,
// durable callback/issuance and response-cookie authority are the scope of this fixture.
type integrationCompletionBudget struct{}

func (integrationCompletionBudget) Allow(
	_ context.Context,
	_ ratelimit.Subject,
	policy ratelimit.Policy,
) (ratelimit.Decision, error) {
	return ratelimit.NewDecision(
		true,
		policy.Capacity(),
		policy.Capacity()-1,
		0,
	)
}

// Callback qualification must never invoke login initiation or transaction creation.
type integrationCompletionInitiation struct{ test *testing.T }

func (port integrationCompletionInitiation) Admit(context.Context, oidcauth.Route) error {
	port.test.Error("callback fixture invoked initiation admission")
	return errors.New("unexpected fixture initiation")
}

func (port integrationCompletionInitiation) Start(context.Context, oidcauth.Route) (oidcauth.StartResult, error) {
	port.test.Error("callback fixture invoked transaction creation")
	return oidcauth.StartResult{}, errors.New("unexpected fixture initiation")
}

type integrationCompletionClock struct {
	mu     sync.RWMutex
	forced time.Time
}

func (clock *integrationCompletionClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	if !clock.forced.IsZero() {
		return clock.forced
	}
	return time.Now()
}
func (clock *integrationCompletionClock) set(at time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.forced = at
}

type integrationCompletionOptions struct {
	params   oidcauth.CallbackCommandParams
	service  *oidcauth.CallbackService
	scenario string
	clock    *integrationCompletionClock
	cancel   context.CancelFunc
}

func integrationBrowserCompletion(
	ctx context.Context,
	t *testing.T,
	options integrationCompletionOptions,
) (*integrationCompletionCallback, *integrationCompletionWriter, error) {
	t.Helper()
	params, scenario := options.params, options.scenario
	var override oidcauth.CallbackCommand
	if scenario == "wrong response route after commit" {
		var err error
		override, err = oidcauth.NewCallbackCommand(params)
		if err != nil {
			t.Fatal(err)
		}
		route := params.Route
		params.Route, err = oidcauth.NewRoute(oidcauth.RouteParams{
			DeploymentID: route.DeploymentID(), ProviderID: route.ProviderID(),
			ClientID: route.ClientID(), ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
			Issuer: route.Issuer(), DiscoveryURI: route.DiscoveryURI(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
			TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(), OIDCClientID: route.OIDCClientID(),
			ConnectorID: route.ConnectorID(),
			ClientKind:  "confidential", ClientAuthMethod: route.ClientAuthMethod(), Scopes: route.Scopes(),
			AllowedAlgorithms: route.AllowedAlgorithms(), RedirectID: route.RedirectID(), RedirectURI: route.RedirectURI(),
			ReturnRouteID: "other-console",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	callbackURL, err := url.Parse(params.Route.RedirectURI())
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"iss": {params.Route.Issuer()}, "state": {params.State.Encoded()}}
	if params.Kind == oidcauth.CallbackProviderErrorReceived {
		query.Set("error", "access_denied")
	} else {
		query.Set("code", params.Code.Encoded())
	}
	request := httptest.NewRequestWithContext(
		ctx,
		http.MethodGet,
		callbackURL.Path+"?"+query.Encode(),
		nil,
	)
	request.Host = callbackURL.Host
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header.Set("Cookie", adapteroidc.PreAuthCookieName+"="+params.PreAuthCookie.Encoded())
	origin := "https://" + callbackURL.Host
	rateKeyID, err := ratelimit.NewDigestKeyID("integration-completion-rate-v1")
	if err != nil {
		t.Fatal(err)
	}
	digester, err := ratelimit.NewDigester(rateKeyID, bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ratelimit.NewPolicy(20, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	port := &integrationCompletionCallback{service: options.service, override: override}
	port.after = func(result oidcauth.CallbackResult) {
		switch scenario {
		case "continuation expired after commit":
			at := time.Now().Add(2 * time.Minute)
			if !result.IsLiveAt(at) {
				t.Error("continuation expiry case also expired Session/provider evidence")
			}
			options.clock.set(at)
		case "backward clock after commit":
			options.clock.set(result.Issued().Session().AuthenticationTime())
		case "cookie subsecond after commit":
			options.clock.set(result.Issued().Session().AbsoluteExpiresAt().Add(-500 * time.Millisecond))
		case "canceled before response":
			options.cancel()
		}
	}
	browser, err := httpapi.NewBrowserLogin(httpapi.BrowserLoginOptions{
		Route: params.Route, Origin: origin, ReturnPath: "/console",
		InitiationKey:   httpapi.BrowserLoginKey{ID: "integration-initiation-v1", Material: bytes.Repeat([]byte{0x76}, 32)},
		CaptureKey:      httpapi.BrowserLoginKey{ID: "integration-capture-v1", Material: bytes.Repeat([]byte{0x71}, 32)},
		ContinuationKey: httpapi.BrowserLoginKey{ID: "integration-continuation-v1", Material: bytes.Repeat([]byte{0x72}, 32)},
		IntentLifetime:  time.Minute, CaptureLifetime: time.Minute, ContinuationLifetime: time.Minute,
		Admission: integrationCompletionInitiation{test: t}, Starter: integrationCompletionInitiation{test: t},
		Callback:          port,
		RateLimitSubjects: digester, RateLimiter: integrationCompletionBudget{},
		SourceRateLimit: policy, StateRateLimit: policy, Clock: options.clock,
		RequestTimeout: 5 * time.Second, CompletionTimeout: 25 * time.Second, MaxConcurrent: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	captured := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := browser.Capture(captured, request); err != nil {
		t.Fatal("private recipe callback capture rejected", err)
	}
	unexpectedCaptureEffects := port.calls != 0 || captured.statusWrites != 1
	invalidCaptureResponse := captured.Code != http.StatusSeeOther || captured.Body.Len() != 0 ||
		captured.Header().Get("Location") != httpapi.LoginCallbackContinuePath
	if unexpectedCaptureEffects || invalidCaptureResponse {
		t.Fatal("callback GET invoked authority or failed clean zero-body redirect")
	}
	capturedResponse := captured.Result()
	cookies := capturedResponse.Cookies()
	if err := capturedResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 || cookies[0].Name != adapteroidc.LoginCallbackCookieName {
		t.Fatal("capture cookie missing or Session issued on GET")
	}
	gate, completion, landing := browser.Continuation(), browser.Completion(), browser.Landing()
	post := func(path string) *http.Request {
		request := httptest.NewRequestWithContext(
			ctx,
			http.MethodPost,
			path,
			strings.NewReader("{}"),
		)
		request.Host, request.RemoteAddr = callbackURL.Host, "192.0.2.10:12345"
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Meshtransit-Login", "v1")
		// A retained Session is syntax only, never new issuance or provider proof.
		retainedCookies := adapteroidc.PreAuthCookieName + "=" + params.PreAuthCookie.Encoded() + "; " +
			adapteroidc.LoginCallbackCookieName + "=" + cookies[0].Value + "; " +
			httpapi.AccountSessionCookieName + "=old-synthetic-session"
		request.Header.Set("Cookie", retainedCookies)
		return request
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		clean := httptest.NewRequestWithContext(
			ctx,
			method,
			httpapi.LoginCallbackContinuePath,
			nil,
		)
		clean.Host, clean.TLS = callbackURL.Host, request.TLS
		clean.Header.Set("Cookie", post(httpapi.LoginCallbackContinuePath).Header.Get("Cookie"))
		presented := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder()}
		if err := landing.Present(presented, clean); err != nil {
			t.Fatal("clean static landing rejected", err)
		}
		unexpectedLandingEffects := port.calls != 0 || presented.statusWrites != 1
		invalidLandingResponse := presented.Code != http.StatusOK || presented.Header().Get("Set-Cookie") != "" ||
			presented.Header().Get("Location") != ""
		if unexpectedLandingEffects || invalidLandingResponse {
			t.Fatal("GET/HEAD landing touched callback authority/cookies")
		}
		if method == http.MethodHead && presented.Body.Len() != 0 {
			t.Fatal("HEAD landing released active content")
		}
		for _, secret := range []string{params.State.Encoded(), params.PreAuthCookie.Encoded(), cookies[0].Value} {
			if strings.Contains(presented.Body.String(), secret) {
				t.Fatal("landing reflected callback custody")
			}
		}
	}
	prepare := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := gate.Prepare(prepare, post(httpapi.LoginContinuationPreparePath)); err != nil {
		t.Fatal(err)
	}
	var proof struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(prepare.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	request = post(httpapi.LoginCallbackContinuePath)
	request.Header.Set(adapteroidc.LoginCSRFHeader, proof.Token)
	writer := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder(), writeMode: scenario}
	if scenario == "response header budget after commit" {
		writer.Header().Set("X-Controlled-Padding", strings.Repeat("x", 15590))
	}
	completionErr := completion.Complete(writer, request)
	options.clock.set(time.Time{}) // Own and restore this fixture's injected clock before replay checks.
	return port, writer, completionErr
}

func assertBrowserCompletionResponse(
	t *testing.T,
	port *integrationCompletionCallback,
	writer *integrationCompletionWriter,
	err error,
	scenario string,
) {
	t.Helper()
	if port.calls != 1 {
		t.Fatal("HTTP completion did not invoke exactly one callback")
	}
	confirmedResponse := scenario == "confirmed" || scenario == "provider error"
	partialResponse := scenario == "delivery failure" || scenario == "short write"
	if !confirmedResponse && !partialResponse {
		unexpectedDelivery := writer.statusWrites != 0 || writer.Body.Len() != 0
		if err == nil || unexpectedDelivery || writer.Header().Get("Set-Cookie") != "" {
			t.Fatal("failed/unknown callback wrote credentials or response")
		}
		return
	}
	if scenario == "delivery failure" || scenario == "short write" {
		invalidDelivery := !errors.Is(err, httpapi.ErrLoginCompletionDelivery) || port.err != nil
		invalidEvidence := !port.result.Issued().IsValid() || writer.statusWrites != 1
		if invalidDelivery || invalidEvidence || strings.Contains(err.Error(), "private writer diagnostic") {
			t.Fatal("partial response inferred non-commit or hid delivery failure")
		}
	} else if err != nil {
		t.Fatal("confirmed response failed", err)
	}
	response := writer.Result()
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	cookies := response.Cookies()
	wantCookies := 4
	if scenario == "provider error" {
		wantCookies = 3
	}
	invalidResponseHeaders := writer.Header().Get("Location") != "" ||
		writer.Header().Get("Cache-Control") != "no-store"
	if len(cookies) != wantCookies || invalidResponseHeaders {
		t.Fatal("cookie scopes, clean response or no-store lost")
	}
	for _, cookie := range cookies {
		invalidScope := cookie.Domain != "" || cookie.Path != "/"
		invalidFlags := !cookie.Secure || !cookie.HttpOnly
		if invalidScope || invalidFlags || len(cookie.String()) >= 4096 {
			t.Fatal("unsafe cookie scope/flags/budget")
		}
		if cookie.Name == httpapi.AccountSessionCookieName {
			session := port.result.Issued().Session()
			invalidToken := cookie.Value != port.result.Issued().Token().Encoded() || cookie.Value == "old-synthetic-session"
			invalidLifetime := cookie.MaxAge < 1 || cookie.MaxAge > 60*60 ||
				cookie.Expires.After(session.AbsoluteExpiresAt()) ||
				cookie.Expires.Before(session.AbsoluteExpiresAt().Add(-time.Second))
			if invalidToken || cookie.SameSite != http.SameSiteLaxMode || invalidLifetime {
				t.Fatal("Session fixation or expiry/flags widening")
			}
		} else {
			knownScope := cookie.Name == adapteroidc.PreAuthCookieName || cookie.Name == adapteroidc.LoginCallbackCookieName ||
				cookie.Name == adapteroidc.LoginInitiationCookieName
			if !knownScope {
				t.Fatal("unexpected transient cookie scope")
			}
			expectedSameSite := http.SameSiteLaxMode
			if cookie.Name == adapteroidc.LoginInitiationCookieName {
				expectedSameSite = http.SameSiteStrictMode
			}
			invalidRemoval := cookie.MaxAge != -1 || cookie.Value != ""
			invalidExpiry := cookie.SameSite != expectedSameSite || !cookie.Expires.Before(time.Now())
			if invalidRemoval || invalidExpiry {
				t.Fatal("transient cookie scope not expired")
			}
		}
	}
	if scenario == "confirmed" && (writer.Code != http.StatusOK || writer.Body.String() != `{"return_path":"/console"}`) {
		t.Fatal("BFF response exposed more than fixed local return path")
	}
	if scenario == "provider error" &&
		(writer.Code != http.StatusForbidden || strings.Contains(writer.Body.String(), "access_denied")) {
		t.Fatal("provider diagnostic or Session escaped no-grant response")
	}
	if token := port.result.Issued().Token().Encoded(); token != "" && strings.Contains(writer.Body.String(), token) {
		t.Fatal("bearer reached JSON")
	}
}
