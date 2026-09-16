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

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	adapteroidc "github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
)

type integrationCompletionCallback struct {
	service  *oidcauth.CallbackService
	result   oidcauth.CallbackResult
	err      error
	calls    int
	after    func(oidcauth.CallbackResult)
	override oidcauth.CallbackCommand
}

func (port *integrationCompletionCallback) CompleteBrowser(ctx context.Context, command oidcauth.CallbackCommand) (oidcauth.CallbackResult, error) {
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

func (integrationCompletionBudget) Allow(_ context.Context, _ ratelimit.Subject, policy ratelimit.Policy) (ratelimit.Decision, error) {
	return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
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
			DeploymentID: route.DeploymentID(), WorkspaceID: route.WorkspaceID(), ProviderID: route.ProviderID(),
			ClientID: route.ClientID(), ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
			Issuer: route.Issuer(), DiscoveryURI: route.DiscoveryURI(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
			TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(), OIDCClientID: route.OIDCClientID(),
			ClientKind: "confidential", ClientAuthMethod: route.ClientAuthMethod(), Scopes: route.Scopes(),
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
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, callbackURL.Path+"?"+query.Encode(), nil)
	request.Host = callbackURL.Host
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header.Set("Cookie", adapteroidc.PreAuthCookieName+"="+params.PreAuthCookie.Encoded())
	reader, err := httpapi.NewLoginCallbackReader(httpapi.LoginCallbackReaderOptions{
		Route: params.Route, Observer: httpapi.NewLoginCallbackTelemetry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := reader.Read(ctx, request)
	if err != nil {
		t.Fatal("synthetic callback transport rejected", err)
	}
	codec, err := httpapi.NewLoginCallbackCapsuleCodec(httpapi.LoginCallbackCapsuleOptions{
		Route: params.Route, KeyID: "integration-capture-v1", KeyMaterial: bytes.Repeat([]byte{0x71}, 32),
		Lifetime: time.Minute, Observer: httpapi.NewLoginCapsuleTelemetry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := codec.Capture(ctx, input, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	captured := httptest.NewRecorder()
	if err := capture.WriteRedirect(ctx, captured, time.Now()); err != nil {
		t.Fatal(err)
	}
	capturedResponse := captured.Result()
	cookies := capturedResponse.Cookies()
	if err := capturedResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 {
		t.Fatal("capture cookie missing")
	}
	origin := "https://" + callbackURL.Host
	guard, err := adapteroidc.NewLoginContinuationGuard(adapteroidc.LoginContinuationOptions{
		Route: params.Route, Origin: origin, KeyID: "integration-continuation-v1",
		KeyMaterial: bytes.Repeat([]byte{0x72}, 32), Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
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
	gate, err := httpapi.NewLoginContinuationGate(httpapi.LoginContinuationGateOptions{
		CSRF: guard, Capsule: codec, RateLimitSubjects: digester, RateLimiter: integrationCompletionBudget{},
		SourceRateLimit: policy, StateRateLimit: policy, Clock: options.clock,
		Observer: httpapi.NewLoginContinuationTelemetry(), RequestTimeout: 5 * time.Second, MaxConcurrentRequests: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string) *http.Request {
		request := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader("{}"))
		request.Host, request.RemoteAddr = callbackURL.Host, "192.0.2.10:12345"
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Meshtransit-Login", "v1")
		// A previously stored cookie is syntactic input only. It must never become
		// the new bearer, be validated as provider proof, or be erased on errors.
		request.Header.Set("Cookie", adapteroidc.PreAuthCookieName+"="+params.PreAuthCookie.Encoded()+"; "+
			adapteroidc.LoginCallbackCookieName+"="+cookies[0].Value+"; "+httpapi.AccountSessionCookieName+"=old-synthetic-session")
		return request
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
			options.clock.set(result.Issued().Session().IdleExpiresAt().Add(-500 * time.Millisecond))
		case "canceled before response":
			options.cancel()
		}
	}
	completion, err := httpapi.NewLoginCompletion(httpapi.LoginCompletionOptions{
		Admission: gate, Callback: port, ReturnRouteID: params.Route.ReturnRouteID(), ReturnPath: "/console",
		Observer: httpapi.NewLoginCompletionTelemetry(), RequestTimeout: 25 * time.Second, MaxConcurrent: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	landing, err := httpapi.NewLoginContinuationLanding(httpapi.LoginContinuationLandingOptions{
		Completion: completion, Observer: httpapi.NewLoginLandingTelemetry(),
		RequestTimeout: 5 * time.Second, MaxConcurrent: 2,
	})
	if err != nil {
		t.Fatal(err)
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
		if port.calls != 0 || presented.statusWrites != 1 || presented.Code != http.StatusOK ||
			presented.Header().Get("Set-Cookie") != "" || presented.Header().Get("Location") != "" {
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
	if scenario != "confirmed" && scenario != "provider error" && scenario != "delivery failure" && scenario != "short write" {
		if err == nil || writer.statusWrites != 0 || writer.Body.Len() != 0 || writer.Header().Get("Set-Cookie") != "" {
			t.Fatal("failed/unknown callback wrote credentials or response")
		}
		return
	}
	if scenario == "delivery failure" || scenario == "short write" {
		if !errors.Is(err, httpapi.ErrLoginCompletionDelivery) || port.err != nil || !port.result.Issued().IsValid() ||
			writer.statusWrites != 1 || strings.Contains(err.Error(), "private writer diagnostic") {
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
	if len(cookies) != wantCookies || writer.Header().Get("Location") != "" || writer.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cookie scopes, clean response or no-store lost")
	}
	for _, cookie := range cookies {
		if cookie.Domain != "" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || len(cookie.String()) >= 4096 {
			t.Fatal("unsafe cookie scope/flags/budget")
		}
		if cookie.Name == httpapi.AccountSessionCookieName {
			session := port.result.Issued().Session()
			if cookie.Value != port.result.Issued().Token().Encoded() || cookie.Value == "old-synthetic-session" ||
				cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge < 1 || cookie.MaxAge > 60 ||
				cookie.Expires.After(session.IdleExpiresAt()) || cookie.Expires.After(session.AbsoluteExpiresAt()) {
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
			if cookie.MaxAge != -1 || cookie.Value != "" || cookie.SameSite != expectedSameSite || !cookie.Expires.Before(time.Now()) {
				t.Fatal("transient cookie scope not expired")
			}
		}
	}
	if scenario == "confirmed" && (writer.Code != http.StatusOK || writer.Body.String() != `{"return_path":"/console"}`) {
		t.Fatal("BFF response exposed more than fixed local return path")
	}
	if scenario == "provider error" && (writer.Code != http.StatusForbidden || strings.Contains(writer.Body.String(), "access_denied")) {
		t.Fatal("provider diagnostic or Session escaped no-grant response")
	}
	if token := port.result.Issued().Token().Encoded(); token != "" && strings.Contains(writer.Body.String(), token) {
		t.Fatal("bearer reached JSON")
	}
}
