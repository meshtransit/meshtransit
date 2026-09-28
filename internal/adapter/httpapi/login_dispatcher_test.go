package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func dispatcherTestGraph(t *testing.T) (*LoginDispatcher, *loginHTTPFixture, *completionTestPort) {
	t.Helper()
	dispatcher, fixture, callback, _ := dispatcherTestGraphWithManagement(t)
	return dispatcher, fixture, callback
}

func dispatcherTestGraphWithManagement(
	t *testing.T,
) (*LoginDispatcher, *loginHTTPFixture, *completionTestPort, *browserManagementFixture) {
	t.Helper()
	options, fixture, callback := browserLoginTestOptions(t)
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	managementOptions, managementFixture := browserManagementTestOptions(t)
	managementOptions.DeploymentID = options.Route.DeploymentID()
	managementOptions.Origin = options.Origin
	management, err := NewBrowserManagement(managementOptions)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewLoginDispatcher(browser, management)
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher, fixture, callback, managementFixture
}

func dispatcherTestInitiationRequest(ctx context.Context, path string) *http.Request {
	request := loginHTTPRequest(ctx, path)
	request.URL.Scheme, request.URL.Host = "", ""
	request.RequestURI = path
	request.TLS.HandshakeComplete = true
	return request
}

func TestLoginDispatcherRejectsIncompleteConstruction(t *testing.T) {
	t.Parallel()
	management, _ := newBrowserManagementFixture(t)
	for _, browser := range []*BrowserLogin{nil, {}, {start: &LoginStartHandler{}}} {
		dispatcher, err := NewLoginDispatcher(browser, management)
		if dispatcher != nil || !errors.Is(err, ErrInvalidLoginDispatcher) {
			t.Fatal("incomplete browser graph released a dispatcher")
		}
	}
	options, _, _ := browserLoginTestOptions(t)
	browser, err := NewBrowserLogin(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, incomplete := range []*BrowserManagement{nil, {}} {
		dispatcher, err := NewLoginDispatcher(browser, incomplete)
		if dispatcher != nil || !errors.Is(err, ErrInvalidLoginDispatcher) {
			t.Fatal("incomplete management graph released a dispatcher")
		}
	}
	for _, path := range []string{
		AccountSessionCSRFPreparePath, AccountSessionLogoutPath, "/machine/register", "/api/v1/callback", "/key",
		"/auth/" + strings.Repeat("x", 251),
	} {
		options, fixture, callback := browserLoginTestOptions(t)
		params := capsuleTestRouteParams(options.Route)
		params.RedirectURI = options.Origin + path
		var err error
		options.Route, err = oidcauth.NewRoute(params)
		if err != nil {
			t.Fatal(err)
		}
		browser, err := NewBrowserLogin(options)
		if err != nil {
			t.Fatal("standalone browser contract changed", err)
		}
		dispatcher, err := NewLoginDispatcher(browser, management)
		if dispatcher != nil || !errors.Is(err, ErrInvalidLoginDispatcher) || len(fixture.calls) != 0 || callback.calls != 0 {
			t.Fatal("callback route overlaps another profile or construction performed effects")
		}
	}
}

func TestLoginDispatcherRejectsRoutingWithoutEffectsOrResponse(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*http.Request)
	}{
		{name: "get prepare", change: func(r *http.Request) { r.Method = http.MethodGet }},
		{name: "head callback", change: func(r *http.Request) {
			r.Method = http.MethodHead
			r.URL.Path = "/auth/callback"
			r.RequestURI = r.URL.Path
		}},
		{name: "options", change: func(r *http.Request) { r.Method = http.MethodOptions }},
		{name: "foreign host", change: func(r *http.Request) { r.Host = "foreign.example.test" }},
		{name: "incomplete tls", change: func(r *http.Request) { r.TLS.HandshakeComplete = false }},
		{name: "no tls", change: func(r *http.Request) { r.TLS = nil }},
		{name: "absolute target", change: func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = r.Host }},
		{name: "raw path", change: func(r *http.Request) { r.URL.RawPath = r.URL.Path }},
		{name: "target mismatch", change: func(r *http.Request) { r.RequestURI = "/auth/other" }},
		{name: "query", change: func(r *http.Request) {
			r.URL.RawQuery = "state=private"
			r.RequestURI = r.URL.RequestURI()
		}},
		{name: "empty query marker", change: func(r *http.Request) { r.URL.ForceQuery = true }},
		{name: "fragment", change: func(r *http.Request) { r.URL.Fragment = "private" }},
		{name: "raw fragment", change: func(r *http.Request) { r.URL.RawFragment = "private" }},
		{name: "userinfo", change: func(r *http.Request) { r.URL.User = url.User("private") }},
		{name: "opaque", change: func(r *http.Request) { r.URL.Opaque = "private" }},
		{name: "authorization empty", change: func(r *http.Request) { r.Header["Authorization"] = []string{} }},
		{name: "noncanonical header", change: func(r *http.Request) { r.Header["authorization"] = []string{"private"} }},
		{name: "trailing path", change: func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.Path }},
		{name: "double path", change: func(r *http.Request) {
			r.URL.Path = "/auth//v1/login/prepare"
			r.RequestURI = r.URL.Path
		}},
		{name: "dot path", change: func(r *http.Request) {
			r.URL.Path = "/auth/v1/../v1/login/prepare"
			r.RequestURI = r.URL.Path
		}},
		{name: "get management prepare", change: func(r *http.Request) {
			r.URL.Path = AccountSessionCSRFPreparePath
			r.RequestURI = r.URL.Path
			r.Method = http.MethodGet
		}},
		{name: "get session logout", change: func(r *http.Request) {
			r.URL.Path = AccountSessionLogoutPath
			r.RequestURI = r.URL.Path
			r.Method = http.MethodGet
		}},
		{name: "client route", change: func(r *http.Request) { r.URL.Path = "/machine/register"; r.RequestURI = r.URL.Path }},
		{name: "unknown path", change: func(r *http.Request) { r.URL.Path = "/auth/private"; r.RequestURI = r.URL.Path }},
		{name: "no url", change: func(r *http.Request) { r.URL = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dispatcher, fixture, callback := dispatcherTestGraph(t)
			request := dispatcherTestInitiationRequest(t.Context(), LoginPreparePath)
			test.change(request)
			body := &dispatchBodySpy{}
			request.Body = body
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := dispatcher.Handle(response, request)
			if !errors.Is(err, ErrInvalidLoginDispatcher) || response.statusWrites != 0 || response.Body.Len() != 0 ||
				len(response.Header()) != 0 || len(fixture.calls) != 0 || callback.calls != 0 || body.reads != 0 {
				t.Fatal("routing rejection delegated, read authority or mutated response", err)
			}
		})
	}
}

type dispatchBodySpy struct{ reads int }

func (body *dispatchBodySpy) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}
func (*dispatchBodySpy) Close() error { return nil }

func TestLoginDispatcherRejectsMethodAliases(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		LoginPreparePath, LoginStartPath, LoginContinuationPreparePath, AccountSessionCSRFPreparePath,
		AccountSessionLogoutPath, LoginCallbackContinuePath, "/auth/callback",
	} {
		for _, method := range []string{"GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE", "TRACE", "PATCH", "post"} {
			fixedPost := method == http.MethodPost && path != "/auth/callback"
			landingRead := (method == http.MethodGet || method == http.MethodHead) && path == LoginCallbackContinuePath
			callbackGet := method == http.MethodGet && path == "/auth/callback"
			if fixedPost || landingRead || callbackGet {
				continue
			}
			t.Run(method+" "+path, func(t *testing.T) {
				t.Parallel()
				dispatcher, fixture, callback := dispatcherTestGraph(t)
				request := dispatcherTestInitiationRequest(t.Context(), path)
				request.Method = method
				response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
				if err := dispatcher.Handle(response, request); !errors.Is(err, ErrInvalidLoginDispatcher) ||
					response.statusWrites != 0 || len(response.Header()) != 0 || len(fixture.calls) != 0 || callback.calls != 0 {
					t.Fatal("method alias reached an owner or synthesized redirect/error", err)
				}
			})
		}
	}
}

func TestLoginDispatcherPreservesSessionPrepareOwnership(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
	request := browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(response, request); err != nil {
		t.Fatal("session preparation did not reach its exact owner", err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body) != 2 ||
		body["csrf_token"] == nil || body["expires_at"] == nil {
		t.Fatal("session preparation changed its bounded response", err)
	}
	if response.Code != http.StatusOK || response.statusWrites != 1 || management.auth != 1 ||
		management.budgets != 2 || len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("session preparation crossed owner boundaries")
	}
}

func TestLoginDispatcherPreservesSessionLogoutOwnership(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
	proof := preparedBrowserProof(t, dispatcher.management)
	request := browserManagementRequest(t, AccountSessionLogoutPath, "{}")
	request.Header.Set("X-MeshTransit-CSRF", proof)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(response, request); err != nil {
		t.Fatal("session logout did not reach its exact owner", err)
	}
	if response.Code != http.StatusNoContent || response.statusWrites != 1 || response.Body.Len() != 0 ||
		management.logout != 1 || management.auth != 2 || management.budgets != 4 ||
		len(response.Header().Values("Set-Cookie")) != 1 || len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("session logout crossed owner boundaries")
	}
}

func TestLoginDispatcherPreservesBrowserManagementOperationOwnership(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"revoke", "publish", "explain"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
			proof := preparedBrowserProof(t, dispatcher.management)
			path, body := validManagementPath(), `{"reason":"compromised peer"}`
			switch operation {
			case "publish":
				path, body = validPolicyPublishPath(), validPolicyPublishBody()
			case "explain":
				path, body = validAccessGraphExplainPath(), validAccessGraphExplainBody()
			}
			request := browserManagementRequest(t, path, body)
			request.Header.Set("X-MeshTransit-CSRF", proof)
			original := request.Header.Clone()
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := dispatcher.Handle(response, request); err != nil {
				t.Fatal("browser management mutation did not reach its exact owner", err)
			}
			if response.Code != http.StatusOK || response.statusWrites != 1 || management.auth != 2 ||
				management.budgets != 4 || management.revoke+management.publish+management.explain != 1 ||
				!reflect.DeepEqual(original, request.Header) || len(fixture.calls) != 0 || callback.calls != 0 {
				t.Fatal("browser management mutation crossed owner boundaries")
			}
			expectedETag := `"2"`
			if operation == "explain" {
				expectedETag = `"6"`
			}
			if response.Header().Get("ETag") != expectedETag || response.Header().Get("Set-Cookie") != "" ||
				response.Header().Get("Www-Authenticate") != "" {
				t.Fatal("browser management mutation changed resource or credential ownership")
			}
		})
	}
}

func TestLoginDispatcherRejectsBrowserManagementOperationAliases(t *testing.T) {
	t.Parallel()
	for _, path := range []string{validManagementPath(), validPolicyPublishPath(), validAccessGraphExplainPath()} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			t.Run(method+" "+path, func(t *testing.T) {
				t.Parallel()
				dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
				request := browserManagementRequest(t, path, `{}`)
				request.Method = method
				body := &dispatchBodySpy{}
				request.Body = body
				response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
				if err := dispatcher.Handle(response, request); !errors.Is(err, ErrInvalidLoginDispatcher) ||
					response.statusWrites != 0 || response.Body.Len() != 0 || len(response.Header()) != 0 ||
					management.auth+management.budgets+management.revoke+management.publish+management.explain != 0 ||
					len(fixture.calls) != 0 || callback.calls != 0 || body.reads != 0 {
					t.Fatal("browser management method alias reached an owner", err)
				}
			})
		}
	}
}

func TestLoginDispatcherPreservesSingleComponentOwnership(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback := dispatcherTestGraph(t)
	if dispatcher.CallbackPath() != "/auth/callback" || len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("constructor changed route or touched effects")
	}
	prepare := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(prepare, dispatcherTestInitiationRequest(t.Context(), LoginPreparePath)); err != nil ||
		prepare.statusWrites != 1 || prepare.Code != http.StatusOK || callback.calls != 0 {
		t.Fatal("prepare did not reach initiation exclusively", err)
	}
	var initiation struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(prepare.Body.Bytes(), &initiation); err != nil {
		t.Fatal(err)
	}
	start := dispatcherTestInitiationRequest(t.Context(), LoginStartPath)
	for _, cookie := range prepare.Result().Cookies() {
		start.AddCookie(cookie)
	}
	start.Header.Set(oidc.LoginCSRFHeader, initiation.Token)
	started := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(started, start); err != nil ||
		started.Code != http.StatusOK || started.statusWrites != 1 ||
		started.Header().Get("Location") != "" || !fixture.pending.IsValid() || callback.calls != 0 {
		t.Fatal("confirmed start changed JSON/transaction ownership", err)
	}
	request := callbackReaderRequest(t.Context(), dispatcher.browser.reader.route)
	capture := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(capture, request); err != nil || capture.Code != http.StatusSeeOther ||
		capture.Body.Len() != 0 || capture.Header().Get("Location") != LoginCallbackContinuePath || callback.calls != 0 {
		t.Fatal("GET capture reached callback authority or changed redirect", err)
	}
	headers := request.Header.Clone()
	for _, cookie := range capture.Result().Cookies() {
		headers.Add("Cookie", cookie.Name+"="+cookie.Value)
	}
	before := len(fixture.calls)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		landing := landingTestRequest().WithContext(t.Context())
		landing.Method = method
		page := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if err := dispatcher.Handle(page, landing); err != nil || page.Code != http.StatusOK || callback.calls != 0 ||
			len(fixture.calls) != before || method == http.MethodHead && page.Body.Len() != 0 {
			t.Fatal("read-only clean landing performed budget/application effects", err)
		}
	}
	continuation := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	continuationRequest := continuationGateRequest(t.Context(), headers, LoginContinuationPreparePath)
	if err := dispatcher.Handle(continuation, continuationRequest); err != nil {
		t.Fatal("protected continuation preparation failed", err)
	}
	var proof struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(continuation.Body.Bytes(), &proof); err != nil || proof.Token == "" {
		t.Fatal("protected proof missing", err)
	}
	post := continuationGateRequest(t.Context(), headers, LoginCallbackContinuePath)
	post.Header.Set(oidc.LoginCSRFHeader, proof.Token)
	completed := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	err := dispatcher.Handle(completed, post)
	if !errors.Is(err, ErrInvalidLoginCompletion) || callback.calls != 1 || completed.statusWrites != 0 ||
		completed.Body.Len() != 0 || completed.Header().Get("Set-Cookie") != "" {
		t.Fatal("POST continuation stopped at syntax or promoted zero result to Session", err)
	}
}

func TestLoginDispatcherDoesNotRewriteFailureOrHeaders(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback := dispatcherTestGraph(t)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	response.Header().Set("Location", "https://foreign.example.test/private")
	before := response.Header().Clone()
	request := dispatcherTestInitiationRequest(t.Context(), LoginPreparePath)
	if err := dispatcher.Handle(response, request); !errors.Is(err, ErrInvalidLoginDispatcher) ||
		!reflect.DeepEqual(before, response.Header()) ||
		len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("pristine response rejection rewrote headers or touched effects")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	request = dispatcherTestInitiationRequest(ctx, LoginPreparePath)
	if err := dispatcher.Handle(response, request); !errors.Is(err, ErrLoginDispatchUnavailable) ||
		len(response.Header()) != 0 || len(fixture.calls) != 0 {
		t.Fatal("canceled dispatch delegated or mutated response")
	}
	// A matched initiation request can produce its existing generic HTTP denial.
	// A normal delegate return is not successful login and must not be remapped.
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	request = dispatcherTestInitiationRequest(t.Context(), LoginPreparePath)
	request.Header.Set("Origin", "https://foreign.example.test")
	if err := dispatcher.Handle(response, request); err != nil || response.Code != http.StatusForbidden ||
		response.statusWrites != 1 || len(fixture.calls) != 0 {
		t.Fatal("dispatcher rewrote the existing HTTP denial or inferred a grant", err)
	}
	// Other owners return closed errors, with no invented dispatcher status/body.
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	request = continuationGateRequest(t.Context(), http.Header{}, LoginCallbackContinuePath)
	if err := dispatcher.Handle(response, request); err == nil || response.statusWrites != 0 || response.Body.Len() != 0 {
		t.Fatal("delegated closed error gained a blanket HTTP response", err)
	}
	var missing *LoginDispatcher
	var missingWriter *continuationStatusRecorder
	if !errors.Is(missing.Handle(response, request), ErrLoginDispatchUnavailable) ||
		!errors.Is(dispatcher.Handle(missingWriter, request), ErrInvalidLoginDispatcher) ||
		!errors.Is(dispatcher.Handle(response, nil), ErrInvalidLoginDispatcher) {
		t.Fatal("missing call/owner panicked or changed failure classification")
	}
}

func TestLoginDispatcherPreservesDeadlineAndPartialDelivery(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback := dispatcherTestGraph(t)
	request := landingTestRequest().WithContext(t.Context())
	response := &landingDeliveryRecorder{
		continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
	}
	response.onWrite = func(body []byte) (int, error) {
		written, err := response.continuationStatusRecorder.Write(body[:1])
		if err != nil {
			t.Fatal(err)
		}
		return written, errors.New("synthetic-private-write")
	}
	err := dispatcher.Handle(response, request)
	if !errors.Is(err, ErrLoginLandingDelivery) || strings.Contains(err.Error(), "synthetic-private-write") ||
		response.statusWrites != 1 || response.Body.Len() != 1 || response.Header().Get("Set-Cookie") != "" ||
		len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("partial delivery was rewritten, retried, or disclosed diagnostics", err)
	}
	if response.read.IsZero() || response.write.IsZero() || !response.read.Equal(response.write) {
		t.Fatal("dispatcher lost the delegate's finite transport deadline")
	}
}

func TestLoginDispatcherDiagnosticsAndMetricsAreClosed(t *testing.T) {
	t.Parallel()
	dispatcher, _, _ := dispatcherTestGraph(t)
	if fmt.Sprintf("%v", dispatcher) != "[REDACTED]" || strings.Contains(fmt.Sprintf("%#v", dispatcher), "example.test") {
		t.Fatal("dispatcher diagnostic exposed private route")
	}
	if body, err := json.Marshal(dispatcher); body != nil || !errors.Is(err, ErrInvalidLoginDispatcher) {
		t.Fatal("dispatcher serialized private graph")
	}
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(dispatcher.MetricsCollector()); err != nil {
		t.Fatal(err)
	}
	for index := range 3 {
		request := dispatcherTestInitiationRequest(t.Context(), "/auth/private-"+fmt.Sprint(index))
		if err := dispatcher.Handle(newLoginHTTPRecorder(), request); !errors.Is(err, ErrInvalidLoginDispatcher) {
			t.Fatal(err)
		}
	}
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("private dispatcher metrics not pedantic", err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "operation" && label.GetValue() != "unknown" ||
					label.GetName() == "result" && label.GetValue() != "invalid" ||
					label.GetName() != "operation" && label.GetName() != "result" {
					t.Fatal("arbitrary route/input entered metric labels")
				}
			}
			if family.GetName() == "meshtransit_browser_login_dispatch_requests_active" && metric.GetGauge().GetValue() != 0 {
				t.Fatal("dispatch observation ownership not joined")
			}
			if family.GetName() == "meshtransit_browser_login_dispatch_requests_total" && metric.GetCounter().GetValue() != 3 {
				t.Fatal("unknown routes grew cardinality or lost observations")
			}
		}
	}
}

func FuzzLoginDispatcherRouting(f *testing.F) {
	f.Add("GET", "/auth/v1/login/prepare", "", "")
	f.Add("OPTIONS", "/auth/callback", "state=private", "")
	f.Add("POST", "/auth//v1/login/start", "", "")
	f.Add("POST", "/auth/v1/login/prepare", "", "private")
	f.Fuzz(func(t *testing.T, method, path, rawPath, query string) {
		dispatcher, fixture, callback := dispatcherTestGraph(t)
		request := dispatcherTestInitiationRequest(t.Context(), LoginPreparePath)
		request.Method, request.URL.Path, request.URL.RawPath, request.URL.RawQuery = method, path, rawPath, query
		request.RequestURI = request.URL.RequestURI()
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		err := dispatcher.Handle(response, request)
		callbackGet := method == http.MethodGet && path == dispatcher.CallbackPath()
		fixedPost := method == http.MethodPost && (path == LoginPreparePath || path == LoginStartPath ||
			path == LoginContinuationPreparePath || path == AccountSessionCSRFPreparePath ||
			path == AccountSessionLogoutPath || path == LoginCallbackContinuePath)
		landingRead := (method == http.MethodGet || method == http.MethodHead) && path == LoginCallbackContinuePath
		matched := rawPath == "" && len(query) <= maximumCallbackQueryBytes && (query == "" || callbackGet) &&
			(callbackGet || fixedPost || landingRead)
		if !matched {
			if !errors.Is(err, ErrInvalidLoginDispatcher) || len(fixture.calls) != 0 || callback.calls != 0 ||
				len(response.Header()) != 0 || response.statusWrites != 0 || response.Body.Len() != 0 {
				t.Fatal("arbitrary routing escaped exact dispatch or mutated output", err)
			}
		} else if errors.Is(err, ErrInvalidLoginDispatcher) {
			t.Fatal("matched canonical routing rejected instead of delegated", err)
		}
	})
}
