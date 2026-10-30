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

	"meshtransit.net/core/internal/adapter/oidc"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	approval "meshtransit.net/core/internal/domain/policy/approval"
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
		AccountSessionCSRFPreparePath, AccountSessionLogoutPath, AccountSessionManagementScopesPath,
		"/machine/register", "/api/v1/callback", "/key",
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

func TestLoginDispatcherRejectsRegistrationQueryOutsideCanonicalRead(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		method string
		suffix string
	}{
		{name: "unknown filter", method: http.MethodGet, suffix: "?network=other"},
		{name: "duplicate Workspace", method: http.MethodGet, suffix: "?workspace=x&workspace=y"},
		{name: "malformed Workspace", method: http.MethodGet, suffix: "?workspace=other"},
		{name: "empty query", method: http.MethodGet, suffix: "?"},
		{name: "POST choice query", method: http.MethodPost,
			suffix: "?workspace=01890f00-0000-7000-8000-000000000103"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			page, choices, _ := browserRegistrationPageFixture(t)
			dispatcher, _, _ := dispatcherTestGraph(t)
			withPage, err := dispatcher.WithRegistration(page)
			if err != nil {
				t.Fatal(err)
			}
			request := newBrowserRegistrationPageRequest(browserRegistrationPagePrefix+browserPageTestToken+test.suffix, "")
			request.Method = test.method
			body := &dispatchBodySpy{}
			request.Body = body
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := withPage.Handle(response, request); !errors.Is(err, ErrInvalidLoginDispatcher) ||
				response.statusWrites != 0 || response.Body.Len() != 0 || choices.calls != 0 || body.reads != 0 {
				t.Fatal("noncanonical chooser query reached authority or response", err)
			}
		})
	}
}

func (body *dispatchBodySpy) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}
func (*dispatchBodySpy) Close() error { return nil }

func TestLoginDispatcherRejectsMethodAliases(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		LoginPreparePath, LoginStartPath, LoginContinuationPreparePath, AccountSessionCSRFPreparePath,
		AccountSessionLogoutPath, AccountSessionManagementScopesPath, DeploymentCapabilitiesPath,
		LoginCallbackContinuePath, "/auth/callback",
	} {
		for _, method := range []string{"GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE", "TRACE", "PATCH", "post"} {
			fixedPost := method == http.MethodPost && (path == LoginPreparePath || path == LoginStartPath ||
				path == LoginContinuationPreparePath || path == AccountSessionCSRFPreparePath ||
				path == AccountSessionLogoutPath || path == LoginCallbackContinuePath)
			landingRead := (method == http.MethodGet || method == http.MethodHead) && path == LoginCallbackContinuePath
			callbackGet := method == http.MethodGet && path == "/auth/callback"
			managementScopeRead := method == http.MethodGet && path == AccountSessionManagementScopesPath
			deploymentCapabilityRead := method == http.MethodGet && path == DeploymentCapabilitiesPath
			if fixedPost || landingRead || callbackGet || managementScopeRead || deploymentCapabilityRead {
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

func TestLoginDispatcherPreservesApprovalCatalogOwnership(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
	snapshot := managementPolicyApprovalSnapshot(t, approval.StatePending)
	for _, path := range []string{
		managementPolicyApprovalCollectionPath() + "/" + snapshot.RequestID().String(),
		managementPolicyApprovalCollectionPath() + "?state=pending&page_size=1",
	} {
		request := browserManagementReadRequest(t, path)
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if err := dispatcher.Handle(response, request); err != nil {
			t.Fatal("approval catalog read did not reach its exact owner", err)
		}
		if response.Code != http.StatusOK || response.statusWrites != 1 ||
			len(fixture.calls) != 0 || callback.calls != 0 || response.Header().Get("Set-Cookie") != "" ||
			response.Header().Get("Www-Authenticate") != "" {
			t.Fatal("approval catalog read crossed owner boundaries")
		}
	}
	if management.auth != 2 || management.budgets != 4 ||
		management.approvalGet != 1 || management.approvalList != 1 {
		t.Fatal("approval catalog read skipped fresh private admission")
	}
}

func TestLoginDispatcherPreservesActivePolicyReadAdmission(t *testing.T) {
	t.Parallel()
	path := "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/policy"
	for _, test := range []struct {
		name   string
		method string
		suffix string
		valid  bool
	}{
		{name: "canonical read", method: http.MethodGet, valid: true},
		{name: "POST alias", method: http.MethodPost},
		{name: "HEAD alias", method: http.MethodHead},
		{name: "query alias", method: http.MethodGet, suffix: "?revision=1"},
		{name: "trailing path", method: http.MethodGet, suffix: "/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
			request := browserManagementReadRequest(t, path+test.suffix)
			request.Method = test.method
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := dispatcher.Handle(response, request)
			if !test.valid {
				if !errors.Is(err, ErrInvalidLoginDispatcher) || management.auth != 0 ||
					management.budgets != 0 || response.statusWrites != 0 {
					t.Fatal("active policy alias reached authority or response", err)
				}
				return
			}
			// This fixture has no active-policy reader. Admission must reach the
			// product handler and fail closed after fresh Session authentication.
			if err != nil || response.Code != http.StatusServiceUnavailable || response.statusWrites != 1 ||
				management.auth != 1 || management.budgets != 2 || len(fixture.calls) != 0 || callback.calls != 0 ||
				response.Header().Get("Set-Cookie") != "" || response.Header().Get("Www-Authenticate") != "" {
				t.Fatal("active policy read skipped admission or crossed owner boundaries", err)
			}
		})
	}
}

func TestLoginDispatcherAdmitsOnlyTheBoundedDeviceGroupMemberQuery(t *testing.T) {
	t.Parallel()
	groups := "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/device-groups"
	members := groups + "/01890f00-0000-7000-8000-000000000301/members"
	for _, test := range []struct {
		name  string
		path  string
		valid bool
	}{
		{name: "first page", path: members + "?limit=100", valid: true},
		{name: "next page", path: members + "?after=01890f00-0000-7000-8000-000000000401&limit=2", valid: true},
		{name: "default page", path: members, valid: true},
		{name: "list with query", path: groups + "?limit=1"},
		{name: "unknown key", path: members + "?state=active"},
		{name: "repeated key", path: members + "?limit=1&limit=2"},
		{name: "limit above page", path: members + "?limit=501"},
		{name: "noncanonical cursor", path: members + "?after=01890F00-0000-7000-8000-000000000401"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
			request := browserManagementReadRequest(t, test.path)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := dispatcher.Handle(response, request)
			if !test.valid {
				if !errors.Is(err, ErrInvalidLoginDispatcher) || management.auth != 0 ||
					management.budgets != 0 || response.statusWrites != 0 {
					t.Fatal("device group query alias reached authority or response", err)
				}
				return
			}
			// This fixture has no Device Group manager: admission must reach the
			// product handler and fail closed after fresh Session authentication.
			if err != nil || response.Code != http.StatusServiceUnavailable || response.statusWrites != 1 ||
				management.auth != 1 || len(fixture.calls) != 0 || callback.calls != 0 ||
				response.Header().Get("Set-Cookie") != "" {
				t.Fatal("device group member read skipped admission or crossed owner boundaries", err)
			}
		})
	}
}

func TestLoginDispatcherAdmitsOnlyTheBoundedNetworkMemberQuery(t *testing.T) {
	t.Parallel()
	members := "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/members"
	for _, test := range []struct {
		name  string
		path  string
		valid bool
	}{
		{name: "first page", path: members + "?limit=100", valid: true},
		{name: "next page", path: members + "?after=01890f00-0000-7000-8000-000000000401&limit=2", valid: true},
		{name: "default page", path: members, valid: true},
		{name: "unknown key", path: members + "?state=active"},
		{name: "repeated key", path: members + "?limit=1&limit=2"},
		{name: "limit above page", path: members + "?limit=201"},
		{name: "noncanonical cursor", path: members + "?after=01890F00-0000-7000-8000-000000000401"},
		{name: "action with query", path: members + "/actions/add?limit=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
			request := browserManagementReadRequest(t, test.path)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := dispatcher.Handle(response, request)
			if !test.valid {
				if !errors.Is(err, ErrInvalidLoginDispatcher) || management.auth != 0 ||
					management.budgets != 0 || response.statusWrites != 0 {
					t.Fatal("Network member query alias reached authority or response", err)
				}
				return
			}
			// This fixture has no Network member manager: admission must reach
			// the product handler and fail closed after fresh Session
			// authentication.
			if err != nil || response.Code != http.StatusServiceUnavailable || response.statusWrites != 1 ||
				management.auth != 1 || len(fixture.calls) != 0 || callback.calls != 0 ||
				response.Header().Get("Set-Cookie") != "" {
				t.Fatal("Network member read skipped admission or crossed owner boundaries", err)
			}
		})
	}
}

func TestLoginDispatcherPreservesManagementScopeOwnership(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
	request := browserManagementReadRequest(t, AccountSessionManagementScopesPath+"?page_size=1")
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(response, request); err != nil {
		t.Fatal("management-scope read did not reach its exact owner", err)
	}
	var body managementScopeEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Data.Networks) != 1 {
		t.Fatal("management-scope read changed its bounded response", err)
	}
	if response.Code != http.StatusOK || response.statusWrites != 1 || management.auth != 1 ||
		management.budgets != 2 || len(fixture.calls) != 0 || callback.calls != 0 ||
		response.Header().Get("Set-Cookie") != "" || response.Header().Get("Www-Authenticate") != "" {
		t.Fatal("management-scope read crossed owner boundaries")
	}
}

func TestLoginDispatcherPreservesDeploymentCapabilityOwnership(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
	request := browserManagementReadRequest(t, DeploymentCapabilitiesPath)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(response, request); err != nil {
		t.Fatal("Deployment capability read did not reach its exact owner", err)
	}
	var body deploymentCapabilityResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.CapabilityRevision != 7 {
		t.Fatal("Deployment capability read changed its bounded response", err)
	}
	if response.Code != http.StatusOK || response.statusWrites != 1 || management.auth != 1 ||
		management.budgets != 2 || management.capabilityReads != 1 || len(fixture.calls) != 0 || callback.calls != 0 ||
		response.Header().Get("Set-Cookie") != "" || response.Header().Get("Www-Authenticate") != "" {
		t.Fatal("Deployment capability read crossed owner boundaries")
	}
}

func TestLoginDispatcherOwnsNewPolicyMutationRoutes(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		managementPolicySimulationPath(),
		managementPolicyApprovalCollectionPath(),
		managementPolicyApprovalCollectionPath() + "/01890f00-0000-7000-8000-000000000901/actions/approve",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
			proof := preparedBrowserProof(t, dispatcher.management)
			request := browserManagementRequest(t, path, "{}")
			request.Header.Set("X-MeshTransit-CSRF", proof)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := dispatcher.Handle(response, request); err != nil {
				t.Fatal("policy mutation did not reach browser management", err)
			}
			if response.statusWrites != 1 || management.auth != 2 || management.budgets != 4 ||
				len(fixture.calls) != 0 || callback.calls != 0 {
				t.Fatal("policy mutation crossed owner boundaries")
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
		managementScopeRead := method == http.MethodGet && path == AccountSessionManagementScopesPath
		deploymentCapabilityRead := method == http.MethodGet && path == DeploymentCapabilitiesPath
		fixedPost := method == http.MethodPost && (path == LoginPreparePath || path == LoginStartPath ||
			path == LoginContinuationPreparePath || path == AccountSessionCSRFPreparePath ||
			path == AccountSessionLogoutPath || path == LoginCallbackContinuePath)
		landingRead := (method == http.MethodGet || method == http.MethodHead) && path == LoginCallbackContinuePath
		matched := rawPath == "" && len(query) <= maximumCallbackQueryBytes &&
			(query == "" || callbackGet || managementScopeRead) &&
			(callbackGet || fixedPost || landingRead || managementScopeRead || deploymentCapabilityRead)
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

func TestLoginDispatcherRegistrationKeepsInvitations(t *testing.T) {
	t.Parallel()
	page, _, _ := browserRegistrationPageFixture(t)
	dispatcher, _, _ := dispatcherTestGraph(t)
	prepare, _ := newInvitationPrepareFixture(t)
	withInvitations, err := dispatcher.WithInvitations(prepare)
	if err != nil {
		t.Fatal(err)
	}
	withPage, err := withInvitations.WithRegistration(page)
	if err != nil {
		t.Fatal(err)
	}
	if withPage.invitations != prepare || withPage.registration != page {
		t.Fatal("adding the registration page dropped the invitation prepare endpoint")
	}
}

// The login dispatcher in front of browser management admits a cluster's
// paged lists and operation reads with their query; it closed the
// connection on them before (K1d d1, found on the POC).
func TestLoginDispatcherAdmitsKubernetesClusterQueries(t *testing.T) {
	t.Parallel()
	dispatcher, _, _, _ := dispatcherTestGraphWithManagement(t)
	cluster := "/" + kubernetesTestCluster
	for _, path := range []string{
		kubernetesClustersTestPath(cluster + "/replicas?page_size=10"),
		kubernetesClustersTestPath(cluster + "/join-keys?page_size=10"),
		kubernetesClustersTestPath(cluster + "/certificate-authorities?page_size=10"),
		kubernetesClustersTestPath(cluster + "/operations?class=write"),
		kubernetesClustersTestPath(cluster + "/replica-requests?page_size=10"),
		kubernetesClustersTestPath(cluster + "/ca-retire-requests?page_size=10"),
		kubernetesClustersTestPath(cluster + "/operation-denial-counts?from=2026-10-29T00:00:00Z&to=2026-10-30T00:00:00Z"),
		kubernetesClustersTestPath(cluster + "/operation-exports?from=2026-10-29T00:00:00Z"),
	} {
		if !dispatcher.validRequest(newLoginHTTPRecorder(), browserManagementReadRequest(t, path)) {
			t.Errorf("the dispatcher refused %s", path)
		}
	}
	// Other queries on a cluster stay refused.
	for _, path := range []string{
		kubernetesClustersTestPath(cluster + "?page_size=10"),
		kubernetesClustersTestPath(cluster + "/replicas?limit=10"),
		kubernetesClustersTestPath(cluster + "/audit-settings?x=1"),
	} {
		if dispatcher.validRequest(newLoginHTTPRecorder(), browserManagementReadRequest(t, path)) {
			t.Errorf("the dispatcher admitted %s", path)
		}
	}
	// A query never rides on a write.
	write := browserManagementReadRequest(t, kubernetesClustersTestPath(cluster+"/join-keys?page_size=10"))
	write.Method = http.MethodPost
	if dispatcher.validRequest(newLoginHTTPRecorder(), write) {
		t.Error("the dispatcher admitted a write with a query")
	}
}
