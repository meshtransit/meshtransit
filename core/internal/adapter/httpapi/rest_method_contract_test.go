package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every migrated path answers a method it does not accept with 405 and the
// methods it does accept, before any dependency or credential is read.
func TestRESTPathsAnswerWrongMethodsWithAllow(t *testing.T) {
	t.Parallel()
	handler, err := NewManagementHandler(validManagementHandlerOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	const id = "01890f00-0000-7000-8000-000000000a01"
	ws := "/api/v1/workspaces/" + managementWorkspaceID()
	net := ws + "/networks/" + networkMemberTestNetwork
	for _, test := range []struct{ method, path, allow string }{
		{http.MethodDelete, ws + "/identity-groups", "GET, POST"},
		{http.MethodGet, ws + "/identity-groups/" + id, "PATCH, DELETE"},
		{http.MethodPost, ws + "/identity-groups/" + id + "/members", "GET, PATCH"},
		{http.MethodDelete, ws + "/device-tags", "GET, POST"},
		{http.MethodPost, ws + "/device-tags/" + id, "PATCH, DELETE"},
		{http.MethodPatch, ws + "/guardrails", "GET, POST"},
		{http.MethodGet, ws + "/guardrails/actions/preview", "POST"},
		{http.MethodPost, ws + "/guardrails/" + id, "PATCH, DELETE"},
		{http.MethodPatch, ws + "/interchanges", "GET, POST"},
		{http.MethodGet, ws + "/interchanges/" + id, "PATCH, DELETE"},
		{http.MethodDelete, ws + "/invitations", "GET, POST"},
		{http.MethodGet, ws + "/invitations/" + id + "/actions/resend", "POST"},
		{http.MethodPost, ws, "PATCH"},
		{http.MethodDelete, net + "/device-groups", "GET, POST"},
		{http.MethodGet, net + "/device-groups/" + id, "PATCH, DELETE"},
		{http.MethodDelete, net + "/members", "GET, POST"},
		{http.MethodPatch, net + "/enrollment-keys", "GET, POST"},
		{http.MethodPost, net + "/alias-ranges", "GET, PATCH"},
		{http.MethodPost, net + "/devices/" + id, "PATCH"},
		{http.MethodPost, net + "/devices/" + id + "/tags", "PATCH"},
		{http.MethodGet, net + "/devices/" + id + "/actions/suspend", "POST"},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, strings.NewReader("{}"))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != test.allow {
			t.Errorf("%s %s = %d Allow %q; want 405 Allow %q", test.method, test.path, response.Code,
				response.Header().Get("Allow"), test.allow)
		}
	}
}

// A PATCH or DELETE through the browser cookie needs the CSRF proof like a
// POST: without it nothing reaches the change.
func TestBrowserChangesWithoutProofAreRefused(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	path := "/api/v1/workspaces/" + managementWorkspaceID() + "/device-tags/01890f00-0000-7000-8000-000000000a01"
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		body := `{"name":"web"}`
		if method == http.MethodDelete {
			body = ""
		}
		request := browserManagementRequest(t, path, body)
		request.Method = method
		if method == http.MethodDelete {
			request.Body, request.ContentLength = http.NoBody, 0
			request.Header.Del("Content-Type")
		}
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if err := browser.Handle(response, request); err != nil || response.Code != http.StatusUnauthorized {
			t.Errorf("%s without a proof = %d, %v; want 401", method, response.Code, err)
		}
	}
	prepare := browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")
	prepare.Method = http.MethodPatch
	if err := browser.Handle(&continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
		prepare); err == nil {
		t.Fatal("a PATCH prepared a CSRF proof")
	}
}
