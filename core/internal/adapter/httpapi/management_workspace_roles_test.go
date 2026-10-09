package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace/roles"
)

const (
	testAssignmentID = "01990f00-0000-7000-8000-000000000a01"
	testPrincipalID  = "01990f00-0000-7000-8000-000000000b01"
)

type workspaceRoleManagerStub struct {
	calls  int
	err    error
	assign roles.AssignCommand
	revoke roles.RevokeCommand
}

func (stub *workspaceRoleManagerStub) ListMembers(_ context.Context, command roles.ListCommand) (roles.Directory, error) {
	stub.calls++
	return roles.Directory{WorkspaceID: command.WorkspaceID, Members: []roles.Member{{
		PrincipalID: publicid.ID(command.Session.PrincipalID()), DisplayName: "Owner", MembershipState: "active", Owner: true,
	}}}, stub.err
}

func (stub *workspaceRoleManagerStub) Assign(_ context.Context, command roles.AssignCommand) (roles.AssignResult, error) {
	stub.calls++
	stub.assign = command
	return roles.AssignResult{Assignment: roles.Assignment{ID: command.AssignmentID, Role: command.Role,
		NetworkID: command.NetworkID, ExpiresAt: command.ExpiresAt, Version: 1, CreatedAt: time.Unix(1, 0).UTC()}}, stub.err
}

func (stub *workspaceRoleManagerStub) Revoke(_ context.Context, command roles.RevokeCommand) (roles.RevokeResult, error) {
	stub.calls++
	stub.revoke = command
	return roles.RevokeResult{AssignmentID: command.AssignmentID, Version: command.ExpectedVersion + 1}, stub.err
}

func TestParseWorkspaceRolePath(t *testing.T) {
	t.Parallel()
	workspace := managementWorkspaceID()
	for _, test := range []struct {
		path string
		ok   bool
		kind workspaceRolePathKind
	}{
		{"/api/v1/workspaces/" + workspace + "/members", true, workspaceRolePathMembers},
		{"/api/v1/workspaces/" + workspace + "/role-assignments", true, workspaceRolePathAssign},
		{"/api/v1/workspaces/" + workspace + "/role-assignments/" + testAssignmentID + "/actions/revoke", true, workspaceRolePathRevoke},
		{"/api/v1/workspaces/" + workspace + "/members/x", false, 0},
		{"/api/v1/workspaces//members", false, 0},
		{"/api/v1/workspaces/" + workspace + "/role-assignments//actions/revoke", false, 0},
		{"/api/v1/workspaces/" + workspace + "/role-assignments/" + testAssignmentID + "/actions/delete", false, 0},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, test.path, nil)
		path, ok := parseWorkspaceRolePath(request)
		if ok != test.ok || path.kind != test.kind {
			t.Fatalf("%s: ok=%v kind=%d", test.path, ok, path.kind)
		}
	}
	query := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/workspaces/"+workspace+"/members?all=1", nil)
	if _, ok := parseWorkspaceRolePath(query); ok {
		t.Fatal("query string accepted")
	}
}

func TestWorkspaceRoleAssignHTTPBoundary(t *testing.T) {
	t.Parallel()
	valid := `{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID + `","role":"it_admin"}`
	for _, test := range []struct {
		name, body    string
		authority     error
		status, calls int
	}{
		{"valid", valid, nil, 201, 1},
		{"network scope", `{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID +
			`","role":"network_admin","network_id":"` + managementNetworkID() + `"}`, nil, 201, 1},
		{"billing at network scope", `{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID +
			`","role":"billing_admin","network_id":"` + managementNetworkID() + `"}`, nil, 400, 0},
		{"unknown role", `{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID + `","role":"owner"}`, nil, 400, 0},
		{"unknown field", `{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID + `","role":"auditor","permissions":["x"]}`, nil, 400, 0},
		{"bad expiry", `{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID + `","role":"auditor","expires_at":"tomorrow"}`, nil, 400, 0},
		{"missing assignment id", `{"principal_id":"` + testPrincipalID + `","role":"auditor"}`, nil, 400, 0},
		{"ceiling", valid, roles.ErrForbidden, 403, 1},
		{"not member", valid, roles.ErrNotFound, 404, 1},
		{"duplicate", valid, roles.ErrConflict, 409, 1},
		{"uncertain commit", valid, errors.New("uncertain"), 503, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &workspaceRoleManagerStub{err: test.authority}
			options.WorkspaceRoles = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodPost, "/api/v1/workspaces/"+managementWorkspaceID()+"/role-assignments", test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || stub.calls != test.calls {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, stub.calls, test.status, test.calls, response.Body)
			}
			if test.status == 201 && response.Header().Get("ETag") != `"1"` {
				t.Fatal("missing version receipt")
			}
		})
	}
}

func TestWorkspaceRoleRevokeHTTPBoundary(t *testing.T) {
	t.Parallel()
	path := "/api/v1/workspaces/" + managementWorkspaceID() + "/role-assignments/" + testAssignmentID + "/actions/revoke"
	for _, test := range []struct {
		name, version string
		authority     error
		status, calls int
	}{
		{"valid", `"1"`, nil, 200, 1},
		{"missing version", "", nil, 428, 0},
		{"stale", `"1"`, roles.ErrConflict, 409, 1},
		{"self or ceiling", `"1"`, roles.ErrForbidden, 403, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &workspaceRoleManagerStub{err: test.authority}
			options.WorkspaceRoles = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodPost, path, `{}`)
			request.Header.Del("If-Match")
			if test.version != "" {
				request.Header.Set("If-Match", test.version)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || stub.calls != test.calls {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, stub.calls, test.status, test.calls, response.Body)
			}
			if test.status == 200 && (response.Header().Get("ETag") != `"2"` || stub.revoke.ExpectedVersion != 1) {
				t.Fatal("revocation receipt does not carry the next version")
			}
		})
	}
}

func TestWorkspaceMembersHTTPBoundary(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	stub := &workspaceRoleManagerStub{}
	options.WorkspaceRoles = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/" + managementWorkspaceID() + "/members"
	request := newManagementRequest(t, http.MethodGet, path, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || stub.calls != 1 {
		t.Fatalf("members status %d calls %d: %s", response.Code, stub.calls, response.Body)
	}
	var body workspaceMembersResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Data.Members) != 1 ||
		!body.Data.Members[0].Owner || body.Data.Members[0].RoleAssignments == nil {
		t.Fatalf("members body %s: %v", response.Body, err)
	}
	post := newManagementRequest(t, http.MethodPost, path, `{}`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, post)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet || stub.calls != 1 {
		t.Fatalf("POST members status %d allow %q", response.Code, response.Header().Get("Allow"))
	}
}

func TestWorkspaceRolesUnavailableWithoutManager(t *testing.T) {
	t.Parallel()
	handler, err := NewManagementHandler(validManagementHandlerOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodGet, "/api/v1/workspaces/"+managementWorkspaceID()+"/members", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager status %d", response.Code)
	}
}

func TestBrowserWorkspaceRoleAssignRequiresCSRF(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	stub := &workspaceRoleManagerStub{}
	browser.management.workspaceRoles = stub
	path := "/api/v1/workspaces/" + managementWorkspaceID() + "/role-assignments"
	body := `{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID + `","role":"auditor"}`
	request := browserManagementRequest(t, path, body)
	if !isBrowserManagementOperation(request) {
		t.Fatal("role assignment is not routed to browser management")
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil || stub.calls != 0 || response.Code != http.StatusUnauthorized {
		t.Fatalf("missing proof: error=%v calls=%d status=%d body=%s", err, stub.calls, response.Code, response.Body)
	}
	request = browserManagementRequest(t, path, body)
	request.Header.Set("X-MeshTransit-CSRF", preparedBrowserProof(t, browser))
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil || stub.calls != 1 || response.Code != http.StatusCreated {
		t.Fatalf("assignment rejected exact browser proof: error=%v status=%d body=%s", err, response.Code, response.Body)
	}
}
