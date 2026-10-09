package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace/selection"
)

type sessionWorkspaceSelectorStub struct {
	candidates []selection.Candidate
	failure    error
	switches   int
}

func (stub *sessionWorkspaceSelectorStub) List(context.Context, accountsession.Session) ([]selection.Candidate, error) {
	return stub.candidates, stub.failure
}

func (stub *sessionWorkspaceSelectorStub) Switch(_ context.Context, command selection.SwitchCommand) (selection.SwitchResult, error) {
	stub.switches++
	return selection.SwitchResult{WorkspaceID: command.WorkspaceID, SessionVersion: command.Session.Version() + 1},
		stub.failure
}

func TestSessionWorkspaceHTTPBoundary(t *testing.T) {
	t.Parallel()
	current, _ := workspace.ParseID(managementWorkspaceID())
	code, _ := identity.ParseDisplayCode("004218650921")
	candidates := []selection.Candidate{{WorkspaceID: current, DisplayName: "Engineering", DisplayCode: code,
		Owner: true, Current: true}}
	switchBody := `{"workspace_id":"01890f00-0000-7000-8000-000000000102"}`
	for _, test := range []struct {
		name, method, path, body string
		failure                  error
		status, switches         int
		want                     string
	}{
		{"list", http.MethodGet, SessionWorkspacesPath, "", nil, 200, 0,
			`"display_name":"Engineering","display_code":"004218650921","owner":true,"current":true`},
		{"list method", http.MethodPost, SessionWorkspacesPath, "{}", nil, 405, 0, "method_not_allowed"},
		{"switch", http.MethodPost, SessionWorkspacePath, switchBody, nil, 200, 1,
			`"workspace_id":"01890f00-0000-7000-8000-000000000102","replayed":false`},
		{"switch method", http.MethodGet, SessionWorkspacePath, "", nil, 405, 0, "method_not_allowed"},
		{"bad ID", http.MethodPost, SessionWorkspacePath, `{"workspace_id":"x"}`, nil, 400, 0, "invalid_request"},
		{"unknown field", http.MethodPost, SessionWorkspacePath, `{"workspace_id":"01890f00-0000-7000-8000-000000000102","x":1}`,
			nil, 400, 0, "invalid_request"},
		{"not available", http.MethodPost, SessionWorkspacePath, switchBody, selection.ErrNotAvailable, 404, 1,
			"workspace_unavailable"},
		{"changed", http.MethodPost, SessionWorkspacePath, switchBody, selection.ErrSessionChanged, 409, 1,
			"session_changed"},
		{"ended", http.MethodGet, SessionWorkspacesPath, "", selection.ErrForbidden, 403, 0, "permission_denied"},
		{"uncertain", http.MethodPost, SessionWorkspacePath, switchBody, errors.New("uncertain"), 503, 1,
			"temporarily_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &sessionWorkspaceSelectorStub{candidates: candidates, failure: test.failure}
			options.SessionWorkspaces = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, test.method, test.path, test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || stub.switches != test.switches {
				t.Fatalf("status/switches %d/%d, want %d/%d; %s", response.Code, stub.switches, test.status,
					test.switches, response.Body)
			}
			if !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("missing %s in %s", test.want, response.Body)
			}
		})
	}
}
