package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/workspace/settings"
)

type workspaceRenameFunc func(context.Context, settings.Command) (settings.Result, error)

func (function workspaceRenameFunc) Rename(ctx context.Context, command settings.Command) (settings.Result, error) {
	return function(ctx, command)
}

func TestWorkspaceRenameHTTPBoundary(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, body, version string
		authority           error
		status, calls       int
	}{
		{"valid", `{"display_name":"New Workspace"}`, `"1"`, nil, 200, 1},
		{"missing version", `{"display_name":"New Workspace"}`, "", nil, 428, 0},
		{"unknown scope field", `{"display_name":"New Workspace","owner":true}`, `"1"`, nil, 400, 0},
		{"invalid name", `{"display_name":" New Workspace"}`, `"1"`, nil, 400, 0},
		{"member", `{"display_name":"New Workspace"}`, `"1"`, settings.ErrForbidden, 403, 1},
		{"stale", `{"display_name":"New Workspace"}`, `"1"`, settings.ErrConflict, 409, 1},
		{"uncertain commit", `{"display_name":"New Workspace"}`, `"1"`, errors.New("uncertain commit"), 503, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := validManagementHandlerOptions(t)
			calls := 0
			options.WorkspaceRenames = workspaceRenameFunc(func(_ context.Context, command settings.Command) (settings.Result, error) {
				calls++
				return settings.Result{WorkspaceID: command.WorkspaceID, DisplayName: command.DisplayName, DisplayCode: identity.DisplayCode("000000000101"), Version: 2}, test.authority
			})
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodPost, "/api/v1/workspaces/"+managementWorkspaceID()+"/actions/rename", test.body)
			request.Header.Del("If-Match")
			if test.version != "" {
				request.Header.Set("If-Match", test.version)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || calls != test.calls {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, calls, test.status, test.calls, response.Body)
			}
			if test.status == 200 && response.Header().Get("ETag") != `"2"` {
				t.Fatal("missing version receipt")
			}
		})
	}
}

func TestBrowserWorkspaceRenameRequiresCSRF(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	calls := 0
	browser.management.workspaceRenames = workspaceRenameFunc(func(_ context.Context, command settings.Command) (settings.Result, error) {
		calls++
		return settings.Result{WorkspaceID: command.WorkspaceID, DisplayName: command.DisplayName, DisplayCode: identity.DisplayCode("000000000101"), Version: 2}, nil
	})
	path := "/api/v1/workspaces/" + managementWorkspaceID() + "/actions/rename"
	request := browserManagementRequest(t, path, `{"display_name":"New Workspace"}`)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil || calls != 0 || response.Code != http.StatusUnauthorized {
		t.Fatalf("missing proof: error=%v calls=%d status=%d body=%s", err, calls, response.Code, response.Body)
	}
	proof := preparedBrowserProof(t, browser)
	request = browserManagementRequest(t, path, `{"display_name":"New Workspace"}`)
	request.Header.Set("X-MeshTransit-CSRF", proof)
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil || calls != 1 || response.Code != http.StatusOK {
		t.Fatal("rename rejected exact browser proof", err)
	}
}
