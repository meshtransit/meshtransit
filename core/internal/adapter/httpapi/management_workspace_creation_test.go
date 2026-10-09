package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/workspace/creation"
)

type workspaceCreatorFunc func(context.Context, creation.Command) (creation.Result, error)

func (function workspaceCreatorFunc) Create(ctx context.Context, command creation.Command) (creation.Result, error) {
	return function(ctx, command)
}

func TestWorkspaceCreationHTTPBoundary(t *testing.T) {
	t.Parallel()
	valid := `{"workspace_id":"01990f00-0000-7000-8000-000000000c01","display_name":"Engineering"}`
	for _, test := range []struct {
		name, method, body string
		replayed           bool
		failure            error
		status, calls      int
		code               string
	}{
		{"created", http.MethodPost, valid, false, nil, 201, 1, ""},
		{"replayed", http.MethodPost, valid, true, nil, 200, 1, ""},
		{"unknown field", http.MethodPost, `{"workspace_id":"01990f00-0000-7000-8000-000000000c01","display_name":"A","owner":"x"}`, false, nil, 400, 0, ""},
		{"padded name", http.MethodPost, `{"workspace_id":"01990f00-0000-7000-8000-000000000c01","display_name":" A"}`, false, nil, 400, 0, ""},
		{"bad id", http.MethodPost, `{"workspace_id":"not-an-id","display_name":"A"}`, false, nil, 400, 0, ""},
		{"account quota", http.MethodPost, valid, false, creation.ErrAccountLimit, 409, 1, "account_workspace_limit"},
		{"deployment ceiling", http.MethodPost, valid, false, creation.ErrDeploymentLimit, 409, 1, "deployment_workspace_limit"},
		{"expired", http.MethodPost, valid, false, creation.ErrEntitlementExpired, 403, 1, "deployment_entitlement_expired"},
		{"conflict", http.MethodPost, valid, false, creation.ErrConflict, 409, 1, "resource_conflict"},
		{"uncertain", http.MethodPost, valid, false, errors.New("uncertain"), 503, 1, "temporarily_unavailable"},
		{"list not offered", http.MethodGet, "", false, nil, 405, 0, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			calls := 0
			options.WorkspaceCreations = workspaceCreatorFunc(func(_ context.Context, command creation.Command) (creation.Result, error) {
				calls++
				return creation.Result{WorkspaceID: command.WorkspaceID, DisplayName: command.DisplayName,
					DisplayCode: identity.DisplayCode("000000000777"), Version: 1, CreatedAt: time.Unix(1, 0).UTC(),
					Replayed: test.replayed}, test.failure
			})
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, test.method, WorkspaceCollectionPath, test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || calls != test.calls {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, calls, test.status, test.calls, response.Body)
			}
			if test.code != "" && !strings.Contains(response.Body.String(), `"`+test.code+`"`) {
				t.Fatalf("missing error code %s in %s", test.code, response.Body)
			}
			if test.status == 201 && response.Header().Get("ETag") != `"1"` {
				t.Fatal("missing version receipt")
			}
		})
	}
}
