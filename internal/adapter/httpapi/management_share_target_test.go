package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/sharing/target"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

type shareTargetResolverStub struct {
	failure error
	calls   int
}

func (stub *shareTargetResolverStub) Resolve(_ context.Context, query target.Query) (target.Target, error) {
	stub.calls++
	remoteWorkspace, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	remoteNetwork, _ := network.ParseID("01890f00-0000-7000-8000-000000000209")
	scope, _ := network.NewScope(remoteWorkspace, remoteNetwork)
	code, _ := identity.ParseDisplayCode("537439945753")
	return target.Target{Scope: scope, WorkspaceCode: code, NetworkCode: query.NetworkCode}, stub.failure
}

func shareTargetTestPath(code string) string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + managementNetworkID() + "/share-targets/" + code
}

func TestShareTargetHTTPBoundary(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, method, path string
		failure            error
		status, calls      int
		want               string
	}{
		{"resolved", http.MethodGet, shareTargetTestPath("798657066103"), nil, 200, 1,
			`"workspace_id":"01890f00-0000-7000-8000-000000000102","network_id":"01890f00-0000-7000-8000-000000000209","workspace_display_code":"537439945753","network_display_code":"798657066103","cross_workspace":true`},
		{"short code", http.MethodGet, shareTargetTestPath("12345"), nil, 400, 0, "invalid_request"},
		{"letters", http.MethodGet, shareTargetTestPath("12345678901a"), nil, 400, 0, "invalid_request"},
		{"bad scope", http.MethodGet, "/api/v1/workspaces/x/networks/" + managementNetworkID() + "/share-targets/798657066103",
			nil, 400, 0, "invalid_request"},
		{"post", http.MethodPost, shareTargetTestPath("798657066103"), nil, 405, 0, "method_not_allowed"},
		{"unknown", http.MethodGet, shareTargetTestPath("798657066103"), target.ErrNotFound, 404, 1, "share_target_not_found"},
		{"forbidden", http.MethodGet, shareTargetTestPath("798657066103"), target.ErrForbidden, 403, 1, "permission_denied"},
		{"uncertain", http.MethodGet, shareTargetTestPath("798657066103"), errors.New("down"), 503, 1, "temporarily_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &shareTargetResolverStub{failure: test.failure}
			options.ShareTargets = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, test.method, test.path, "")
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || stub.calls != test.calls {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, stub.calls, test.status, test.calls, response.Body)
			}
			if !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("missing %s in %s", test.want, response.Body)
			}
		})
	}
}
