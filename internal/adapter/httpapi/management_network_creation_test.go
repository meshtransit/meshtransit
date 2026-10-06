package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network/provisioning"
)

type networkCreatorFunc func(context.Context, provisioning.Command) (provisioning.Result, error)

func (function networkCreatorFunc) Create(ctx context.Context, command provisioning.Command) (provisioning.Result, error) {
	return function(ctx, command)
}

func TestNetworkCreationHTTPBoundary(t *testing.T) {
	t.Parallel()
	body := func(ipv4, ipv6 string) string {
		return `{"network_id":"01990f00-0000-7000-8000-000000000d01","display_name":"Office","ipv4_prefix":"` + ipv4 +
			`","ipv6_prefix":"` + ipv6 + `"}`
	}
	valid := body("100.64.10.0/24", "fd42:42:42:10::/64")
	for _, test := range []struct {
		name, body    string
		failure       error
		status, calls int
		code          string
	}{
		{"created", valid, nil, 201, 1, ""},
		{"outside CGNAT", body("192.168.1.0/24", "fd42:42:42:10::/64"), nil, 400, 0, "invalid_request"},
		{"host bits", body("100.64.10.1/24", "fd42:42:42:10::/64"), nil, 400, 0, "invalid_request"},
		{"too large", body("100.64.0.0/12", "fd42:42:42:10::/64"), nil, 400, 0, "invalid_request"},
		{"overlap", valid, provisioning.ErrPrefixOverlap, 409, 1, "network_prefix_overlap"},
		{"outside pool", valid, provisioning.ErrPrefixOutsidePool, 422, 1, "network_prefix_outside_pool"},
		{"forbidden", valid, provisioning.ErrForbidden, 403, 1, "permission_denied"},
		{"conflict", valid, provisioning.ErrConflict, 409, 1, "resource_conflict"},
		{"uncertain", valid, errors.New("uncertain"), 503, 1, "temporarily_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			calls := 0
			options.NetworkCreations = networkCreatorFunc(func(_ context.Context, command provisioning.Command) (provisioning.Result, error) {
				calls++
				return provisioning.Result{NetworkID: command.NetworkID, DisplayCode: identity.DisplayCode("000000000888"),
					Version: 1, CreatedAt: time.Unix(1, 0).UTC()}, test.failure
			})
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodPost, "/api/v1/workspaces/"+managementWorkspaceID()+"/networks", test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || calls != test.calls {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, calls, test.status, test.calls, response.Body)
			}
			if test.code != "" && !strings.Contains(response.Body.String(), `"`+test.code+`"`) {
				t.Fatalf("missing %s in %s", test.code, response.Body)
			}
		})
	}
}
