package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/memberlifecycle"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

type memberRemovalStub struct {
	requests []memberlifecycle.RemovalRequest
	failure  error
}

func (stub *memberRemovalStub) Change(context.Context, accountsession.Session, memberlifecycle.Request) (
	memberlifecycle.Result, error) {
	return memberlifecycle.Result{}, memberlifecycle.ErrInvalid
}

func (stub *memberRemovalStub) Remove(_ context.Context, _ accountsession.Session,
	request memberlifecycle.RemovalRequest) (memberlifecycle.RemovalResult, error) {
	stub.requests = append(stub.requests, request)
	if stub.failure != nil {
		return memberlifecycle.RemovalResult{}, stub.failure
	}
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000c01")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	return memberlifecycle.RemovalResult{
		After: memberlifecycle.Member{PrincipalID: request.MemberID, State: "revoked", Version: 3},
		Devices: []memberlifecycle.RemovedDevice{{
			DeviceID: device, NetworkID: networkID, Hostname: "laptop", Action: memberlifecycle.DeviceRevoke,
			State: "revoked",
		}},
		KeysRevoked: 2, GroupsLeft: 1, RolesRevoked: 1, SessionsEnded: 1,
		Networks: []memberlifecycle.AdvancedNetwork{{NetworkID: networkID, NetworkRevision: 9}},
	}, nil
}

func TestMemberRemovalHTTPBoundary(t *testing.T) {
	t.Parallel()
	path := "/api/v1/workspaces/" + managementWorkspaceID() +
		"/members/01890f00-0000-7000-8000-000000000402/actions/remove"
	const device = "01890f00-0000-7000-8000-000000000c01"
	const owner = "01890f00-0000-7000-8000-000000000403"
	for _, test := range []struct {
		name, body string
		failure    error
		status     int
		calls      int
		want       string
	}{
		{"revoke everything", `{"reason":"Left","devices":[]}`, nil, 200, 1,
			`"membership_state":"revoked"`},
		{"each action", `{"reason":"Left","devices":[{"device_id":"` + device + `","action":"transfer_member","new_owner_id":"` +
			owner + `"}]}`, nil, 200, 1, `"enrollment_keys_revoked":2,"identity_groups_left":1`},
		{"no devices field", `{"reason":"Left"}`, nil, 400, 0, "invalid_request"},
		{"handover without owner", `{"reason":"Left","devices":[{"device_id":"` + device +
			`","action":"transfer_member"}]}`, nil, 400, 0, "invalid_request"},
		{"unknown field", `{"reason":"Left","devices":[{"device_id":"` + device + `","action":"revoke","x":1}]}`,
			nil, 400, 0, "invalid_request"},
		{"uppercase ID", `{"reason":"Left","devices":[{"device_id":"` + strings.ToUpper(device) +
			`","action":"revoke"}]}`, nil, 400, 0, "invalid_request"},
		{"plan conflict", `{"reason":"Left","devices":[]}`, memberlifecycle.ErrPlan, 409, 1, "device_plan_conflict"},
		{"new owner", `{"reason":"Left","devices":[]}`, memberlifecycle.ErrNewOwner, 409, 1, "new_owner_unavailable"},
		{"protected", `{"reason":"Left","devices":[]}`, memberlifecycle.ErrProtected, 403, 1, "member_protected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &memberRemovalStub{failure: test.failure}
			options.MemberLifecycle = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodPost, path, test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || len(stub.requests) != test.calls ||
				!strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, len(stub.requests), test.status,
					test.calls, response.Body)
			}
		})
	}
}

func TestParseMemberRemovalPlanKeepsChoices(t *testing.T) {
	t.Parallel()
	device, action, owner := "01890f00-0000-7000-8000-000000000c01", "transfer_member",
		"01890f00-0000-7000-8000-000000000403"
	plans, ok := parseMemberRemovalPlan([]memberRemovalDeviceRequest{{DeviceID: &device, Action: &action,
		NewOwnerID: &owner}})
	wantOwner, _ := publicid.Parse(owner)
	if !ok || len(plans) != 1 || plans[0].Action != memberlifecycle.DeviceTransferMember ||
		plans[0].NewOwnerID != wantOwner {
		t.Fatalf("plans = %+v %t", plans, ok)
	}
	if _, ok := parseMemberRemovalPlan(make([]memberRemovalDeviceRequest, memberlifecycle.MaximumPlanDevices+1)); ok {
		t.Fatal("an oversized plan was accepted")
	}
}
