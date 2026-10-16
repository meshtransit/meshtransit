package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	networkMemberTestNetwork = "01890f00-0000-7000-8000-000000000201"
	networkMemberTestMember  = "01890f00-0000-7000-8000-000000000402"
	networkMemberTestOther   = "01890f00-0000-7000-8000-000000000403"
)

func networkMembersTestPath(rest string) string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + networkMemberTestNetwork + "/members" + rest
}

type networkMemberStub struct {
	lists     []string
	additions [][]publicid.ID
	removals  []memberlifecycle.NetworkRemovalRequest
	failure   error
}

func (stub *networkMemberStub) List(_ context.Context, _ accountsession.Session, scope network.Scope,
	after publicid.ID, limit int) (memberlifecycle.NetworkMemberPage, error) {
	stub.lists = append(stub.lists, fmt.Sprintf("%s|%v|%d", scope.NetworkID(), after.IsValid(), limit))
	if stub.failure != nil {
		return memberlifecycle.NetworkMemberPage{}, stub.failure
	}
	member, _ := publicid.Parse(networkMemberTestMember)
	other, _ := publicid.Parse(networkMemberTestOther)
	membership, _ := publicid.Parse("01890f00-0000-7000-8000-000000000601")
	return memberlifecycle.NetworkMemberPage{
		CanManage: true, HasMore: true,
		Members: []memberlifecycle.NetworkMember{
			{PrincipalID: member, DisplayName: "Ana", WorkspaceState: "active", Membership: &memberlifecycle.NetworkMembership{
				MembershipID: membership, PrincipalID: member, State: "active", Version: 1,
				AddedAt: time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
			}},
			{PrincipalID: other, DisplayName: "Bo", WorkspaceState: "suspended"},
		},
	}, nil
}

func (stub *networkMemberStub) Add(_ context.Context, _ accountsession.Session, _ network.Scope,
	members []publicid.ID, _ publicid.ID) (memberlifecycle.NetworkAdditionResult, error) {
	stub.additions = append(stub.additions, members)
	if stub.failure != nil {
		return memberlifecycle.NetworkAdditionResult{}, stub.failure
	}
	membership, _ := publicid.Parse("01890f00-0000-7000-8000-000000000601")
	return memberlifecycle.NetworkAdditionResult{
		NetworkRevision: 5,
		Added: []memberlifecycle.NetworkMembership{{
			MembershipID: membership, PrincipalID: members[0], State: "active", Version: 1,
			AddedAt: time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
		}},
		Unchanged: append([]publicid.ID(nil), members[1:]...),
	}, nil
}

func (stub *networkMemberStub) Remove(_ context.Context, _ accountsession.Session,
	request memberlifecycle.NetworkRemovalRequest) (memberlifecycle.NetworkRemovalResult, error) {
	stub.removals = append(stub.removals, request)
	if stub.failure != nil {
		return memberlifecycle.NetworkRemovalResult{}, stub.failure
	}
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000c01")
	membership, _ := publicid.Parse("01890f00-0000-7000-8000-000000000601")
	return memberlifecycle.NetworkRemovalResult{
		After: memberlifecycle.NetworkMembership{
			MembershipID: membership, PrincipalID: request.MemberID, State: "revoked", Version: 2,
		},
		Devices: []memberlifecycle.RemovedDevice{{
			DeviceID: device, NetworkID: request.Scope.NetworkID(), Hostname: "laptop",
			Action: memberlifecycle.DeviceRevoke, State: "revoked",
		}},
		KeysRevoked: 1, RolesRevoked: 1,
		Network: memberlifecycle.AdvancedNetwork{NetworkID: request.Scope.NetworkID(), NetworkRevision: 9},
	}, nil
}

func TestParseNetworkMemberPath(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		method, path string
		valid        bool
		operation    string
		limit        int
	}{
		{http.MethodGet, networkMembersTestPath(""), true, "network_member_list", 100},
		{http.MethodGet, networkMembersTestPath("?limit=200&after=" + networkMemberTestMember), true,
			"network_member_list", 200},
		{http.MethodGet, networkMembersTestPath("?limit=201"), false, "", 0},
		{http.MethodGet, networkMembersTestPath("?limit=0"), false, "", 0},
		{http.MethodGet, networkMembersTestPath("?limit=01"), false, "", 0},
		{http.MethodGet, networkMembersTestPath("?after=" + strings.ToUpper(networkMemberTestMember)), false, "", 0},
		{http.MethodGet, networkMembersTestPath("?other=1"), false, "", 0},
		{http.MethodGet, networkMembersTestPath("?limit=1&limit=2"), false, "", 0},
		{http.MethodPost, networkMembersTestPath(""), true, "network_member_add", 0},
		{http.MethodPost, networkMembersTestPath("?x=1"), false, "", 0},
		{http.MethodPost, networkMembersTestPath("?limit=10"), false, "", 0},
		{http.MethodPost, networkMembersTestPath("/actions/add"), false, "", 0},
		{http.MethodPost, networkMembersTestPath("/actions/delete"), false, "", 0},
		{http.MethodPost, networkMembersTestPath("/" + networkMemberTestMember + "/actions/remove"), true,
			"network_member_remove", 0},
		{http.MethodPost, networkMembersTestPath("/" + strings.ToUpper(networkMemberTestMember) + "/actions/remove"),
			false, "", 0},
		{http.MethodPost, networkMembersTestPath("/" + networkMemberTestMember + "/actions/suspend"), false, "", 0},
		{http.MethodPost, networkMembersTestPath("/" + networkMemberTestMember), false, "", 0},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseNetworkMemberPath(request)
		if ok != test.valid {
			t.Errorf("%s %s: matched = %t, want %t", test.method, test.path, ok, test.valid)
			continue
		}
		if ok && (path.operation() != test.operation || path.limit != test.limit) {
			t.Errorf("%s: operation/limit = %s/%d", test.path, path.operation(), path.limit)
		}
		if ok && !isNetworkMemberOperation(request) {
			t.Errorf("%s %s is not admitted", test.method, test.path)
		}
	}
	wrongMethod := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, networkMembersTestPath(""), nil)
	if path, ok := parseNetworkMemberPath(wrongMethod); !ok || isNetworkMemberOperation(wrongMethod) ||
		path.methods.header() != "GET, POST" {
		t.Error("DELETE on the member list must match for a 405 and not be admitted")
	}
	add := httptest.NewRequestWithContext(t.Context(), http.MethodPost, networkMembersTestPath(""), nil)
	if isNetworkMemberRead(add) {
		t.Error("adding members is not a read")
	}
}

func TestNetworkMemberHTTPBoundary(t *testing.T) {
	t.Parallel()
	ids := func(count int) string {
		items := make([]string, count)
		for index := range items {
			items[index] = fmt.Sprintf(`"01890f00-0000-7000-8000-%012d"`, 500+index)
		}
		return `{"principal_ids":[` + strings.Join(items, ",") + `]}`
	}
	remove := networkMembersTestPath("/" + networkMemberTestMember + "/actions/remove")
	const device = "01890f00-0000-7000-8000-000000000c01"
	for _, test := range []struct {
		name, method, path, body string
		failure                  error
		status                   int
		calls                    int
		want                     string
	}{
		{"list", http.MethodGet, networkMembersTestPath("?limit=2"), "", nil, 200, 1,
			`"next_after":"` + networkMemberTestOther + `"`},
		{"list shows membership", http.MethodGet, networkMembersTestPath(""), "", nil, 200, 1,
			`"network_membership":null`},
		{"list forbidden", http.MethodGet, networkMembersTestPath(""), "", memberlifecycle.ErrForbidden, 403, 1,
			"permission_denied"},
		{"add", http.MethodPost, networkMembersTestPath(""), ids(2), nil, 200, 1,
			`"unchanged":["01890f00-0000-7000-8000-000000000501"]`},
		{"add the maximum", http.MethodPost, networkMembersTestPath(""),
			ids(memberlifecycle.MaximumNetworkAdditions), nil, 200, 1, `"added":[`},
		{"add too many", http.MethodPost, networkMembersTestPath(""),
			ids(memberlifecycle.MaximumNetworkAdditions + 1), nil, 400, 0, "invalid_request"},
		{"add nobody", http.MethodPost, networkMembersTestPath(""), `{"principal_ids":[]}`, nil, 400, 0,
			"invalid_request"},
		{"add twice", http.MethodPost, networkMembersTestPath(""),
			`{"principal_ids":["` + networkMemberTestMember + `","` + networkMemberTestMember + `"]}`, nil, 400, 0,
			"invalid_request"},
		{"add without field", http.MethodPost, networkMembersTestPath(""), `{}`, nil, 400, 0,
			"invalid_request"},
		{"add uppercase", http.MethodPost, networkMembersTestPath(""),
			`{"principal_ids":["` + strings.ToUpper(networkMemberTestMember) + `"]}`, nil, 400, 0, "invalid_request"},
		{"add suspended", http.MethodPost, networkMembersTestPath(""), ids(1),
			memberlifecycle.ErrWrongState, 409, 1, "member_state_conflict"},
		{"add stranger", http.MethodPost, networkMembersTestPath(""), ids(1),
			memberlifecycle.ErrNotFound, 404, 1, "member_not_found"},
		{"add forbidden", http.MethodPost, networkMembersTestPath(""), ids(1),
			memberlifecycle.ErrForbidden, 403, 1, "permission_denied"},
		{"remove", http.MethodPost, remove, `{"reason":"Moved team","devices":[{"device_id":"` + device +
			`","action":"revoke"}]}`, nil, 200, 1, `"network_revision":9`},
		{"remove without devices", http.MethodPost, remove, `{"reason":"Moved team"}`, nil, 400, 0, "invalid_request"},
		{"remove protected", http.MethodPost, remove, `{"reason":"Moved team","devices":[]}`,
			memberlifecycle.ErrProtected, 403, 1, "member_protected"},
		{"remove new owner elsewhere", http.MethodPost, remove, `{"reason":"Moved team","devices":[]}`,
			memberlifecycle.ErrNewOwner, 409, 1, "new_owner_unavailable"},
		{"remove plan conflict", http.MethodPost, remove, `{"reason":"Moved team","devices":[]}`,
			memberlifecycle.ErrPlan, 409, 1, "device_plan_conflict"},
		{"remove stranger", http.MethodPost, remove, `{"reason":"Moved team","devices":[]}`,
			memberlifecycle.ErrNotFound, 404, 1, "member_not_found"},
		{"wrong method", http.MethodDelete, networkMembersTestPath(""), "", nil, 405, 0,
			"method_not_allowed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &networkMemberStub{failure: test.failure}
			options.NetworkMembers = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, test.method, test.path, test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			calls := len(stub.lists) + len(stub.additions) + len(stub.removals)
			if response.Code != test.status || calls != test.calls ||
				!strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, calls, test.status, test.calls,
					response.Body)
			}
			if test.status == 200 && response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("a member response may be cached")
			}
		})
	}
}

func TestNetworkMembersUnavailableWithoutManager(t *testing.T) {
	t.Parallel()
	handler, err := NewManagementHandler(validManagementHandlerOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodGet, networkMembersTestPath(""), "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; %s", response.Code, response.Body)
	}
}

func TestClassifyNetworkMemberError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		memberlifecycle.ErrForbidden:   "permission_denied",
		memberlifecycle.ErrProtected:   "member_protected",
		memberlifecycle.ErrNotFound:    "member_not_found",
		memberlifecycle.ErrWrongState:  "member_state_conflict",
		memberlifecycle.ErrPlan:        "device_plan_conflict",
		memberlifecycle.ErrNewOwner:    "new_owner_unavailable",
		memberlifecycle.ErrInvalid:     "invalid_request",
		errors.New("database is down"): "temporarily_unavailable",
	} {
		if got := classifyNetworkMemberError(err).Code; got != code {
			t.Errorf("%v: code = %q, want %q", err, got, code)
		}
	}
}
