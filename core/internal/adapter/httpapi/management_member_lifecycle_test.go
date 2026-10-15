package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestParseMemberLifecyclePath(t *testing.T) {
	t.Parallel()
	const prefix = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/members/" +
		"01890f00-0000-7000-8000-000000000402/actions/"
	for path, valid := range map[string]bool{
		prefix + "suspend": true, prefix + "resume": true, prefix + "revoke-sessions": true,
		prefix + "remove": true, prefix + "delete": false, prefix + "suspend?x=1": false, prefix + "suspend/now": false,
		prefix + "revoke_sessions": false,
		strings.Replace(prefix, "01890f00-0000-7000-8000-000000000402", "01890F00-0000-7000-8000-000000000402", 1) +
			"suspend": false,
		"/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/members": false,
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
		if _, ok := parseMemberLifecyclePath(request); ok != valid {
			t.Errorf("%s: matched = %t, want %t", path, ok, valid)
		}
	}
	revoke := httptest.NewRequestWithContext(t.Context(), http.MethodPost, prefix+"revoke-sessions", nil)
	if path, ok := parseMemberLifecyclePath(revoke); !ok || path.operation() != "workspace_member_revoke_sessions" {
		t.Errorf("revoke-sessions operation = %q", path.operation())
	}
	get := httptest.NewRequestWithContext(t.Context(), http.MethodGet, prefix+"suspend", nil)
	if isMemberLifecycleOperation(get) {
		t.Error("only POST is a member action")
	}
}

func TestMemberLifecycleResultBodyAndErrors(t *testing.T) {
	t.Parallel()
	member, _ := publicid.Parse("01890f00-0000-7000-8000-000000000402")
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	expires := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	body := newMemberLifecycleResultBody(memberlifecycle.Result{
		After:         memberlifecycle.Member{PrincipalID: member, State: "suspended", ExpiresAt: &expires, Version: 3},
		Devices:       []memberlifecycle.ChangedDevice{{DeviceID: device, NetworkID: networkID, Hostname: "laptop", State: "suspended"}},
		SessionsEnded: 2,
		Networks:      []memberlifecycle.AdvancedNetwork{{NetworkID: networkID, NetworkRevision: 7, GroupRevision: 4}},
	})
	if body.Member.State != "suspended" || body.Member.ExpiresAt == nil || *body.Member.ExpiresAt != "2027-01-01T00:00:00Z" ||
		len(body.Devices) != 1 || body.Devices[0].NetworkID != networkID.String() || body.SessionsEnded != 2 ||
		body.NetworkCount != 1 {
		t.Fatalf("body = %+v", body)
	}
	for err, code := range map[error]string{
		memberlifecycle.ErrForbidden:   "permission_denied",
		memberlifecycle.ErrProtected:   "member_protected",
		memberlifecycle.ErrNotFound:    "member_not_found",
		memberlifecycle.ErrWrongState:  "member_state_conflict",
		memberlifecycle.ErrInvalid:     "invalid_request",
		errors.New("database is down"): "temporarily_unavailable",
	} {
		if got := classifyMemberLifecycleError(err).Code; got != code {
			t.Errorf("%v: code = %q, want %q", err, got, code)
		}
	}
}
