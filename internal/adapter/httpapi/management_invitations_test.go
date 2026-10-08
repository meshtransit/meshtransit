package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/invitation"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestParseInvitationPath(t *testing.T) {
	t.Parallel()
	const base = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/invitations"
	const id = "/01890f00-0000-7000-8000-000000000a01"
	for _, test := range []struct {
		method, path string
		action       string
		valid, admit bool
	}{
		{http.MethodGet, base, "", true, true},
		{http.MethodPost, base, "", true, false},
		{http.MethodPost, base + "/actions/create", "create", true, true},
		{http.MethodGet, base + "/actions/create", "create", true, false},
		{http.MethodPost, base + id + "/actions/resend", "resend", true, true},
		{http.MethodPost, base + id + "/actions/revoke", "revoke", true, true},
		{http.MethodPost, base + id + "/actions/accept", "", false, false},
		{http.MethodPost, base + "/actions/delete", "", false, false},
		{http.MethodGet, base + "?state=pending", "", false, false},
		{http.MethodPost, base + "/01890F00-0000-7000-8000-000000000A01/actions/resend", "", false, false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseInvitationPath(request)
		if ok != test.valid || (ok && path.action != test.action) || isInvitationOperation(request) != test.admit {
			t.Errorf("%s %s: parsed %+v %t, admitted %t", test.method, test.path, path, ok, isInvitationOperation(request))
		}
	}
}

func TestInvitationBodyAndErrors(t *testing.T) {
	t.Parallel()
	id, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a01")
	inviter, _ := publicid.Parse("01890f00-0000-7000-8000-000000000401")
	sent := time.Date(2026, time.October, 8, 9, 0, 0, 0, time.UTC)
	body := newInvitationBody(invitation.Invitation{
		ID: id, Email: "member@example.com", Role: "auditor", State: "pending",
		ExpiresAt: sent.Add(invitation.Lifetime), InvitedBy: invitation.Person{PrincipalID: inviter, DisplayName: "Lan"},
		DeliveryState: "sent", LastSentAt: &sent, SendCount: 1, CreatedAt: sent, Version: 2,
	})
	if body.Role == nil || *body.Role != "auditor" || body.LastSentAt == nil || body.ExpiresAt != "2026-10-15T09:00:00Z" ||
		body.InvitedBy.DisplayName != "Lan" {
		t.Fatalf("body = %+v", body)
	}
	if plain := newInvitationBody(invitation.Invitation{ID: id, InvitedBy: invitation.Person{PrincipalID: inviter}}); plain.Role != nil ||
		plain.LastSentAt != nil {
		t.Fatalf("absent role and delivery must be null: %+v", plain)
	}
	for err, want := range map[error]struct {
		code   string
		status int
	}{
		invitation.ErrForbidden:       {"permission_denied", 403},
		invitation.ErrNotFound:        {"invitation_not_found", 404},
		invitation.ErrVersionConflict: {"version_conflict", 412},
		invitation.ErrAlreadyInvited:  {"already_invited", 409},
		invitation.ErrTooMany:         {"too_many_invitations", 409},
		invitation.ErrNotPending:      {"invitation_not_pending", 409},
		invitation.ErrTooSoon:         {"resent_too_soon", 429},
		invitation.ErrInvalid:         {"invalid_request", 400},
		errors.New("down"):            {"temporarily_unavailable", 503},
	} {
		if got := classifyInvitationError(err); got.Code != want.code || got.Status != want.status {
			t.Errorf("%v: = %s %d, want %s %d", err, got.Code, got.Status, want.code, want.status)
		}
	}
}
