package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/invitation"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
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
		{http.MethodPost, base, "create", true, true},
		{http.MethodDelete, base, "", true, false},
		{http.MethodPost, base + "/actions/create", "", false, false},
		{http.MethodGet, base + id + "/actions/resend", "", true, false},
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
		wantRead := ok && path.action == "" && test.method == http.MethodGet
		if isInvitationRead(request) != wantRead {
			t.Errorf("%s %s: read admission = %t, want %t", test.method, test.path, !wantRead, wantRead)
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

type invitationManagerStub struct {
	listed []invitation.Invitation
	lists  int
}

func (stub *invitationManagerStub) Create(context.Context, accountsession.Session, invitation.CreateRequest) (invitation.Sent, error) {
	return invitation.Sent{}, invitation.ErrInvalid
}

func (stub *invitationManagerStub) Resend(context.Context, accountsession.Session, invitation.ActionRequest) (invitation.Sent, error) {
	return invitation.Sent{}, invitation.ErrInvalid
}

func (stub *invitationManagerStub) Revoke(context.Context, accountsession.Session, invitation.ActionRequest) (invitation.Invitation, error) {
	return invitation.Invitation{}, invitation.ErrInvalid
}

func (stub *invitationManagerStub) List(context.Context, accountsession.Session, workspace.ID) ([]invitation.Invitation, error) {
	stub.lists++
	return stub.listed, nil
}

func (stub *invitationManagerStub) MailConfigured() bool { return true }

func TestInvitationHTTPMethods(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + managementWorkspaceID() + "/invitations"
	for _, test := range []struct {
		name, method, path, body string
		status, lists            int
		allow, want              string
	}{
		{"list", http.MethodGet, base, "", 200, 1, "", `"invitations":[],"mail_configured":true`},
		{"list by DELETE", http.MethodDelete, base, "", 405, 0, "GET, POST", "method_not_allowed"},
		{"revoke by GET", http.MethodGet, base + "/01890f00-0000-7000-8000-000000000a01/actions/revoke", "", 405, 0,
			http.MethodPost, "method_not_allowed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &invitationManagerStub{listed: []invitation.Invitation{}}
			options.Invitations = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, test.method, test.path, test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || stub.lists != test.lists ||
				response.Header().Get("Allow") != test.allow || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("status/lists/allow %d/%d/%q, want %d/%d/%q; %s", response.Code, stub.lists,
					response.Header().Get("Allow"), test.status, test.lists, test.allow, response.Body)
			}
		})
	}
}
