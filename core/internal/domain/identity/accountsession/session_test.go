package accountsession_test

import (
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestSessionOwnsAuthorityEvidence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	params := validSessionParams(t, now)
	session, err := accountsession.NewSession(params)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	params.AMR[0] = "changed"
	if got := session.AMR(); len(got) != 2 || got[0] != "pwd" {
		t.Fatalf("AMR() = %v, want defensive copy", got)
	}
	gotAMR := session.AMR()
	gotAMR[0] = "changed"
	if session.AMR()[0] != "pwd" {
		t.Fatal("AMR() exposed mutable storage")
	}
	if !session.IsValid() || !session.IsActiveAt(now) ||
		session.IsActiveAt(session.IdleExpiresAt()) ||
		session.IsActiveAt(session.AbsoluteExpiresAt()) {
		t.Fatal("Session active-window contract is invalid")
	}
	workspaceID, ok := session.LoginWorkspaceID()
	if !ok || workspaceID != params.LoginWorkspaceID {
		t.Fatal("Session lost login Workspace qualifier")
	}
}

func TestSessionRejectsMalformedAuthority(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*accountsession.Params)
	}{
		{name: "missing session", mutate: func(params *accountsession.Params) { params.ID = accountsession.ID{} }},
		{name: "missing workspace", mutate: func(params *accountsession.Params) { params.LoginWorkspaceID = workspace.ID{} }},
		{name: "unexpected workspace", mutate: func(params *accountsession.Params) { params.HasLoginWorkspace = false }},
		{name: "zero generation", mutate: func(params *accountsession.Params) { params.PrincipalAuthorityGeneration = 0 }},
		{name: "idle after absolute", mutate: func(params *accountsession.Params) { params.IdleExpiresAt = params.AbsoluteExpiresAt.Add(time.Second) }},
		{name: "invalid acr", mutate: func(params *accountsession.Params) { params.ACR = " mfa" }},
		{name: "empty amr", mutate: func(params *accountsession.Params) { params.AMR = []string{""} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := validSessionParams(t, now)
			test.mutate(&params)
			if _, err := accountsession.NewSession(params); err == nil {
				t.Fatal("NewSession() error = nil")
			}
		})
	}
}

func validSessionParams(t *testing.T, now time.Time) accountsession.Params {
	t.Helper()
	sessionID, err := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	if err != nil {
		t.Fatalf("ParseID() error = %v", err)
	}
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	principalID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000711")
	if err != nil {
		t.Fatalf("ParseIdentitySubjectID() error = %v", err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	return accountsession.Params{
		ID:                           sessionID,
		DeploymentID:                 deploymentID,
		PrincipalID:                  principalID,
		IdentitySubjectID:            subjectID,
		LoginWorkspaceID:             workspaceID,
		HasLoginWorkspace:            true,
		AuthenticationTime:           now.Add(-time.Minute),
		ACR:                          "urn:meshtransit:assurance:mfa",
		AMR:                          []string{"pwd", "mfa"},
		Version:                      3,
		PrincipalAuthorityGeneration: 4,
		AccountSessionGeneration:     5,
		ProviderGeneration:           6,
		DeploymentRecoveryEpoch:      7,
		IdleExpiresAt:                now.Add(time.Hour),
		AbsoluteExpiresAt:            now.Add(8 * time.Hour),
	}
}
