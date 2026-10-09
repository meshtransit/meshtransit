package target_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing/target"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var now = time.Date(2026, time.October, 6, 1, 0, 0, 0, time.UTC)

type stubStore struct {
	result target.Target
	err    error
}

func (store stubStore) Resolve(context.Context, target.Query) (target.Target, error) {
	return store.result, store.err
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func newID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func scope(t *testing.T, ws workspace.ID) network.Scope {
	t.Helper()
	value, err := network.NewScope(ws, network.ID(newID(t)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func code(t *testing.T, value string) identity.DisplayCode {
	t.Helper()
	parsed, err := identity.ParseDisplayCode(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestResolveChecksReceipt(t *testing.T) {
	t.Parallel()
	providerWorkspace := workspace.ID(newID(t))
	session, err := accountsession.NewSession(accountsession.Params{
		ID: accountsession.ID(newID(t)), DeploymentID: deployment.ID(newID(t)), PrincipalID: identity.PrincipalID(newID(t)),
		IdentitySubjectID: accountsession.IdentitySubjectID(newID(t)), LoginWorkspaceID: providerWorkspace,
		HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test",
		AMR: []string{"mfa"}, Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := scope(t, providerWorkspace)
	query := target.Query{Session: session, Provider: provider, NetworkCode: code(t, "798657066103")}
	remote := target.Target{Scope: scope(t, workspace.ID(newID(t))), WorkspaceCode: code(t, "537439945753"),
		NetworkCode: query.NetworkCode}
	for _, test := range []struct {
		name    string
		result  target.Target
		err     error
		wantErr error
	}{
		{name: "resolved", result: remote},
		{name: "other code", result: target.Target{Scope: remote.Scope, WorkspaceCode: remote.WorkspaceCode,
			NetworkCode: code(t, "111111111111")}, wantErr: target.ErrInvalid},
		{name: "no scope", result: target.Target{WorkspaceCode: remote.WorkspaceCode, NetworkCode: query.NetworkCode},
			wantErr: target.ErrInvalid},
		{name: "not found", err: target.ErrNotFound, wantErr: target.ErrNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, err := target.NewService(stubStore{result: test.result, err: test.err}, fixedClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			got, err := service.Resolve(context.Background(), query)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Resolve() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && !got.CrossWorkspace(provider) {
				t.Fatal("a target in another Workspace must be cross-Workspace")
			}
		})
	}
	expired, err := target.NewService(stubStore{result: remote}, fixedClock{now: now.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expired.Resolve(context.Background(), query); !errors.Is(err, target.ErrForbidden) {
		t.Fatalf("expired Session: %v", err)
	}
}
