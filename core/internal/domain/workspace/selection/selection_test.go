package selection_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/domain/workspace/selection"
)

var now = time.Date(2026, time.October, 6, 1, 0, 0, 0, time.UTC)

type stubStore struct {
	candidates []selection.Candidate
	result     selection.SwitchResult
	err        error
}

func (store stubStore) List(context.Context, accountsession.Session) ([]selection.Candidate, error) {
	return store.candidates, store.err
}

func (store stubStore) Switch(context.Context, selection.SwitchCommand) (selection.SwitchResult, error) {
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

func testSession(t *testing.T, version int64) accountsession.Session {
	t.Helper()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: accountsession.ID(newID(t)), DeploymentID: deployment.ID(newID(t)), PrincipalID: identity.PrincipalID(newID(t)),
		IdentitySubjectID: accountsession.IdentitySubjectID(newID(t)), LoginWorkspaceID: workspace.ID(newID(t)),
		HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test",
		AMR: []string{"mfa"}, Version: version, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func candidate(t *testing.T, current bool) selection.Candidate {
	t.Helper()
	code, err := identity.ParseDisplayCode("004218650921")
	if err != nil {
		t.Fatal(err)
	}
	return selection.Candidate{WorkspaceID: workspace.ID(newID(t)), DisplayName: "Finance", DisplayCode: code,
		Current: current}
}

func TestListChecksCandidates(t *testing.T) {
	t.Parallel()
	session := testSession(t, 3)
	duplicate := candidate(t, false)
	unnamed := candidate(t, false)
	unnamed.DisplayName = ""
	for _, test := range []struct {
		name       string
		candidates []selection.Candidate
		wantErr    error
	}{
		{name: "valid", candidates: []selection.Candidate{candidate(t, true), candidate(t, false)}},
		{name: "empty", candidates: nil},
		{name: "two current", candidates: []selection.Candidate{candidate(t, true), candidate(t, true)},
			wantErr: selection.ErrInvalid},
		{name: "duplicate", candidates: []selection.Candidate{duplicate, duplicate}, wantErr: selection.ErrInvalid},
		{name: "unnamed", candidates: []selection.Candidate{unnamed}, wantErr: selection.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, err := selection.NewService(stubStore{candidates: test.candidates}, fixedClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			got, err := service.List(context.Background(), session)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("List() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && len(got) != len(test.candidates) {
				t.Fatalf("List() = %d candidates, want %d", len(got), len(test.candidates))
			}
		})
	}
	expired, err := selection.NewService(stubStore{}, fixedClock{now: now.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expired.List(context.Background(), session); !errors.Is(err, selection.ErrForbidden) {
		t.Fatalf("expired Session: %v", err)
	}
}

func TestSwitchChecksReceipt(t *testing.T) {
	t.Parallel()
	session := testSession(t, 3)
	target := workspace.ID(newID(t))
	other := workspace.ID(newID(t))
	for _, test := range []struct {
		name    string
		result  selection.SwitchResult
		err     error
		wantErr error
	}{
		{name: "switched", result: selection.SwitchResult{WorkspaceID: target, SessionVersion: 4}},
		{name: "replayed", result: selection.SwitchResult{WorkspaceID: target, SessionVersion: 3, Replayed: true}},
		{name: "other Workspace", result: selection.SwitchResult{WorkspaceID: other, SessionVersion: 4},
			wantErr: selection.ErrInvalid},
		{name: "version skipped", result: selection.SwitchResult{WorkspaceID: target, SessionVersion: 5},
			wantErr: selection.ErrInvalid},
		{name: "replay advanced", result: selection.SwitchResult{WorkspaceID: target, SessionVersion: 4, Replayed: true},
			wantErr: selection.ErrInvalid},
		{name: "store error", err: selection.ErrNotAvailable, wantErr: selection.ErrNotAvailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, err := selection.NewService(stubStore{result: test.result, err: test.err}, fixedClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Switch(context.Background(), selection.SwitchCommand{Session: session, WorkspaceID: target,
				CorrelationID: newID(t)})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Switch() error = %v, want %v", err, test.wantErr)
			}
		})
	}
	if _, err := selection.NewService(nil, fixedClock{}); !errors.Is(err, selection.ErrInvalid) {
		t.Fatal("nil store accepted")
	}
}
