package memberlifecycle_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/memberlifecycle"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

var testNow = time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)

func testSession(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: testNow.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: testNow.Add(time.Hour), AbsoluteExpiresAt: testNow.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type recordingStore struct{ changes []memberlifecycle.Change }

func (store *recordingStore) Change(_ context.Context, change memberlifecycle.Change) (memberlifecycle.Result, error) {
	store.changes = append(store.changes, change)
	return memberlifecycle.Result{}, nil
}

func baseRequest(t *testing.T) memberlifecycle.Request {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	member, _ := publicid.Parse("01890f00-0000-7000-8000-000000000402")
	correlation, _ := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	return memberlifecycle.Request{
		WorkspaceID: workspaceID, MemberID: member, Action: memberlifecycle.ActionSuspend,
		Reason: "Left the company", CorrelationID: correlation,
	}
}

func TestServiceStampsAndValidatesChanges(t *testing.T) {
	t.Parallel()
	session := testSession(t)
	tests := []struct {
		name   string
		mutate func(*memberlifecycle.Request)
		want   error
	}{
		{name: "suspend", mutate: func(*memberlifecycle.Request) {}},
		{name: "resume", mutate: func(request *memberlifecycle.Request) {
			request.Action = memberlifecycle.ActionResume
		}},
		{name: "unknown action", mutate: func(request *memberlifecycle.Request) {
			request.Action = "remove"
		}, want: memberlifecycle.ErrInvalid},
		{name: "no reason", mutate: func(request *memberlifecycle.Request) {
			request.Reason = ""
		}, want: memberlifecycle.ErrInvalid},
		{name: "multi-line reason", mutate: func(request *memberlifecycle.Request) {
			request.Reason = "one\ntwo"
		}, want: memberlifecycle.ErrInvalid},
		{name: "long reason", mutate: func(request *memberlifecycle.Request) {
			request.Reason = strings.Repeat("x", memberlifecycle.MaximumReasonBytes+1)
		}, want: memberlifecycle.ErrInvalid},
		{name: "no member", mutate: func(request *memberlifecycle.Request) {
			request.MemberID = publicid.ID{}
		}, want: memberlifecycle.ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingStore{}
			service, err := memberlifecycle.NewService(store, fixedClock{now: testNow})
			if err != nil {
				t.Fatal(err)
			}
			request := baseRequest(t)
			test.mutate(&request)
			_, err = service.Change(t.Context(), session, request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Change() error = %v, want %v", err, test.want)
			}
			if test.want == nil && (len(store.changes) != 1 || !store.changes[0].EvaluatedAt.Equal(testNow)) {
				t.Fatalf("store changes = %+v", store.changes)
			}
		})
	}
}

func TestServiceRefusesAnEndedSession(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	service, err := memberlifecycle.NewService(store, fixedClock{now: testNow.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Change(t.Context(), testSession(t), baseRequest(t)); !errors.Is(err, memberlifecycle.ErrForbidden) {
		t.Fatalf("Change() error = %v, want forbidden", err)
	}
	if _, err := memberlifecycle.NewService(nil, fixedClock{}); !errors.Is(err, memberlifecycle.ErrInvalid) {
		t.Fatal("a service needs a store")
	}
}
