package devicelifecycle_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/devicelifecycle"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
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

type fixedClock struct{}

func (fixedClock) Now() time.Time { return testNow }

type recordingStore struct{ changes []devicelifecycle.Change }

func (store *recordingStore) Change(_ context.Context, change devicelifecycle.Change) (devicelifecycle.Result, error) {
	store.changes = append(store.changes, change)
	return devicelifecycle.Result{}, nil
}

func baseRequest(t *testing.T) devicelifecycle.Request {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
	correlation, _ := publicid.Parse("01890f00-0000-7000-8000-000000000999")
	return devicelifecycle.Request{Scope: scope, DeviceID: device, ExpectedVersion: 3,
		Reason: "Laptop handed to Bao", CorrelationID: correlation}
}

func TestServiceValidatesEachAction(t *testing.T) {
	t.Parallel()
	owner, _ := publicid.Parse("01890f00-0000-7000-8000-000000000402")
	hostname, _ := node.ParseHostname("db-primary")
	with := func(change func(*devicelifecycle.Request)) devicelifecycle.Request {
		request := baseRequest(t)
		change(&request)
		return request
	}
	valid := map[string]devicelifecycle.Request{
		"suspend":      with(func(r *devicelifecycle.Request) { r.Action = devicelifecycle.ActionSuspend }),
		"resume":       with(func(r *devicelifecycle.Request) { r.Action = devicelifecycle.ActionResume }),
		"to Workspace": with(func(r *devicelifecycle.Request) { r.Action = devicelifecycle.ActionTransferWorkspace }),
		"to member":    with(func(r *devicelifecycle.Request) { r.Action, r.NewOwner = devicelifecycle.ActionTransferMember, owner }),
		"rename":       with(func(r *devicelifecycle.Request) { r.Action, r.Hostname = devicelifecycle.ActionRename, hostname }),
		"rename, no reason": with(func(r *devicelifecycle.Request) {
			r.Action, r.Hostname, r.Reason = devicelifecycle.ActionRename, hostname, ""
		}),
	}
	invalid := map[string]devicelifecycle.Request{
		"unknown action":     with(func(r *devicelifecycle.Request) { r.Action = "delete" }),
		"suspend, no reason": with(func(r *devicelifecycle.Request) { r.Action, r.Reason = devicelifecycle.ActionSuspend, "" }),
		"multi-line reason":  with(func(r *devicelifecycle.Request) { r.Action, r.Reason = devicelifecycle.ActionSuspend, "a\nb" }),
		"overlong reason": with(func(r *devicelifecycle.Request) {
			r.Action, r.Reason = devicelifecycle.ActionSuspend, strings.Repeat("a", 257)
		}),
		"member, no owner": with(func(r *devicelifecycle.Request) { r.Action = devicelifecycle.ActionTransferMember }),
		"Workspace with owner": with(func(r *devicelifecycle.Request) {
			r.Action, r.NewOwner = devicelifecycle.ActionTransferWorkspace, owner
		}),
		"rename, no hostname": with(func(r *devicelifecycle.Request) { r.Action = devicelifecycle.ActionRename }),
		"suspend with name":   with(func(r *devicelifecycle.Request) { r.Action, r.Hostname = devicelifecycle.ActionSuspend, hostname }),
		"stale version":       with(func(r *devicelifecycle.Request) { r.Action, r.ExpectedVersion = devicelifecycle.ActionSuspend, 0 }),
	}
	store := &recordingStore{}
	service, err := devicelifecycle.NewService(store, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	session := testSession(t)
	for name, request := range valid {
		if _, err := service.Change(t.Context(), session, request); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, request := range invalid {
		if _, err := service.Change(t.Context(), session, request); !errors.Is(err, devicelifecycle.ErrInvalid) {
			t.Errorf("%s: error = %v, want ErrInvalid", name, err)
		}
	}
	if len(store.changes) != len(valid) || !store.changes[0].EvaluatedAt.Equal(testNow) {
		t.Fatalf("store saw %d changes", len(store.changes))
	}
}
