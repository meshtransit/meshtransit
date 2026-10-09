package devicegroup_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestDefinitionValidation(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		definition devicegroup.Definition
		valid      bool
	}{
		"plain":            {devicegroup.Definition{Name: "Servers", Description: "Production hosts"}, true},
		"unicode":          {devicegroup.Definition{Name: "Máy chủ"}, true},
		"longest name":     {devicegroup.Definition{Name: strings.Repeat("a", devicegroup.MaximumNameLength)}, true},
		"blank":            {devicegroup.Definition{Name: "  "}, false},
		"padded":           {devicegroup.Definition{Name: " Servers"}, false},
		"too long":         {devicegroup.Definition{Name: strings.Repeat("a", devicegroup.MaximumNameLength+1)}, false},
		"control":          {devicegroup.Definition{Name: "Ser\nvers"}, false},
		"long description": {devicegroup.Definition{Name: "A", Description: strings.Repeat("d", 281)}, false},
		"control in text":  {devicegroup.Definition{Name: "A", Description: "x\x00"}, false},
	}
	for name, test := range cases {
		if got := test.definition.IsValid(); got != test.valid {
			t.Errorf("%s: IsValid() = %v, want %v", name, got, test.valid)
		}
	}
}

type recordingStore struct {
	membership devicegroup.MembershipChange
	calls      int
}

func (store *recordingStore) List(context.Context, accountsession.Session, network.Scope, time.Time) (
	devicegroup.Listing, error) {
	store.calls++
	return devicegroup.Listing{}, nil
}

func (store *recordingStore) Members(context.Context, accountsession.Session, network.Scope, devicegroup.ID,
	node.ID, int, time.Time) (devicegroup.MemberPage, error) {
	store.calls++
	return devicegroup.MemberPage{}, nil
}

func (store *recordingStore) Change(context.Context, devicegroup.Change) (devicegroup.Result, error) {
	store.calls++
	return devicegroup.Result{}, nil
}

func (store *recordingStore) ChangeMembers(_ context.Context, change devicegroup.MembershipChange) (
	devicegroup.MembershipResult, error) {
	store.calls++
	store.membership = change
	return devicegroup.MembershipResult{}, nil
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

func TestChangeMembersRejectsAmbiguousChangesBeforeTheStore(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	now := time.Date(2026, time.October, 7, 10, 0, 0, 0, time.UTC)
	service, err := devicegroup.NewService(store, fixedClock{now}, devicegroup.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, now)
	login, _ := session.LoginWorkspaceID()
	scope, err := network.NewScope(login, network.ID(newID(t)))
	if err != nil {
		t.Fatal(err)
	}
	group := devicegroup.ID(newID(t))
	device := node.ID(newID(t))
	many := make([]node.ID, devicegroup.MaximumMembersPerChange+1)
	for index := range many {
		many[index] = node.ID(newID(t))
	}
	cases := map[string]struct {
		add, remove []node.ID
	}{
		"empty":            {nil, nil},
		"added twice":      {[]node.ID{device, device}, nil},
		"added and gone":   {[]node.ID{device}, []node.ID{device}},
		"too many":         {many, nil},
		"invalid device":   {[]node.ID{{}}, nil},
		"too many removed": {nil, many},
	}
	for name, test := range cases {
		_, err := service.ChangeMembers(context.Background(), session, scope, group, 1,
			test.add, test.remove, newID(t))
		if !errors.Is(err, devicegroup.ErrInvalid) {
			t.Errorf("%s: error = %v, want refusal", name, err)
		}
	}
	if store.calls != 0 {
		t.Fatalf("store called %d times for refused changes", store.calls)
	}
	if _, err := service.ChangeMembers(context.Background(), session, scope, group, 1, []node.ID{device}, nil,
		newID(t)); err != nil || len(store.membership.AddMemberIDs) != 1 || !store.membership.AddMemberIDs[0].IsValid() {
		t.Fatalf("valid change = %+v, error = %v; want one fresh member ID", store.membership, err)
	}
	if _, err := service.List(context.Background(), session, scope); err != nil {
		t.Fatal(err)
	}
	expired := fixedClock{now.Add(3 * time.Hour)}
	late, err := devicegroup.NewService(store, expired, devicegroup.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := late.List(context.Background(), session, scope); !errors.Is(err, devicegroup.ErrForbidden) {
		t.Fatalf("expired Session listed groups: %v", err)
	}
}

func activeSession(t *testing.T, now time.Time) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID, IdentitySubjectID: subjectID,
		LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}
