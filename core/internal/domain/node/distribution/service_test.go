package distribution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var testNow = time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return testNow }

type fakeReader struct {
	target    Target
	err       error
	gotAfter  node.ID
	gotLimit  int
	gotScope  network.Scope
	callCount int
}

func (reader *fakeReader) ReadDistribution(_ context.Context, _ accountsession.Session, scope network.Scope,
	after node.ID, limit int, _ time.Time) (Target, error) {
	reader.callCount++
	reader.gotScope, reader.gotAfter, reader.gotLimit = scope, after, limit
	return reader.target, reader.err
}

type fakeObservations struct {
	byID map[node.ID]Observation
	err  error
}

func (loader fakeObservations) LoadObservations(_ context.Context, ids []node.ID) ([]Observation, error) {
	if loader.err != nil {
		return nil, loader.err
	}
	result := make([]Observation, len(ids))
	for index, id := range ids {
		result[index] = loader.byID[id]
	}
	return result, nil
}

func testScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

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

func testDeviceID(t *testing.T, suffix string) node.ID {
	t.Helper()
	id, err := node.ParseID("01890f00-0000-7000-8000-000000000" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func known(revision int64, online bool) Observation {
	return Observation{Known: true, SessionGeneration: 1, NetworkRevision: revision, PolicyRevision: 3,
		DeliveredAt: testNow.Add(-time.Minute), SeenAt: testNow.Add(-10 * time.Second), Online: online}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		observation Observation
		want        Status
	}{
		{"online with the current revision", known(7, true), StatusInSync},
		{"online with a newer revision than read", known(8, true), StatusInSync},
		{"online but behind", known(6, true), StatusBehind},
		{"online without a recorded delivery", Observation{Online: true}, StatusBehind},
		{"offline after a delivery", known(7, false), StatusOffline},
		{"never connected", Observation{}, StatusNeverConnected},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := Classify(7, test.observation); got != test.want {
				t.Fatalf("Classify() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestServiceJoinsIntentWithDeliveriesAndPages(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	first, second, third := testDeviceID(t, "301"), testDeviceID(t, "302"), testDeviceID(t, "303")
	reader := &fakeReader{target: Target{Scope: scope, NetworkRevision: 7, PolicyRevision: 3, Devices: []TargetDevice{
		{ID: first, Hostname: "poc-01", State: "active"},
		{ID: second, Hostname: "poc-02", State: "active"},
		{ID: third, Hostname: "poc-03", State: "suspended"},
	}}}
	observations := fakeObservations{byID: map[node.ID]Observation{first: known(7, true), second: known(5, false)}}
	service, err := NewService(reader, observations, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}

	page, err := service.Read(t.Context(), testSession(t), scope, node.ID{}, 2)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if reader.gotLimit != 3 || reader.gotScope != scope {
		t.Fatalf("reader asked for limit %d scope %+v", reader.gotLimit, reader.gotScope)
	}
	if page.NetworkRevision != 7 || page.PolicyRevision != 3 || !page.ObservationsAvailable ||
		len(page.Devices) != 2 || page.Next != second {
		t.Fatalf("page = %+v", page)
	}
	if page.Devices[0].Status != StatusInSync || page.Devices[1].Status != StatusOffline ||
		page.Devices[1].Observation.NetworkRevision != 5 {
		t.Fatalf("statuses = %+v", page.Devices)
	}
}

func TestServiceStillListsDevicesWhenDeliveriesAreUnavailable(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	device := testDeviceID(t, "301")
	reader := &fakeReader{target: Target{Scope: scope, NetworkRevision: 2, Devices: []TargetDevice{
		{ID: device, Hostname: "poc-01", State: "active"},
	}}}
	service, _ := NewService(reader, fakeObservations{err: errors.New("redis down")}, fixedClock{})

	page, err := service.Read(t.Context(), testSession(t), scope, node.ID{}, 10)
	if err != nil || page.ObservationsAvailable || len(page.Devices) != 1 ||
		page.Devices[0].Status != StatusUnknown || page.Next != (node.ID{}) {
		t.Fatalf("Read() = %+v, %v", page, err)
	}
}

func TestServiceRejectsBadInputAndEvidence(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	session := testSession(t)
	device := testDeviceID(t, "301")
	service, _ := NewService(&fakeReader{}, fakeObservations{}, fixedClock{})
	for _, limit := range []int{0, MaximumPageSize + 1} {
		if _, err := service.Read(t.Context(), session, scope, node.ID{}, limit); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("limit %d error = %v", limit, err)
		}
	}

	for name, target := range map[string]Target{
		"foreign scope":     {Scope: network.Scope{}, NetworkRevision: 1},
		"no revision":       {Scope: scope},
		"expired device":    {Scope: scope, NetworkRevision: 1, Devices: []TargetDevice{{ID: device, Hostname: "a", State: "expired"}}},
		"unordered devices": {Scope: scope, NetworkRevision: 1, Devices: []TargetDevice{{ID: device, Hostname: "a", State: "active"}, {ID: device, Hostname: "b", State: "active"}}},
	} {
		reader := &fakeReader{target: target}
		service, _ := NewService(reader, fakeObservations{}, fixedClock{})
		if _, err := service.Read(t.Context(), session, scope, node.ID{}, 5); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("%s: error = %v, want ErrInvalidResult", name, err)
		}
	}

	forbidden := &fakeReader{err: ErrForbidden}
	service, _ = NewService(forbidden, fakeObservations{}, fixedClock{})
	if _, err := service.Read(t.Context(), session, scope, node.ID{}, 5); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forbidden error = %v", err)
	}
}
