package distribution

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/workspace"
)

var testNow = time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return testNow }

type fakeReader struct {
	target    Target
	err       error
	gotID     node.ID
	gotScope  network.Scope
	callCount int
}

func (reader *fakeReader) ReadTarget(_ context.Context, _ accountsession.Session, scope network.Scope,
	id node.ID) (Target, error) {
	reader.callCount++
	reader.gotScope, reader.gotID = scope, id
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

func TestServiceJoinsIntentWithDelivery(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	device := testDeviceID(t, "301")
	for _, test := range []struct {
		name        string
		observation Observation
		want        Status
	}{
		{"current", known(7, true), StatusInSync},
		{"behind", known(5, true), StatusBehind},
		{"offline", known(5, false), StatusOffline},
		{"never", Observation{}, StatusNeverConnected},
	} {
		reader := &fakeReader{target: Target{Scope: scope, NetworkRevision: 7, PolicyRevision: 3,
			Devices: []TargetDevice{{ID: device, Hostname: "poc-01", State: "active"}}}}
		observations := fakeObservations{byID: map[node.ID]Observation{device: test.observation}}
		service, err := NewService(reader, observations, fixedClock{})
		if err != nil {
			t.Fatal(err)
		}
		report, err := service.ReadDevice(t.Context(), testSession(t), scope, device)
		if err != nil || reader.gotID != device || reader.gotScope != scope || report.NetworkRevision != 7 ||
			report.PolicyRevision != 3 || !report.ObservationsAvailable || report.Device.Status != test.want {
			t.Fatalf("%s: ReadDevice() = %+v, %v", test.name, report, err)
		}
	}
}

func TestServiceStillReportsWhenDeliveriesAreUnavailable(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	device := testDeviceID(t, "301")
	reader := &fakeReader{target: Target{Scope: scope, NetworkRevision: 2, Devices: []TargetDevice{
		{ID: device, Hostname: "poc-01", State: "active"},
	}}}
	service, _ := NewService(reader, fakeObservations{err: errors.New("redis down")}, fixedClock{})
	report, err := service.ReadDevice(t.Context(), testSession(t), scope, device)
	if err != nil || report.ObservationsAvailable || report.Device.Status != StatusUnknown {
		t.Fatalf("ReadDevice() = %+v, %v", report, err)
	}
}

func TestServiceRejectsBadInputAndEvidence(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	session := testSession(t)
	device := testDeviceID(t, "301")
	service, _ := NewService(&fakeReader{}, fakeObservations{}, fixedClock{})
	if _, err := service.ReadDevice(t.Context(), session, scope, node.ID{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero Device error = %v", err)
	}
	for name, target := range map[string]Target{
		"foreign scope":  {Scope: network.Scope{}, NetworkRevision: 1},
		"no revision":    {Scope: scope},
		"expired device": {Scope: scope, NetworkRevision: 1, Devices: []TargetDevice{{ID: device, Hostname: "a", State: "expired"}}},
		"another device": {Scope: scope, NetworkRevision: 1, Devices: []TargetDevice{{ID: testDeviceID(t, "302"), Hostname: "a", State: "active"}}},
		"two devices": {Scope: scope, NetworkRevision: 1, Devices: []TargetDevice{
			{ID: device, Hostname: "a", State: "active"}, {ID: device, Hostname: "a", State: "active"}}},
	} {
		service, _ := NewService(&fakeReader{target: target}, fakeObservations{}, fixedClock{})
		if _, err := service.ReadDevice(t.Context(), session, scope, device); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("%s: error = %v, want ErrInvalidResult", name, err)
		}
	}
	service, _ = NewService(&fakeReader{target: Target{Scope: scope, NetworkRevision: 1}}, fakeObservations{}, fixedClock{})
	if _, err := service.ReadDevice(t.Context(), session, scope, device); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed Device error = %v", err)
	}
	service, _ = NewService(&fakeReader{err: ErrForbidden}, fakeObservations{}, fixedClock{})
	if _, err := service.ReadDevice(t.Context(), session, scope, device); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forbidden error = %v", err)
	}
}
