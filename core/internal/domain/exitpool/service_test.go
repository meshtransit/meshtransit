package exitpool_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type recordingStore struct {
	calls  int
	change exitpool.Change
	node   exitpool.NodeChange
}

func (store *recordingStore) List(context.Context, accountsession.Session, network.Scope, exitpool.ID,
	int) (exitpool.Listing, error) {
	store.calls++
	return exitpool.Listing{}, nil
}

func (store *recordingStore) Read(context.Context, accountsession.Session, network.Scope,
	exitpool.ID) (exitpool.Reading, error) {
	store.calls++
	return exitpool.Reading{}, nil
}

func (store *recordingStore) Change(_ context.Context, change exitpool.Change) (exitpool.Result, error) {
	store.calls++
	store.change = change
	return exitpool.Result{}, nil
}

func (store *recordingStore) ChangeNode(_ context.Context, change exitpool.NodeChange) (exitpool.Result, error) {
	store.calls++
	store.node = change
	return exitpool.Result{}, nil
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

func TestServiceValidatesBeforeTheStore(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	now := time.Date(2026, time.October, 20, 10, 0, 0, 0, time.UTC)
	service, err := exitpool.NewService(store, fixedClock{now}, exitpool.SystemIDs{}, exitpool.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, now)
	login, _ := session.LoginWorkspaceID()
	scope, err := network.NewScope(login, network.ID(newID(t)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bad := exitpool.Definition{Name: "SG", ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer,
		DNSUpstreams: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	if _, err := service.Create(ctx, session, scope, bad, newID(t)); !errors.Is(err, exitpool.ErrNotInternet) {
		t.Fatalf("a private resolver = %v", err)
	}
	pool := exitpool.ID(newID(t))
	device := node.ID(newID(t))
	if _, err := service.PutNode(ctx, session, scope, pool, 3, exitpool.NodeAssignment{DeviceID: device,
		Priority: 1000, State: exitpool.NodeActive}, newID(t)); !errors.Is(err, exitpool.ErrInvalid) {
		t.Fatalf("a priority out of range = %v", err)
	}
	if _, err := service.Update(ctx, session, scope, pool, 0, bad, newID(t)); !errors.Is(err, exitpool.ErrInvalid) &&
		!errors.Is(err, exitpool.ErrNotInternet) {
		t.Fatalf("an update without version = %v", err)
	}
	if _, err := service.List(ctx, session, scope, exitpool.ID{}, exitpool.MaximumPage+1); !errors.Is(err,
		exitpool.ErrInvalid) {
		t.Fatalf("a page too large = %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("store called %d times for invalid requests", store.calls)
	}

	good := exitpool.Definition{Name: "SG", ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer,
		DNSUpstreams: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}}
	if _, err := service.Create(ctx, session, scope, good, newID(t)); err != nil {
		t.Fatal(err)
	}
	if store.change.Operation != exitpool.OperationCreate || !store.change.PoolID.IsValid() ||
		store.change.PoolLimit != exitpool.MaximumPoolsPerNetwork ||
		store.change.Definition.DNSUpstreams[0] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("create change = %+v", store.change)
	}
	if _, err := service.PutNode(ctx, session, scope, pool, 3, exitpool.NodeAssignment{DeviceID: device,
		Priority: 5, State: exitpool.NodeDraining}, newID(t)); err != nil {
		t.Fatal(err)
	}
	if store.node.Operation != exitpool.NodePut || store.node.NodeLimit != exitpool.MaximumNodesPerPool ||
		!store.node.NodeRowID.IsValid() || store.node.ExpectedVersion != 3 {
		t.Fatalf("node change = %+v", store.node)
	}
	if _, err := service.RemoveNode(ctx, session, scope, pool, 4, device, newID(t)); err != nil {
		t.Fatal(err)
	}
	if store.node.Operation != exitpool.NodeDelete || store.node.Assignment.DeviceID != device {
		t.Fatalf("node removal = %+v", store.node)
	}
	if _, err := service.Delete(ctx, session, scope, pool, 5, newID(t)); err != nil {
		t.Fatal(err)
	}
	if store.change.Operation != exitpool.OperationDelete || store.change.ExpectedVersion != 5 {
		t.Fatalf("delete change = %+v", store.change)
	}
}

func TestServiceRefusesAnExpiredSession(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	now := time.Date(2026, time.October, 20, 10, 0, 0, 0, time.UTC)
	service, err := exitpool.NewService(store, fixedClock{now.Add(3 * time.Hour)}, exitpool.SystemIDs{},
		exitpool.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, now)
	login, _ := session.LoginWorkspaceID()
	scope, _ := network.NewScope(login, network.ID(newID(t)))
	if _, err := service.Read(context.Background(), session, scope, exitpool.ID(newID(t))); !errors.Is(err,
		exitpool.ErrForbidden) {
		t.Fatalf("an expired session = %v", err)
	}
	if store.calls != 0 {
		t.Fatal("the store was called for an expired session")
	}
}

func TestNewServiceRefusesBadLimits(t *testing.T) {
	t.Parallel()
	if _, err := exitpool.NewService(&recordingStore{}, fixedClock{}, exitpool.SystemIDs{},
		exitpool.Limits{}); !errors.Is(err, exitpool.ErrInvalid) {
		t.Fatalf("zero limits = %v", err)
	}
}
