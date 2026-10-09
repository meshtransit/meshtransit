package mapsession

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

func TestServiceLoadsSnapshotForBoundIdentity(t *testing.T) {
	snapshot := snapshotFixture(t)
	store := &recordingSnapshotStore{snapshot: snapshot}
	endpoints := &recordingEndpointObserver{}
	service := newServiceFixture(t, store, endpoints)
	machine, request := authenticatedRequestFixture(t, snapshot)

	got, err := service.Open(context.Background(), machine, request)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !got.IsValid() || got.NodeID() != snapshot.NodeID() {
		t.Fatalf("Open() snapshot = %+v, want validated fixture", got)
	}
	if !store.identity.IsValid() || store.identity.NodeKey() != request.NodeKey() ||
		store.identity.MachineFingerprint() != snapshot.MachineKey().Fingerprint() {
		t.Fatalf("store identity was not bound to authenticated request")
	}
	if endpoints.calls != 0 {
		t.Fatalf("endpoint observer calls = %d, want zero without a report", endpoints.calls)
	}
}

func TestServiceLoadsConnectivityOnlyForSelfAndAuthorizedPeers(t *testing.T) {
	t.Parallel()

	snapshot, peer := snapshotWithAuthorizedPeerFixture(t)
	connectivity := &recordingConnectivityStore{}
	service, err := NewService(
		&recordingSnapshotStore{snapshot: snapshot},
		&recordingEndpointObserver{},
		connectivity,
		ServiceOptions{EndpointTTL: 30 * time.Second, EndpointTimeout: time.Second},
	)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, snapshot)
	result, err := service.Open(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if connectivity.calls != 1 || len(connectivity.keys) != 2 ||
		connectivity.keys[0].NodeID() != snapshot.NodeID() ||
		connectivity.keys[1].NodeID() != peer.NodeID() {
		t.Fatalf("LoadConnectivity() keys = %+v after %d calls, want self then authorized peer", connectivity.keys, connectivity.calls)
	}
	if _, found := result.ConnectivityFor(peer.NodeID()); !found {
		t.Fatal("Open() omitted authorized peer connectivity projection")
	}
}

func TestServiceOmitsStalePreferredRelayOutsideCurrentDirectory(t *testing.T) {
	t.Parallel()

	snapshot := snapshotFixture(t)
	key, err := NewConnectivityKey(snapshot.NodeID(), snapshot.SessionGeneration())
	if err != nil {
		t.Fatalf("NewConnectivityKey() error = %v", err)
	}
	stale, err := NewConnectivity(ConnectivityParams{
		Key:                   key,
		PreferredRelay:        2,
		PreferredRelayPresent: true,
	})
	if err != nil {
		t.Fatalf("NewConnectivity() error = %v", err)
	}
	connectivity := &recordingConnectivityStore{values: []Connectivity{stale}}
	service, err := NewService(
		&recordingSnapshotStore{snapshot: snapshot},
		&recordingEndpointObserver{},
		connectivity,
		ServiceOptions{EndpointTTL: 30 * time.Second, EndpointTimeout: time.Second},
	)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, snapshot)
	result, err := service.Open(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	projected, found := result.ConnectivityFor(snapshot.NodeID())
	if !found {
		t.Fatal("Open() omitted self connectivity")
	}
	if preferredRelay, present := projected.PreferredRelay(); present || preferredRelay != 0 {
		t.Fatalf("PreferredRelay() = (%d, %t), want omitted stale region", preferredRelay, present)
	}
}

func TestServiceObservesEndpointsAfterAuthoritativeIdentityBinding(t *testing.T) {
	snapshot := snapshotFixture(t)
	store := &recordingSnapshotStore{snapshot: snapshot}
	observer := &recordingEndpointObserver{accepted: true}
	service := newServiceFixture(t, store, observer)
	machine, request := authenticatedRequestFixture(t, snapshot)
	request = withEndpointSetFixture(t, request)
	request, err := request.WithPreferredRelay(1)
	if err != nil {
		t.Fatalf("Request.WithPreferredRelay() error = %v", err)
	}

	if _, err := service.Open(t.Context(), machine, request); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	preferredRelay, preferredRelayPresent := observer.observation.PreferredRelay()
	if observer.calls != 1 || !observer.observation.IsValid() ||
		observer.scope != snapshot.Scope() ||
		observer.observation.NodeID() != snapshot.NodeID() ||
		observer.observation.Generation() != snapshot.SessionGeneration() ||
		observer.observation.TTL() != 30*time.Second ||
		preferredRelay != 1 || !preferredRelayPresent {
		t.Fatalf("endpoint observation = %+v after %d calls, want bound snapshot observation", observer.observation, observer.calls)
	}
}

func TestServiceRejectsPreferredRelayOutsideAuthorizedDirectory(t *testing.T) {
	t.Parallel()

	snapshot := snapshotFixture(t)
	observer := &recordingEndpointObserver{accepted: true}
	service := newServiceFixture(t, &recordingSnapshotStore{snapshot: snapshot}, observer)
	machine, request := authenticatedRequestFixture(t, snapshot)
	request = withEndpointSetFixture(t, request)
	request, err := request.WithPreferredRelay(2)
	if err != nil {
		t.Fatalf("Request.WithPreferredRelay() error = %v", err)
	}
	if _, err := service.Open(t.Context(), machine, request); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open() error = %v, want ErrOpen", err)
	}
	if observer.calls != 0 {
		t.Fatalf("endpoint observer calls = %d, want zero for unknown relay", observer.calls)
	}
}

func TestServiceFailsClosedWhenEndpointObservationIsUnavailableOrStale(t *testing.T) {
	snapshot := snapshotFixture(t)
	machine, request := authenticatedRequestFixture(t, snapshot)
	request = withEndpointSetFixture(t, request)
	wantErr := errors.New("redis unavailable")
	for _, test := range []struct {
		name     string
		observer *recordingEndpointObserver
		want     error
	}{
		{name: "unavailable", observer: &recordingEndpointObserver{err: wantErr}, want: wantErr},
		{name: "stale", observer: &recordingEndpointObserver{}, want: ErrEndpointObservationRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := newServiceFixture(t, &recordingSnapshotStore{snapshot: snapshot}, test.observer)
			if _, err := service.Open(t.Context(), machine, request); !errors.Is(err, test.want) ||
				!errors.Is(err, ErrOpen) {
				t.Fatalf("Open() error = %v, want ErrOpen and %v", err, test.want)
			}
		})
	}
}

func TestServiceFailsClosedOnMismatchedSnapshot(t *testing.T) {
	snapshot := snapshotFixture(t)
	params := snapshot.params()
	params.NodeKey, _ = node.NewKey([32]byte{9})
	mismatched, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	observer := &recordingEndpointObserver{accepted: true}
	service := newServiceFixture(t, &recordingSnapshotStore{snapshot: mismatched}, observer)
	machine, request := authenticatedRequestFixture(t, snapshot)
	request = withEndpointSetFixture(t, request)

	if _, err := service.Open(context.Background(), machine, request); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open() error = %v, want ErrOpen", err)
	}
	if observer.calls != 0 {
		t.Fatalf("endpoint observer calls = %d, want zero before snapshot validation", observer.calls)
	}
}

func TestServicePropagatesCancellationWithoutStorageCall(t *testing.T) {
	snapshot := snapshotFixture(t)
	store := &recordingSnapshotStore{snapshot: snapshot}
	observer := &recordingEndpointObserver{accepted: true}
	service := newServiceFixture(t, store, observer)
	machine, request := authenticatedRequestFixture(t, snapshot)
	request = withEndpointSetFixture(t, request)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := service.Open(ctx, machine, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want context cancellation", err)
	}
	if store.calls != 0 {
		t.Fatalf("storage calls = %d, want zero", store.calls)
	}
	if observer.calls != 0 {
		t.Fatalf("endpoint observer calls = %d, want zero", observer.calls)
	}
}

func TestNewServiceRejectsInvalidComposition(t *testing.T) {
	t.Parallel()

	validOptions := ServiceOptions{EndpointTTL: 30 * time.Second, EndpointTimeout: time.Second}
	connectivity := &recordingConnectivityStore{}
	if _, err := NewService(nil, &recordingEndpointObserver{}, connectivity, validOptions); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewService(nil store) error = %v, want ErrInvalidService", err)
	}
	if _, err := NewService(&recordingSnapshotStore{}, nil, connectivity, validOptions); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewService(nil observer) error = %v, want ErrInvalidService", err)
	}
	if _, err := NewService(
		&recordingSnapshotStore{},
		&recordingEndpointObserver{},
		nil,
		validOptions,
	); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewService(nil connectivity) error = %v, want ErrInvalidService", err)
	}
	if _, err := NewService(&recordingSnapshotStore{}, &recordingEndpointObserver{}, connectivity, ServiceOptions{}); !errors.Is(
		err,
		ErrInvalidService,
	) {
		t.Fatalf("NewService(zero options) error = %v, want ErrInvalidService", err)
	}
}

func authenticatedRequestFixture(
	t *testing.T,
	snapshot Snapshot,
) (control.AuthenticatedMachine, Request) {
	t.Helper()
	machine, err := control.NewAuthenticatedMachine(snapshot.MachineKey())
	if err != nil {
		t.Fatalf("control.NewAuthenticatedMachine() error = %v", err)
	}
	request, err := NewRequest(snapshot.NodeKey(), 142)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return machine, request
}

func withEndpointSetFixture(t testing.TB, request Request) Request {
	t.Helper()
	discoveryKey, err := node.NewDiscoveryKey([32]byte{3})
	if err != nil {
		t.Fatalf("node.NewDiscoveryKey() error = %v", err)
	}
	endpoint, err := node.NewEndpoint(
		netip.MustParseAddrPort("192.0.2.10:41641"),
		node.EndpointSourceSTUN,
	)
	if err != nil {
		t.Fatalf("node.NewEndpoint() error = %v", err)
	}
	set, err := node.NewEndpointSet(discoveryKey, []node.Endpoint{endpoint})
	if err != nil {
		t.Fatalf("node.NewEndpointSet() error = %v", err)
	}
	request, err = request.WithEndpointSet(set)
	if err != nil {
		t.Fatalf("Request.WithEndpointSet() error = %v", err)
	}
	return request
}

func newServiceFixture(
	t testing.TB,
	store SnapshotStore,
	endpoints EndpointObserver,
) *Service {
	t.Helper()
	service, err := NewService(store, endpoints, &recordingConnectivityStore{}, ServiceOptions{
		EndpointTTL:     30 * time.Second,
		EndpointTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

type recordingSnapshotStore struct {
	snapshot Snapshot
	err      error
	identity control.AuthenticatedNode
	calls    int
}

type recordingEndpointObserver struct {
	accepted    bool
	err         error
	observation node.EndpointObservation
	scope       network.Scope
	calls       int
}

func (observer *recordingEndpointObserver) ObserveEndpoints(
	_ context.Context,
	scope network.Scope,
	observation node.EndpointObservation,
) (bool, error) {
	observer.calls++
	observer.scope = scope
	observer.observation = observation
	return observer.accepted, observer.err
}

type recordingConnectivityStore struct {
	keys   []ConnectivityKey
	values []Connectivity
	calls  int
	err    error
}

func (store *recordingConnectivityStore) LoadConnectivity(
	_ context.Context,
	keys []ConnectivityKey,
) ([]Connectivity, error) {
	store.calls++
	store.keys = slices.Clone(keys)
	if store.err != nil {
		return nil, store.err
	}
	if store.values != nil {
		return slices.Clone(store.values), nil
	}
	values := make([]Connectivity, len(keys))
	for index, key := range keys {
		var err error
		values[index], err = NewConnectivity(ConnectivityParams{Key: key})
		if err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (store *recordingSnapshotStore) Load(
	_ context.Context,
	identity control.AuthenticatedNode,
) (Snapshot, error) {
	store.calls++
	store.identity = identity
	return store.snapshot, store.err
}
