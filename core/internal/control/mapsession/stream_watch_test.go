package mapsession

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
)

func TestStreamSharingDependencyRefreshesBeforeFirstRuleAndReleasesRemovedScopes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider, consumer, _ := directDeviceFixtureAt(t, policy.ProtocolICMP, nil, time.Now())
		initial, err := provider.WithSharingDependencies([]network.Scope{consumer.Scope()})
		if err != nil {
			t.Fatal(err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, initial, provider}}
		revisions := newScopedRevisionFixture()
		connectivity := newScopedConnectivityFixture()
		service := newStreamServiceWithWatchersFixture(t, opener, &streamPresenceStore{}, revisions, connectivity)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()
		synctest.Wait()
		// The remote revision can be below the local number; it must still reread.
		revision, err := network.NewRevisionAdvanced(consumer.Scope().NetworkID().String(), 1)
		if err != nil {
			t.Fatal(err)
		}
		revisions.channel(consumer.Scope().NetworkID()) <- revision
		synctest.Wait()
		if calls, _ := opener.state(); calls != 4 {
			t.Fatalf("opens=%d, want immediate remote refresh", calls)
		}
		if len(initial.AuthorizedPeers()) != len(provider.AuthorizedPeers()) || !initial.PacketPolicy().Equal(provider.PacketPolicy()) {
			t.Fatal("dependency granted packet authority")
		}
		if !slices.Equal(revisions.activeScopes(), []network.ID{provider.Scope().NetworkID()}) {
			t.Fatal("removed dependency still subscribed")
		}
		snapshots, _ := sink.state()
		if len(snapshots) != 1 || len(sink.connectivityDeltas()) != 0 {
			t.Fatal("subscription-only change emitted a packet map")
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if len(revisions.activeScopes()) != 0 || connectivity.active() != 0 {
			t.Fatal("watch lifecycle leaked")
		}
	})
}

func TestStreamRemoteRuleRemovalSendsFullWithdrawalAtUnchangedLocalRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider, consumer, evidence := directDeviceFixtureAt(t, policy.ProtocolICMP, nil, time.Now())
		projection, err := NewDirectDeviceProjection(directDeviceParams(t, provider, provider, consumer, evidence))
		if err != nil {
			t.Fatal(err)
		}
		initial, err := provider.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, initial, provider}}
		revisions := newScopedRevisionFixture()
		connectivity := newScopedConnectivityFixture()
		service := newStreamServiceWithWatchersFixture(t, opener, &streamPresenceStore{}, revisions, connectivity)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()
		synctest.Wait()
		revision, err := network.NewRevisionAdvanced(consumer.Scope().NetworkID().String(), 1)
		if err != nil {
			t.Fatal(err)
		}
		revisions.channel(consumer.Scope().NetworkID()) <- revision
		synctest.Wait()
		snapshots, _ := sink.state()
		if len(snapshots) != 2 || len(snapshots[1].AuthorizedPeers()) != 0 || snapshots[1].NetworkRevision() != initial.NetworkRevision() {
			t.Fatal("remote grant removal was not sent immediately as a complete map")
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestStreamWatchCoalescesBurstAndRejectsWrongNetwork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		revisions := newScopedRevisionFixture()
		service := newStreamServiceWithWatchersFixture(t, &streamSnapshotOpener{}, &streamPresenceStore{}, revisions, newScopedConnectivityFixture())
		watch, err := service.watchSnapshot(t.Context(), initial)
		if err != nil {
			t.Fatal(err)
		}
		defer watch.close()
		for number := int64(1); number <= 8; number++ {
			revision, err := network.NewRevisionAdvanced(initial.Scope().NetworkID().String(), number)
			if err != nil {
				t.Fatal(err)
			}
			revisions.channel(initial.Scope().NetworkID()) <- revision
		}
		synctest.Wait()
		if wake := <-watch.updates; !wake.reconcile {
			t.Fatal("bounded burst did not coalesce to a complete authority reread")
		} else if wake.revision.Number() != 8 || wake.revision.NetworkID() != initial.Scope().NetworkID() {
			// A refresh from a shared view needs the newest announced revision.
			t.Fatalf("coalesced wakeup names revision %d, want 8", wake.revision.Number())
		}
		wrong, err := network.NewRevisionAdvanced("01890f00-0000-7000-8000-000000000999", 1)
		if err != nil {
			t.Fatal(err)
		}
		revisions.channel(initial.Scope().NetworkID()) <- wrong
		synctest.Wait()
		if err := <-watch.failure; !errors.Is(err, ErrStreamDiscontinuity) {
			t.Fatal(err)
		}
	})
}

func TestSharingDependenciesAreImmutableAndDenyUnsafeScopes(t *testing.T) {
	t.Parallel()
	provider, consumer, _ := directDeviceFixture(t, policy.ProtocolICMP, nil)
	values := []network.Scope{consumer.Scope()}
	snapshot, err := provider.WithSharingDependencies(values)
	if err != nil {
		t.Fatal(err)
	}
	values[0] = network.Scope{}
	returned := snapshot.SharingScopes()
	returned[0] = network.Scope{}
	if !slices.Equal(snapshot.SharingScopes(), []network.Scope{consumer.Scope()}) {
		t.Fatal("dependency slice escaped immutable snapshot")
	}
	for _, values := range [][]network.Scope{{{}}, {provider.Scope()}, {consumer.Scope(), consumer.Scope()}, make([]network.Scope, MaximumDirectDeviceProjections+1)} {
		if _, err := provider.WithSharingDependencies(values); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("unsafe dependency accepted: %v", err)
		}
	}
}

type scopedRevisionFixture struct {
	mu       sync.Mutex
	channels map[network.ID]chan network.RevisionAdvanced
	active   map[network.ID]int
}

func newScopedRevisionFixture() *scopedRevisionFixture {
	return &scopedRevisionFixture{channels: make(map[network.ID]chan network.RevisionAdvanced), active: make(map[network.ID]int)}
}
func (fixture *scopedRevisionFixture) WatchNetwork(id network.ID) (<-chan network.RevisionAdvanced, func(), error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.channels[id] == nil {
		fixture.channels[id] = make(chan network.RevisionAdvanced, 8)
	}
	fixture.active[id]++
	var once sync.Once
	return fixture.channels[id], func() { once.Do(func() { fixture.mu.Lock(); defer fixture.mu.Unlock(); fixture.active[id]-- }) }, nil
}
func (fixture *scopedRevisionFixture) channel(id network.ID) chan network.RevisionAdvanced {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.channels[id]
}
func (fixture *scopedRevisionFixture) activeScopes() []network.ID {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	result := []network.ID{}
	for id, count := range fixture.active {
		if count > 0 {
			result = append(result, id)
		}
	}
	return result
}

type scopedConnectivityFixture struct {
	mu       sync.Mutex
	channels map[network.ID]chan ConnectivityChanged
	count    int
}

func newScopedConnectivityFixture() *scopedConnectivityFixture {
	return &scopedConnectivityFixture{channels: make(map[network.ID]chan ConnectivityChanged)}
}
func (fixture *scopedConnectivityFixture) WatchNetwork(id network.ID) (<-chan ConnectivityChanged, func(), error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.channels[id] == nil {
		fixture.channels[id] = make(chan ConnectivityChanged, 1)
	}
	fixture.count++
	var once sync.Once
	return fixture.channels[id], func() { once.Do(func() { fixture.mu.Lock(); defer fixture.mu.Unlock(); fixture.count-- }) }, nil
}
func (fixture *scopedConnectivityFixture) active() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.count
}

func TestStreamInitialSharingCatchupNeverPublishesRevokedProjection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider, consumer, evidence := directDeviceFixtureAt(t, policy.ProtocolICMP, nil, time.Now())
		projection, err := NewDirectDeviceProjection(directDeviceParams(t, provider, provider, consumer, evidence))
		if err != nil {
			t.Fatal(err)
		}
		initial, err := provider.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, provider}}
		revisions := newScopedRevisionFixture()
		connectivity := newScopedConnectivityFixture()
		service := newStreamServiceWithWatchersFixture(t, opener, &streamPresenceStore{}, revisions, connectivity)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()
		synctest.Wait()
		maps, _ := sink.state()
		if len(maps) != 1 || len(maps[0].AuthorizedPeers()) != 0 {
			t.Fatal("pre-subscription grant escaped initial catchup")
		}
		if !slices.Equal(revisions.activeScopes(), []network.ID{provider.Scope().NetworkID()}) {
			t.Fatal("removed initial scope leaked subscription")
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if connectivity.active() != 0 || len(revisions.activeScopes()) != 0 {
			t.Fatal("catchup leaked watchers")
		}
	})
}

func TestStreamInitialSharingCatchupFailsClosedOnReadFailureAndChurn(t *testing.T) {
	for _, name := range []string{"read failure", "scope churn"} {
		synctest.Test(t, func(t *testing.T) {
			provider, consumer, _ := directDeviceFixtureAt(t, policy.ProtocolICMP, nil, time.Now())
			initial, err := provider.WithSharingDependencies([]network.Scope{consumer.Scope()})
			if err != nil {
				t.Fatal(err)
			}
			otherID, err := network.ParseID("01890f00-0000-7000-8000-000000000999")
			if err != nil {
				t.Fatal(err)
			}
			otherScope, err := network.NewScope(provider.Scope().WorkspaceID(), otherID)
			if err != nil {
				t.Fatal(err)
			}
			other, err := provider.WithSharingDependencies([]network.Scope{otherScope})
			if err != nil {
				t.Fatal(err)
			}
			opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, other, initial, other, initial}}
			if name == "read failure" {
				opener.failures = []error{nil, ErrUnauthorized}
			}
			revisions := newScopedRevisionFixture()
			connectivity := newScopedConnectivityFixture()
			presence := &streamPresenceStore{}
			service := newStreamServiceWithWatchersFixture(t, opener, presence, revisions, connectivity)
			machine, request := authenticatedRequestFixture(t, initial)
			sink := &recordingStreamSink{}
			if err := service.Serve(t.Context(), machine, request, sink); err == nil {
				t.Fatal("unsafe initial catchup succeeded")
			}
			maps, _ := sink.state()
			if len(maps) != 0 || connectivity.active() != 0 || len(revisions.activeScopes()) != 0 {
				t.Fatal("unsafe catchup released authority or leaked watchers")
			}
			if state := presence.state(); state.acquires != 0 {
				t.Fatal("failed catchup acquired presence")
			}
		})
	}
}
