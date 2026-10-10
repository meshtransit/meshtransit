package mapsession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

type countingRelayAccess struct {
	mu       sync.Mutex
	requests []RelayGrantRequest
	fail     bool
}

func (access *countingRelayAccess) GrantRelayAccess(_ context.Context, request RelayGrantRequest) (RelayGrant, error) {
	access.mu.Lock()
	defer access.mu.Unlock()
	access.requests = append(access.requests, request)
	if access.fail {
		return RelayGrant{}, errors.New("signer unavailable")
	}
	return NewRelayGrant(request, []byte(`{"version":1}`), time.Now().Add(15*time.Minute))
}

func (access *countingRelayAccess) count() int {
	access.mu.Lock()
	defer access.mu.Unlock()
	return len(access.requests)
}

func snapshotWithSelfDiscoKey(t *testing.T, keyByte byte) Snapshot {
	t.Helper()
	base := snapshotFixture(t)
	self := connectivityFixture(t, base.NodeID(), base.SessionGeneration(), keyByte, "198.51.100.9:41641", true)
	snapshot, err := base.WithConnectivity([]Connectivity{self})
	if err != nil {
		t.Fatalf("WithConnectivity() error = %v", err)
	}
	return snapshot
}

func serveWithRelayAccess(t *testing.T, access RelayAccess, snapshots ...Snapshot) (*recordingStreamSink, context.CancelFunc, chan error) {
	t.Helper()
	options := streamOptionsFixture(t)
	options.RelayAccess = access
	service, err := NewStreamService(
		&streamSnapshotOpener{snapshots: snapshots},
		&streamPresenceStore{},
		newStreamRevisionWatcher(),
		newStreamConnectivityWatcher(),
		options,
	)
	if err != nil {
		t.Fatalf("NewStreamService() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, snapshots[0])
	sink := &recordingStreamSink{}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- service.Serve(ctx, machine, request, sink) }()
	return sink, cancel, result
}

func TestStreamGrantsAndRenewsRelayAccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotWithSelfDiscoKey(t, 7)
		access := &countingRelayAccess{}
		sink, cancel, result := serveWithRelayAccess(t, access, snapshot)

		synctest.Wait()
		snapshots, _ := sink.state()
		if access.count() != 1 || len(snapshots) != 1 || !snapshots[0].RelayGrant().IsValid() {
			t.Fatalf("initial grant: issued %d, snapshots %d", access.count(), len(snapshots))
		}
		access.mu.Lock()
		request := access.requests[0]
		access.mu.Unlock()
		if request.NodeKey != snapshot.NodeKey() || request.DiscoveryKey != (node.DiscoveryKey{7}) ||
			request.Network != snapshot.Scope().NetworkID() || !request.NotAfter.Equal(snapshot.KeyExpiry()) {
			t.Fatalf("grant request = %+v", request)
		}

		// Reconciles of an unchanged map keep the grant.
		time.Sleep(time.Minute)
		synctest.Wait()
		if access.count() != 1 || sink.relayGrantCount() != 0 {
			t.Fatalf("grant reissued without need: %d", access.count())
		}

		// Five minutes before expiry the grant is renewed and sent on its own.
		time.Sleep(9 * time.Minute)
		synctest.Wait()
		if renewals := sink.relayGrantCount(); access.count() != 2 || renewals != 1 {
			t.Fatalf("renewal: issued %d, relay grant updates %d", access.count(), renewals)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}
	})
}

func TestStreamRegrantsWhenDiscoKeyChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		access := &countingRelayAccess{}
		sink, cancel, result := serveWithRelayAccess(t, access, snapshotWithSelfDiscoKey(t, 7), snapshotWithSelfDiscoKey(t, 8))

		time.Sleep(6 * time.Second) // one reconcile
		synctest.Wait()
		access.mu.Lock()
		requests := append([]RelayGrantRequest(nil), access.requests...)
		access.mu.Unlock()
		if len(requests) != 2 || requests[1].DiscoveryKey != (node.DiscoveryKey{8}) {
			t.Fatalf("new disco key not granted: %d", access.count())
		}
		// The disco key change already sends the node's entry (a
		// connectivity delta), so no separate grant message is needed.
		sink.mu.Lock()
		deltas, grants := len(sink.deltas), len(sink.relayGrants)
		sink.mu.Unlock()
		if deltas != 1 || grants != 0 {
			t.Fatalf("deltas %d, grant updates %d", deltas, grants)
		}
		cancel()
		synctest.Wait()
		<-result
	})
}

func TestStreamWithoutDiscoKeyOrAccessSendsNoGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		access := &countingRelayAccess{}
		sink, cancel, result := serveWithRelayAccess(t, access, snapshotFixture(t))
		synctest.Wait()
		snapshots, _ := sink.state()
		if access.count() != 0 || snapshots[0].RelayGrant().IsValid() {
			t.Fatal("granted relay access without a disco key")
		}
		cancel()
		synctest.Wait()
		<-result

		failing := &countingRelayAccess{fail: true}
		sink, cancel, result = serveWithRelayAccess(t, failing, snapshotWithSelfDiscoKey(t, 7))
		synctest.Wait()
		snapshots, _ = sink.state()
		if failing.count() != 1 || len(snapshots) != 1 || snapshots[0].RelayGrant().IsValid() {
			t.Fatal("a failed grant must not stop the map stream")
		}
		cancel()
		synctest.Wait()
		<-result
	})
}

func (sink *recordingStreamSink) relayGrantCount() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return len(sink.relayGrants)
}

// releasingPresence records explicit lease releases.
type releasingPresence struct {
	streamPresenceStore
	released chan node.PresenceLease
}

func (store *releasingPresence) ReleasePresence(_ context.Context, _ network.Scope, lease node.PresenceLease) (bool, error) {
	store.released <- lease
	return true, nil
}

func TestStreamReleasesPresenceWhenDeviceIsSuspended(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}, failures: []error{nil, ErrSuspended}}
		presence := &releasingPresence{released: make(chan node.PresenceLease, 1)}
		service, err := NewStreamService(opener, presence, newStreamRevisionWatcher(), newStreamConnectivityWatcher(), streamOptionsFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		machine, request := authenticatedRequestFixture(t, snapshot)
		sink := &recordingStreamSink{}
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()

		time.Sleep(6 * time.Second) // the reconcile finds the Device suspended
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrSuspended) {
			t.Fatalf("Serve() error = %v, want ErrSuspended", err)
		}
		select {
		case lease := <-presence.released:
			if lease.NodeID() != snapshot.NodeID() {
				t.Fatal("released another node's lease")
			}
		default:
			t.Fatal("presence left to expire after suspension")
		}
		sink.mu.Lock()
		pauses := len(sink.pauses)
		sink.mu.Unlock()
		if pauses != 1 {
			t.Fatalf("pause frames = %d", pauses)
		}
	})
}

// A connectivity-only reload rebuilds the snapshot from the store, which
// never carries a relay grant; the stream must keep the node's grant, or
// the node loses every relay (its entry arrives without a ticket).
func TestStreamKeepsRelayGrantAcrossConnectivityReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := snapshotFixture(t)
		before := connectivityFixture(t, base.NodeID(), base.SessionGeneration(), 7, "198.51.100.9:41641", true)
		after := connectivityFixture(t, base.NodeID(), base.SessionGeneration(), 7, "198.51.100.10:41641", true)
		initial, err := base.WithConnectivity([]Connectivity{before})
		if err != nil {
			t.Fatalf("WithConnectivity(initial) error = %v", err)
		}
		reloaded, err := base.WithConnectivity([]Connectivity{after})
		if err != nil {
			t.Fatalf("WithConnectivity(reloaded) error = %v", err)
		}
		access := &countingRelayAccess{}
		options := streamOptionsFixture(t)
		options.RelayAccess = access
		connectivity := newStreamConnectivityWatcher()
		opener := &reloadingSnapshotOpener{streamSnapshotOpener: streamSnapshotOpener{snapshots: []Snapshot{initial}}, reloaded: reloaded}
		service, err := NewStreamService(opener, &streamPresenceStore{}, newStreamRevisionWatcher(), connectivity, options)
		if err != nil {
			t.Fatalf("NewStreamService() error = %v", err)
		}
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		change, err := NewConnectivityChanged(initial.Scope().NetworkID(), base.NodeID(), base.SessionGeneration(), ConnectivityChangeEndpoints)
		if err != nil {
			t.Fatalf("NewConnectivityChanged() error = %v", err)
		}
		connectivity.send(t, change)
		synctest.Wait()
		deltas := sink.connectivityDeltas()
		if opener.reloads.Load() != 1 || len(deltas) != 1 || !deltas[0].SelfChanged() {
			t.Fatalf("reload %d, deltas %d", opener.reloads.Load(), len(deltas))
		}
		if !deltas[0].Snapshot().RelayGrant().IsValid() {
			t.Fatal("the node's entry was sent without its relay grant")
		}
		if access.count() != 1 {
			t.Fatalf("grant reissued on a connectivity change: %d", access.count())
		}

		cancel()
		synctest.Wait()
		<-result
	})
}

func TestWithConnectivityKeepsRelayGrant(t *testing.T) {
	snapshot := snapshotWithSelfDiscoKey(t, 7)
	request, ok := snapshot.RelayGrantRequest()
	if !ok {
		t.Fatal("RelayGrantRequest() missing")
	}
	grant, err := NewRelayGrant(request, []byte(`{"version":1}`), time.Now().Add(15*time.Minute))
	if err != nil {
		t.Fatalf("NewRelayGrant() error = %v", err)
	}
	granted := snapshot.WithRelayGrant(grant)
	self := connectivityFixture(t, snapshot.NodeID(), snapshot.SessionGeneration(), 7, "198.51.100.10:41641", true)
	next, err := granted.WithConnectivity([]Connectivity{self})
	if err != nil {
		t.Fatalf("WithConnectivity() error = %v", err)
	}
	if !next.RelayGrant().IsValid() {
		t.Fatal("WithConnectivity dropped the relay grant")
	}
}
