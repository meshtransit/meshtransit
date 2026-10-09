package mapsession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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
