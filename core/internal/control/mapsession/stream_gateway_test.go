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

// gatewayPresenceStore records a Kubernetes gateway stream's presence calls.
type gatewayPresenceStore struct {
	streamPresenceStore
	mu         sync.Mutex
	claim      GatewayClaim
	acquireErr error
	renewed    bool
	acquired   []node.PresenceLease
	renewals   []node.PresenceLease
	released   []node.PresenceLease
	handedOff  []node.PresenceLease
	windows    []time.Duration
	endCtxLive bool
}

func (store *gatewayPresenceStore) AcquireGatewayPresence(_ context.Context, _ network.Scope,
	lease node.PresenceLease, window time.Duration) (GatewayClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.acquired = append(store.acquired, lease)
	store.windows = append(store.windows, window)
	return store.claim, store.acquireErr
}

func (store *gatewayPresenceStore) RenewGatewayPresence(_ context.Context, lease node.PresenceLease) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.renewals = append(store.renewals, lease)
	return store.renewed, nil
}

func (store *gatewayPresenceStore) ReleaseGatewayPresence(ctx context.Context, _ network.Scope,
	lease node.PresenceLease) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.released = append(store.released, lease)
	_, deadline := ctx.Deadline()
	store.endCtxLive = ctx.Err() == nil && deadline
	return true, nil
}

func (store *gatewayPresenceStore) HandOffGatewayPresence(ctx context.Context, lease node.PresenceLease) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.handedOff = append(store.handedOff, lease)
	_, deadline := ctx.Deadline()
	store.endCtxLive = ctx.Err() == nil && deadline
	return true, nil
}

func (store *gatewayPresenceStore) CheckGatewayRotation(context.Context, node.PresenceLease) (GatewayRotationState,
	error) {
	return GatewayRotationHeld, nil
}

type gatewayPresenceCalls struct {
	acquired, renewals, released, handedOff []node.PresenceLease
	windows                                 []time.Duration
	endCtxLive                              bool
}

func (store *gatewayPresenceStore) calls() gatewayPresenceCalls {
	store.mu.Lock()
	defer store.mu.Unlock()
	return gatewayPresenceCalls{acquired: store.acquired, renewals: store.renewals, released: store.released,
		handedOff: store.handedOff, windows: store.windows, endCtxLive: store.endCtxLive}
}

// gatewayStreamSink is a Kubernetes gateway's sink.
type gatewayStreamSink struct {
	recordingStreamSink
	mu       sync.Mutex
	claimed  []node.PresenceLease
	scopes   []network.Scope
	fought   int
	handsOff bool
	keeps    bool
}

func (sink *gatewayStreamSink) PresenceClaimed(scope network.Scope, lease node.PresenceLease) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.claimed = append(sink.claimed, lease)
	sink.scopes = append(sink.scopes, scope)
}

func (sink *gatewayStreamSink) GatewayKeysFought() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.fought++
}

func (sink *gatewayStreamSink) HandsOffPresence() bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.handsOff
}

func (sink *gatewayStreamSink) KeepsPresence() bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.keeps
}

func (sink *gatewayStreamSink) state() ([]node.PresenceLease, int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.claimed, sink.fought
}

// A gateway's stream holds its presence by a fresh holder, tells the
// session before the first snapshot, renews by holder and releases it when
// it ends (K1a1 plan §16.12).
func TestStreamServiceHoldsAGatewayPresenceByHolder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &gatewayPresenceStore{claim: GatewayClaim{Claimed: true}, renewed: true}
		sink := &gatewayStreamSink{}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine.AsKubernetesGateway(), request, sink) }()
		synctest.Wait()

		calls := presence.calls()
		claimed, fought := sink.state()
		if len(calls.acquired) != 1 || len(claimed) != 1 || fought != 0 {
			t.Fatalf("acquired %d, claimed %d, fought %d", len(calls.acquired), len(claimed), fought)
		}
		lease := calls.acquired[0]
		machineKey := snapshot.MachineKey()
		if !lease.Gateway() || lease != claimed[0] || lease.MachineFingerprint() != machineKey.Fingerprint() ||
			lease.NodeID() != snapshot.NodeID() || lease.Generation() != snapshot.SessionGeneration() ||
			calls.windows[0] != GatewayContestWindow {
			t.Fatalf("lease %+v, claimed %+v, window %v", lease, claimed[0], calls.windows)
		}
		if acquires := presence.state().acquires; acquires != 0 {
			t.Fatalf("the Node presence was acquired %d times", acquires)
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if calls = presence.calls(); len(calls.renewals) != 1 || calls.renewals[0] != lease {
			t.Fatalf("renewals %+v", calls.renewals)
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}
		if calls = presence.calls(); len(calls.released) != 1 || calls.released[0] != lease ||
			len(calls.handedOff) != 0 || !calls.endCtxLive {
			t.Fatalf("released %+v, handed off %+v, live %t", calls.released, calls.handedOff, calls.endCtxLive)
		}
	})
}

// Core moving the session (Shutdown, Shed) keeps the lease, marked handed
// off; a take that made the keys fought over is told to the session.
func TestStreamServiceHandsOffAGatewayPresence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &gatewayPresenceStore{claim: GatewayClaim{Claimed: true, Fight: true}, renewed: true}
		sink := &gatewayStreamSink{handsOff: true}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine.AsKubernetesGateway(), request, sink) }()
		synctest.Wait()
		if _, fought := sink.state(); fought != 1 {
			t.Fatalf("fought %d", fought)
		}
		cancel()
		synctest.Wait()
		<-result
		if calls := presence.calls(); len(calls.handedOff) != 1 || len(calls.released) != 0 ||
			calls.handedOff[0] != calls.acquired[0] || !calls.endCtxLive {
			t.Fatalf("handed off %+v, released %+v", calls.handedOff, calls.released)
		}
	})
}

// A stream the session stopped to rotate the gateway's machine key leaves
// its lease alone: the session ends it after the rotation commits.
func TestStreamServiceKeepsAGatewayPresenceForARotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &gatewayPresenceStore{claim: GatewayClaim{Claimed: true}, renewed: true}
		sink := &gatewayStreamSink{keeps: true, handsOff: true}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine.AsKubernetesGateway(), request, sink) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		<-result
		if calls := presence.calls(); len(calls.released) != 0 || len(calls.handedOff) != 0 {
			t.Fatalf("released %+v, handed off %+v", calls.released, calls.handedOff)
		}
	})
}

// A lease another holder took ends the stream with ErrPresenceTaken, which
// is an ErrPresenceLost; the release then touches only this holder's lease.
func TestStreamServiceEndsAGatewayStreamWhosePresenceWasTaken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &gatewayPresenceStore{claim: GatewayClaim{Claimed: true}}
		sink := &gatewayStreamSink{}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine.AsKubernetesGateway(), request, sink) }()
		synctest.Wait()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		err := <-result
		if !errors.Is(err, ErrPresenceTaken) || !errors.Is(err, ErrPresenceLost) {
			t.Fatalf("Serve() error = %v, want ErrPresenceTaken", err)
		}
		if calls := presence.calls(); len(calls.released) != 1 || calls.released[0] != calls.acquired[0] {
			t.Fatalf("released %+v", calls.released)
		}
	})
}

// A claim refused, or one whose answer was lost, still releases this
// holder's lease: Redis may have applied it.
func TestStreamServiceReleasesAGatewayClaimItDidNotGet(t *testing.T) {
	for name, presence := range map[string]*gatewayPresenceStore{
		"refused": {},
		"failed":  {acquireErr: errors.New("redis: timeout")},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				snapshot := snapshotFixture(t)
				opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
				sink := &gatewayStreamSink{}
				service := newStreamServiceFixture(t, opener, presence)
				machine, request := authenticatedRequestFixture(t, snapshot)
				err := service.Serve(t.Context(), machine.AsKubernetesGateway(), request, sink)
				if err == nil {
					t.Fatal("Serve() succeeded")
				}
				claimed, _ := sink.state()
				calls := presence.calls()
				if len(claimed) != 0 || len(calls.released) != 1 || calls.released[0] != calls.acquired[0] {
					t.Fatalf("claimed %d, released %+v", len(claimed), calls.released)
				}
			})
		})
	}
}

// A gateway's stream needs a store and a sink that know gateways.
func TestStreamServiceRefusesAGatewayWithoutGatewayPresence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		machine, request := authenticatedRequestFixture(t, snapshot)
		gatewayMachine := machine.AsKubernetesGateway()
		plain := newStreamServiceFixture(t, &streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
			&streamPresenceStore{})
		if err := plain.Serve(t.Context(), gatewayMachine, request, &gatewayStreamSink{}); !errors.Is(err,
			ErrInvalidStreamService) {
			t.Fatalf("Serve() with a Node store = %v", err)
		}
		gateway := newStreamServiceFixture(t, &streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
			&gatewayPresenceStore{claim: GatewayClaim{Claimed: true}})
		if err := gateway.Serve(t.Context(), gatewayMachine, request, &recordingStreamSink{}); !errors.Is(err,
			ErrInvalidStreamService) {
			t.Fatalf("Serve() with a Node sink = %v", err)
		}
	})
}

// The contest window outlasts a gateway's return after another holder took
// its presence, with every term written out (K1a1 plan §16.12): learning it
// at the next renewal, a churn window, and two reconnect attempts.
func TestGatewayContestWindowOutlastsAGatewaysReturn(t *testing.T) {
	t.Parallel()
	const (
		churnWindow  = time.Minute
		attempt      = time.Minute
		coordination = 5 * time.Second
	)
	for _, ttl := range []time.Duration{3 * time.Second, 30 * time.Second, 5 * time.Minute} {
		if worst := ttl/3 + coordination + churnWindow + 2*attempt; GatewayContestWindow <= worst {
			t.Errorf("TTL %s: window %s, return within %s", ttl, GatewayContestWindow, worst)
		}
	}
}
