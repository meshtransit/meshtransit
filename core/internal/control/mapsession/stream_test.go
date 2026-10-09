package mapsession

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/relay"
)

func TestStreamServiceOwnsBoundedPresenceLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		advanced := advancedStreamSnapshot(t, initial)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
		presence := &streamPresenceStore{}
		sink := &recordingStreamSink{}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		openerCalls, openerDeadline := opener.state()
		presenceState := presence.state()
		snapshots, keepAlives := sink.state()
		if openerCalls != 1 || !openerDeadline || presenceState.acquires != 1 ||
			!presenceState.sawAcquireDeadline || presenceState.renews != 0 ||
			len(snapshots) != 1 || keepAlives != 0 {
			t.Fatalf(
				"initial stream = opener(%d,%t) presence(%d,%t,%d) sink(%d,%d)",
				openerCalls,
				openerDeadline,
				presenceState.acquires,
				presenceState.sawAcquireDeadline,
				presenceState.renews,
				len(snapshots),
				keepAlives,
			)
		}
		if presenceState.lease.NodeID() != initial.NodeID() ||
			presenceState.lease.Generation() != initial.SessionGeneration() ||
			presenceState.lease.TTL() != 9*time.Second {
			t.Fatalf("presence lease = %+v, want snapshot-bound 9s lease", presenceState.lease)
		}

		time.Sleep(3 * time.Second)
		synctest.Wait()
		presenceState = presence.state()
		if presenceState.acquires != 1 || presenceState.renews != 1 ||
			!presenceState.sawRenewDeadline {
			t.Fatalf(
				"presence operations after renewal = (%d,%d,%t), want (1,1,true)",
				presenceState.acquires,
				presenceState.renews,
				presenceState.sawRenewDeadline,
			)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		_, keepAlives = sink.state()
		if keepAlives != 1 {
			t.Fatalf("keepalives = %d, want 1", keepAlives)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		openerCalls, _ = opener.state()
		snapshots, _ = sink.state()
		if openerCalls != 2 || len(snapshots) != 2 ||
			snapshots[1].NetworkRevision() != advanced.NetworkRevision() ||
			len(sink.connectivityDeltas()) != 0 {
			t.Fatalf("reconciled stream = opener %d snapshots %+v", openerCalls, snapshots)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
		presenceState = presence.state()
		if presenceState.acquires != 1 || presenceState.renews != 1 {
			t.Fatalf(
				"presence operations after disconnect = (%d,%d), want lease left to expire",
				presenceState.acquires,
				presenceState.renews,
			)
		}
	})
}

func TestStreamServiceReconcilesImmediatelyOnRevisionWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		advanced := advancedStreamSnapshot(t, initial)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(
			t,
			opener,
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		wakeup, err := network.NewRevisionAdvanced(
			initial.Scope().NetworkID().String(),
			advanced.NetworkRevision(),
		)
		if err != nil {
			t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
		}
		revisions.send(t, wakeup)
		synctest.Wait()
		if calls, _ := opener.state(); calls != 2 {
			t.Fatalf("snapshot opens after wakeup = %d, want 2", calls)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
		if watches, releases := revisions.state(); watches != 1 || releases != 1 {
			t.Fatalf("revision watches = (%d, %d), want one owned lifecycle", watches, releases)
		}
	})
}

func TestStreamServiceUsesAuthorityDeltaForContiguousRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, peer := authorityDeltaSnapshotsFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(
			t,
			opener,
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		wakeup, err := network.NewRevisionAdvanced(
			initial.Scope().NetworkID().String(),
			advanced.NetworkRevision(),
		)
		if err != nil {
			t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
		}
		revisions.send(t, wakeup)
		synctest.Wait()

		snapshots, _ := sink.state()
		deltas := sink.authorityDeltaSnapshots()
		if len(snapshots) != 1 || len(deltas) != 1 || len(sink.connectivityDeltas()) != 0 ||
			deltas[0].Snapshot().NetworkRevision() != advanced.NetworkRevision() ||
			len(deltas[0].ChangedPeers()) != 1 ||
			deltas[0].ChangedPeers()[0].NodeID() != peer.NodeID() {
			t.Fatalf(
				"contiguous refresh = snapshots %+v authority deltas %+v",
				snapshots,
				deltas,
			)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestStreamServiceUsesFullSnapshotAfterRevisionGap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, _ := authorityDeltaSnapshotsFixture(t)
		gapParams := advanced.params()
		gapParams.NetworkRevision++
		gap, err := NewSnapshot(gapParams)
		if err != nil {
			t.Fatalf("NewSnapshot(gap) error = %v", err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, gap}}
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(
			t,
			opener,
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		wakeup, err := network.NewRevisionAdvanced(
			initial.Scope().NetworkID().String(),
			gap.NetworkRevision(),
		)
		if err != nil {
			t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
		}
		revisions.send(t, wakeup)
		synctest.Wait()

		snapshots, _ := sink.state()
		if len(snapshots) != 2 || len(sink.authorityDeltaSnapshots()) != 0 ||
			snapshots[1].NetworkRevision() != gap.NetworkRevision() {
			t.Fatalf("gap refresh snapshots = %+v, want full replacement", snapshots)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestStreamServiceUsesFullSnapshotAfterRelayDirectoryAdvance(t *testing.T) {
	t.Parallel()

	initial := snapshotFixture(t)
	directory, err := relay.NewDirectory(relay.DirectoryParams{
		Revision: initial.RelayDirectory().Revision() + 1,
		Regions:  initial.RelayDirectory().Regions(),
	})
	if err != nil {
		t.Fatalf("relay.NewDirectory() error = %v", err)
	}
	params := initial.params()
	params.RelayDirectory = directory
	next, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	opener := &streamSnapshotOpener{snapshots: []Snapshot{next}}
	service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
	machine, request := authenticatedRequestFixture(t, initial)
	sink := &recordingStreamSink{}

	refreshed, err := service.refresh(t.Context(), machine, request, sink, initial)
	if err != nil {
		t.Fatalf("refresh() error = %v", err)
	}
	snapshots, _ := sink.state()
	if len(snapshots) != 1 || snapshots[0].RelayDirectory().Revision() != directory.Revision() ||
		len(sink.authorityDeltaSnapshots()) != 0 || len(sink.connectivityDeltas()) != 0 ||
		refreshed.RelayDirectory().Revision() != directory.Revision() {
		t.Fatalf("directory refresh = snapshots %+v refreshed %v", snapshots, refreshed)
	}
}

func TestStreamServiceRejectsRelayDirectoryDiscontinuity(t *testing.T) {
	t.Parallel()

	base := snapshotFixture(t)
	for _, test := range []struct {
		name            string
		currentRevision uint64
		currentHost     string
		nextRevision    uint64
		nextHost        string
	}{
		{
			name:            "revision regression",
			currentRevision: 2,
			currentHost:     "relay-sin.example.com",
			nextRevision:    1,
			nextHost:        "relay-sin.example.com",
		},
		{
			name:            "same revision different topology",
			currentRevision: 1,
			currentHost:     "relay-sin.example.com",
			nextRevision:    1,
			nextHost:        "relay-alt-sin.example.com",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			current := snapshotWithRelayDirectoryFixture(
				t,
				base,
				test.currentRevision,
				test.currentHost,
			)
			next := snapshotWithRelayDirectoryFixture(
				t,
				base,
				test.nextRevision,
				test.nextHost,
			)
			opener := &streamSnapshotOpener{snapshots: []Snapshot{next}}
			service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
			machine, request := authenticatedRequestFixture(t, current)
			sink := &recordingStreamSink{}

			_, err := service.refresh(t.Context(), machine, request, sink, current)
			if !errors.Is(err, ErrStreamDiscontinuity) {
				t.Fatalf("refresh() error = %v, want ErrStreamDiscontinuity", err)
			}
			withdrawals := sink.authorityWithdrawals()
			if len(withdrawals) != 1 ||
				withdrawals[0].RelayDirectory().Fingerprint() != current.RelayDirectory().Fingerprint() ||
				len(sink.authorityDeltaSnapshots()) != 0 || len(sink.connectivityDeltas()) != 0 {
				t.Fatalf("discontinuity sink withdrawals = %+v", withdrawals)
			}
		})
	}
}

func snapshotWithRelayDirectoryFixture(
	t *testing.T,
	base Snapshot,
	revision uint64,
	hostName string,
) Snapshot {
	t.Helper()

	relayNode, err := relay.NewNode(relay.NodeParams{
		Name:      "1a",
		HostName:  hostName,
		IPv4:      "192.0.2.10",
		IPv6:      "2001:db8::10",
		STUNPort:  3478,
		RelayPort: 443,
	})
	if err != nil {
		t.Fatalf("relay.NewNode() error = %v", err)
	}
	region, err := relay.NewRegion(relay.RegionParams{
		ID: 1, Code: "sin", Name: "Singapore", Nodes: []relay.Node{relayNode},
	})
	if err != nil {
		t.Fatalf("relay.NewRegion() error = %v", err)
	}
	directory, err := relay.NewDirectory(relay.DirectoryParams{
		Revision: revision,
		Regions:  []relay.Region{region},
	})
	if err != nil {
		t.Fatalf("relay.NewDirectory() error = %v", err)
	}
	params := base.params()
	params.RelayDirectory = directory
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return snapshot
}

func TestStreamServiceIgnoresStaleRevisionWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial}}
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(
			t,
			opener,
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			result <- service.Serve(ctx, machine, request, &recordingStreamSink{})
		}()

		synctest.Wait()
		wakeup, err := network.NewRevisionAdvanced(
			initial.Scope().NetworkID().String(),
			initial.NetworkRevision(),
		)
		if err != nil {
			t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
		}
		revisions.send(t, wakeup)
		synctest.Wait()
		if calls, _ := opener.state(); calls != 1 {
			t.Fatalf("snapshot opens after stale wakeup = %d, want 1", calls)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestStreamServiceReconcilesImmediatelyOnConnectivityWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base, peer := snapshotWithAuthorizedPeerFixture(t)
		selfKey, err := NewConnectivityKey(base.NodeID(), base.SessionGeneration())
		if err != nil {
			t.Fatalf("NewConnectivityKey(self) error = %v", err)
		}
		peerKey, err := NewConnectivityKey(peer.NodeID(), peer.SessionGeneration())
		if err != nil {
			t.Fatalf("NewConnectivityKey(peer) error = %v", err)
		}
		self, err := NewConnectivity(ConnectivityParams{Key: selfKey})
		if err != nil {
			t.Fatalf("NewConnectivity(self) error = %v", err)
		}
		offline, err := NewConnectivity(ConnectivityParams{Key: peerKey})
		if err != nil {
			t.Fatalf("NewConnectivity(peer offline) error = %v", err)
		}
		initial, err := base.WithConnectivity([]Connectivity{self, offline})
		if err != nil {
			t.Fatalf("WithConnectivity(initial) error = %v", err)
		}
		online := connectivityFixture(
			t,
			peer.NodeID(),
			peer.SessionGeneration(),
			4,
			"198.51.100.2:41641",
			true,
		)
		advanced, err := base.WithConnectivity([]Connectivity{self, online})
		if err != nil {
			t.Fatalf("WithConnectivity(advanced) error = %v", err)
		}

		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
		connectivity := newStreamConnectivityWatcher()
		service := newStreamServiceWithWatchersFixture(
			t,
			opener,
			&streamPresenceStore{},
			newStreamRevisionWatcher(),
			connectivity,
		)
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		change, err := NewConnectivityChanged(
			initial.Scope().NetworkID(),
			peer.NodeID(),
			peer.SessionGeneration(),
			ConnectivityChangeEndpoints,
		)
		if err != nil {
			t.Fatalf("NewConnectivityChanged() error = %v", err)
		}
		connectivity.send(t, change)
		synctest.Wait()
		snapshots, _ := sink.state()
		deltas := sink.connectivityDeltas()
		if calls, _ := opener.state(); calls != 2 || len(snapshots) != 1 ||
			len(deltas) != 1 || deltas[0].Snapshot().NetworkRevision() != initial.NetworkRevision() {
			t.Fatalf(
				"connectivity refresh = opener %d snapshots %+v deltas %+v",
				calls,
				snapshots,
				deltas,
			)
		}
		projected, found := deltas[0].Snapshot().ConnectivityFor(peer.NodeID())
		if !found || !projected.Online() {
			t.Fatalf("refreshed peer connectivity = (%+v, %t), want online", projected, found)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
		if watches, releases := connectivity.state(); watches != 1 || releases != 1 {
			t.Fatalf("connectivity watches = (%d, %d), want one owned lifecycle", watches, releases)
		}
	})
}

func TestStreamServiceFailsClosedWhenRevisionFeedStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		revisions := newStreamRevisionWatcher()
		sink := &recordingStreamSink{}
		service := newStreamServiceWithRevisionsFixture(
			t,
			&streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()

		synctest.Wait()
		revisions.closeUpdates()
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrStreamUnavailable) {
			t.Fatalf("Serve() error = %v, want ErrStreamUnavailable", err)
		}
		if withdrawals := sink.authorityWithdrawals(); len(withdrawals) != 0 {
			t.Fatalf("revision feed loss sent %d authority withdrawals, want 0", len(withdrawals))
		}
	})
}

func TestStreamServiceFailsClosedWhenPresenceIsLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &streamPresenceStore{rejectRenew: 1}
		sink := &recordingStreamSink{}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()

		synctest.Wait()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrPresenceLost) {
			t.Fatalf("Serve() error = %v, want ErrPresenceLost", err)
		}
		if withdrawals := sink.authorityWithdrawals(); len(withdrawals) != 0 {
			t.Fatalf("presence loss sent %d authority withdrawals, want 0", len(withdrawals))
		}
	})
}

func TestStreamServiceRejectsConcurrentLocalOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &streamPresenceStore{}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		ctx, cancel := context.WithCancel(t.Context())
		firstResult := make(chan error, 1)
		go func() {
			firstResult <- service.Serve(ctx, machine, request, &recordingStreamSink{})
		}()
		synctest.Wait()

		secondErr := service.Serve(t.Context(), machine, request, &recordingStreamSink{})
		if !errors.Is(secondErr, ErrPresenceConflict) {
			t.Fatalf("concurrent Serve() error = %v, want ErrPresenceConflict", secondErr)
		}
		if acquires := presence.state().acquires; acquires != 1 {
			t.Fatalf("Redis presence acquisitions = %d, want only the admitted stream", acquires)
		}

		cancel()
		synctest.Wait()
		if err := <-firstResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("first Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestStreamServiceRejectsAuthorityDiscontinuity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		params := initial.params()
		params.RecoveryEpoch++
		discontinuous, err := NewSnapshot(params)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, discontinuous}}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		machine, request := authenticatedRequestFixture(t, initial)
		sink := &recordingStreamSink{}
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()

		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrStreamDiscontinuity) {
			t.Fatalf("Serve() error = %v, want ErrStreamDiscontinuity", err)
		}
		withdrawals := sink.authorityWithdrawals()
		if len(withdrawals) != 1 || withdrawals[0].NodeID() != initial.NodeID() ||
			withdrawals[0].NodeKey() != initial.NodeKey() {
			t.Fatalf("authority withdrawals = %+v, want current snapshot", withdrawals)
		}
	})
}

func TestStreamServiceWithdrawsAuthorityWhenRefreshIsUnauthorized(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		opener := &streamSnapshotOpener{
			snapshots: []Snapshot{initial},
			failures:  []error{nil, ErrUnauthorized},
		}
		sink := &recordingStreamSink{}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		machine, request := authenticatedRequestFixture(t, initial)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()

		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrUnauthorized) ||
			!errors.Is(err, ErrStreamUnavailable) {
			t.Fatalf("Serve() error = %v, want unauthorized stream failure", err)
		}
		withdrawals := sink.authorityWithdrawals()
		if len(withdrawals) != 1 || withdrawals[0].NodeID() != initial.NodeID() ||
			len(sink.authorityDeltaSnapshots()) != 0 ||
			len(sink.connectivityDeltas()) != 0 {
			t.Fatalf("unauthorized refresh sink state = withdrawals %+v", withdrawals)
		}
	})
}

func TestStreamServicePausesSuspendedDevice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		opener := &streamSnapshotOpener{
			snapshots: []Snapshot{initial},
			failures:  []error{nil, ErrSuspended},
		}
		sink := &recordingStreamSink{}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		machine, request := authenticatedRequestFixture(t, initial)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()

		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrSuspended) || errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Serve() error = %v, want suspension", err)
		}
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if len(sink.pauses) != 1 || sink.pauses[0].NodeID() != initial.NodeID() ||
			len(sink.withdrawals) != 0 {
			t.Fatalf("suspended refresh pauses %d, withdrawals %d; want 1 and 0",
				len(sink.pauses), len(sink.withdrawals))
		}
	})
}

func TestStreamServiceFollowsAMovedAuthorityDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		params := snapshotFixture(t).params()
		params.CreatedAt = time.Now().Add(-time.Hour)
		params.KeyExpiry = time.Now().Add(7 * time.Second)
		initial, err := NewSnapshot(params)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		params.NetworkRevision++
		params.KeyExpiry = time.Now().Add(time.Hour)
		extended, err := NewSnapshot(params)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		if !streamCanAdvance(initial, extended) {
			t.Fatal("a later revision with a new deadline must advance")
		}
		if _, err := NewAuthorityDelta(initial, extended); err == nil {
			t.Fatal("a new deadline must not be delta-encoded")
		}
		same := initial.params()
		same.KeyExpiry = time.Now().Add(time.Hour)
		sameRevision, err := NewSnapshot(same)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		if streamCanAdvance(initial, sameRevision) {
			t.Fatal("a new deadline without a new revision must not advance")
		}

		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, extended}}
		sink := &recordingStreamSink{}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		snapshots, _ := sink.state()
		if len(snapshots) != 2 || !snapshots[1].KeyExpiry().Equal(extended.KeyExpiry()) {
			t.Fatalf("sent %d snapshots, want the initial and the extended one", len(snapshots))
		}
		if withdrawals := sink.authorityWithdrawals(); len(withdrawals) != 0 {
			t.Fatalf("extended authority sent %d withdrawals, want 0", len(withdrawals))
		}
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want cancellation", err)
		}
	})
}

func TestStreamSnapshotRequiresStableCandidatesAtSameRevision(t *testing.T) {
	currentParams := snapshotFixture(t).params()
	currentParams.PeerCandidates = []PeerCandidate{peerCandidateFixture(
		t,
		snapshotFixture(t),
		"01890f00-0000-7000-8000-000000000702",
		2,
	)}
	current, err := NewSnapshot(currentParams)
	if err != nil {
		t.Fatalf("NewSnapshot(current) error = %v", err)
	}
	nextParams := current.params()
	nextParams.PeerCandidates = nil
	next, err := NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot(next) error = %v", err)
	}
	if streamCanAdvance(current, next) {
		t.Fatal("streamCanAdvance() = true for changed candidates at the same revision")
	}
	nextParams.NetworkRevision++
	next, err = NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot(advanced) error = %v", err)
	}
	if !streamCanAdvance(current, next) {
		t.Fatal("streamCanAdvance() = false after an authoritative revision advance")
	}
}

func TestStreamSnapshotRequiresStablePacketPolicyAtSameRevision(t *testing.T) {
	current := snapshotFixture(t)
	candidate := peerCandidateFixture(
		t,
		current,
		"01890f00-0000-7000-8000-000000000702",
		2,
	)
	currentParams := current.params()
	currentParams.PeerCandidates = []PeerCandidate{candidate}
	current, err := NewSnapshot(currentParams)
	if err != nil {
		t.Fatalf("NewSnapshot(current) error = %v", err)
	}
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                ruleID,
		Scope:             current.Scope(),
		SourceNodeID:      current.NodeID(),
		DestinationNodeID: candidate.NodeID(),
		Protocol:          policy.ProtocolICMP,
	})
	if err != nil {
		t.Fatalf("policy.NewRule() error = %v", err)
	}
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    current.Scope(),
		Revision: current.PacketPolicy().Revision(),
		Rules:    []policy.Rule{rule},
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	nextParams := current.params()
	nextParams.PacketPolicy = packetPolicy
	next, err := NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot(next) error = %v", err)
	}
	if streamCanAdvance(current, next) {
		t.Fatal("streamCanAdvance() = true for changed packet policy at the same revision")
	}
}

func TestStreamSnapshotRejectsRegressedPacketPolicyRevision(t *testing.T) {
	t.Parallel()

	current := snapshotFixture(t)
	regressedPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    current.Scope(),
		Revision: current.PacketPolicy().Revision() - 1,
		Rules:    current.PacketPolicy().Rules(),
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	nextParams := current.params()
	nextParams.NetworkRevision++
	nextParams.PacketPolicy = regressedPolicy
	next, err := NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	if streamCanAdvance(current, next) {
		t.Fatal("streamCanAdvance() = true for regressed packet-policy revision")
	}
}

func TestStreamSnapshotRequiresNetworkRevisionForNameChange(t *testing.T) {
	t.Parallel()

	current := snapshotFixture(t)
	nextParams := current.params()
	nextName, err := network.ParseDisplayName("Development Mesh Live")
	if err != nil {
		t.Fatalf("network.ParseDisplayName() error = %v", err)
	}
	nextParams.NetworkName = nextName
	next, err := NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot(next) error = %v", err)
	}
	if streamCanAdvance(current, next) {
		t.Fatal("streamCanAdvance() = true for changed Network name at the same revision")
	}

	nextParams.NetworkRevision++
	next, err = NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot(advanced) error = %v", err)
	}
	if !streamCanAdvance(current, next) {
		t.Fatal("streamCanAdvance() = false for revisioned Network name change")
	}
}

func TestStreamTracksOnlyRelevantConnectivityChanges(t *testing.T) {
	t.Parallel()

	snapshot, peer := snapshotWithAuthorizedPeerFixture(t)
	change := func(
		nodeID node.ID,
		generation int64,
		kind ConnectivityChangeKind,
	) ConnectivityChanged {
		result, err := NewConnectivityChanged(
			snapshot.Scope().NetworkID(),
			nodeID,
			generation,
			kind,
		)
		if err != nil {
			t.Fatalf("NewConnectivityChanged() error = %v", err)
		}
		return result
	}
	for _, test := range []struct {
		name   string
		change ConnectivityChanged
		want   bool
	}{
		{
			name: "self endpoint",
			change: change(
				snapshot.NodeID(),
				snapshot.SessionGeneration(),
				ConnectivityChangeEndpoints,
			),
			want: true,
		},
		{
			name: "self presence ignored",
			change: change(
				snapshot.NodeID(),
				snapshot.SessionGeneration(),
				ConnectivityChangePresence,
			),
		},
		{
			name: "peer presence",
			change: change(
				peer.NodeID(),
				peer.SessionGeneration(),
				ConnectivityChangePresence,
			),
			want: true,
		},
		{
			name: "stale peer generation",
			change: change(
				peer.NodeID(),
				peer.SessionGeneration()-1,
				ConnectivityChangeEndpoints,
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := streamTracksConnectivity(snapshot, test.change); got != test.want {
				t.Fatalf("streamTracksConnectivity() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestStreamServiceStopsAtAuthorizationExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		params := snapshotFixture(t).params()
		params.CreatedAt = time.Now().Add(-time.Hour)
		params.KeyExpiry = time.Now().Add(2 * time.Second)
		snapshot, err := NewSnapshot(params)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		service := newStreamServiceFixture(
			t,
			&streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
			&streamPresenceStore{},
		)
		machine, request := authenticatedRequestFixture(t, snapshot)
		sink := &recordingStreamSink{}
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()

		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrAuthorizationExpired) {
			t.Fatalf("Serve() error = %v, want ErrAuthorizationExpired", err)
		}
		withdrawals := sink.authorityWithdrawals()
		if len(withdrawals) != 1 || withdrawals[0].NodeID() != snapshot.NodeID() {
			t.Fatalf("authority withdrawals = %+v, want expiring snapshot", withdrawals)
		}
	})
}

func TestNewStreamServiceRejectsUnsafeComposition(t *testing.T) {
	t.Parallel()

	options := streamOptionsFixture(t)
	revisions := newStreamRevisionWatcher()
	var nilRevisions *streamRevisionWatcher
	if _, err := NewStreamService(
		&streamSnapshotOpener{},
		&streamPresenceStore{},
		nilRevisions,
		newStreamConnectivityWatcher(),
		options,
	); !errors.Is(err, ErrInvalidStreamService) {
		t.Fatalf("NewStreamService(typed nil) error = %v, want ErrInvalidStreamService", err)
	}
	if _, err := NewStreamService(
		nil,
		&streamPresenceStore{},
		revisions,
		newStreamConnectivityWatcher(),
		options,
	); !errors.Is(
		err,
		ErrInvalidStreamService,
	) {
		t.Fatalf("NewStreamService(nil) error = %v, want ErrInvalidStreamService", err)
	}
	options.CoordinationTimeout = options.PresenceTTL / 3
	if _, err := NewStreamService(
		&streamSnapshotOpener{},
		&streamPresenceStore{},
		revisions,
		newStreamConnectivityWatcher(),
		options,
	); !errors.Is(
		err,
		ErrInvalidStreamService,
	) {
		t.Fatalf("NewStreamService(unsafe timeout) error = %v, want ErrInvalidStreamService", err)
	}
}

func newStreamServiceFixture(
	t *testing.T,
	opener SnapshotOpener,
	presence PresenceStore,
) *StreamService {
	t.Helper()
	return newStreamServiceWithRevisionsFixture(
		t,
		opener,
		presence,
		newStreamRevisionWatcher(),
	)
}

func newStreamServiceWithRevisionsFixture(
	t *testing.T,
	opener SnapshotOpener,
	presence PresenceStore,
	revisions RevisionWatcher,
) *StreamService {
	t.Helper()
	return newStreamServiceWithWatchersFixture(
		t,
		opener,
		presence,
		revisions,
		newStreamConnectivityWatcher(),
	)
}

func newStreamServiceWithWatchersFixture(
	t *testing.T,
	opener SnapshotOpener,
	presence PresenceStore,
	revisions RevisionWatcher,
	connectivity ConnectivityWatcher,
) *StreamService {
	t.Helper()
	service, err := NewStreamService(
		opener,
		presence,
		revisions,
		connectivity,
		streamOptionsFixture(t),
	)
	if err != nil {
		t.Fatalf("NewStreamService() error = %v", err)
	}
	return service
}

func streamOptionsFixture(t *testing.T) StreamOptions {
	t.Helper()
	replicaID, err := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return StreamOptions{
		ReplicaID:           replicaID,
		SnapshotTimeout:     time.Second,
		PresenceTTL:         9 * time.Second,
		CoordinationTimeout: time.Second,
		KeepAliveInterval:   4 * time.Second,
		ReconcileInterval:   5 * time.Second,
	}
}

func advancedStreamSnapshot(t *testing.T, initial Snapshot) Snapshot {
	t.Helper()
	params := initial.params()
	params.NetworkRevision++
	hostname, err := node.ParseHostname("node-2.example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	params.Hostname = hostname
	advanced, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return advanced
}

type streamSnapshotOpener struct {
	mu          sync.Mutex
	snapshots   []Snapshot
	failures    []error
	calls       int
	sawDeadline bool
}

func (opener *streamSnapshotOpener) Open(
	ctx context.Context,
	_ control.AuthenticatedMachine,
	_ Request,
) (Snapshot, error) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	opener.calls++
	_, hasDeadline := ctx.Deadline()
	opener.sawDeadline = opener.sawDeadline || hasDeadline
	if index := opener.calls - 1; index < len(opener.failures) && opener.failures[index] != nil {
		return Snapshot{}, opener.failures[index]
	}
	if len(opener.snapshots) == 0 {
		return Snapshot{}, errors.New("controlled snapshot failure")
	}
	index := min(opener.calls-1, len(opener.snapshots)-1)
	return opener.snapshots[index], nil
}

func (opener *streamSnapshotOpener) state() (int, bool) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.calls, opener.sawDeadline
}

type streamPresenceStore struct {
	mu                 sync.Mutex
	lease              node.PresenceLease
	acquires           int
	renews             int
	rejectAcquire      int
	rejectRenew        int
	sawAcquireDeadline bool
	sawRenewDeadline   bool
}

func (store *streamPresenceStore) AcquirePresence(
	ctx context.Context,
	_ network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.acquires++
	store.lease = lease
	_, store.sawAcquireDeadline = ctx.Deadline()
	return store.rejectAcquire == 0 || store.acquires != store.rejectAcquire, nil
}

func (store *streamPresenceStore) RenewPresence(
	ctx context.Context,
	lease node.PresenceLease,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.renews++
	store.lease = lease
	_, store.sawRenewDeadline = ctx.Deadline()
	return store.rejectRenew == 0 || store.renews != store.rejectRenew, nil
}

type streamPresenceState struct {
	lease              node.PresenceLease
	acquires           int
	renews             int
	sawAcquireDeadline bool
	sawRenewDeadline   bool
}

func (store *streamPresenceStore) state() streamPresenceState {
	store.mu.Lock()
	defer store.mu.Unlock()
	return streamPresenceState{
		lease:              store.lease,
		acquires:           store.acquires,
		renews:             store.renews,
		sawAcquireDeadline: store.sawAcquireDeadline,
		sawRenewDeadline:   store.sawRenewDeadline,
	}
}

type recordingStreamSink struct {
	mu              sync.Mutex
	snapshots       []Snapshot
	authorityDeltas []AuthorityDelta
	deltas          []ConnectivityDelta
	withdrawals     []Snapshot
	pauses          []Snapshot
	relayGrants     []Snapshot
	keepAlives      int
}

func (sink *recordingStreamSink) SendSnapshot(_ context.Context, snapshot Snapshot) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.snapshots = append(sink.snapshots, snapshot)
	return nil
}

func (sink *recordingStreamSink) SendConnectivityDelta(
	_ context.Context,
	delta ConnectivityDelta,
) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.deltas = append(sink.deltas, delta)
	return nil
}

func (sink *recordingStreamSink) SendAuthorityDelta(
	_ context.Context,
	delta AuthorityDelta,
) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.authorityDeltas = append(sink.authorityDeltas, delta)
	return nil
}

func (sink *recordingStreamSink) SendAuthorityWithdrawal(
	_ context.Context,
	snapshot Snapshot,
) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.withdrawals = append(sink.withdrawals, snapshot)
	return nil
}

func (sink *recordingStreamSink) SendAuthorityPause(
	_ context.Context,
	snapshot Snapshot,
) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.pauses = append(sink.pauses, snapshot)
	return nil
}

func (sink *recordingStreamSink) SendRelayGrant(_ context.Context, snapshot Snapshot) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.relayGrants = append(sink.relayGrants, snapshot)
	return nil
}

func (sink *recordingStreamSink) SendKeepAlive(context.Context) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.keepAlives++
	return nil
}

func (sink *recordingStreamSink) state() ([]Snapshot, int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return slices.Clone(sink.snapshots), sink.keepAlives
}

func (sink *recordingStreamSink) connectivityDeltas() []ConnectivityDelta {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return slices.Clone(sink.deltas)
}

func (sink *recordingStreamSink) authorityDeltaSnapshots() []AuthorityDelta {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return slices.Clone(sink.authorityDeltas)
}

func (sink *recordingStreamSink) authorityWithdrawals() []Snapshot {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return slices.Clone(sink.withdrawals)
}

type streamRevisionWatcher struct {
	mu       sync.Mutex
	updates  chan network.RevisionAdvanced
	watches  int
	releases int
}

func newStreamRevisionWatcher() *streamRevisionWatcher {
	return &streamRevisionWatcher{updates: make(chan network.RevisionAdvanced, 1)}
}

func (watcher *streamRevisionWatcher) WatchNetwork(
	network.ID,
) (<-chan network.RevisionAdvanced, func(), error) {
	watcher.mu.Lock()
	watcher.watches++
	watcher.mu.Unlock()
	var releaseOnce sync.Once
	return watcher.updates, func() {
		releaseOnce.Do(func() {
			watcher.mu.Lock()
			watcher.releases++
			watcher.mu.Unlock()
		})
	}, nil
}

func (watcher *streamRevisionWatcher) send(t *testing.T, revision network.RevisionAdvanced) {
	t.Helper()
	select {
	case watcher.updates <- revision:
	case <-t.Context().Done():
		t.Fatalf("send revision wakeup: %v", t.Context().Err())
	}
}

func (watcher *streamRevisionWatcher) closeUpdates() { close(watcher.updates) }

func (watcher *streamRevisionWatcher) state() (int, int) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	return watcher.watches, watcher.releases
}

type streamConnectivityWatcher struct {
	mu       sync.Mutex
	updates  chan ConnectivityChanged
	watches  int
	releases int
}

func newStreamConnectivityWatcher() *streamConnectivityWatcher {
	return &streamConnectivityWatcher{updates: make(chan ConnectivityChanged, 1)}
}

func (watcher *streamConnectivityWatcher) WatchNetwork(
	network.ID,
) (<-chan ConnectivityChanged, func(), error) {
	watcher.mu.Lock()
	watcher.watches++
	watcher.mu.Unlock()
	var releaseOnce sync.Once
	return watcher.updates, func() {
		releaseOnce.Do(func() {
			watcher.mu.Lock()
			watcher.releases++
			watcher.mu.Unlock()
		})
	}, nil
}

func (watcher *streamConnectivityWatcher) send(t *testing.T, change ConnectivityChanged) {
	t.Helper()
	select {
	case watcher.updates <- change:
	case <-t.Context().Done():
		t.Fatalf("send connectivity wakeup: %v", t.Context().Err())
	}
}

func (watcher *streamConnectivityWatcher) state() (int, int) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	return watcher.watches, watcher.releases
}
