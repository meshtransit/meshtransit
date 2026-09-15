package mapsession

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestStreamServiceOwnsBoundedPresenceLifecycle(t *testing.T) {
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
		if openerCalls != 1 || !openerDeadline || presenceState.claims != 1 ||
			!presenceState.sawClaimDeadline || len(snapshots) != 1 || keepAlives != 0 {
			t.Fatalf(
				"initial stream = opener(%d,%t) presence(%d,%t) sink(%d,%d)",
				openerCalls,
				openerDeadline,
				presenceState.claims,
				presenceState.sawClaimDeadline,
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
		if presenceState.claims != 2 {
			t.Fatalf("presence claims after renewal = %d, want 2", presenceState.claims)
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
		if presenceState.releases != 1 || !presenceState.sawReleaseDeadline {
			t.Fatalf("presence releases = (%d,%t), want one bounded release", presenceState.releases, presenceState.sawReleaseDeadline)
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
		service := newStreamServiceWithRevisionsFixture(
			t,
			&streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		revisions.closeUpdates()
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrStreamUnavailable) {
			t.Fatalf("Serve() error = %v, want ErrStreamUnavailable", err)
		}
	})
}

func TestStreamServiceFailsClosedWhenPresenceIsLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &streamPresenceStore{rejectClaim: 2}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrPresenceLost) {
			t.Fatalf("Serve() error = %v, want ErrPresenceLost", err)
		}
		if releases := presence.state().releases; releases != 1 {
			t.Fatalf("presence releases = %d, want one exact cleanup attempt", releases)
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
		if claims := presence.state().claims; claims != 1 {
			t.Fatalf("Redis presence claims = %d, want only the admitted stream", claims)
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
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrStreamDiscontinuity) {
			t.Fatalf("Serve() error = %v, want ErrStreamDiscontinuity", err)
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
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrAuthorizationExpired) {
			t.Fatalf("Serve() error = %v, want ErrAuthorizationExpired", err)
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
	claims             int
	releases           int
	rejectClaim        int
	sawClaimDeadline   bool
	sawReleaseDeadline bool
}

func (store *streamPresenceStore) ClaimPresence(
	ctx context.Context,
	_ network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.claims++
	store.lease = lease
	_, store.sawClaimDeadline = ctx.Deadline()
	return store.rejectClaim == 0 || store.claims != store.rejectClaim, nil
}

func (store *streamPresenceStore) ReleasePresence(
	ctx context.Context,
	_ network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.releases++
	store.lease = lease
	_, store.sawReleaseDeadline = ctx.Deadline()
	return true, nil
}

type streamPresenceState struct {
	lease              node.PresenceLease
	claims             int
	releases           int
	sawClaimDeadline   bool
	sawReleaseDeadline bool
}

func (store *streamPresenceStore) state() streamPresenceState {
	store.mu.Lock()
	defer store.mu.Unlock()
	return streamPresenceState{
		lease:              store.lease,
		claims:             store.claims,
		releases:           store.releases,
		sawClaimDeadline:   store.sawClaimDeadline,
		sawReleaseDeadline: store.sawReleaseDeadline,
	}
}

type recordingStreamSink struct {
	mu              sync.Mutex
	snapshots       []Snapshot
	authorityDeltas []AuthorityDelta
	deltas          []ConnectivityDelta
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
