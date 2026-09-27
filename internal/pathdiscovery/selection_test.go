package pathdiscovery

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
)

func TestPathSelectorSelectsAndSmoothsAuthenticatedPath(t *testing.T) {
	t.Parallel()

	remote := netip.MustParseAddrPort("203.0.113.10:41641")
	selector, snapshot, generation := activePathSelector(t, remote)
	now := time.Unix(1_000, 0)
	first := pathObservation(generation, remote, 30*time.Millisecond, now)
	result, err := selector.Observe(first)
	if err != nil {
		t.Fatalf("Observe(first) error = %v", err)
	}
	if len(result.Changes) != 1 || result.Changes[0].Previous.IsValid() ||
		result.Changes[0].Current.RemoteEndpoint != remote ||
		result.ExpiresAt != now.Add(defaultPathTrust) {
		t.Fatalf("Observe(first) result = %#v", result)
	}

	second := pathObservation(
		generation,
		remote,
		10*time.Millisecond,
		now.Add(time.Second),
	)
	result, err = selector.Observe(second)
	if err != nil {
		t.Fatalf("Observe(second) error = %v", err)
	}
	if len(result.Changes) != 1 ||
		result.Changes[0].Previous.RemoteEndpoint != remote ||
		result.Changes[0].Current.RemoteEndpoint != remote ||
		result.ExpiresAt != second.ObservedAt.Add(defaultPathTrust) {
		t.Fatalf("Observe(second) result = %#v", result)
	}
	selected := selector.Selections()
	if len(selected) != 1 || selected[0].PeerID != snapshot.Peers[0].ID ||
		selected[0].Generation != generation ||
		selected[0].RemoteEndpoint != remote ||
		selected[0].ObservedLocalEndpoint != second.ObservedLocalEndpoint ||
		selected[0].RoundTrip != 25*time.Millisecond ||
		selected[0].ConfirmedAt != second.ObservedAt ||
		selected[0].ExpiresAt != second.ObservedAt.Add(defaultPathTrust) ||
		!selected[0].IsValid() {
		t.Fatalf("Selections() = %#v", selected)
	}
}

func TestPathSelectorDoesNotReassertUnselectedPath(t *testing.T) {
	t.Parallel()

	selected := netip.MustParseAddrPort("203.0.113.10:41641")
	unselected := netip.MustParseAddrPort("192.168.1.10:41641")
	selector, _, generation := activePathSelector(t, selected, unselected)
	now := time.Unix(1_500, 0)
	if _, err := selector.Observe(
		pathObservation(generation, selected, 10*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe(selected) error = %v", err)
	}
	result, err := selector.Observe(pathObservation(
		generation,
		unselected,
		100*time.Millisecond,
		now.Add(time.Millisecond),
	))
	if err != nil {
		t.Fatalf("Observe(unselected) error = %v", err)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("Observe(unselected) changes = %#v", result.Changes)
	}
}

func TestPathSelectorUsesStablePreferenceAndSwitchThreshold(t *testing.T) {
	t.Parallel()

	public := netip.MustParseAddrPort("203.0.113.20:41641")
	private := netip.MustParseAddrPort("192.168.1.20:41641")
	selector, _, generation := activePathSelector(t, public, private)
	now := time.Unix(2_000, 0)
	if _, err := selector.Observe(
		pathObservation(generation, public, 100*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe(public) error = %v", err)
	}
	result, err := selector.Observe(pathObservation(
		generation,
		private,
		104*time.Millisecond,
		now.Add(time.Millisecond),
	))
	if err != nil {
		t.Fatalf("Observe(private) error = %v", err)
	}
	if len(result.Changes) != 1 ||
		result.Changes[0].Current.RemoteEndpoint != private {
		t.Fatalf("near-equal private result = %#v", result)
	}

	result, err = selector.Observe(pathObservation(
		generation,
		public,
		40*time.Millisecond,
		now.Add(2*time.Millisecond),
	))
	if err != nil {
		t.Fatalf("Observe(faster public) error = %v", err)
	}
	if len(result.Changes) != 1 ||
		result.Changes[0].Current.RemoteEndpoint != public ||
		result.Changes[0].Current.RoundTrip != 85*time.Millisecond {
		t.Fatalf("materially faster result = %#v", result)
	}
}

func TestPathSelectorDeterministicallyBreaksEquivalentTies(t *testing.T) {
	t.Parallel()

	higherV4 := netip.MustParseAddrPort("203.0.113.31:41641")
	lowerV4 := netip.MustParseAddrPort("203.0.113.30:41641")
	publicV6 := netip.MustParseAddrPort("[2001:db8::30]:41641")
	now := time.Unix(3_000, 0)

	selector, _, generation := activePathSelector(t, higherV4, lowerV4)
	if _, err := selector.Observe(
		pathObservation(generation, higherV4, 50*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe(higher) error = %v", err)
	}
	result, err := selector.Observe(pathObservation(
		generation,
		lowerV4,
		50*time.Millisecond,
		now.Add(time.Millisecond),
	))
	if err != nil {
		t.Fatalf("Observe(lower) error = %v", err)
	}
	if len(result.Changes) != 1 ||
		result.Changes[0].Current.RemoteEndpoint != lowerV4 {
		t.Fatalf("address tie result = %#v", result)
	}

	selector, _, generation = activePathSelector(t, higherV4, publicV6)
	if _, err := selector.Observe(
		pathObservation(generation, higherV4, 50*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe(ipv4) error = %v", err)
	}
	result, err = selector.Observe(pathObservation(
		generation,
		publicV6,
		51*time.Millisecond,
		now.Add(time.Millisecond),
	))
	if err != nil {
		t.Fatalf("Observe(ipv6) error = %v", err)
	}
	if len(result.Changes) != 1 ||
		result.Changes[0].Current.RemoteEndpoint != publicV6 {
		t.Fatalf("address-family tie result = %#v", result)
	}
}

func TestPathSelectorExpiresAndFallsBackAtExactDeadlines(t *testing.T) {
	t.Parallel()

	first := netip.MustParseAddrPort("203.0.113.40:41641")
	second := netip.MustParseAddrPort("203.0.113.41:41641")
	selector, _, generation := activePathSelector(t, first, second)
	now := time.Unix(4_000, 0)
	if _, err := selector.Observe(
		pathObservation(generation, first, 10*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe(first) error = %v", err)
	}
	secondObservation := pathObservation(
		generation,
		second,
		30*time.Millisecond,
		now.Add(time.Second),
	)
	if _, err := selector.Observe(secondObservation); err != nil {
		t.Fatalf("Observe(second) error = %v", err)
	}

	result, err := selector.Expire(now.Add(defaultPathTrust))
	if err != nil {
		t.Fatalf("Expire(first) error = %v", err)
	}
	if len(result.Changes) != 1 ||
		result.Changes[0].Previous.RemoteEndpoint != first ||
		result.Changes[0].Current.RemoteEndpoint != second ||
		result.ExpiresAt != secondObservation.ObservedAt.Add(defaultPathTrust) {
		t.Fatalf("Expire(first) result = %#v", result)
	}

	result, err = selector.Expire(secondObservation.ObservedAt.Add(defaultPathTrust))
	if err != nil {
		t.Fatalf("Expire(second) error = %v", err)
	}
	if len(result.Changes) != 1 ||
		result.Changes[0].Previous.RemoteEndpoint != second ||
		result.Changes[0].Current.IsValid() || !result.ExpiresAt.IsZero() ||
		len(selector.Selections()) != 0 {
		t.Fatalf("Expire(second) result = %#v selections=%#v", result, selector.Selections())
	}
}

func TestPathSelectorGenerationLifecycleIsAtomic(t *testing.T) {
	t.Parallel()

	remote := netip.MustParseAddrPort("203.0.113.50:41641")
	selector, snapshot, generation := activePathSelector(t, remote)
	now := time.Unix(5_000, 0)
	if _, err := selector.Observe(
		pathObservation(generation, remote, 20*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	result, err := selector.Activate(snapshot, generation)
	if err != nil || len(result.Changes) != 0 || len(selector.Selections()) != 1 {
		t.Fatalf("Activate(same) result=%#v error=%v selections=%#v", result, err, selector.Selections())
	}

	changedAtSameRevision := cloneSelectionSnapshot(snapshot)
	changedAtSameRevision.Peers[0].Endpoints = append(
		changedAtSameRevision.Peers[0].Endpoints,
		netip.MustParseAddrPort("203.0.113.51:41641"),
	)
	if _, err := selector.Activate(changedAtSameRevision, generation); !errors.Is(err, ErrInvalidPathSnapshot) {
		t.Fatalf("Activate(changed same generation) error = %v", err)
	}
	if len(selector.Selections()) != 1 {
		t.Fatal("failed replacement changed the active selection")
	}
	changedIdentityAtSameRevision := cloneSelectionSnapshot(snapshot)
	changedIdentityAtSameRevision.Peers[0].DiscoveryKey = "discokey:replacement"
	if _, err := selector.Activate(
		changedIdentityAtSameRevision,
		generation,
	); !errors.Is(err, ErrInvalidPathSnapshot) {
		t.Fatalf("Activate(changed identity same generation) error = %v", err)
	}
	if len(selector.Selections()) != 1 {
		t.Fatal("failed identity replacement changed the active selection")
	}

	replacement := cloneSelectionSnapshot(snapshot)
	replacement.Revision++
	replacementGeneration := generation
	replacementGeneration.MapRevision = replacement.Revision
	result, err = selector.Activate(replacement, replacementGeneration)
	selected := selector.Selections()
	if err != nil || len(result.Changes) != 0 ||
		len(selected) != 1 || selected[0].Generation != replacementGeneration ||
		selected[0].RemoteEndpoint != remote ||
		selected[0].ExpiresAt != now.Add(defaultPathTrust) {
		t.Fatalf("Activate(replacement) result=%#v error=%v", result, err)
	}

	changedAuthority := cloneSelectionSnapshot(replacement)
	changedAuthority.Revision++
	changedAuthority.Peers[0].Endpoints = append(
		changedAuthority.Peers[0].Endpoints,
		netip.MustParseAddrPort("203.0.113.52:41641"),
	)
	changedGeneration := replacementGeneration
	changedGeneration.MapRevision = changedAuthority.Revision
	result, err = selector.Activate(changedAuthority, changedGeneration)
	if err != nil || len(result.Changes) != 1 ||
		result.Changes[0].Previous.RemoteEndpoint != remote ||
		result.Changes[0].Current.IsValid() || len(selector.Selections()) != 0 {
		t.Fatalf("Activate(changed authority) result=%#v error=%v", result, err)
	}
	selector.Deactivate()
	if _, err := selector.Activate(snapshot, generation); !errors.Is(err, ErrInvalidPathSnapshot) {
		t.Fatalf("Activate(rollback) error = %v", err)
	}
}

func TestPathSelectorEquivalentRevisionPreservesOnlyRemainingLease(t *testing.T) {
	t.Parallel()

	remote := netip.MustParseAddrPort("203.0.113.53:41641")
	selector, snapshot, generation := activePathSelector(t, remote)
	now := time.Unix(5_500, 0)
	if _, err := selector.Observe(
		pathObservation(generation, remote, 20*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe() error = %v", err)
	}

	snapshot.Revision++
	generation.MapRevision = snapshot.Revision
	result, err := selector.Activate(snapshot, generation)
	if err != nil || len(result.Changes) != 0 ||
		result.ExpiresAt != now.Add(defaultPathTrust) {
		t.Fatalf("Activate(equivalent revision) result=%#v error=%v", result, err)
	}

	result, err = selector.Expire(now.Add(defaultPathTrust))
	if err != nil || len(result.Changes) != 1 ||
		result.Changes[0].Previous.Generation != generation ||
		result.Changes[0].Previous.RemoteEndpoint != remote ||
		result.Changes[0].Current.IsValid() || !result.ExpiresAt.IsZero() {
		t.Fatalf("Expire(carried lease) result=%#v error=%v", result, err)
	}
}

func TestPathSelectorSocketChangeRetiresAuthenticatedPath(t *testing.T) {
	t.Parallel()

	remote := netip.MustParseAddrPort("203.0.113.54:41641")
	selector, snapshot, generation := activePathSelector(t, remote)
	now := time.Unix(5_600, 0)
	if _, err := selector.Observe(
		pathObservation(generation, remote, 20*time.Millisecond, now),
	); err != nil {
		t.Fatalf("Observe() error = %v", err)
	}

	snapshot.Revision++
	generation.MapRevision = snapshot.Revision
	generation.Socket.Generation++
	result, err := selector.Activate(snapshot, generation)
	if err != nil || len(result.Changes) != 1 ||
		result.Changes[0].Previous.RemoteEndpoint != remote ||
		result.Changes[0].Current.IsValid() || len(selector.Selections()) != 0 {
		t.Fatalf("Activate(new socket) result=%#v error=%v", result, err)
	}
}

func TestPathSelectorRejectsUnauthorizedAndRegressingObservations(t *testing.T) {
	t.Parallel()

	remote := netip.MustParseAddrPort("203.0.113.60:41641")
	selector := NewPathSelector()
	generation := testProbeGeneration(7)
	now := time.Unix(6_000, 0)
	observation := pathObservation(generation, remote, time.Millisecond, now)
	if _, err := selector.Observe(observation); !errors.Is(err, ErrPathSelectionInactive) {
		t.Fatalf("Observe(inactive) error = %v", err)
	}

	snapshot := selectionSnapshot(generation.MapRevision, remote)
	if _, err := selector.Activate(snapshot, generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*PathObservation)
	}{
		{name: "generation", mutate: func(value *PathObservation) { value.Generation.MapRevision++ }},
		{name: "peer", mutate: func(value *PathObservation) { value.PeerID++ }},
		{name: "remote", mutate: func(value *PathObservation) {
			value.RemoteEndpoint = netip.MustParseAddrPort("203.0.113.61:41641")
		}},
		{name: "observed local", mutate: func(value *PathObservation) {
			value.ObservedLocalEndpoint = netip.MustParseAddrPort("127.0.0.1:41641")
		}},
		{name: "round trip", mutate: func(value *PathObservation) {
			value.RoundTrip = defaultProbeLifetime
		}},
		{name: "time", mutate: func(value *PathObservation) { value.ObservedAt = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := observation
			test.mutate(&candidate)
			if _, err := selector.Observe(candidate); !errors.Is(err, ErrInvalidPathObservation) {
				t.Fatalf("Observe() error = %v", err)
			}
		})
	}

	if _, err := selector.Observe(observation); err != nil {
		t.Fatalf("Observe(valid) error = %v", err)
	}
	regression := observation
	regression.ObservedAt = now.Add(-time.Nanosecond)
	if _, err := selector.Observe(regression); !errors.Is(err, ErrPathTimeRegression) {
		t.Fatalf("Observe(regression) error = %v", err)
	}
	if _, err := selector.Expire(now.Add(-time.Nanosecond)); !errors.Is(err, ErrPathTimeRegression) {
		t.Fatalf("Expire(regression) error = %v", err)
	}
}

func TestPathSelectorValidatesBoundedAuthority(t *testing.T) {
	t.Parallel()

	selector := NewPathSelector()
	generation := testProbeGeneration(8)
	snapshot := selectionSnapshot(generation.MapRevision)
	for index := 0; index < maxPathCandidatesPerPeer+1; index++ {
		snapshot.Peers[0].Endpoints = append(
			snapshot.Peers[0].Endpoints,
			netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{203, 0, byte(index / 250), byte(index%250 + 1)}),
				41641,
			),
		)
	}
	if _, err := selector.Activate(snapshot, generation); !errors.Is(err, ErrInvalidPathSnapshot) {
		t.Fatalf("Activate(too many endpoints) error = %v", err)
	}

	tooManyPeers := selectionSnapshot(generation.MapRevision)
	for peerID := uint64(3); peerID <= maxPathPeers+2; peerID++ {
		tooManyPeers.Peers = append(tooManyPeers.Peers, networkmap.Node{
			ID:                peerID,
			MachineAuthorized: true,
		})
	}
	if _, err := selector.Activate(tooManyPeers, generation); !errors.Is(err, ErrInvalidPathSnapshot) {
		t.Fatalf("Activate(too many peers) error = %v", err)
	}

	duplicateEndpoint := selectionSnapshot(
		generation.MapRevision,
		netip.MustParseAddrPort("203.0.113.79:41641"),
		netip.MustParseAddrPort("203.0.113.79:41641"),
	)
	if _, err := selector.Activate(duplicateEndpoint, generation); !errors.Is(err, ErrInvalidPathSnapshot) {
		t.Fatalf("Activate(duplicate endpoint) error = %v", err)
	}

	unauthorized := selectionSnapshot(generation.MapRevision, netip.MustParseAddrPort("203.0.113.80:41641"))
	unauthorized.Peers[0].MachineAuthorized = false
	if _, err := selector.Activate(unauthorized, generation); !errors.Is(err, ErrInvalidPathSnapshot) {
		t.Fatalf("Activate(unauthorized peer) error = %v", err)
	}

	withoutDiscovery := selectionSnapshot(
		generation.MapRevision,
		netip.MustParseAddrPort("203.0.113.81:41641"),
	)
	withoutDiscovery.Peers[0].DiscoveryKey = ""
	freshSelector := NewPathSelector()
	if _, err := freshSelector.Activate(withoutDiscovery, generation); err != nil {
		t.Fatalf("Activate(without discovery identity) error = %v", err)
	}
	if _, err := freshSelector.Observe(pathObservation(
		generation,
		withoutDiscovery.Peers[0].Endpoints[0],
		time.Millisecond,
		time.Unix(6_500, 0),
	)); !errors.Is(err, ErrInvalidPathObservation) {
		t.Fatalf("Observe(without discovery identity) error = %v", err)
	}
}

func TestPathSelectorConcurrentEquivalentObservationsConverge(t *testing.T) {
	t.Parallel()

	higher := netip.MustParseAddrPort("203.0.113.91:41641")
	lower := netip.MustParseAddrPort("203.0.113.90:41641")
	selector, _, generation := activePathSelector(t, higher, lower)
	now := time.Unix(7_000, 0)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := range 64 {
		endpoint := higher
		if index%2 == 0 {
			endpoint = lower
		}
		workers.Go(func() {
			<-start
			if _, err := selector.Observe(pathObservation(
				generation,
				endpoint,
				50*time.Millisecond,
				now,
			)); err != nil {
				t.Errorf("Observe(%v) error = %v", endpoint, err)
			}
		})
	}
	close(start)
	workers.Wait()
	selected := selector.Selections()
	if len(selected) != 1 || selected[0].RemoteEndpoint != lower {
		t.Fatalf("Selections() = %#v", selected)
	}
}

func FuzzPathSelectorObserve(f *testing.F) {
	f.Add(uint64(2), uint64(9), uint64(9), uint64(9), uint16(41641), int64(1_000_000), int64(0))
	f.Add(uint64(0), uint64(0), uint64(0), uint64(0), uint16(0), int64(-1), int64(-1))

	f.Fuzz(func(
		t *testing.T,
		peerID uint64,
		scope uint64,
		revision uint64,
		socketGeneration uint64,
		port uint16,
		roundTripNanos int64,
		secondsOffset int64,
	) {
		remote := netip.MustParseAddrPort("203.0.113.100:41641")
		activeGeneration := ProbeGeneration{
			Scope:       9,
			MapRevision: 9,
			Socket: Socket{
				Port:       41641,
				Generation: 9,
			},
		}
		selector := NewPathSelector()
		if _, err := selector.Activate(
			selectionSnapshot(activeGeneration.MapRevision, remote),
			activeGeneration,
		); err != nil {
			t.Fatalf("Activate() error = %v", err)
		}
		candidate := PathObservation{
			PeerID: peerID,
			Generation: ProbeGeneration{
				Scope:       scope,
				MapRevision: revision,
				Socket: Socket{
					Port:       port,
					Generation: socketGeneration,
				},
			},
			RemoteEndpoint: netip.AddrPortFrom(remote.Addr(), port),
			ObservedLocalEndpoint: netip.AddrPortFrom(
				netip.MustParseAddr("198.51.100.100"),
				port,
			),
			RoundTrip:  time.Duration(roundTripNanos),
			ObservedAt: time.Unix(8_000+secondsOffset%1_000_000, 0),
		}
		_, _ = selector.Observe(candidate)
		for _, selected := range selector.Selections() {
			if !selected.IsValid() || selected.Generation != activeGeneration ||
				selected.PeerID != 2 || selected.RemoteEndpoint != remote {
				t.Fatalf("invalid selection published: %#v", selected)
			}
		}
	})
}

func activePathSelector(
	t *testing.T,
	endpoints ...netip.AddrPort,
) (*PathSelector, networkmap.Snapshot, ProbeGeneration) {
	t.Helper()

	generation := testProbeGeneration(5)
	snapshot := selectionSnapshot(generation.MapRevision, endpoints...)
	selector := NewPathSelector()
	if result, err := selector.Activate(snapshot, generation); err != nil ||
		len(result.Changes) != 0 || !result.ExpiresAt.IsZero() {
		t.Fatalf("Activate() result=%#v error=%v", result, err)
	}

	return selector, snapshot, generation
}

func selectionSnapshot(
	revision uint64,
	endpoints ...netip.AddrPort,
) networkmap.Snapshot {
	return networkmap.Snapshot{
		Revision: revision,
		Self: networkmap.Node{
			ID: 1,
		},
		Peers: []networkmap.Node{{
			ID:                2,
			PublicKey:         "nodekey:test",
			DiscoveryKey:      "discokey:test",
			Endpoints:         append([]netip.AddrPort(nil), endpoints...),
			MachineAuthorized: true,
		}},
	}
}

func pathObservation(
	generation ProbeGeneration,
	remote netip.AddrPort,
	roundTrip time.Duration,
	observedAt time.Time,
) PathObservation {
	return PathObservation{
		PeerID:                2,
		Generation:            generation,
		RemoteEndpoint:        remote,
		ObservedLocalEndpoint: netip.MustParseAddrPort("198.51.100.100:41641"),
		RoundTrip:             roundTrip,
		ObservedAt:            observedAt,
	}
}

func cloneSelectionSnapshot(snapshot networkmap.Snapshot) networkmap.Snapshot {
	clone := snapshot
	clone.Peers = append([]networkmap.Node(nil), snapshot.Peers...)
	for index := range clone.Peers {
		clone.Peers[index].Endpoints = append(
			[]netip.AddrPort(nil),
			snapshot.Peers[index].Endpoints...,
		)
	}

	return clone
}
