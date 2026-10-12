package pathdiscovery

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

// scaleSelectionSnapshot has count peers, IDs from 2, with three map
// endpoints each.
func scaleSelectionSnapshot(revision uint64, count int) networkmap.Snapshot {
	snapshot := networkmap.Snapshot{Revision: revision, Self: networkmap.Node{ID: 1}}
	for index := range count {
		peer := networkmap.Node{
			ID:                uint64(index + 2),
			PublicKey:         fmt.Sprintf("nodekey:%d", index),
			DiscoveryKey:      fmt.Sprintf("discokey:%d", index),
			MachineAuthorized: true,
		}
		for endpoint := range 3 {
			peer.Endpoints = append(peer.Endpoints, netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{203, 0, byte(endpoint), 1}), uint16(1000+index),
			))
		}
		snapshot.Peers = append(snapshot.Peers, peer)
	}
	return snapshot
}

// referenceSelections recomputes every peer's selection the way the
// selector did before the expiry heap: retire every candidate due at now,
// then re-select every peer.
func referenceSelections(s *PathSelector, now time.Time) map[uint64]PathSelection {
	clone := &PathSelector{trust: s.trust, active: s.active, peers: make(map[uint64]*peerPathState, len(s.peers))}
	for peerID, peer := range s.peers {
		copied := *peer
		copied.candidates = maps.Clone(peer.candidates)
		clone.peers[peerID] = &copied
	}
	for _, peer := range clone.peers {
		for endpoint, candidate := range peer.candidates {
			if !candidate.confirmedAt.IsZero() && !candidate.expiresAt.After(now) {
				peer.candidates[endpoint] = pathCandidateState{}
			}
		}
		clone.selectPeerLocked(peer, now)
	}
	return clone.selectionsLocked()
}

// TestPathSelectorMatchesFullReevaluation drives random pongs and expiries
// and checks after each step that evaluating only the touched peers gives
// the selections a full re-evaluation gives, and that ExpiresAt is the
// earliest live deadline.
func TestPathSelectorMatchesFullReevaluation(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(7, 8)) //nolint:gosec // seeded test input, not a secret
	generation := testProbeGeneration(5)
	snapshot := scaleSelectionSnapshot(generation.MapRevision, 40)
	selector := newPathSelector(3 * time.Second)
	if _, err := selector.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(50_000, 0)
	for step := range 3000 {
		now = now.Add(time.Duration(random.IntN(400)) * time.Millisecond)
		var result PathSelectionResult
		var err error
		if random.IntN(5) == 0 {
			result, err = selector.Expire(now)
		} else {
			peer := snapshot.Peers[random.IntN(len(snapshot.Peers))]
			result, err = selector.Observe(PathObservation{
				PeerID:         peer.ID,
				Generation:     generation,
				RemoteEndpoint: peer.Endpoints[random.IntN(len(peer.Endpoints))],
				RoundTrip:      time.Duration(1+random.IntN(80)) * time.Millisecond,
				ObservedAt:     now,

				ObservedLocalEndpoint: netip.MustParseAddrPort("198.51.100.100:41641"),
			})
		}
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		selector.mu.Lock()
		got, want := selector.selectionsLocked(), referenceSelections(selector, now)
		var earliest time.Time
		for _, peer := range selector.peers {
			for _, candidate := range peer.candidates {
				if !candidate.confirmedAt.IsZero() && candidate.expiresAt.After(now) &&
					(earliest.IsZero() || candidate.expiresAt.Before(earliest)) {
					earliest = candidate.expiresAt
				}
			}
		}
		selector.mu.Unlock()
		if !maps.Equal(got, want) {
			t.Fatalf("step %d: selections differ from a full re-evaluation", step)
		}
		if !result.ExpiresAt.Equal(earliest) {
			t.Fatalf("step %d: ExpiresAt %v, earliest live deadline %v", step, result.ExpiresAt, earliest)
		}
	}
}

// BenchmarkPathSelectorObserveTenThousandPeers measures one pong with
// maxPathPeers peers, each with a confirmed path.
func BenchmarkPathSelectorObserveTenThousandPeers(b *testing.B) {
	generation := testProbeGeneration(5)
	snapshot := scaleSelectionSnapshot(generation.MapRevision, maxPathPeers)
	selector := NewPathSelector()
	if _, err := selector.Activate(snapshot, generation); err != nil {
		b.Fatal(err)
	}
	local := netip.MustParseAddrPort("198.51.100.100:41641")
	now := time.Unix(50_000, 0)
	for _, peer := range snapshot.Peers {
		if _, err := selector.Observe(PathObservation{
			PeerID: peer.ID, Generation: generation, RemoteEndpoint: peer.Endpoints[0],
			RoundTrip: time.Millisecond, ObservedAt: now, ObservedLocalEndpoint: local,
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for index := range b.N {
		peer := snapshot.Peers[index%len(snapshot.Peers)]
		if _, err := selector.Observe(PathObservation{
			PeerID: peer.ID, Generation: generation, RemoteEndpoint: peer.Endpoints[0],
			RoundTrip: time.Millisecond, ObservedAt: now, ObservedLocalEndpoint: local,
		}); err != nil {
			b.Fatal(err)
		}
	}
}
