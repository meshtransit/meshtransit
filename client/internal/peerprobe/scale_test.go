package peerprobe

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/disco"
)

// scalePeers builds count peers with distinct node and discovery keys and
// one map endpoint each, IDs from 2.
func scalePeers(t *testing.T, count int) []networkmap.Node {
	t.Helper()
	peers := make([]networkmap.Node, 0, count)
	for index := range count {
		peers = append(peers, networkmap.Node{
			ID:                uint64(index + 2),
			PublicKey:         fmt.Sprintf("nodekey:%064x", index+1),
			DiscoveryKey:      MapDiscoveryKey(testIdentity(t).Public()),
			MachineAuthorized: true,
			Endpoints:         []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 1}), uint16(1000+index))},
		})
	}
	return peers
}

// TestRoundTargetsRotateSoNoPeerStarves: with more peers than one round can
// probe, each round starts after the last peer of the previous one.
func TestRoundTargetsRotateSoNoPeerStarves(t *testing.T) {
	t.Parallel()
	runtime, _, _, _, _, snapshot, generation := testRuntime(t)
	runtime.scheduleLimit = 4
	snapshot.Peers = scalePeers(t, 10)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	// Answered candidates are due every round, whatever the rounds the
	// scheduler runs meanwhile sent (budget.go).
	for _, peer := range snapshot.Peers {
		runtime.registry.ConfirmProbe(peer.ID, peer.Endpoints[0], time.Now())
	}
	ids := func(targets []probeTarget) []uint64 {
		out := make([]uint64, 0, len(targets))
		for _, target := range targets {
			out = append(out, target.peerID)
		}
		return out
	}
	// Activate ran the first round (peers 2-5).
	for round, want := range [][]uint64{{6, 7, 8, 9}, {10, 11, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11}} {
		if got := ids(runtime.roundTargets()); !slices.Equal(got, want) {
			t.Fatalf("round %d probed %v, want %v", round, got, want)
		}
	}
}

// TestRegistryKeepsPeerChannelsAcrossMaps: a new map derives a channel key
// only for peers whose discovery key is new.
func TestRegistryKeepsPeerChannelsAcrossMaps(t *testing.T) {
	t.Parallel()
	runtime, _, _, _, _, snapshot, generation := testRuntime(t)
	snapshot.Peers = scalePeers(t, 3)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	before := runtime.registry.byID[2].wire
	next := snapshot
	next.Revision++
	next.Peers = append(slices.Clone(snapshot.Peers), scalePeers(t, 4)[3])
	nextGeneration := generation
	nextGeneration.MapRevision = next.Revision
	if _, _, err := runtime.Activate(next, nextGeneration); err != nil {
		t.Fatal(err)
	}
	if runtime.registry.byID[2].wire != before {
		t.Fatal("an unchanged peer's channel key was derived again")
	}
	if runtime.registry.byID[5].wire == nil {
		t.Fatal("a new peer has no channel key")
	}
}

// TestCallMeMaybeRespectsTheTickBudget: due peers beyond the budget wait for
// later ticks, which reach them in turn.
func TestCallMeMaybeRespectsTheTickBudget(t *testing.T) {
	t.Parallel()
	runtime, transport, local, _ := newRelayRuntime(t)
	runtime.callMeMaybeBudget = 3
	snapshot, generation := runtimeSnapshot(t, local, testIdentity(t))
	snapshot.Peers = scalePeers(t, 7)
	transport.relayed = make(chan relaySend, 64)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	runtime.SetLocalEndpoints([]disco.Endpoint{{
		Kind: disco.EndpointServerReflex, Addr: netip.MustParseAddrPort("198.51.100.5:41641"),
	}}, disco.NATInfo{Mapping: disco.MappingEndpointIndependent})
	drain := func() int {
		count := 0
		for {
			select {
			case <-transport.relayed:
				count++
			case <-time.After(50 * time.Millisecond):
				return count
			}
		}
	}
	drain() // the runtime's own ticker may already have run once
	sent := 0
	for range 3 {
		runtime.sendCallMeMaybes(transport)
		got := drain()
		if got > runtime.callMeMaybeBudget {
			t.Fatalf("tick sent %d CALL_ME_MAYBE, budget %d", got, runtime.callMeMaybeBudget)
		}
		sent += got
	}
	if sent == 0 {
		t.Fatal("no CALL_ME_MAYBE sent")
	}
}

// TestRegistryReplacesTenThousandPeersQuickly: a second map with the same
// peers reuses every channel key, so it costs no X25519.
func TestRegistryReplacesTenThousandPeersQuickly(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	t.Parallel()
	runtime, _, _, _, _, snapshot, generation := testRuntime(t)
	snapshot.Peers = scalePeers(t, maxPeerChannels)
	started := time.Now()
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	first := time.Since(started)
	next := snapshot
	next.Revision++
	nextGeneration := generation
	nextGeneration.MapRevision = next.Revision
	started = time.Now()
	if _, _, err := runtime.Activate(next, nextGeneration); err != nil {
		t.Fatal(err)
	}
	second := time.Since(started)
	t.Logf("activate %d peers: first %v, same peers again %v", len(snapshot.Peers), first, second)
	if second > first/2 {
		t.Fatalf("re-activation took %v after %v: channel keys were derived again", second, first)
	}
}
