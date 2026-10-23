package networkmap

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// secondAliasPeer is another alias peer of aliasTestSnapshot's Self, with
// addresses and keys of its own.
func secondAliasPeer(snapshot Snapshot) Node {
	peer := cloneNode(snapshot.Peers[0])
	peer.ID, peer.StableID = 3, "provider-3"
	peer.PublicKey = "nodekey:" + strings.Repeat("33", 32)
	peer.Alias.PeerKey = peer.PublicKey
	peer.Alias.EndpointID = "00000000-0000-4000-8000-000000000003"
	peer.Addresses = []netip.Prefix{netip.MustParsePrefix("100.96.0.3/32"), netip.MustParsePrefix("fd00:2::3/128")}
	peer.AllowedIPs = append([]netip.Prefix{}, peer.Addresses...)
	peer.Alias.SelfIPv4, peer.Alias.SelfIPv6 = netip.MustParseAddr("100.96.0.4"), netip.MustParseAddr("fd00:2::4")
	return peer
}

func ordinaryTestPeer(now time.Time) Node {
	peer := Node{
		ID: 4, StableID: "peer-4", Name: "ordinary.example.test",
		PublicKey: "nodekey:" + strings.Repeat("44", 32), MachineAuthorized: true,
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.10.4/32")}, KeyExpiry: now.Add(time.Hour),
	}
	peer.AllowedIPs = append([]netip.Prefix{}, peer.Addresses...)
	return peer
}

func peerIDs(snapshot Snapshot) []uint64 {
	ids := make([]uint64, 0, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		ids = append(ids, peer.ID)
	}
	return ids
}

// An alias that cannot be used now leaves out its peer only; the rest of
// the map stays valid.
func TestWithoutUnusableAliasesDropsOnlyTheBadPeers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*Node)
	}{
		{"expired", func(peer *Node) { peer.Alias.ExpiresAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }},
		{"invalid identity", func(peer *Node) { peer.Alias.ContractID = "not-a-contract" }},
		{"no services", func(peer *Node) { peer.Alias.Services = nil }},
		{"local alias on a mapped address", func(peer *Node) { peer.Alias.SelfIPv4 = netip.MustParseAddr("100.64.10.4") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot, now := aliasTestSnapshot()
			bad := secondAliasPeer(snapshot)
			test.edit(&bad)
			snapshot.Peers = append(snapshot.Peers, bad, ordinaryTestPeer(now))
			if _, err := ValidateAndClone(snapshot, now); err == nil {
				t.Fatal("the unpruned map validated")
			}
			pruned, dropped := WithoutUnusableAliases(snapshot, now)
			if dropped != 1 || !slices.Equal(peerIDs(pruned), []uint64{2, 4}) {
				t.Fatalf("dropped %d, peers %v", dropped, peerIDs(pruned))
			}
			if _, err := ValidateAndClone(pruned, now); err != nil {
				t.Fatalf("pruned map: %v", err)
			}
			if len(snapshot.Peers) != 3 {
				t.Fatal("the caller's map changed")
			}
		})
	}
}

// Two providers that claim one local alias for unrelated endpoints: the
// first keeps it, the second is left out.
func TestWithoutUnusableAliasesKeepsTheFirstOwnerOfALocalAlias(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasTestSnapshot()
	snapshot.Peers[0].Alias.Role = AliasProvider
	second := secondAliasPeer(snapshot)
	second.Alias.Role = AliasProvider
	second.Alias.SelfIPv4, second.Alias.SelfIPv6 = snapshot.Peers[0].Alias.SelfIPv4, snapshot.Peers[0].Alias.SelfIPv6
	snapshot.Peers = append(snapshot.Peers, second)
	pruned, dropped := WithoutUnusableAliases(snapshot, now)
	if dropped != 1 || !slices.Equal(peerIDs(pruned), []uint64{2}) {
		t.Fatalf("dropped %d, peers %v", dropped, peerIDs(pruned))
	}
}

// What only Core's mistake can produce still refuses the whole map: a
// binding on Self, more alias peers than a map may hold.
func TestWithoutUnusableAliasesLeavesWholeMapFaults(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasTestSnapshot()
	pruned, dropped := WithoutUnusableAliases(snapshot, now)
	if dropped != 0 || len(pruned.Peers) != 1 {
		t.Fatalf("a usable map lost %d peers", dropped)
	}
	snapshot.Self.Alias = snapshot.Peers[0].Alias
	pruned, dropped = WithoutUnusableAliases(snapshot, now)
	if dropped != 0 {
		t.Fatalf("dropped %d with a Self binding", dropped)
	}
	if _, err := ValidateAndClone(pruned, now); err == nil {
		t.Fatal("a Self binding validated")
	}
}

// Providers of one endpoint share a local alias and both stay; a peer whose
// IPv6 alias collides is left out and its IPv4 alias stays free for a later
// one.
func TestWithoutUnusableAliasesKeepsSharedEndpointsAndFreesClaims(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasTestSnapshot()
	snapshot.Peers[0].Alias.Role = AliasProvider
	same := secondAliasPeer(snapshot)
	same.Alias.EndpointID = snapshot.Peers[0].Alias.EndpointID
	same.Alias.SelfIPv4, same.Alias.SelfIPv6 = snapshot.Peers[0].Alias.SelfIPv4, snapshot.Peers[0].Alias.SelfIPv6
	snapshot.Peers = append(snapshot.Peers, same)
	if pruned, dropped := WithoutUnusableAliases(snapshot, now); dropped != 0 || len(pruned.Peers) != 2 {
		t.Fatalf("one endpoint's providers: dropped %d", dropped)
	}

	snapshot, now = aliasTestSnapshot()
	colliding := secondAliasPeer(snapshot)
	colliding.Alias.SelfIPv6 = snapshot.Peers[0].Alias.SelfIPv6 // the first peer's
	later := secondAliasPeer(snapshot)
	later.ID, later.StableID, later.PublicKey = 5, "provider-5", "nodekey:"+strings.Repeat("55", 32)
	later.Alias.PeerKey = later.PublicKey
	later.Alias.EndpointID = "00000000-0000-4000-8000-000000000005"
	later.Addresses = []netip.Prefix{netip.MustParsePrefix("100.96.0.5/32"), netip.MustParsePrefix("fd00:2::5/128")}
	later.AllowedIPs = append([]netip.Prefix{}, later.Addresses...)
	later.Alias.SelfIPv6 = netip.MustParseAddr("fd00:2::6") // its IPv4 alias is the colliding peer's
	snapshot.Peers = append(snapshot.Peers, colliding, later)
	pruned, dropped := WithoutUnusableAliases(snapshot, now)
	if dropped != 1 || !slices.Equal(peerIDs(pruned), []uint64{2, 5}) {
		t.Fatalf("dropped %d, peers %v", dropped, peerIDs(pruned))
	}
	if _, err := ValidateAndClone(pruned, now); err != nil {
		t.Fatal(err)
	}
}
