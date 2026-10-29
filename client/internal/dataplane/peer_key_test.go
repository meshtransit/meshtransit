package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// An address's key is the installed peer's that holds it as a
// single-address allowed IP; a covering prefix names no one; an address two
// peers claim is no one's; a peer removed is gone at once.
func TestPeerKeyAt(t *testing.T) {
	t.Parallel()
	engine := &WireGuardEngine{}
	if _, found := engine.PeerKeyAt(netip.MustParseAddr("100.64.0.10")); found {
		t.Fatal("a key before any configuration")
	}
	engine.peers = map[uint64]wireGuardPeerState{
		1: {key: [32]byte{1}, allowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")}},
		2: {key: [32]byte{2}, allowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")}},
		3: {key: [32]byte{3}, allowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.20/32")}},
		4: {key: [32]byte{4}, allowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.20/32")}},
	}
	engine.publishAddressKeys()
	if key, found := engine.PeerKeyAt(netip.MustParseAddr("::ffff:100.64.0.10")); !found || key != [32]byte{2} {
		t.Fatalf("single address: %x, %t", key, found)
	}
	for _, address := range []string{"100.64.0.11", "100.64.0.20", "100.65.0.1"} {
		if _, found := engine.PeerKeyAt(netip.MustParseAddr(address)); found {
			t.Fatalf("%s: a key", address)
		}
	}
	engine.addressKeys.remove(4, engine.peers[4])
	if key, found := engine.PeerKeyAt(netip.MustParseAddr("100.64.0.20")); !found || key != [32]byte{3} {
		t.Fatalf("one claimant left: %x, %t", key, found)
	}

	// Before a plan is configured, an address whose holder changes is no
	// one's; one that stays keeps its key (re-review b5a M-1).
	engine.withholdChangedAddresses([]wireGuardPeerPlan{
		{id: 2, key: [32]byte{5}, allowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")}},
		{id: 3, key: [32]byte{3}, allowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.20/32")}},
	})
	if _, found := engine.PeerKeyAt(netip.MustParseAddr("100.64.0.10")); found {
		t.Fatal("an address changing hands kept its key")
	}
	if key, found := engine.PeerKeyAt(netip.MustParseAddr("100.64.0.20")); !found || key != [32]byte{3} {
		t.Fatalf("an unchanged peer: %x, %t", key, found)
	}
}

// With lazy peers the index follows what wireguard-go holds: a peer
// installed on demand after Apply is found, an evicted one is not
// (re-review b5a H).
func TestPeerKeyAtFollowsLazyPeers(t *testing.T) {
	t.Parallel()
	engine, _, clock, privateKey, snapshot := newLazyTestEngine(t, 0, 2)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	address := snapshot.Peers[0].Addresses[0].Addr()
	if _, found := engine.PeerKeyAt(address); found {
		t.Fatal("a key for a peer not installed")
	}
	self := snapshot.Self.Addresses[0].Addr()
	engine.lazy.outbound(tuntest.Ping(address, self))
	if key, found := engine.PeerKeyAt(address); !found || key != peerKeyOf(t, snapshot.Peers[0]) {
		t.Fatalf("installed on demand: %x, %t", key, found)
	}
	if _, found := engine.PeerKeyAt(snapshot.Peers[1].Addresses[0].Addr()); found {
		t.Fatal("a key for the other peer, never installed")
	}

	clock.Advance(lazyIdleTimeout + time.Second)
	engine.evictIdleLazyPeers(clock.Now())
	if _, found := engine.PeerKeyAt(address); found {
		t.Fatal("an evicted peer kept its address")
	}
}
