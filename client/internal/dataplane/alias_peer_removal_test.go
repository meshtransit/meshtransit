package dataplane

import (
	"crypto/ecdh"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

// A Device that holds a shared-Device alias keeps its data plane when a later
// map removes another, ordinary peer (a rule or group membership ended).
func TestAliasConsumerSurvivesOrdinaryPeerRemoval(t *testing.T) {
	t.Parallel()
	privateKey, original := testWireGuardSnapshot(t)
	snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
	snapshot.Self.PublicKey = original.Self.PublicKey
	snapshot.Peers[0].PublicKey = original.Peers[0].PublicKey
	snapshot.Peers[0].Endpoints = append([]netip.AddrPort{}, original.Peers[0].Endpoints...)
	snapshot.Peers[0].Alias.SelfKey = snapshot.Self.PublicKey
	snapshot.Peers[0].Alias.PeerKey = snapshot.Peers[0].PublicKey

	ordinary := ordinaryPeer(t, now)
	snapshot.Peers = append(snapshot.Peers, ordinary)

	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	engine.clock = func() time.Time { return now }
	engine.filter.clock = engine.clock
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state == StateFailed {
		t.Fatalf("initial Apply() = %q, %v", state, err)
	}

	removed := snapshot
	removed.Revision++
	removed.Peers = append([]networkmap.Node{}, snapshot.Peers[:1]...)
	state, err := engine.Apply(t.Context(), removed, privateKey)
	if err != nil || state == StateFailed {
		t.Fatalf("Apply() after removing an ordinary peer = %q, %v", state, err)
	}
	if device.closeCalls != 0 || engine.device == nil {
		t.Fatalf("data plane closed: close=%d device=%v", device.closeCalls, engine.device != nil)
	}
}

// hexKey is a map's "nodekey:" public key as WireGuard's configuration
// writes it.
func hexKey(t *testing.T, key string) string {
	t.Helper()
	encoded, found := strings.CutPrefix(key, "nodekey:")
	if !found {
		t.Fatalf("key %q", key)
	}
	return encoded
}

func ordinaryPeer(t *testing.T, now time.Time) networkmap.Node {
	t.Helper()
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(index + 65)
	}
	key, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	address4 := netip.MustParsePrefix("100.64.10.7/32")
	address6 := netip.MustParsePrefix("fd00:1::7/128")
	return networkmap.Node{
		ID: 3, StableID: "peer-3", Name: "ordinary.example.test",
		PublicKey:         "nodekey:" + hex.EncodeToString(key.PublicKey().Bytes()),
		MachineAuthorized: true, KeyExpiry: now.Add(time.Hour),
		Addresses:  []netip.Prefix{address4, address6},
		AllowedIPs: []netip.Prefix{address4, address6},
		Endpoints:  []netip.AddrPort{netip.MustParseAddrPort("203.0.113.30:41641")},
	}
}

// An alias that ends between two applies of a map (the phone slept, the
// clock moved on) leaves out its peer only: the data plane and every other
// peer stay up, and the alias admits no more packets.
func TestExpiredAliasLeavesOutItsPeerOnly(t *testing.T) {
	t.Parallel()
	privateKey, original := testWireGuardSnapshot(t)
	snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
	snapshot.Self.PublicKey = original.Self.PublicKey
	snapshot.Peers[0].PublicKey = original.Peers[0].PublicKey
	snapshot.Peers[0].Endpoints = append([]netip.AddrPort{}, original.Peers[0].Endpoints...)
	snapshot.Peers[0].Alias.SelfKey = snapshot.Self.PublicKey
	snapshot.Peers[0].Alias.PeerKey = snapshot.Peers[0].PublicKey
	snapshot.Peers = append(snapshot.Peers, ordinaryPeer(t, now))

	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(&wireGuardTUNOpener{}, 41641, &fakeWireGuardFactory{device: device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	clock := now
	engine.clock = func() time.Time { return clock }
	engine.filter.clock = engine.clock
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state == StateFailed {
		t.Fatalf("initial Apply() = %q, %v", state, err)
	}
	vector := aliasRoundtripVectors(t)[0]
	assertAliasPacket(t, engine.filter, PacketOutbound, aliasPacket(t, vector.ConsumerKernel), vector.ConsumerWire)

	clock = now.Add(2 * time.Minute) // past the alias's deadline
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state == StateFailed {
		t.Fatalf("Apply() with an expired alias = %q, %v", state, err)
	}
	if device.closeCalls != 0 || engine.device == nil {
		t.Fatalf("data plane closed: close=%d device=%v", device.closeCalls, engine.device != nil)
	}
	if engine.filter.ProcessPacket(PacketOutbound, aliasPacket(t, vector.ConsumerKernel)) {
		t.Fatal("an expired alias still admits packets")
	}
	// WireGuard removes the alias peer and leaves the ordinary one as it is.
	aliasKey := hexKey(t, snapshot.Peers[0].PublicKey)
	ordinaryKey := hexKey(t, snapshot.Peers[1].PublicKey)
	if !strings.Contains(device.configuration, "public_key="+aliasKey+"\nremove=true") ||
		strings.Contains(device.configuration, ordinaryKey) {
		t.Fatalf("configuration after expiry:\n%s", device.configuration)
	}
	engine.filter.mu.Lock()
	_, ordinaryKept := engine.filter.peers[netip.MustParseAddr("100.64.10.7")]
	_, aliasKept := engine.filter.aliases[snapshot.Peers[0].Addresses[0].Addr()]
	engine.filter.mu.Unlock()
	if !ordinaryKept || aliasKept {
		t.Fatalf("ordinary peer kept %t, alias kept %t", ordinaryKept, aliasKept)
	}
}
