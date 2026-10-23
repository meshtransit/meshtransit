package dataplane

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
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

// Core sending an older grant than one already used leaves out that peer
// in Apply too: the data plane and every other peer stay up.
func TestApplyLeavesOutARegressedAliasPeer(t *testing.T) {
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
	engine.clock = func() time.Time { return now }
	engine.filter.clock = engine.clock
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state == StateFailed {
		t.Fatalf("initial Apply() = %q, %v", state, err)
	}

	older := snapshot
	older.Revision++
	older.Peers = append([]networkmap.Node{}, snapshot.Peers...)
	binding := *snapshot.Peers[0].Alias
	binding.GrantRevision--
	older.Peers[0].Alias = &binding
	state, err := engine.Apply(t.Context(), older, privateKey)
	if err != nil || state == StateFailed {
		t.Fatalf("Apply() with an older grant = %q, %v", state, err)
	}
	if device.closeCalls != 0 || engine.device == nil {
		t.Fatalf("data plane closed: close=%d device=%v", device.closeCalls, engine.device != nil)
	}
	aliasKey := hexKey(t, snapshot.Peers[0].PublicKey)
	if !strings.Contains(device.configuration, "public_key="+aliasKey+"\nremove=true") {
		t.Fatalf("configuration after an older grant:\n%s", device.configuration)
	}
	engine.filter.mu.Lock()
	_, ordinaryKept := engine.filter.peers[netip.MustParseAddr("100.64.10.7")]
	_, aliasKept := engine.filter.aliases[snapshot.Peers[0].Addresses[0].Addr()]
	engine.filter.mu.Unlock()
	if !ordinaryKept || aliasKept {
		t.Fatalf("ordinary peer kept %t, alias kept %t", ordinaryKept, aliasKept)
	}
}

// The fence against an older grant of one endpoint outlives the peer: after
// an empty map, or once the alias was left out as expired, a map that brings
// that endpoint back with an older or altered grant leaves out that peer
// only, while a newer grant, a new key of this node, or a new contract after
// a reset are accepted.
func TestAliasGrantFenceOutlivesThePeer(t *testing.T) {
	t.Parallel()
	alter := func(change func(*networkmap.Snapshot, *networkmap.AliasBinding)) func(networkmap.Snapshot) networkmap.Snapshot {
		return func(snapshot networkmap.Snapshot) networkmap.Snapshot {
			snapshot.Peers = append([]networkmap.Node{}, snapshot.Peers...)
			binding := *snapshot.Peers[0].Alias
			binding.Services = slices.Clone(binding.Services)
			change(&snapshot, &binding)
			snapshot.Peers[0].Alias = &binding
			return snapshot
		}
	}
	cases := []struct {
		name     string
		next     func(networkmap.Snapshot) networkmap.Snapshot
		accepted bool
	}{
		{"older grant", alter(func(_ *networkmap.Snapshot, b *networkmap.AliasBinding) { b.GrantRevision-- }), false},
		{"same grant, other services", alter(func(_ *networkmap.Snapshot, b *networkmap.AliasBinding) {
			b.Services = b.Services[:1]
		}), false},
		{"newer grant", alter(func(_ *networkmap.Snapshot, b *networkmap.AliasBinding) { b.GrantRevision++ }), true},
		{"same grant", alter(func(*networkmap.Snapshot, *networkmap.AliasBinding) {}), true},
		{"new key of this node", alter(func(s *networkmap.Snapshot, b *networkmap.AliasBinding) {
			s.Self.PublicKey = "nodekey:" + strings.Repeat("33", 32)
			b.SelfKey = s.Self.PublicKey
			b.SelfIPv4 = netip.MustParseAddr("100.96.0.3")
		}), true},
		{"new contract after a reset", alter(func(_ *networkmap.Snapshot, b *networkmap.AliasBinding) {
			b.ContractID = "00000000-0000-4000-8000-000000000009"
			b.Generation, b.GrantRevision = 1, 1
		}), true},
	}
	for _, gap := range []string{"empty map", "pruned"} {
		for _, test := range cases {
			t.Run(gap+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
				snapshot.Peers = append(snapshot.Peers, ordinaryPeer(t, now))
				clock := now
				filter := newPolicyFilter()
				filter.clock = func() time.Time { return clock }
				filter.UpdateNetwork(snapshot)
				switch gap {
				case "empty map":
					filter.UpdateNetwork(networkmap.Snapshot{})
				case "pruned":
					clock = snapshot.Peers[0].Alias.ExpiresAt.Add(time.Second)
					filter.UpdateNetwork(snapshot)
					clock = now
				}
				next := test.next(snapshot)
				filter.UpdateNetwork(next)
				filter.mu.Lock()
				_, aliasKept := filter.aliases[next.Peers[0].Addresses[0].Addr()]
				_, ordinaryKept := filter.peers[netip.MustParseAddr("100.64.10.7")]
				filter.mu.Unlock()
				if aliasKept != test.accepted || !ordinaryKept {
					t.Fatalf("alias kept %t, want %t; ordinary peer kept %t", aliasKept, test.accepted, ordinaryKept)
				}
			})
		}
	}
}

// A refused map records no marks, and past the bound expired marks go
// first, then those ending soonest, never the current map's, until a tenth
// of the room is free.
func TestAliasMarksBound(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	refused := snapshot
	refused.Self.Alias = snapshot.Peers[0].Alias
	filter.UpdateNetwork(refused)
	if len(filter.aliasMarks) != 0 {
		t.Fatalf("a refused map left %d marks", len(filter.aliasMarks))
	}

	filter.aliasMarkLimit = 2
	mark := func(contract string, expiresAt time.Time) aliasGrantKey {
		binding := *snapshot.Peers[0].Alias
		binding.ContractID = contract
		key := aliasGrantKeyOf(binding)
		filter.aliasMarks[key] = aliasMark{expiresAt: expiresAt}
		return key
	}
	expired := mark("expired", now.Add(-time.Second))
	soon := mark("soon", now.Add(time.Second))
	later := mark("later", now.Add(time.Hour))
	filter.UpdateNetwork(snapshot)
	current := aliasGrantKeyOf(*snapshot.Peers[0].Alias)
	for key, want := range map[aliasGrantKey]bool{expired: false, soon: false, later: true, current: true} {
		if _, kept := filter.aliasMarks[key]; kept != want {
			t.Errorf("mark %x kept %t, want %t", key[:4], kept, want)
		}
	}

	filter.aliasMarkLimit = 10
	for index := range 10 {
		mark(fmt.Sprintf("contract-%d", index), now.Add(time.Duration(index+1)*time.Hour))
	}
	filter.UpdateNetwork(snapshot)
	if _, kept := filter.aliasMarks[current]; len(filter.aliasMarks) != 9 || !kept {
		t.Fatalf("%d marks after eviction (want 9), current kept %t", len(filter.aliasMarks), kept)
	}
}
