package dataplane

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/networkmap"
	"github.com/meshtransit/meshtransit/client/internal/packetmeta"
)

type aliasRoundtripVector struct {
	Name                  string `json:"name"`
	ProviderBareSYN       string `json:"provider_bare_syn"`
	ConsumerBareSYN       string `json:"consumer_bare_syn"`
	ConsumerKernel        string `json:"consumer_kernel"`
	ConsumerWire          string `json:"consumer_wire"`
	ProviderKernel        string `json:"provider_kernel"`
	ProviderReply         string `json:"provider_reply"`
	ProviderWire          string `json:"provider_wire"`
	ConsumerReply         string `json:"consumer_reply"`
	DeniedConsumerKernel  string `json:"denied_consumer_kernel"`
	SpoofedConsumerKernel string `json:"spoofed_consumer_kernel"`
	ReverseProviderKernel string `json:"reverse_provider_kernel"`
	ReverseConsumerWire   string `json:"reverse_consumer_wire"`
}

func aliasRoundtripVectors(t *testing.T) []aliasRoundtripVector {
	t.Helper()
	content, err := os.ReadFile("testdata/alias_roundtrips_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int                    `json:"version"`
		Cases   []aliasRoundtripVector `json:"cases"`
	}
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Cases) != 6 {
		t.Fatal("invalid packet fixture")
	}
	return fixture.Cases
}

func aliasPacket(t testing.TB, value string) []byte {
	t.Helper()
	packet, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func aliasPolicySnapshot(role networkmap.AliasRole) (networkmap.Snapshot, time.Time) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	selfKey, peerKey := "nodekey:"+strings.Repeat("11", 32), "nodekey:"+strings.Repeat("22", 32)
	local4, local6 := netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("fd00:2::2")
	peer4, peer6 := netip.MustParsePrefix("100.96.0.1/32"), netip.MustParsePrefix("fd00:2::1/128")
	if role == networkmap.AliasProvider {
		selfKey, peerKey = peerKey, selfKey
		local4, local6 = peer4.Addr(), peer6.Addr()
		peer4, peer6 = netip.MustParsePrefix("100.96.0.2/32"), netip.MustParsePrefix("fd00:2::2/128")
	}
	self := networkmap.Node{
		ID: 1, StableID: "self-1", Name: "self.example.test",
		PublicKey: selfKey, MachineAuthorized: true, KeyExpiry: now.Add(time.Hour),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.10.1/32"), netip.MustParsePrefix("fd00:1::1/128")},
	}
	self.AllowedIPs = append([]netip.Prefix{}, self.Addresses...)
	peer := networkmap.Node{
		ID: 2, StableID: "peer-2", Name: "peer.example.test",
		PublicKey: peerKey, MachineAuthorized: true, KeyExpiry: now.Add(time.Hour),
		Addresses: []netip.Prefix{peer4, peer6},
	}
	peer.AllowedIPs = append([]netip.Prefix{}, peer.Addresses...)
	peer.Alias = &networkmap.AliasBinding{
		ContractID: "00000000-0000-4000-8000-000000000001", EndpointID: "00000000-0000-4000-8000-000000000002",
		Generation: 3, GrantRevision: 4, RecoveryEpoch: 1, Role: role, SelfKey: selfKey, PeerKey: peerKey,
		SelfIPv4: local4, SelfIPv6: local6, ExpiresAt: now.Add(time.Minute),
		Services: []networkmap.AliasService{
			{Protocol: 1},
			{Protocol: 6, PortFrom: 443, PortTo: 443},
			{Protocol: 17, PortFrom: 53, PortTo: 53},
			{Protocol: 58},
		},
	}
	policy := []networkmap.Rule{{
		Sources:      []networkmap.Selector{{Kind: networkmap.SelectorAny}},
		Destinations: []networkmap.Destination{{Selector: networkmap.Selector{Kind: networkmap.SelectorAny}, PortTo: 65535}},
	}}
	return networkmap.Snapshot{Revision: 1, Self: self, Peers: []networkmap.Node{peer}, Policy: policy}, now
}

func newAliasFilter(t *testing.T, role networkmap.AliasRole) *policyFilter {
	t.Helper()
	snapshot, now := aliasPolicySnapshot(role)
	if _, err := networkmap.ValidateAndClone(snapshot, now); err != nil {
		t.Fatal(err)
	}
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.UpdateNetwork(snapshot)
	return filter
}

func assertAliasPacket(t *testing.T, filter *policyFilter, direction PacketDirection, packet []byte, expected string) {
	t.Helper()
	if !filter.ProcessPacket(direction, packet) {
		t.Fatal("authorized packet denied")
	}
	if !bytes.Equal(packet, aliasPacket(t, expected)) {
		t.Fatalf("packet=%x, want=%s", packet, expected)
	}
	if _, err := packetmeta.CheckAliasPacket(packet); err != nil {
		t.Fatal(err)
	}
}

func TestAliasPacketRoundtripWithOverlappingCanonicalAddresses(t *testing.T) {
	t.Parallel()
	for _, vector := range aliasRoundtripVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			consumer, provider := newAliasFilter(t, networkmap.AliasConsumer), newAliasFilter(t, networkmap.AliasProvider)
			request := aliasPacket(t, vector.ConsumerKernel)
			assertAliasPacket(t, consumer, PacketOutbound, request, vector.ConsumerWire)
			assertAliasPacket(t, provider, PacketInbound, request, vector.ProviderKernel)
			reply := aliasPacket(t, vector.ProviderReply)
			assertAliasPacket(t, provider, PacketOutbound, reply, vector.ProviderWire)
			assertAliasPacket(t, consumer, PacketInbound, reply, vector.ConsumerReply)
		})
	}
}

func TestAliasPacketRejectsSpoofingRawAddressesAndReverseInitiation(t *testing.T) {
	t.Parallel()
	for _, vector := range aliasRoundtripVectors(t) {
		for _, test := range []struct {
			name      string
			role      networkmap.AliasRole
			direction PacketDirection
			packet    string
		}{
			{"adjacent port or icmp error", networkmap.AliasConsumer, PacketOutbound, vector.DeniedConsumerKernel},
			{"spoofed source", networkmap.AliasConsumer, PacketOutbound, vector.SpoofedConsumerKernel},
			{"provider raw destination", networkmap.AliasProvider, PacketInbound, vector.ProviderKernel},
			{"consumer raw destination", networkmap.AliasConsumer, PacketInbound, vector.ConsumerReply},
			{"provider reverse initiation", networkmap.AliasProvider, PacketOutbound, vector.ReverseProviderKernel},
			{"consumer unsolicited inbound", networkmap.AliasConsumer, PacketInbound, vector.ReverseConsumerWire},
		} {
			t.Run(vector.Name+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				filter := newAliasFilter(t, test.role)
				packet := aliasPacket(t, test.packet)
				before := bytes.Clone(packet)
				if filter.ProcessPacket(test.direction, packet) {
					t.Fatal("unsafe alias packet accepted")
				}
				if !bytes.Equal(packet, before) {
					t.Fatal("rejected packet was mutated")
				}
			})
		}
	}
}

func TestAliasPacketCannotBypassEmptyProviderPolicy(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasPolicySnapshot(networkmap.AliasProvider)
	snapshot.Policy = nil
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.UpdateNetwork(snapshot)
	vector := aliasRoundtripVectors(t)[0]
	if filter.ProcessPacket(PacketInbound, aliasPacket(t, vector.ConsumerWire)) {
		t.Fatal("grant bypassed empty policy")
	}
	if filter.ProcessPacket(PacketOutbound, aliasPacket(t, vector.ProviderReply)) {
		t.Fatal("denied request opened reply state")
	}
}

func TestAliasPacketExpiryAndAuthorityReplacementRemoveTrackedFlows(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"expiry", "revoke", "policy", "downgrade", "generation"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
			filter := newPolicyFilter()
			filter.clock = func() time.Time { return now }
			filter.UpdateNetwork(snapshot)
			vector := aliasRoundtripVectors(t)[0]
			assertAliasPacket(t, filter, PacketOutbound, aliasPacket(t, vector.ConsumerKernel), vector.ConsumerWire)
			switch name {
			case "expiry":
				now = snapshot.Peers[0].Alias.ExpiresAt
			case "revoke":
				snapshot.Peers = []networkmap.Node{}
				filter.UpdateNetwork(snapshot)
			case "policy":
				snapshot.Peers[0].Alias.GrantRevision++
				snapshot.Peers[0].Alias.Services = []networkmap.AliasService{{Protocol: 6, PortFrom: 443, PortTo: 443}}
				filter.UpdateNetwork(snapshot)
			case "downgrade":
				snapshot.Peers[0].Alias = nil
				filter.UpdateNetwork(snapshot)
			case "generation":
				snapshot.Peers[0].Alias.Generation++
				snapshot.Peers[0].Alias.GrantRevision++
				filter.UpdateNetwork(snapshot)
			}
			packet := aliasPacket(t, vector.ProviderWire)
			if filter.ProcessPacket(PacketInbound, packet) {
				t.Fatal("old flow survived authority replacement")
			}
		})
	}
}

func TestAliasPacketEndpointUpdatePreservesOnlyCurrentFlow(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.UpdateNetwork(snapshot)
	vector := aliasRoundtripVectors(t)[0]
	assertAliasPacket(t, filter, PacketOutbound, aliasPacket(t, vector.ConsumerKernel), vector.ConsumerWire)
	snapshot.Peers[0].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")}
	filter.UpdateNetwork(snapshot)
	assertAliasPacket(t, filter, PacketInbound, aliasPacket(t, vector.ProviderWire), vector.ConsumerReply)
	filter.suspendFor(snapshot)
	if filter.ProcessPacket(PacketInbound, aliasPacket(t, vector.ProviderWire)) {
		t.Fatal("packet admitted during transition")
	}
	filter.resume()
	assertAliasPacket(t, filter, PacketInbound, aliasPacket(t, vector.ProviderWire), vector.ConsumerReply)
}

func TestAliasObservedTUNTranslatesBothBoundaries(t *testing.T) {
	t.Parallel()
	vector := aliasRoundtripVectors(t)[0]
	device := &batchTUNDevice{readPackets: [][]byte{aliasPacket(t, vector.ConsumerKernel)}}
	wrapped := &observedTUN{Device: device, filter: newAliasFilter(t, networkmap.AliasConsumer)}
	buffers := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	count, err := wrapped.Read(buffers, sizes, 4)
	if err != nil || count != 1 || !bytes.Equal(buffers[0][4:4+sizes[0]], aliasPacket(t, vector.ConsumerWire)) {
		t.Fatalf("outbound alias TUN: %d %v", count, err)
	}
	count, err = wrapped.Write([][]byte{aliasPacket(t, vector.ProviderWire)}, 0)
	if err != nil || count != 1 || len(device.writtenPackets) != 1 || !bytes.Equal(device.writtenPackets[0], aliasPacket(t, vector.ConsumerReply)) {
		t.Fatalf("inbound alias TUN: %d %v", count, err)
	}
}

func TestAliasConcurrentReplacementNeverMixesBindings(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.UpdateNetwork(snapshot)
	vector := aliasRoundtripVectors(t)[0]
	var workers sync.WaitGroup
	workers.Go(func() {
		for index := range 100 {
			next := snapshot
			peer := snapshot.Peers[0]
			binding := *peer.Alias
			binding.Generation += uint64(index) + 1
			binding.GrantRevision += uint64(index) + 1
			if index%2 == 0 {
				binding.SelfIPv4 = netip.MustParseAddr("100.96.0.4")
				peer.Addresses = []netip.Prefix{netip.MustParsePrefix("100.96.0.3/32"), peer.Addresses[1]}
				peer.AllowedIPs = append([]netip.Prefix{}, peer.Addresses...)
			}
			peer.Alias = &binding
			next.Peers = []networkmap.Node{peer}
			filter.UpdateNetwork(next)
		}
	})
	for range 100 {
		for _, pair := range []struct{ target, source netip.Addr }{
			{netip.MustParseAddr("100.96.0.1"), netip.MustParseAddr("100.96.0.2")},
			{netip.MustParseAddr("100.96.0.3"), netip.MustParseAddr("100.96.0.4")},
		} {
			packet := aliasPacket(t, vector.ConsumerKernel)
			original := packetmeta.AddressPair{Source: netip.MustParseAddr("100.64.10.1"), Destination: netip.MustParseAddr("100.96.0.1")}
			if err := packetmeta.RewriteAddresses(packet, original, packetmeta.AddressPair{Source: original.Source, Destination: pair.target}); err != nil {
				t.Error(err)
				continue
			}
			if filter.ProcessPacket(PacketOutbound, packet) {
				header, err := packetmeta.CheckAliasPacket(packet)
				if err != nil || header.Source != pair.source || header.Destination != pair.target {
					t.Errorf("mixed binding: %v %v", header, err)
				}
			}
		}
	}
	workers.Wait()
}

func TestAliasFlowCapacityDeniesBeforeDelivery(t *testing.T) {
	t.Parallel()
	vectors := aliasRoundtripVectors(t)
	for _, role := range []networkmap.AliasRole{networkmap.AliasConsumer, networkmap.AliasProvider} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			filter := newAliasFilter(t, role)
			filter.maximumFlows = 1
			direction, first, second := PacketOutbound, vectors[0].ConsumerKernel, vectors[1].ConsumerKernel
			if role == networkmap.AliasProvider {
				direction, first, second = PacketInbound, vectors[0].ConsumerWire, vectors[1].ConsumerWire
			}
			if !filter.ProcessPacket(direction, aliasPacket(t, first)) {
				t.Fatal("first flow denied")
			}
			packet := aliasPacket(t, second)
			before := bytes.Clone(packet)
			if filter.ProcessPacket(direction, packet) || !bytes.Equal(before, packet) {
				t.Fatal("capacity overflow admitted or mutated a new flow")
			}
		})
	}
}

func TestAliasBareSYNIsNotAReplyOnAnExistingTuple(t *testing.T) {
	t.Parallel()
	for _, vector := range aliasRoundtripVectors(t) {
		if !strings.HasSuffix(vector.Name, "tcp") {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			consumer, provider := newAliasFilter(t, networkmap.AliasConsumer), newAliasFilter(t, networkmap.AliasProvider)
			request := aliasPacket(t, vector.ConsumerKernel)
			assertAliasPacket(t, consumer, PacketOutbound, request, vector.ConsumerWire)
			assertAliasPacket(t, provider, PacketInbound, request, vector.ProviderKernel)
			if provider.ProcessPacket(PacketOutbound, aliasPacket(t, vector.ProviderBareSYN)) ||
				consumer.ProcessPacket(PacketInbound, aliasPacket(t, vector.ConsumerBareSYN)) {
				t.Fatal("bare SYN bypassed directed initiation")
			}
		})
	}
}
