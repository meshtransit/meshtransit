package dataplane

import (
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
)

func TestPolicyFilterEnforcesExclusivePeerDeadlineWithoutMapUpdate(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	now := start
	snapshot := testPolicySnapshot()
	snapshot.Self.KeyExpiry = start.Add(time.Hour)
	snapshot.Peers[0].KeyExpiry = start.Add(time.Second)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.UpdateNetwork(snapshot)
	inbound := testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 42000, 18080, packetmeta.ProtocolTCP, 0x02)
	outbound := testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 42000, 18080, packetmeta.ProtocolTCP, 0x02)
	if !filter.Allow(PacketInbound, inbound) || !filter.Allow(PacketOutbound, outbound) {
		t.Fatal("live peer denied")
	}
	now = snapshot.Peers[0].KeyExpiry
	if filter.Allow(PacketInbound, inbound) || filter.Allow(PacketOutbound, outbound) {
		t.Fatal("peer accepted at exclusive deadline")
	}
	now = now.Add(time.Minute)
	if filter.Allow(PacketInbound, inbound) || filter.Allow(PacketOutbound, outbound) {
		t.Fatal("silent stream extended peer authority")
	}
}

func TestPolicyFilterExpiredPeerCannotUseTrackedReply(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	now := start
	snapshot := testPolicySnapshot()
	snapshot.Policy = nil
	snapshot.Peers[0].KeyExpiry = start.Add(time.Second)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.UpdateNetwork(snapshot)
	outbound := testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 42000, 18080, packetmeta.ProtocolTCP, 0x02)
	reply := testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 18080, 42000, packetmeta.ProtocolTCP, 0x12)
	if !filter.Allow(PacketOutbound, outbound) || !filter.Allow(PacketInbound, reply) {
		t.Fatal("live tracked reply denied")
	}
	now = snapshot.Peers[0].KeyExpiry
	if filter.Allow(PacketInbound, reply) {
		t.Fatal("tracked flow bypassed peer deadline")
	}
	snapshot.Peers[0].KeyExpiry = now.Add(time.Minute)
	filter.UpdateNetwork(snapshot)
	if filter.Allow(PacketInbound, reply) {
		t.Fatal("extended authority resurrected old flow")
	}
	if !filter.Allow(PacketOutbound, outbound) || !filter.Allow(PacketInbound, reply) {
		t.Fatal("fresh flow denied after new authority")
	}
}

func TestPolicyFilterSelfAndExplicitPeerExpiryFailClosed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*networkmap.Snapshot)
	}{
		{"self deadline", func(s *networkmap.Snapshot) { s.Self.KeyExpiry = now }},
		{"explicit self expiry", func(s *networkmap.Snapshot) { s.Self.Expired = true }},
		{"explicit peer expiry", func(s *networkmap.Snapshot) { s.Peers[0].Expired = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := testPolicySnapshot()
			test.mutate(&snapshot)
			filter := newPolicyFilter()
			filter.clock = func() time.Time { return now }
			filter.UpdateNetwork(snapshot)
			packet := testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 42000, 18080, packetmeta.ProtocolTCP, 0x02)
			if filter.Allow(PacketInbound, packet) {
				t.Fatal("expired authority admitted packet")
			}
		})
	}
}

func TestPolicyFilterReplacedPeerIdentityDropsTrackedFlow(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*networkmap.Node)
	}{
		{"Device replacement", func(p *networkmap.Node) { p.ID++ }},
		{"Node key replacement", func(p *networkmap.Node) { p.PublicKey = "replacement-test-key" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := testPolicySnapshot()
			snapshot.Policy = nil
			snapshot.Peers[0].ID = 2
			snapshot.Peers[0].PublicKey = "original-test-key"
			filter := newPolicyFilter()
			filter.UpdateNetwork(snapshot)
			outbound := testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 42000, 18080, packetmeta.ProtocolTCP, 0x02)
			reply := testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 18080, 42000, packetmeta.ProtocolTCP, 0x12)
			if !filter.Allow(PacketOutbound, outbound) || !filter.Allow(PacketInbound, reply) {
				t.Fatal("initial flow denied")
			}
			test.mutate(&snapshot.Peers[0])
			filter.UpdateNetwork(snapshot)
			if filter.Allow(PacketInbound, reply) {
				t.Fatal("old tracked flow transferred to replaced peer")
			}
		})
	}
}
