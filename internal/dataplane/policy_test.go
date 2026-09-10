package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/packetmeta"
)

func TestPolicyFilterEnforcesInboundProtocolAndPort(t *testing.T) {
	t.Parallel()

	filter := newPolicyFilter()
	filter.UpdateNetwork(testPolicySnapshot())

	tests := []struct {
		name      string
		packet    []byte
		direction PacketDirection
		allowed   bool
	}{
		{
			name:      "allowed inbound tcp port",
			packet:    testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 42000, 18080, packetmeta.ProtocolTCP, 0x02),
			direction: PacketInbound,
			allowed:   true,
		},
		{
			name:      "denied inbound tcp port",
			packet:    testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 42000, 18081, packetmeta.ProtocolTCP, 0x02),
			direction: PacketInbound,
		},
		{
			name:      "denied inbound udp protocol",
			packet:    testIPv4TransportPacket([4]byte{100, 64, 0, 4}, [4]byte{100, 64, 0, 3}, 42000, 18080, packetmeta.ProtocolUDP, 0),
			direction: PacketInbound,
		},
		{
			name:      "denied spoofed outbound source",
			packet:    testIPv4TransportPacket([4]byte{100, 64, 0, 9}, [4]byte{100, 64, 0, 4}, 42000, 18080, packetmeta.ProtocolTCP, 0x02),
			direction: PacketOutbound,
		},
		{
			name:      "allowed outbound to signed peer",
			packet:    testIPv4TransportPacket([4]byte{100, 64, 0, 3}, [4]byte{100, 64, 0, 4}, 42000, 18080, packetmeta.ProtocolTCP, 0x02),
			direction: PacketOutbound,
			allowed:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if allowed := filter.Allow(test.direction, test.packet); allowed != test.allowed {
				t.Fatalf("Allow() = %t, want %t", allowed, test.allowed)
			}
		})
	}
}

func TestPolicyFilterAllowsReplyToOutboundFlow(t *testing.T) {
	t.Parallel()

	filter := newPolicyFilter()
	snapshot := testPolicySnapshot()
	snapshot.Policy = []networkmap.Rule{}
	filter.UpdateNetwork(snapshot)
	outbound := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 3},
		[4]byte{100, 64, 0, 4},
		48326,
		18080,
		packetmeta.ProtocolTCP,
		0x02,
	)
	inboundReply := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 4},
		[4]byte{100, 64, 0, 3},
		18080,
		48326,
		packetmeta.ProtocolTCP,
		0x12,
	)
	if !filter.Allow(PacketOutbound, outbound) {
		t.Fatal("outbound SYN was denied")
	}
	if !filter.Allow(PacketInbound, inboundReply) {
		t.Fatal("inbound SYN-ACK for tracked flow was denied")
	}
	filter.UpdateNetwork(snapshot)
	if !filter.Allow(PacketInbound, inboundReply) {
		t.Fatal("unchanged map unexpectedly removed tracked flow")
	}
	snapshot.Policy = testPolicySnapshot().Policy
	filter.UpdateNetwork(snapshot)
	if filter.Allow(PacketInbound, inboundReply) {
		t.Fatal("policy update retained stale flow authorization")
	}
}

func TestPolicyFilterAllowsUDPAndICMPEchoReplies(t *testing.T) {
	t.Parallel()

	filter := newPolicyFilter()
	snapshot := testPolicySnapshot()
	snapshot.Policy = []networkmap.Rule{}
	filter.UpdateNetwork(snapshot)

	udpRequest := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 3},
		[4]byte{100, 64, 0, 4},
		48327,
		53,
		packetmeta.ProtocolUDP,
		0,
	)
	if !filter.Allow(PacketOutbound, udpRequest) ||
		!filter.Allow(PacketInbound, reverseTestPacket(udpRequest)) {
		t.Fatal("UDP request or reply was denied")
	}

	icmpRequest := testIPv4ICMPPacket(
		[4]byte{100, 64, 0, 3},
		[4]byte{100, 64, 0, 4},
		8,
		42,
	)
	icmpReply := testIPv4ICMPPacket(
		[4]byte{100, 64, 0, 4},
		[4]byte{100, 64, 0, 3},
		0,
		42,
	)
	if !filter.Allow(PacketOutbound, icmpRequest) || !filter.Allow(PacketInbound, icmpReply) {
		t.Fatal("ICMP echo request or reply was denied")
	}
	unsolicitedRequest := append([]byte{}, icmpReply...)
	unsolicitedRequest[20] = 8
	if filter.Allow(PacketInbound, unsolicitedRequest) {
		t.Fatal("tracked echo flow allowed an inbound echo request")
	}
}

func TestPolicyFilterAllowsICMPv6(t *testing.T) {
	t.Parallel()

	self := netip.MustParsePrefix("fd7a:115c:a1e0::f/128")
	peer := netip.MustParsePrefix("fd7a:115c:a1e0::5/128")
	snapshot := networkmap.Snapshot{
		Self:  networkmap.Node{Addresses: []netip.Prefix{self}},
		Peers: []networkmap.Node{{Addresses: []netip.Prefix{peer}}},
	}
	filter := newPolicyFilter()
	filter.UpdateNetwork(snapshot)
	outboundRequest := testIPv6ICMPPacket(self.Addr(), peer.Addr(), 128, 42)
	inboundReply := testIPv6ICMPPacket(peer.Addr(), self.Addr(), 129, 42)
	if !filter.Allow(PacketOutbound, outboundRequest) || !filter.Allow(PacketInbound, inboundReply) {
		t.Fatal("ICMPv6 echo request or reply was denied")
	}
	wrongIdentifier := testIPv6ICMPPacket(peer.Addr(), self.Addr(), 129, 43)
	if filter.Allow(PacketInbound, wrongIdentifier) {
		t.Fatal("untracked ICMPv6 echo reply was allowed")
	}

	snapshot.Policy = []networkmap.Rule{{
		Sources: []networkmap.Selector{{Kind: networkmap.SelectorPrefix, Prefix: peer}},
		Destinations: []networkmap.Destination{{
			Selector: networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: self},
			PortFrom: 0,
			PortTo:   65535,
		}},
		Protocols: []uint8{packetmeta.ProtocolICMPv6},
	}}
	filter.UpdateNetwork(snapshot)
	inboundRequest := testIPv6ICMPPacket(peer.Addr(), self.Addr(), 128, 42)
	if !filter.Allow(PacketInbound, inboundRequest) {
		t.Fatal("policy-authorized ICMPv6 echo request was denied")
	}
}

func TestPolicyFilterExpiresAndBoundsFlows(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	filter.maximumFlows = 1
	snapshot := testPolicySnapshot()
	snapshot.Policy = []networkmap.Rule{}
	filter.UpdateNetwork(snapshot)

	first := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 3},
		[4]byte{100, 64, 0, 4},
		40001,
		53,
		packetmeta.ProtocolUDP,
		0,
	)
	second := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 3},
		[4]byte{100, 64, 0, 4},
		40002,
		53,
		packetmeta.ProtocolUDP,
		0,
	)
	if !filter.Allow(PacketOutbound, first) || !filter.Allow(PacketOutbound, second) {
		t.Fatal("valid outbound UDP packet was denied")
	}
	if !filter.Allow(PacketInbound, reverseTestPacket(first)) {
		t.Fatal("reply for retained flow was denied")
	}
	if filter.Allow(PacketInbound, reverseTestPacket(second)) {
		t.Fatal("reply for untracked over-capacity flow was allowed")
	}
	now = now.Add(udpFlowTimeout + time.Second)
	if filter.Allow(PacketInbound, reverseTestPacket(first)) {
		t.Fatal("expired flow was allowed")
	}
}

func TestPolicyFilterRejectsMalformedAndFragmentedPackets(t *testing.T) {
	t.Parallel()

	filter := newPolicyFilter()
	filter.UpdateNetwork(testPolicySnapshot())
	fragment := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 4},
		[4]byte{100, 64, 0, 3},
		42000,
		18080,
		packetmeta.ProtocolTCP,
		0x02,
	)
	binary.BigEndian.PutUint16(fragment[6:8], 0x2000)
	if filter.Allow(PacketInbound, []byte{0x45}) {
		t.Fatal("truncated packet was allowed")
	}
	if filter.Allow(PacketInbound, fragment) {
		t.Fatal("fragmented packet was allowed")
	}
}

func testPolicySnapshot() networkmap.Snapshot {
	selfAddress := netip.MustParsePrefix("100.64.0.3/32")
	peerAddress := netip.MustParsePrefix("100.64.0.4/32")

	return networkmap.Snapshot{
		Self:  networkmap.Node{Addresses: []netip.Prefix{selfAddress}},
		Peers: []networkmap.Node{{Addresses: []netip.Prefix{peerAddress}}},
		Policy: []networkmap.Rule{{
			Sources: []networkmap.Selector{{
				Kind:   networkmap.SelectorPrefix,
				Prefix: peerAddress,
			}},
			Destinations: []networkmap.Destination{{
				Selector: networkmap.Selector{
					Kind:   networkmap.SelectorPrefix,
					Prefix: selfAddress,
				},
				PortFrom: 18080,
				PortTo:   18080,
			}},
			Protocols: []uint8{packetmeta.ProtocolTCP},
		}},
	}
}

func testIPv4TransportPacket(
	source, destination [4]byte,
	sourcePort, destinationPort uint16,
	protocol uint8,
	tcpFlags uint8,
) []byte {
	length := 28
	if protocol == packetmeta.ProtocolTCP {
		length = 40
	}
	packet := make([]byte, length)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	if protocol == packetmeta.ProtocolTCP {
		packet[32] = 0x50
		packet[33] = tcpFlags
	} else {
		binary.BigEndian.PutUint16(packet[24:26], 8)
	}

	return packet
}

func reverseTestPacket(packet []byte) []byte {
	reversed := append([]byte{}, packet...)
	copy(reversed[12:16], packet[16:20])
	copy(reversed[16:20], packet[12:16])
	copy(reversed[20:22], packet[22:24])
	copy(reversed[22:24], packet[20:22])

	return reversed
}

func testIPv4ICMPPacket(source, destination [4]byte, messageType uint8, identifier uint16) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 28)
	packet[8] = 64
	packet[9] = packetmeta.ProtocolICMPv4
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	packet[20] = messageType
	binary.BigEndian.PutUint16(packet[24:26], identifier)

	return packet
}

func testIPv6ICMPPacket(
	source, destination netip.Addr,
	messageType uint8,
	identifier uint16,
) []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 8)
	packet[6] = packetmeta.ProtocolICMPv6
	packet[7] = 64
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	packet[40] = messageType
	binary.BigEndian.PutUint16(packet[44:46], identifier)

	return packet
}
