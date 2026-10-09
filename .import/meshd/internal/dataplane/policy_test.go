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

func TestPolicyFilterEnforcesSupportedProtocolMatrix(t *testing.T) {
	t.Parallel()

	self4 := netip.MustParsePrefix("100.64.0.3/32")
	peer4 := netip.MustParsePrefix("100.64.0.4/32")
	self6 := netip.MustParsePrefix("fd7a:115c:a1e0::3/128")
	peer6 := netip.MustParsePrefix("fd7a:115c:a1e0::4/128")
	tests := []struct {
		name     string
		self     netip.Prefix
		peer     netip.Prefix
		protocol uint8
		portFrom uint16
		portTo   uint16
		packet   []byte
		allowed  bool
	}{
		{
			name:     "ipv4 tcp allowed port",
			self:     self4,
			peer:     peer4,
			protocol: packetmeta.ProtocolTCP,
			portFrom: 443,
			portTo:   443,
			packet: testIPv4TransportPacket(
				peer4.Addr().As4(), self4.Addr().As4(), 42000, 443, packetmeta.ProtocolTCP, 0x02,
			),
			allowed: true,
		},
		{
			name:     "ipv4 tcp denied port",
			self:     self4,
			peer:     peer4,
			protocol: packetmeta.ProtocolTCP,
			portFrom: 443,
			portTo:   443,
			packet: testIPv4TransportPacket(
				peer4.Addr().As4(), self4.Addr().As4(), 42000, 444, packetmeta.ProtocolTCP, 0x02,
			),
		},
		{
			name:     "ipv4 udp allowed port",
			self:     self4,
			peer:     peer4,
			protocol: packetmeta.ProtocolUDP,
			portFrom: 5353,
			portTo:   5353,
			packet: testIPv4TransportPacket(
				peer4.Addr().As4(), self4.Addr().As4(), 42000, 5353, packetmeta.ProtocolUDP, 0,
			),
			allowed: true,
		},
		{
			name:     "ipv4 udp denied protocol",
			self:     self4,
			peer:     peer4,
			protocol: packetmeta.ProtocolTCP,
			portFrom: 5353,
			portTo:   5353,
			packet: testIPv4TransportPacket(
				peer4.Addr().As4(), self4.Addr().As4(), 42000, 5353, packetmeta.ProtocolUDP, 0,
			),
		},
		{
			name:     "ipv4 udp denied port",
			self:     self4,
			peer:     peer4,
			protocol: packetmeta.ProtocolUDP,
			portFrom: 5353,
			portTo:   5353,
			packet: testIPv4TransportPacket(
				peer4.Addr().As4(), self4.Addr().As4(), 42000, 5354, packetmeta.ProtocolUDP, 0,
			),
		},
		{
			name:     "ipv4 icmp allowed",
			self:     self4,
			peer:     peer4,
			protocol: packetmeta.ProtocolICMPv4,
			portFrom: 0,
			portTo:   65535,
			packet:   testIPv4ICMPPacket(peer4.Addr().As4(), self4.Addr().As4(), 8, 42),
			allowed:  true,
		},
		{
			name:     "ipv6 tcp allowed port",
			self:     self6,
			peer:     peer6,
			protocol: packetmeta.ProtocolTCP,
			portFrom: 8443,
			portTo:   8443,
			packet: testIPv6TransportPacket(
				peer6.Addr(), self6.Addr(), 42000, 8443, packetmeta.ProtocolTCP, 0x02,
			),
			allowed: true,
		},
		{
			name:     "ipv6 udp allowed port",
			self:     self6,
			peer:     peer6,
			protocol: packetmeta.ProtocolUDP,
			portFrom: 5353,
			portTo:   5353,
			packet: testIPv6TransportPacket(
				peer6.Addr(), self6.Addr(), 42000, 5353, packetmeta.ProtocolUDP, 0,
			),
			allowed: true,
		},
		{
			name:     "ipv6 icmp allowed",
			self:     self6,
			peer:     peer6,
			protocol: packetmeta.ProtocolICMPv6,
			portFrom: 0,
			portTo:   65535,
			packet:   testIPv6ICMPPacket(peer6.Addr(), self6.Addr(), 128, 42),
			allowed:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			filter := newPolicyFilter()
			filter.UpdateNetwork(testPolicySnapshotFor(
				test.self,
				test.peer,
				test.protocol,
				test.portFrom,
				test.portTo,
			))
			if allowed := filter.Allow(PacketInbound, test.packet); allowed != test.allowed {
				t.Fatalf("Allow() = %t, want %t", allowed, test.allowed)
			}
		})
	}
}

func TestPolicyFilterRequiresAllPortsForPortlessProtocol(t *testing.T) {
	t.Parallel()

	const protocolGRE uint8 = 47
	self := netip.MustParsePrefix("100.64.0.3/32")
	peer := netip.MustParsePrefix("100.64.0.4/32")
	packet := testIPv4ProtocolPacket(peer.Addr().As4(), self.Addr().As4(), protocolGRE)
	filter := newPolicyFilter()
	filter.UpdateNetwork(testPolicySnapshotFor(self, peer, protocolGRE, 0, 80))
	if filter.Allow(PacketInbound, packet) {
		t.Fatal("narrow port range authorized a portless protocol")
	}
	icmp := testIPv4ICMPPacket(peer.Addr().As4(), self.Addr().As4(), 8, 42)
	filter.UpdateNetwork(testPolicySnapshotFor(self, peer, packetmeta.ProtocolICMPv4, 0, 80))
	if filter.Allow(PacketInbound, icmp) {
		t.Fatal("narrow port range authorized ICMP")
	}
	filter.UpdateNetwork(testPolicySnapshotFor(self, peer, protocolGRE, 0, 65535))
	if !filter.Allow(PacketInbound, packet) {
		t.Fatal("all-port rule denied an explicitly authorized portless protocol")
	}
	snapshot := testPolicySnapshotFor(self, peer, 0, 0, 65535)
	snapshot.Policy[0].Protocols = nil
	filter.UpdateNetwork(snapshot)
	if filter.Allow(PacketInbound, packet) {
		t.Fatal("default protocol set unexpectedly authorized a portless protocol")
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
	wrongIdentifier := testIPv4ICMPPacket(
		[4]byte{100, 64, 0, 4},
		[4]byte{100, 64, 0, 3},
		0,
		43,
	)
	if filter.Allow(PacketInbound, wrongIdentifier) {
		t.Fatal("tracked echo flow allowed a reply with the wrong identifier")
	}
}

func TestPolicyFilterRequiresTCPInitiationAndExactReplyTuple(t *testing.T) {
	t.Parallel()

	filter := newPolicyFilter()
	snapshot := testPolicySnapshot()
	snapshot.Policy = nil
	filter.UpdateNetwork(snapshot)
	outboundACK := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 3},
		[4]byte{100, 64, 0, 4},
		48326,
		443,
		packetmeta.ProtocolTCP,
		0x10,
	)
	inbound := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 4},
		[4]byte{100, 64, 0, 3},
		443,
		48326,
		packetmeta.ProtocolTCP,
		0x10,
	)
	if !filter.Allow(PacketOutbound, outboundACK) {
		t.Fatal("valid outbound TCP packet was denied")
	}
	if filter.Allow(PacketInbound, inbound) {
		t.Fatal("outbound non-SYN packet created return-flow authority")
	}
	outboundSYN := append([]byte(nil), outboundACK...)
	outboundSYN[33] = 0x02
	if !filter.Allow(PacketOutbound, outboundSYN) {
		t.Fatal("outbound SYN was denied")
	}
	wrongTuple := append([]byte(nil), inbound...)
	binary.BigEndian.PutUint16(wrongTuple[22:24], 48327)
	if filter.Allow(PacketInbound, wrongTuple) {
		t.Fatal("tracked flow authorized a different destination port")
	}
	if !filter.Allow(PacketInbound, inbound) {
		t.Fatal("exact reply tuple was denied")
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

	return testPolicySnapshotFor(
		selfAddress,
		peerAddress,
		packetmeta.ProtocolTCP,
		18080,
		18080,
	)
}

func testPolicySnapshotFor(
	selfAddress netip.Prefix,
	peerAddress netip.Prefix,
	protocol uint8,
	portFrom uint16,
	portTo uint16,
) networkmap.Snapshot {
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
				PortFrom: portFrom,
				PortTo:   portTo,
			}},
			Protocols: []uint8{protocol},
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

func testIPv4ProtocolPacket(source, destination [4]byte, protocol uint8) []byte {
	const packetSize = 20
	packet := make([]byte, packetSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], packetSize)
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])

	return packet
}

func testIPv6TransportPacket(
	source, destination netip.Addr,
	sourcePort, destinationPort uint16,
	protocol uint8,
	tcpFlags uint8,
) []byte {
	transportLength := 8
	if protocol == packetmeta.ProtocolTCP {
		transportLength = 20
	}
	packet := make([]byte, 40+transportLength)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(transportLength))
	packet[6] = protocol
	packet[7] = 64
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[40:42], sourcePort)
	binary.BigEndian.PutUint16(packet[42:44], destinationPort)
	if protocol == packetmeta.ProtocolTCP {
		packet[52] = 0x50
		packet[53] = tcpFlags
	} else {
		binary.BigEndian.PutUint16(packet[44:46], uint16(transportLength))
	}

	return packet
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
