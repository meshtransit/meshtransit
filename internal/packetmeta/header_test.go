package packetmeta

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		packet   []byte
		protocol uint8
		source   netip.Addr
		dest     netip.Addr
		srcPort  uint16
		dstPort  uint16
	}{
		{
			name:     "ipv4 tcp",
			packet:   testIPv4Packet(ProtocolTCP, 42000, 443),
			protocol: ProtocolTCP,
			source:   netip.MustParseAddr("100.64.0.3"),
			dest:     netip.MustParseAddr("100.64.0.4"),
			srcPort:  42000,
			dstPort:  443,
		},
		{
			name:     "ipv6 udp after hop by hop header",
			packet:   testIPv6UDPWithExtension(),
			protocol: ProtocolUDP,
			source:   netip.MustParseAddr("fd7a:115c:a1e0::3"),
			dest:     netip.MustParseAddr("fd7a:115c:a1e0::4"),
			srcPort:  53000,
			dstPort:  53,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			header, err := Parse(test.packet)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if header.Protocol != test.protocol || header.Source != test.source ||
				header.Destination != test.dest || header.SourcePort != test.srcPort ||
				header.DestinationPort != test.dstPort || header.Length != len(test.packet) {
				t.Fatalf("Parse() = %#v", header)
			}
		})
	}
}

func TestParseRejectsFragmentsAndMalformedTransport(t *testing.T) {
	t.Parallel()

	fragment := testIPv4Packet(ProtocolTCP, 42000, 443)
	binary.BigEndian.PutUint16(fragment[6:8], 0x2000)
	badTCP := testIPv4Packet(ProtocolTCP, 42000, 443)
	badTCP[32] = 0x10
	ipv4ICMPv6 := testIPv4ICMPPacket(ProtocolICMPv6, 128, 0)
	ipv6ICMPv4 := testIPv6ICMPPacket(ProtocolICMPv4, 8, 0)
	badICMPv4Code := testIPv4ICMPPacket(ProtocolICMPv4, 8, 1)
	badICMPv6Code := testIPv6ICMPPacket(ProtocolICMPv6, 128, 1)

	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty", packet: nil},
		{name: "ipv4 fragment", packet: fragment},
		{name: "invalid tcp data offset", packet: badTCP},
		{name: "ipv6 fragment", packet: testIPv6Fragment()},
		{name: "icmpv6 inside ipv4", packet: ipv4ICMPv6},
		{name: "icmpv4 inside ipv6", packet: ipv6ICMPv4},
		{name: "icmpv4 echo with nonzero code", packet: badICMPv4Code},
		{name: "icmpv6 echo with nonzero code", packet: badICMPv6Code},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(test.packet); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(testIPv4Packet(ProtocolTCP, 42000, 443))
	f.Add(testIPv6UDPWithExtension())
	f.Add([]byte{0x45})

	f.Fuzz(func(t *testing.T, packet []byte) {
		header, err := Parse(packet)
		if err != nil {
			return
		}
		if !header.Source.IsValid() || !header.Destination.IsValid() ||
			header.Length <= 0 || header.Length > len(packet) {
			t.Fatalf("Parse() returned invalid header %#v", header)
		}
	})
}

func testIPv4Packet(protocol uint8, sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], []byte{100, 64, 0, 3})
	copy(packet[16:20], []byte{100, 64, 0, 4})
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	packet[32] = 0x50
	packet[33] = 0x02

	return packet
}

func testIPv6UDPWithExtension() []byte {
	packet := make([]byte, 56)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 16)
	packet[6] = 0
	packet[7] = 64
	source := netip.MustParseAddr("fd7a:115c:a1e0::3").As16()
	destination := netip.MustParseAddr("fd7a:115c:a1e0::4").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	packet[40] = ProtocolUDP
	binary.BigEndian.PutUint16(packet[48:50], 53000)
	binary.BigEndian.PutUint16(packet[50:52], 53)
	binary.BigEndian.PutUint16(packet[52:54], 8)

	return packet
}

func testIPv6Fragment() []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 8)
	packet[6] = 44

	return packet
}

func testIPv4ICMPPacket(protocol, messageType, code uint8) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], []byte{100, 64, 0, 3})
	copy(packet[16:20], []byte{100, 64, 0, 4})
	packet[20] = messageType
	packet[21] = code
	binary.BigEndian.PutUint16(packet[24:26], 42)

	return packet
}

func testIPv6ICMPPacket(protocol, messageType, code uint8) []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 8)
	packet[6] = protocol
	packet[7] = 64
	source := netip.MustParseAddr("fd7a:115c:a1e0::3").As16()
	destination := netip.MustParseAddr("fd7a:115c:a1e0::4").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	packet[40] = messageType
	packet[41] = code
	binary.BigEndian.PutUint16(packet[44:46], 42)

	return packet
}
