package packetmeta

import (
	"encoding/binary"
	"net/netip"
)

const (
	probeHopLimit = 64
	// TCPFlagSYN, TCPFlagRST and TCPFlagACK are the TCP header flags a
	// router self-test sends and reads (RFC 9293).
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagACK uint8 = 0x10
	// ICMPv4EchoReply and ICMPv6EchoReply answer an echo request.
	ICMPv4EchoReply uint8 = 0
	ICMPv6EchoReply uint8 = 129
	icmpv4Echo      uint8 = 8
	icmpv6Echo      uint8 = 128
)

// EchoRequest builds an ICMP (or ICMPv6) echo request from source to
// destination, both of one family, with no payload.
func EchoRequest(source, destination netip.Addr, identifier, sequence uint16) []byte {
	protocol, kind := ProtocolICMPv4, icmpv4Echo
	if !source.Is4() {
		protocol, kind = ProtocolICMPv6, icmpv6Echo
	}
	packet, header, transport := probePacket(source, destination, protocol, 8)
	transport[0] = kind
	binary.BigEndian.PutUint16(transport[4:6], identifier)
	binary.BigEndian.PutUint16(transport[6:8], sequence)
	if source.Is4() {
		binary.BigEndian.PutUint16(transport[2:4], ^checksumSum(transport))
	} else {
		binary.BigEndian.PutUint16(transport[2:4], ^transportChecksum(header, transport))
	}
	return packet
}

// TCPSegment builds a TCP segment with flags and no options or payload,
// from source to destination of one family.
func TCPSegment(source, destination netip.Addr, sourcePort, destinationPort uint16, sequence, acknowledgment uint32,
	flags uint8,
) []byte {
	packet, header, transport := probePacket(source, destination, ProtocolTCP, 20)
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	binary.BigEndian.PutUint32(transport[4:8], sequence)
	binary.BigEndian.PutUint32(transport[8:12], acknowledgment)
	transport[12] = 5 << 4
	transport[13] = flags
	binary.BigEndian.PutUint16(transport[14:16], 1024)
	binary.BigEndian.PutUint16(transport[16:18], ^transportChecksum(header, transport))
	return packet
}

// probePacket lays out an IP packet of one family with a zeroed transport
// of size bytes, and returns it with its header and transport.
func probePacket(source, destination netip.Addr, protocol uint8, size int) ([]byte, Header, []byte) {
	header := Header{Source: source, Destination: destination, Protocol: protocol}
	if source.Is4() {
		packet := make([]byte, 20+size)
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet))) //nolint:gosec // G115: at most 40 bytes
		packet[6] = 0x40                                             // do not fragment
		packet[8], packet[9] = probeHopLimit, protocol
		from, to := source.As4(), destination.As4()
		copy(packet[12:16], from[:])
		copy(packet[16:20], to[:])
		binary.BigEndian.PutUint16(packet[10:12], ^checksumSum(packet[:20]))
		header.Length = len(packet)
		return packet, header, packet[20:]
	}
	packet := make([]byte, 40+size)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(size)) //nolint:gosec // G115: at most 20 bytes
	packet[6], packet[7] = protocol, probeHopLimit
	from, to := source.As16(), destination.As16()
	copy(packet[8:24], from[:])
	copy(packet[24:40], to[:])
	header.Length = len(packet)
	return packet, header, packet[40:]
}
