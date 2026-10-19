package packetmeta

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	// unreachableQuoteIPv4 keeps an IPv4 answer within the 576 bytes every
	// host accepts (RFC 1812 §4.3.2.3); unreachableQuoteIPv6 an IPv6 one
	// within the 1,280-byte minimum MTU (RFC 4443 §2.4).
	unreachableQuoteIPv4 = 576 - 20 - 8
	unreachableQuoteIPv6 = 1280 - 40 - 8
	unreachableHopLimit  = 64
)

// ErrNoUnreachable means the packet must not be answered with an ICMP error:
// it is itself one, or it is not a packet this node could have sent.
var ErrNoUnreachable = errors.New("packetmeta: packet is not answered unreachable")

// Unreachable builds the ICMP "host unreachable" answer to packet, from its
// destination back to its source, for a node to write into its own TUN so
// the sending application fails at once. An ICMP error is never answered
// (RFC 1122 §3.2.2), nor an ICMP message other than an echo request.
func Unreachable(packet []byte) ([]byte, error) {
	header, err := Parse(packet)
	if err != nil {
		return nil, err
	}
	switch header.Protocol {
	case ProtocolICMPv4:
		if header.ICMPType != 8 {
			return nil, ErrNoUnreachable
		}
	case ProtocolICMPv6:
		if header.ICMPType != 128 {
			return nil, ErrNoUnreachable
		}
	}
	if !header.Source.IsGlobalUnicast() && !header.Source.IsPrivate() {
		return nil, ErrNoUnreachable
	}
	// Nor a packet to a broadcast or multicast address (RFC 1122 §3.2.2).
	if header.Destination.IsMulticast() || header.Destination == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return nil, ErrNoUnreachable
	}
	if header.Source.Is4() {
		return unreachableIPv4(header, packet), nil
	}
	return unreachableIPv6(header, packet), nil
}

func unreachableIPv4(header Header, packet []byte) []byte {
	quote := packet[:min(len(packet), unreachableQuoteIPv4)]
	answer := make([]byte, 20+8+len(quote))
	answer[0] = 0x45
	binary.BigEndian.PutUint16(answer[2:4], uint16(len(answer))) //nolint:gosec // G115: at most 576
	answer[8] = unreachableHopLimit
	answer[9] = ProtocolICMPv4
	source, destination := header.Destination.As4(), header.Source.As4()
	copy(answer[12:16], source[:])
	copy(answer[16:20], destination[:])
	binary.BigEndian.PutUint16(answer[10:12], ^checksumSum(answer[:20]))
	icmp := answer[20:]
	icmp[0], icmp[1] = 3, 1 // destination unreachable: host unreachable
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], ^checksumSum(icmp))
	return answer
}

func unreachableIPv6(header Header, packet []byte) []byte {
	quote := packet[:min(len(packet), unreachableQuoteIPv6)]
	answer := make([]byte, 40+8+len(quote))
	answer[0] = 0x60
	binary.BigEndian.PutUint16(answer[4:6], uint16(8+len(quote))) //nolint:gosec // G115: at most 1,240
	answer[6] = ProtocolICMPv6
	answer[7] = unreachableHopLimit
	source, destination := header.Destination.As16(), header.Source.As16()
	copy(answer[8:24], source[:])
	copy(answer[24:40], destination[:])
	icmp := answer[40:]
	icmp[0], icmp[1] = 1, 3 // destination unreachable: address unreachable
	copy(icmp[8:], quote)
	reply := Header{Source: header.Destination, Destination: header.Source, Protocol: ProtocolICMPv6}
	binary.BigEndian.PutUint16(icmp[2:4], ^transportChecksum(reply, icmp))
	return answer
}
