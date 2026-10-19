package packetmeta

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// icmpError wraps quote in an ICMP error of type from source to destination.
func icmpError(source, destination netip.Addr, messageType uint8, quote []byte) []byte {
	if source.Is4() {
		packet := make([]byte, 28+len(quote))
		packet[0], packet[8], packet[9] = 0x45, 64, ProtocolICMPv4
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet))) //nolint:gosec // G115: test packets are small
		from, to := source.As4(), destination.As4()
		copy(packet[12:16], from[:])
		copy(packet[16:20], to[:])
		packet[20], packet[21] = messageType, 4 // fragmentation needed for type 3
		copy(packet[28:], quote)
		return packet
	}
	packet := make([]byte, 48+len(quote))
	packet[0], packet[6], packet[7] = 0x60, ProtocolICMPv6, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(quote))) //nolint:gosec // G115: test packets are small
	from, to := source.As16(), destination.As16()
	copy(packet[8:24], from[:])
	copy(packet[24:40], to[:])
	packet[40] = messageType
	copy(packet[48:], quote)
	return packet
}

func tcpQuote(source, destination netip.Addr, sourcePort, destinationPort uint16) []byte {
	if source.Is4() {
		quote := make([]byte, 28)
		quote[0], quote[9] = 0x45, ProtocolTCP
		binary.BigEndian.PutUint16(quote[2:4], 1400)
		from, to := source.As4(), destination.As4()
		copy(quote[12:16], from[:])
		copy(quote[16:20], to[:])
		binary.BigEndian.PutUint16(quote[20:22], sourcePort)
		binary.BigEndian.PutUint16(quote[22:24], destinationPort)
		return quote
	}
	quote := make([]byte, 48)
	quote[0], quote[6] = 0x60, ProtocolTCP
	from, to := source.As16(), destination.As16()
	copy(quote[8:24], from[:])
	copy(quote[24:40], to[:])
	binary.BigEndian.PutUint16(quote[40:42], sourcePort)
	binary.BigEndian.PutUint16(quote[42:44], destinationPort)
	return quote
}

func TestICMPErrorQuote(t *testing.T) {
	t.Parallel()
	self, site := netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("10.35.0.4")
	router := netip.MustParseAddr("10.35.0.2")
	quoted, ok := ICMPErrorQuote(icmpError(router, self, 3, tcpQuote(self, site, 40000, 443)))
	if !ok || quoted.Source != self || quoted.Destination != site || quoted.Protocol != ProtocolTCP ||
		quoted.SourcePort != 40000 || quoted.DestinationPort != 443 {
		t.Fatalf("ICMPErrorQuote(v4) = %+v, %t", quoted, ok)
	}
	self6, site6 := netip.MustParseAddr("fd7a::3"), netip.MustParseAddr("fd12::4")
	quoted, ok = ICMPErrorQuote(icmpError(netip.MustParseAddr("fd12::1"), self6, 2, tcpQuote(self6, site6, 40000, 443)))
	if !ok || quoted.Source != self6 || quoted.DestinationPort != 443 {
		t.Fatalf("ICMPErrorQuote(v6 packet too big) = %+v, %t", quoted, ok)
	}
	for name, packet := range map[string][]byte{
		"echo request":   icmpError(router, self, 8, tcpQuote(self, site, 40000, 443)),
		"short quote":    icmpError(router, self, 3, tcpQuote(self, site, 40000, 443)[:24]),
		"family changes": icmpError(router, self, 3, tcpQuote(self6, site6, 40000, 443)),
		"not icmp":       tcpQuote(self, site, 40000, 443),
	} {
		if _, ok := ICMPErrorQuote(packet); ok {
			t.Errorf("%s: ICMPErrorQuote() accepted the packet", name)
		}
	}
}
