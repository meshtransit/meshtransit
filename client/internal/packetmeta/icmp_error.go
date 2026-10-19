package packetmeta

import (
	"encoding/binary"
	"net/netip"
)

// ICMPErrorQuote returns the header of the packet an ICMP error quotes:
// destination unreachable (including "fragmentation needed", which path MTU
// discovery depends on), time exceeded or parameter problem. The quote is
// truncated by design, so only addresses, protocol, ports and the echo
// identifier are read; ok is false for anything else.
func ICMPErrorQuote(packet []byte) (Header, bool) {
	header, err := Parse(packet)
	if err != nil {
		return Header{}, false
	}
	var offset int
	switch {
	case header.Protocol == ProtocolICMPv4 && (header.ICMPType == 3 || header.ICMPType == 11 || header.ICMPType == 12):
		offset = int(packet[0]&0x0f) * 4
	case header.Protocol == ProtocolICMPv6 && header.ICMPType >= 1 && header.ICMPType <= 4:
		walked, _, err := walkIPv6Extensions(packet[:header.Length], 40, packet[6])
		if err != nil {
			return Header{}, false
		}
		offset = walked
	default:
		return Header{}, false
	}
	quote := packet[min(offset+8, header.Length):header.Length]
	inner, ok := quotedHeader(quote)
	if !ok || inner.Source.Is4() != header.Source.Is4() {
		return Header{}, false
	}
	return inner, true
}

// quotedHeader reads the start of a quoted packet.
func quotedHeader(quote []byte) (Header, bool) {
	var inner Header
	var offset int
	switch {
	case len(quote) >= 20 && quote[0]>>4 == 4:
		offset = int(quote[0]&0x0f) * 4
		if offset < 20 || binary.BigEndian.Uint16(quote[6:8])&0x1fff != 0 {
			return Header{}, false // a later fragment quotes no ports
		}
		inner.Source = netip.AddrFrom4([4]byte(quote[12:16]))
		inner.Destination = netip.AddrFrom4([4]byte(quote[16:20]))
		inner.Protocol = quote[9]
	case len(quote) >= 40 && quote[0]>>4 == 6:
		offset = 40
		inner.Source = netip.AddrFrom16([16]byte(quote[8:24]))
		inner.Destination = netip.AddrFrom16([16]byte(quote[24:40]))
		inner.Protocol = quote[6]
	default:
		return Header{}, false
	}
	if len(quote) < offset+8 {
		return Header{}, false
	}
	transport := quote[offset:]
	switch inner.Protocol {
	case ProtocolTCP, ProtocolUDP:
		inner.SourcePort = binary.BigEndian.Uint16(transport[0:2])
		inner.DestinationPort = binary.BigEndian.Uint16(transport[2:4])
		if inner.Protocol == ProtocolTCP {
			inner.TCPFlags = 0x10 // an ACK: the quote is part of a flow, never its start
		}
	case ProtocolICMPv4, ProtocolICMPv6:
		inner.ICMPType, inner.ICMPCode = transport[0], transport[1]
		inner.ICMPIdentifier, inner.HasICMPIdentifier = binary.BigEndian.Uint16(transport[4:6]), true
	default:
		return Header{}, false
	}
	return inner, true
}
