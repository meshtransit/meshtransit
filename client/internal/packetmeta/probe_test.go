package packetmeta

import (
	"net/netip"
	"testing"
)

func TestProbePacketsParse(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]netip.Addr{
		{netip.MustParseAddr("100.64.0.0"), netip.MustParseAddr("10.35.0.4")},
		{netip.MustParseAddr("fd00::"), netip.MustParseAddr("2001:db8::4")},
	} {
		source, destination := pair[0], pair[1]
		echo := EchoRequest(source, destination, 0x1234, 7)
		header, err := Parse(echo)
		if err != nil || header.Source != source || header.Destination != destination ||
			!header.HasICMPIdentifier || header.ICMPIdentifier != 0x1234 {
			t.Fatalf("echo %s: %+v, %v", source, header, err)
		}
		if source.Is4() && (header.Protocol != ProtocolICMPv4 || header.ICMPType != icmpv4Echo) {
			t.Fatalf("echo is not an ICMP echo request: %+v", header)
		}
		if !source.Is4() && (header.Protocol != ProtocolICMPv6 || header.ICMPType != icmpv6Echo) {
			t.Fatalf("echo is not an ICMPv6 echo request: %+v", header)
		}
		syn := TCPSegment(source, destination, 40000, 22, 99, 0, TCPFlagSYN)
		header, err = Parse(syn)
		if err != nil || header.Protocol != ProtocolTCP || header.SourcePort != 40000 || header.DestinationPort != 22 ||
			header.TCPFlags != TCPFlagSYN {
			t.Fatalf("syn %s: %+v, %v", source, header, err)
		}
		// A valid transport checksum sums to all ones with the pseudo
		// header; the IPv4 header checksum likewise.
		if got := transportChecksum(header, syn[len(syn)-20:]); got != 0xffff {
			t.Fatalf("tcp checksum does not verify: %#x", got)
		}
		if source.Is4() && checksumSum(syn[:20]) != 0xffff {
			t.Fatal("ipv4 header checksum does not verify")
		}
	}
}
