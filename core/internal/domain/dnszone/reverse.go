package dnszone

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Reverse zones (DNS design D5c): a zone under in-addr.arpa or ip6.arpa
// forwards the reverse names of one address range to the resolvers that
// hold them, as an office's Active Directory does. It covers whole octets
// (IPv4) or nibbles (IPv6), never the mesh's own ranges, whose reverse names
// each Device answers, and holds no names of its own.

const (
	ipv4Reverse = "in-addr.arpa"
	ipv6Reverse = "ip6.arpa"
)

// reverseMesh are the ranges of the mesh: the overlay, share aliases and the
// unique local block the client takes as the mesh's.
var reverseMesh = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fd00::/8"),
}

// reverseSpecial are ranges whose reverse names no resolver of a Network
// holds: this host, link-local, multicast, reserved.
var reverseSpecial = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/8"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// reversePrivate are the private ranges: a reverse zone of anything else is
// public and needs confirming.
var reversePrivate = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// IsReverse reports a domain under in-addr.arpa or ip6.arpa.
func (domain Domain) IsReverse() bool {
	value := string(domain)
	return strings.HasSuffix(value, "."+ipv4Reverse) || strings.HasSuffix(value, "."+ipv6Reverse)
}

// ReversePrefix returns the address range a reverse domain covers.
func ReversePrefix(domain Domain) (netip.Prefix, bool) {
	value := string(domain)
	if labels, ok := strings.CutSuffix(value, "."+ipv4Reverse); ok {
		return reverseIPv4(strings.Split(labels, "."))
	}
	if labels, ok := strings.CutSuffix(value, "."+ipv6Reverse); ok {
		return reverseIPv6(strings.Split(labels, "."))
	}
	return netip.Prefix{}, false
}

// reverseIPv4 reads 1 to 3 decimal octets, least significant first.
func reverseIPv4(labels []string) (netip.Prefix, bool) {
	if len(labels) == 0 || len(labels) > 3 {
		return netip.Prefix{}, false
	}
	var octets [4]byte
	for index, label := range labels {
		value, err := strconv.Atoi(label)
		if err != nil || value < 0 || value > 255 || strconv.Itoa(value) != label {
			return netip.Prefix{}, false
		}
		octets[len(labels)-1-index] = byte(value)
	}
	return netip.PrefixFrom(netip.AddrFrom4(octets), 8*len(labels)), true
}

// reverseIPv6 reads 1 to 31 hexadecimal nibbles, least significant first.
func reverseIPv6(labels []string) (netip.Prefix, bool) {
	if len(labels) == 0 || len(labels) > 31 {
		return netip.Prefix{}, false
	}
	var bytes [16]byte
	for index, label := range labels {
		if len(label) != 1 || !strings.Contains("0123456789abcdef", label) {
			return netip.Prefix{}, false
		}
		nibble := byte(strings.IndexByte("0123456789abcdef", label[0])) //nolint:gosec // G115: 0 to 15, checked above
		position := len(labels) - 1 - index
		if position%2 == 0 {
			bytes[position/2] |= nibble << 4
		} else {
			bytes[position/2] |= nibble
		}
	}
	return netip.PrefixFrom(netip.AddrFrom16(bytes), 4*len(labels)), true
}

// parseReverse checks a reverse domain: whole octets or nibbles, none of
// the mesh's ranges nor special ones; its class is private for a private
// range.
func parseReverse(domain Domain) (Domain, Class, error) {
	prefix, ok := ReversePrefix(domain)
	if !ok {
		return "", "", ErrInvalid
	}
	overlaps := func(ranges []netip.Prefix) bool {
		return slices.ContainsFunc(ranges, prefix.Overlaps)
	}
	switch {
	case overlaps(reverseMesh[:]):
		return "", "", ErrDomainMeshSuffix
	case overlaps(reverseSpecial[:]):
		return "", "", ErrDomainSpecialUse
	case slices.ContainsFunc(reversePrivate[:], func(private netip.Prefix) bool {
		return private.Bits() <= prefix.Bits() && private.Contains(prefix.Addr())
	}):
		return domain, ClassPrivate, nil
	default:
		return domain, ClassPublic, nil
	}
}
