// Package endpointpolicy is the policy for which addresses a node may be told to
// probe (mtcp-v1 §8.1). Core applies it to the endpoints Devices report and
// nodes to the endpoints they learn, so a Device cannot point its peers'
// probes at an address they must never send to.
package endpointpolicy

import (
	"net/netip"
	"slices"
)

// unusablePrefixes are global unicast ranges no node probes:
//   - 100.64.0.0/10 holds every Network's IPv4 overlay, so a probe there
//     would loop through the tunnel;
//   - 0.0.0.0/8 and 240.0.0.0/4 are not valid destinations, 100::/64 is
//     discard-only;
//   - IPv4-compatible (::/96) and SIIT (::ffff:0:0:0/96) addresses, 6to4
//     (2002::/16) and Teredo (2001::/32) embed an IPv4 address that would
//     escape the IPv4 rules, and no current path needs them.
//
// Private ranges and ULA stay, because they are LAN paths, and so do the
// documentation ranges, which no Internet host can be reached at.
var unusablePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// nat64 is the well-known NAT64 prefix (RFC 6052). A peer on an IPv6-only
// network reaches an IPv4 host through it, so its embedded IPv4 address is
// held to the IPv4 rules; RFC 6052 allows only global ones there.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// Usable reports whether a node may probe address: a canonical global
// unicast address outside the unusable ranges, whose NAT64-embedded IPv4
// address, if any, is a usable global one.
func Usable(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address != address.Unmap() || !usableUnicast(address) {
		return false
	}
	if embedded, ok := EmbeddedIPv4(address); ok {
		return usableUnicast(embedded) && !embedded.IsPrivate()
	}
	return true
}

// EmbeddedIPv4 returns the IPv4 address a NAT64 address translates to.
func EmbeddedIPv4(address netip.Addr) (netip.Addr, bool) {
	if !address.Is6() || !nat64.Contains(address) {
		return netip.Addr{}, false
	}
	bytes := address.As16()
	return netip.AddrFrom4([4]byte(bytes[12:])), true
}

// Matches reports whether match holds for address or for the IPv4 address
// it translates to, so a contextual rule (a relay, the overlay) cannot be
// sidestepped through NAT64.
func Matches(address netip.Addr, match func(netip.Addr) bool) bool {
	if match(address) {
		return true
	}
	embedded, ok := EmbeddedIPv4(address)
	return ok && match(embedded)
}

func usableUnicast(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsUnspecified() || address.IsMulticast() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	return !slices.ContainsFunc(unusablePrefixes, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}
