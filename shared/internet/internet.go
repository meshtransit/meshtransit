// Package internet decides which addresses are the Internet an exit node
// forwards to (exit node design §4.1). Core holds the addresses an Exit Pool
// is configured with to it, and an exit node subtracts the same set, plus
// the addresses it learns locally, from every rule Core sends it, so a
// compromised Core cannot open the exit node's LAN, its cloud metadata or
// the mesh itself to a node granted the Internet.
package internet

import (
	"net/netip"
	"slices"
)

// globalUnicast is the only IPv6 space on the Internet (RFC 4291 §2.4).
// Everything outside it is excluded: loopback, IPv4-mapped and -compatible
// addresses, NAT64 (64:ff9b::/96, 64:ff9b:1::/48), discard, unique local
// (the mesh overlay, AWS metadata), link-local and multicast.
var globalUnicast = netip.MustParsePrefix("2000::/3")

// excluded are the ranges no exit node forwards to, whatever a rule says.
var excluded = [...]netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),        // this network
	netip.MustParsePrefix("10.0.0.0/8"),       // private
	netip.MustParsePrefix("100.64.0.0/10"),    // shared address space and the mesh overlay
	netip.MustParsePrefix("127.0.0.0/8"),      // loopback
	netip.MustParsePrefix("168.63.129.16/32"), // Azure wire server, a host service on a public address
	netip.MustParsePrefix("169.254.0.0/16"),   // link-local: cloud metadata services
	netip.MustParsePrefix("172.16.0.0/12"),    // private
	netip.MustParsePrefix("192.0.0.0/24"),     // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),     // documentation
	netip.MustParsePrefix("192.31.196.0/24"),  // AS112
	netip.MustParsePrefix("192.52.193.0/24"),  // AMT
	netip.MustParsePrefix("192.88.99.0/24"),   // former 6to4 relay anycast
	netip.MustParsePrefix("192.168.0.0/16"),   // private
	netip.MustParsePrefix("198.18.0.0/15"),    // benchmarking and the mesh alias range
	netip.MustParsePrefix("198.51.100.0/24"),  // documentation
	netip.MustParsePrefix("203.0.113.0/24"),   // documentation
	netip.MustParsePrefix("224.0.0.0/4"),      // multicast
	netip.MustParsePrefix("240.0.0.0/4"),      // reserved and limited broadcast
	// IPv6 inside 2000::/3
	netip.MustParsePrefix("2001::/32"),     // Teredo: embeds an IPv4 address
	netip.MustParsePrefix("2001:2::/48"),   // benchmarking
	netip.MustParsePrefix("2001:10::/28"),  // ORCHID
	netip.MustParsePrefix("2001:20::/28"),  // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("2002::/16"),     // 6to4: embeds an IPv4 address
	netip.MustParsePrefix("3fff::/20"),     // documentation (RFC 9637)
}

// Excluded returns the ranges inside the IPv4 space and 2000::/3 that are
// not the Internet. IPv6 outside 2000::/3 is excluded as a whole.
func Excluded() []netip.Prefix {
	return slices.Clone(excluded[:])
}

// outsideGlobalUnicast is the IPv6 space outside 2000::/3.
var outsideGlobalUnicast = [...]netip.Prefix{
	netip.MustParsePrefix("::/3"),
	netip.MustParsePrefix("4000::/2"),
	netip.MustParsePrefix("8000::/1"),
}

// NotInternet returns every range that is not the Internet: Excluded and
// the IPv6 space outside 2000::/3, as a packet filter needs them.
func NotInternet() []netip.Prefix {
	return append(slices.Clone(excluded[:]), outsideGlobalUnicast[:]...)
}

// Contains reports whether address is on the Internet: a valid address
// without a zone, IPv4 outside the excluded ranges or IPv6 global unicast
// outside them. IPv4-mapped IPv6 addresses are not: an exit node is never
// asked to reach IPv4 through them.
func Contains(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	if address.Is6() && !globalUnicast.Contains(address) {
		return false
	}
	return !slices.ContainsFunc(excluded[:], func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}

// OnlyInternet reports whether every address of prefix is on the Internet.
func OnlyInternet(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return false
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is6() && (prefix.Bits() < globalUnicast.Bits() || !globalUnicast.Contains(prefix.Addr())) {
		return false
	}
	return !slices.ContainsFunc(excluded[:], prefix.Overlaps)
}
