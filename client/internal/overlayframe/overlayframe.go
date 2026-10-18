// Package overlayframe holds the fixed outer bound of every overlay address
// and route a client installs: the CGNAT overlay, the shared-Device alias
// range and IPv6 unique local addresses, where each Workspace draws its
// random /48. Control decides the exact prefixes inside it, so a new
// Workspace or alias pool needs no local configuration, while a compromised
// Core or meshd still cannot claim a LAN, a public range or the default route.
package overlayframe

import "net/netip"

var frame = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fd00::/8"),
}

// Prefixes returns a copy of the frame.
func Prefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), frame[:]...)
}

// Contains reports whether prefix lies wholly inside one frame prefix. An
// IPv4-mapped IPv6 prefix is never inside: overlay prefixes are canonical.
func Contains(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	for _, outer := range frame {
		if prefix.Bits() >= outer.Bits() && outer.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
