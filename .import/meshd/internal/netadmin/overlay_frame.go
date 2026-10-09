package netadmin

import "net/netip"

// safeOverlayFrame bounds every address and route meshnetd will install:
// the CGNAT overlay, the shared-Device alias range and IPv6 unique local
// addresses, where each Workspace draws its random /48. Control decides the
// exact prefixes inside it, so a new Workspace or alias pool needs no local
// configuration, while a compromised meshd still cannot claim a LAN, a
// public range or the default route.
var safeOverlayFrame = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fd00::/8"),
}

// SafeOverlayFrame returns the fixed outer bound for helper allowlists. It is
// also the allowlist meshnetd uses when none is configured.
func SafeOverlayFrame() []netip.Prefix {
	return append([]netip.Prefix(nil), safeOverlayFrame[:]...)
}

// withinSafeOverlayFrame reports whether prefix lies wholly inside one frame
// prefix. An allowlist may narrow the frame, never widen it.
func withinSafeOverlayFrame(prefix netip.Prefix) bool {
	for _, frame := range safeOverlayFrame {
		if prefix.Bits() >= frame.Bits() && frame.Contains(prefix.Addr()) {
			return true
		}
	}

	return false
}
