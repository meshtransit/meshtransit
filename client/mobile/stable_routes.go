package mobile

import (
	"net/netip"

	"meshtransit.net/client/internal/prefixset"
)

// A mobile VPN interface cannot change its routes in place, so every peer
// that joins or leaves would rebuild it. The interface therefore routes
// stable blocks of the overlay rather than each peer: the /16 of the IPv4
// overlay range, or the /64 of the IPv6 one, that holds a peer. A Network's
// IPv4 range is at most a /16; an IPv6 Network is a /56 or narrower, so its
// peers fall in a few /64 blocks. Traffic to an address of such a block
// that is not a peer enters the tunnel and goes nowhere. A route outside
// the overlay ranges stays exact, so the interface never takes a LAN; but
// 100.64.0.0/10 is also carrier-grade NAT space, so a carrier or Wi-Fi
// address inside a block that holds peers (rare: it would also collide
// with the overlay) is no longer reachable off the tunnel.
const (
	stableIPv4Bits  = 16
	stableIPv6Bits  = 64
	maxStableRoutes = 1024
)

var (
	overlayIPv4 = netip.MustParsePrefix("100.64.0.0/10")
	overlayIPv6 = netip.MustParsePrefix("fd00::/8")
)

// stableRoutes widens the overlay routes of a map to their stable blocks
// and summarizes the result. A map whose blocks would exceed
// maxStableRoutes keeps its exact routes.
func stableRoutes(routes []netip.Prefix) []netip.Prefix {
	widened := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		switch {
		case route.Addr().Is4() && overlayIPv4.Contains(route.Addr()) && route.Bits() > stableIPv4Bits:
			route = netip.PrefixFrom(route.Addr(), stableIPv4Bits).Masked()
		case route.Addr().Is6() && overlayIPv6.Contains(route.Addr()) && route.Bits() > stableIPv6Bits:
			route = netip.PrefixFrom(route.Addr(), stableIPv6Bits).Masked()
		}
		widened = append(widened, route)
	}
	summarized := prefixset.Summarize(widened)
	if len(summarized) > maxStableRoutes {
		return prefixset.Summarize(routes)
	}
	return summarized
}
