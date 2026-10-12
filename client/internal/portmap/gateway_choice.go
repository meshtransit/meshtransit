package portmap

import "net/netip"

// gatewayCandidate is one IPv4 default route, with the metric Windows ranks
// it by: the route metric plus the interface metric. An on-link route has no
// next hop.
type gatewayCandidate struct {
	nextHop netip.Addr
	index   int
	metric  uint64
}

// preferredGateway finds the default route the host sends through, the
// lowest metric and then the lowest interface index, and returns its next
// hop. When that route is on-link (PPP, mobile broadband) there is no
// gateway to ask for a mapping, even if a worse route has one.
func preferredGateway(candidates []gatewayCandidate) (netip.Addr, bool) {
	if len(candidates) == 0 {
		return netip.Addr{}, false
	}
	best := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.metric < best.metric ||
			(candidate.metric == best.metric && candidate.index < best.index) {
			best = candidate
		}
	}
	nextHop := best.nextHop.Unmap()
	if !nextHop.Is4() || nextHop.IsUnspecified() || nextHop.IsMulticast() {
		return netip.Addr{}, false
	}

	return nextHop, true
}
