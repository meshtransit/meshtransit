package mtcp

import (
	"net/netip"
	"slices"

	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/shared/endpointpolicy"
)

// maxDeniedEndpointPrefixes bounds the operator's list, like the trusted
// proxy list it is configured beside.
const maxDeniedEndpointPrefixes = 16

// endpointFilter drops endpoints peers must not probe beyond the ranges
// node.NewEndpoint refuses (mtcp-v1 §8.1): the Device's own overlay
// addresses, which would send a peer's probe into its tunnel, the relays'
// addresses and the operator's denied ranges, such as Core and its load
// balancers, so a Device cannot point its Network's probes at the
// infrastructure. A NAT64 address is held to the rules of the IPv4
// address it translates to.
//
// Core applies it when a report arrives and again when it sends a map, so
// endpoints stored before a relay or a denied range was added are not sent
// either.
type endpointFilter struct {
	relays []netip.Addr
	denied []netip.Prefix
}

// newEndpointFilter takes the relays of directory that have an address; a
// relay named only by hostname is covered by the operator's denied ranges.
func newEndpointFilter(directory relay.Directory, denied []netip.Prefix) endpointFilter {
	filter := endpointFilter{denied: denied}
	for _, region := range directory.Regions() {
		for _, relayNode := range region.Nodes() {
			for _, value := range []string{relayNode.IPv4(), relayNode.IPv6()} {
				if address, err := netip.ParseAddr(value); err == nil {
					filter.relays = append(filter.relays, address.Unmap())
				}
			}
		}
	}
	return filter
}

// allows reports whether peers may be sent address as an endpoint of the
// Device whose overlay addresses are overlay.
func (filter endpointFilter) allows(address netip.Addr, overlay []netip.Prefix) bool {
	return !endpointpolicy.Matches(address, func(candidate netip.Addr) bool {
		return slices.Contains(filter.relays, candidate) ||
			slices.ContainsFunc(overlay, func(prefix netip.Prefix) bool { return prefix.Addr() == candidate }) ||
			slices.ContainsFunc(filter.denied, func(prefix netip.Prefix) bool { return prefix.Contains(candidate) })
	})
}

func validDeniedEndpointPrefixes(prefixes []netip.Prefix) bool {
	if len(prefixes) > maxDeniedEndpointPrefixes {
		return false
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" {
			return false
		}
	}
	return true
}
