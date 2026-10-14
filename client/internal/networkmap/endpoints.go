package networkmap

import (
	"net/netip"
	"slices"

	"meshtransit.net/shared/endpointpolicy"
)

// UsableEndpoint reports whether a node may probe endpoint under the probe
// policy Core applies too (mtcp-v1 §8.1): a canonical address with a port
// that endpointpolicy.Usable accepts. Private ranges and ULA are usable,
// because they are LAN paths.
func UsableEndpoint(endpoint netip.AddrPort) bool {
	return endpoint.IsValid() && endpoint.Port() != 0 && endpointpolicy.Usable(endpoint.Addr())
}

// EndpointFilter refuses, beyond UsableEndpoint, the addresses of one map
// that no endpoint may name: the nodes' overlay addresses, since a probe to
// one would enter the tunnel, and the relays' addresses, so a peer cannot
// point this node's probes at the infrastructure. A NAT64 address is held
// to the rules of the IPv4 address it translates to. Routes a peer
// advertises are not refused: a LAN behind a subnet router is still a
// direct path for a node on that LAN.
type EndpointFilter struct {
	refused map[netip.Addr]struct{}
}

// NewEndpointFilter collects the refused addresses of snapshot.
func NewEndpointFilter(snapshot Snapshot) EndpointFilter {
	refused := make(map[netip.Addr]struct{}, len(snapshot.Peers)+1)
	add := func(node Node) {
		for _, prefix := range node.Addresses {
			refused[prefix.Addr()] = struct{}{}
		}
	}
	add(snapshot.Self)
	for index := range snapshot.Peers {
		add(snapshot.Peers[index])
	}
	for _, region := range snapshot.Relays {
		for _, relay := range region.Nodes {
			for _, value := range []string{relay.IPv4, relay.IPv6} {
				if address, err := netip.ParseAddr(value); err == nil {
					refused[address.Unmap()] = struct{}{}
				}
			}
		}
	}
	return EndpointFilter{refused: refused}
}

// Allows reports whether a node may probe endpoint.
func (filter EndpointFilter) Allows(endpoint netip.AddrPort) bool {
	return UsableEndpoint(endpoint) && !endpointpolicy.Matches(endpoint.Addr(), func(address netip.Addr) bool {
		_, refused := filter.refused[address]
		return refused
	})
}

// WithUsableEndpoints returns snapshot with every node's endpoints that the
// map's EndpointFilter refuses, or that repeat, removed. Core already drops
// them; a map from an older Core keeps the rest of its peers instead of
// being refused whole. snapshot is not modified, and a node whose endpoints
// are all kept keeps its slice.
func WithUsableEndpoints(snapshot Snapshot) Snapshot {
	filter := NewEndpointFilter(snapshot)
	usable := func(node Node) Node {
		for index, endpoint := range node.Endpoints {
			if filter.Allows(endpoint) && !slices.Contains(node.Endpoints[:index], endpoint) {
				continue
			}
			kept := make([]netip.AddrPort, 0, len(node.Endpoints))
			for _, candidate := range node.Endpoints {
				if filter.Allows(candidate) && !slices.Contains(kept, candidate) {
					kept = append(kept, candidate)
				}
			}
			node.Endpoints = kept
			return node
		}
		return node
	}
	filtered := snapshot
	filtered.Self = usable(snapshot.Self)
	filtered.Peers = make([]Node, len(snapshot.Peers))
	for index := range snapshot.Peers {
		filtered.Peers[index] = usable(snapshot.Peers[index])
	}
	return filtered
}
