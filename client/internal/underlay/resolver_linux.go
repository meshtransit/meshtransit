//go:build linux && !android

package underlay

import (
	"net"
	"net/netip"
)

// resolver is the resolver of the client's own dials: on Linux the one that
// asks systemd-resolved's upstreams directly (upstreamResolver).
func resolver() *net.Resolver { return upstreamResolver }

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver { return upstreamResolver }

// NetworkResolvers returns the resolvers of the host's networks, which
// systemd-resolved asks: the ones MeshTransit's resolver asks during a
// captive portal window.
func NetworkResolvers() []netip.AddrPort {
	var servers []netip.AddrPort
	for _, server := range readUpstreams(upstreamResolvers) {
		if !server.Addr().IsLoopback() && !testNet.Contains(server.Addr()) {
			servers = append(servers, server)
		}
	}
	return servers
}
