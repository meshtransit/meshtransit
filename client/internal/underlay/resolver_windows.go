package underlay

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/winadapter"
)

// physicalResolver asks the DNS servers of the host's own interfaces
// directly, from sockets bound to the physical path: while the host routes
// the Internet into the mesh, the system resolver follows the NRPT rule to
// the MeshTransit resolver, which cannot answer before the mesh is up, and
// the kill switch drops every other process's queries.
var physicalResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Control: Control}).DialContext(ctx, network, address)
	},
}

// resolver is the resolver of the client's own dials: the system one, or
// physicalResolver while the host routes the Internet into the mesh.
func resolver() *net.Resolver {
	if ExitBound() {
		return physicalResolver
	}
	return nil
}

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver {
	if ExitBound() {
		return physicalResolver
	}
	return net.DefaultResolver
}

// NetworkResolvers returns the DNS servers of the host's adapters but
// MeshTransit's, on port 53, at most maximumUpstreams: the ones MeshTransit's
// resolver asks during a captive portal window.
func NetworkResolvers() []netip.AddrPort {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagSkipUnicast|
		winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipFriendlyName)
	if err != nil {
		return nil
	}
	mesh, _ := winadapter.LUID()
	var servers []netip.AddrPort
	for _, adapter := range adapters {
		if uint64(adapter.LUID) == mesh {
			continue
		}
		for server := adapter.FirstDNSServerAddress; server != nil && len(servers) < maximumUpstreams; server = server.Next {
			address, ok := netip.AddrFromSlice(server.Address.IP())
			address = address.Unmap()
			if !ok || address.IsLoopback() || address.IsUnspecified() || address.IsLinkLocalUnicast() ||
				testNet.Contains(address) || overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) {
				continue
			}
			candidate := netip.AddrPortFrom(address, upstreamPort)
			if !slices.Contains(servers, candidate) {
				servers = append(servers, candidate)
			}
		}
	}
	return servers
}
