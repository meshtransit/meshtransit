package underlay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

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
// It asks only the servers of the host's own adapters (NetworkResolvers):
// one Go would take from MeshTransit's adapter is replaced.
var physicalResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if servers := NetworkResolvers(); len(servers) != 0 {
			if target, err := netip.ParseAddrPort(address); err != nil || !slices.Contains(servers, target) {
				address = servers[physicalRotation.Add(1)%uint32(len(servers))].String()
			}
		} else if target, err := netip.ParseAddrPort(address); err != nil || meshResolver(target.Addr()) {
			// No adapter of the host's has a server: the one Go took is
			// MeshTransit's own, which cannot answer for it (TD-CLI-70).
			return nil, errNoNetworkResolver
		}
		return (&net.Dialer{Control: Control}).DialContext(ctx, network, address)
	},
}

// errNoNetworkResolver reports a host none of whose own adapters has a DNS
// server.
var errNoNetworkResolver = errors.New("underlay: no DNS server on the host's own adapters")

// physicalRotation spreads the replaced dials over the adapters' servers.
var physicalRotation atomic.Uint32

// resolver is the resolver of the client's own dials: the system one, or
// physicalResolver while the host routes the Internet into the mesh or
// sends every name to a root zone (SetRootZone).
func resolver() *net.Resolver {
	if ExitBound() || RootZone() {
		return physicalResolver
	}
	return nil
}

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver {
	if ExitBound() || RootZone() {
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
