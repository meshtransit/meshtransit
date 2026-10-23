//go:build (!linux && !windows && !darwin) || android || ios

package underlay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// resolver is the resolver of the client's own dials: the system's, or,
// once the platform reported its networks' resolvers, those asked from the
// client's own sockets (DNS design D4 §3.6). The system's would ask the
// resolver the client's VPN interface may point the device at.
func resolver() *net.Resolver {
	if len(ReportedResolvers()) == 0 {
		return nil
	}
	return reportedResolver()
}

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver {
	if resolver := resolver(); resolver != nil {
		return resolver
	}
	return net.DefaultResolver
}

// NetworkResolvers returns the resolvers of the host's networks the
// platform reported (SetReportedResolvers), best first.
func NetworkResolvers() []netip.AddrPort {
	reported := ReportedResolvers()
	addresses := make([]netip.AddrPort, 0, len(reported))
	for _, resolver := range reported {
		addresses = append(addresses, resolver.Address)
	}
	return addresses
}

// reportedResolver resolves the client's own names with the reported
// resolvers, asked from its own sockets, so a mobile client's lookups never
// go to the in-process resolver its VPN interface may point the device at.
func reportedResolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		resolvers := ReportedResolvers()
		if len(resolvers) == 0 {
			return nil, fmt.Errorf("underlay: no reported resolver")
		}
		address := resolvers[upstreamRotation.Add(1)%uint32(len(resolvers))].Address //nolint:gosec // G115: a handful
		dialer := &net.Dialer{Control: Control}
		return dialer.DialContext(ctx, network, address.String())
	}}
}
