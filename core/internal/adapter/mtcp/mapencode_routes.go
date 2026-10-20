package mtcp

import (
	"net/netip"
	"slices"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/policy"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// encodeRoutes encodes the Sites a node may reach (mtcp-v1 §7.6), without
// the prefixes holding an address clients dial; nil when there are none.
func encodeRoutes(view mapsession.RouteView, filter endpointFilter) *mtcpv1.RouteConfig {
	sites := view.Sites()
	config := &mtcpv1.RouteConfig{Sites: make([]*mtcpv1.SiteRoute, 0, len(sites))}
	for _, site := range sites {
		prefixes := filter.routable(site.Prefixes)
		if len(prefixes) == 0 {
			continue
		}
		route := &mtcpv1.SiteRoute{SiteRef: site.Ref, Prefixes: encodePrefixes(prefixes),
			Generation: uint64(site.Generation), Status: routeStatus(site.Status)} //nolint:gosec // positive
		for _, candidate := range site.Candidates {
			route.Candidates = append(route.Candidates, candidate.String())
		}
		if site.Primary.IsValid() {
			route.Primary = site.Primary.String()
		}
		config.Sites = append(config.Sites, route)
	}
	if len(config.Sites) == 0 {
		return nil
	}
	return config
}

// encodeServed encodes the Sites a router forwards to, without the prefixes
// its consumers are not sent; nil when there are none.
func encodeServed(view mapsession.RouteView, filter endpointFilter) *mtcpv1.ServedRoutes {
	sites := view.Served()
	served := &mtcpv1.ServedRoutes{Sites: make([]*mtcpv1.ServedSite, 0, len(sites))}
	for _, site := range sites {
		prefixes := filter.routable(site.Prefixes)
		if len(prefixes) == 0 {
			continue
		}
		encoded := &mtcpv1.ServedSite{SiteRef: site.Ref, Prefixes: encodePrefixes(prefixes),
			Masquerade: site.Masquerade}
		for _, probe := range site.Probes {
			kind, port := mtcpv1.RouteProbe_ICMP, uint32(0)
			if probe.TCP {
				kind, port = mtcpv1.RouteProbe_TCP, uint32(probe.Port)
			}
			encoded.Probes = append(encoded.Probes, &mtcpv1.RouteProbe{Ip: probe.Address.Unmap().AsSlice(),
				Kind: kind, Port: port})
		}
		served.Sites = append(served.Sites, encoded)
	}
	if len(served.Sites) == 0 {
		return nil
	}
	return served
}

func encodePrefixes(prefixes []netip.Prefix) []*mtcpv1.Prefix {
	encoded := make([]*mtcpv1.Prefix, len(prefixes))
	for index, prefix := range prefixes {
		encoded[index] = sharedmtcp.AppendPrefix(prefix)
	}
	return encoded
}

func routeStatus(status mapsession.RouteStatus) mtcpv1.SiteRoute_Status {
	switch status {
	case mapsession.RouteServed:
		return mtcpv1.SiteRoute_SERVED
	case mapsession.RouteConflict:
		return mtcpv1.SiteRoute_CONFLICT
	case mapsession.RouteCapacity:
		return mtcpv1.SiteRoute_CAPACITY
	default:
		return mtcpv1.SiteRoute_UNSERVED
	}
}

// routedDestinations encodes the destinations and protocols of routed
// traffic a router admits: the granted prefixes, with ports for TCP and
// UDP, and ICMP or ICMPv6 as the prefixes' families need.
func routedDestinations(rule mapsession.RoutedInbound) ([]*mtcpv1.Destination, []uint32, error) {
	var protocols []uint32
	var ports []*mtcpv1.PortRange
	switch rule.Protocol {
	case policy.ProtocolTCP, policy.ProtocolUDP:
		protocols = []uint32{6}
		if rule.Protocol == policy.ProtocolUDP {
			protocols = []uint32{17}
		}
		for _, portRange := range rule.Ports {
			ports = append(ports, &mtcpv1.PortRange{First: uint32(portRange.First()), Last: uint32(portRange.Last())})
		}
		if len(ports) == 0 {
			return nil, nil, ErrMapEncoding
		}
	case policy.ProtocolICMP:
		if slices.ContainsFunc(rule.Prefixes, func(prefix netip.Prefix) bool { return prefix.Addr().Is4() }) {
			protocols = append(protocols, 1)
		}
		if slices.ContainsFunc(rule.Prefixes, func(prefix netip.Prefix) bool { return prefix.Addr().Is6() }) {
			protocols = append(protocols, 58)
		}
	default:
		return nil, nil, ErrMapEncoding
	}
	destinations := make([]*mtcpv1.Destination, 0, len(rule.Prefixes))
	for _, prefix := range rule.Prefixes {
		destinations = append(destinations, &mtcpv1.Destination{Prefix: sharedmtcp.AppendPrefix(prefix), Ports: ports})
	}
	if len(destinations) == 0 || len(protocols) == 0 {
		return nil, nil, ErrMapEncoding
	}
	return destinations, protocols, nil
}
