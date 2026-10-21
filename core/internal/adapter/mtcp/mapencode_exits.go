package mtcp

import (
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// internetDestinations are the destinations of every exit rule: the exit
// node subtracts what is not the Internet itself (mtcp-v1 §7.7).
var internetDestinations = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// encodeExits encodes the Exit Pools a node may use (mtcp-v1 §7.7), each
// candidate with the overlay addresses of its DNS forwarder when it is a
// peer of the map; nil when there are none.
func encodeExits(snapshot mapsession.Snapshot) *mtcpv1.ExitConfig {
	pools := snapshot.Routes().Exits()
	if len(pools) == 0 {
		return nil
	}
	peers := make(map[node.ID]mapsession.PeerCandidate)
	for _, candidate := range snapshot.AuthorizedPeers() {
		peers[candidate.NodeID()] = candidate
	}
	config := &mtcpv1.ExitConfig{Pools: make([]*mtcpv1.ExitPool, 0, len(pools))}
	for _, pool := range pools {
		encoded := &mtcpv1.ExitPool{PoolRef: pool.Ref, Name: pool.Name,
			Generation: uint64(pool.Generation), Status: exitStatus(pool.Status), //nolint:gosec // positive
			Mode: mtcpv1.ExitPool_FAILOVER, CaptiveOff: pool.CaptiveOff}
		if pool.Spread {
			encoded.Mode = mtcpv1.ExitPool_SPREAD
		}
		for _, candidate := range pool.Candidates {
			exitCandidate := &mtcpv1.ExitCandidate{DeviceId: candidate.String(),
				Draining: slices.Contains(pool.Draining, candidate)}
			if peer, ok := peers[candidate]; ok {
				for _, prefix := range peer.Addresses() {
					if address := prefix.Addr().Unmap(); address.Is4() {
						exitCandidate.DnsIpv4 = address.AsSlice()
					} else {
						exitCandidate.DnsIpv6 = address.AsSlice()
					}
				}
			}
			encoded.Candidates = append(encoded.Candidates, exitCandidate)
		}
		if pool.Primary.IsValid() {
			encoded.Primary = pool.Primary.String()
		}
		config.Pools = append(config.Pools, encoded)
	}
	return config
}

func exitStatus(status mapsession.RouteStatus) mtcpv1.ExitPool_Status {
	switch status {
	case mapsession.RouteServed:
		return mtcpv1.ExitPool_SERVED
	case mapsession.RouteCapacity:
		return mtcpv1.ExitPool_CAPACITY
	default:
		return mtcpv1.ExitPool_UNSERVED
	}
}

// encodeServedExits encodes the Exit Pool an exit node serves, with the
// pool's rules as filter rules from its consumers' overlay addresses to
// 0.0.0.0/0 and ::/0. Rules opening the same traffic are merged and their
// sources split at the per-rule limit; a traffic group that does not fit
// the filter limit is left out whole and counted. Nil when it serves none.
func encodeServedExits(snapshot mapsession.Snapshot) (*mtcpv1.ServedExits, error) {
	pools := snapshot.Routes().ServedExits()
	if len(pools) == 0 {
		return nil, nil
	}
	rules, err := exitFilterRules(snapshot)
	if err != nil {
		return nil, err
	}
	served := &mtcpv1.ServedExits{Pools: make([]*mtcpv1.ServedExit, 0, len(pools))}
	for _, pool := range pools {
		encoded := &mtcpv1.ServedExit{PoolRef: pool.Ref, SmtpAllowed: pool.SMTPAllowed,
			ConntrackPerConsumer: uint32(pool.ConntrackPerConsumer), Rules: rules} //nolint:gosec // bounded
		for _, probe := range pool.Probes {
			encoded.Probes = append(encoded.Probes, &mtcpv1.ExitProbe{Ip: probe.Address.Unmap().AsSlice(),
				Port: uint32(probe.Port)})
		}
		for _, upstream := range pool.DNSUpstreams {
			encoded.DnsUpstreams = append(encoded.DnsUpstreams, upstream.Unmap().AsSlice())
		}
		served.Pools = append(served.Pools, encoded)
	}
	return served, nil
}

func exitFilterRules(snapshot mapsession.Snapshot) ([]*mtcpv1.FilterRule, error) {
	candidates := make(map[node.ID]mapsession.PeerCandidate)
	for _, candidate := range snapshot.AuthorizedPeers() {
		candidates[candidate.NodeID()] = candidate
	}
	type merged struct {
		destinations []*mtcpv1.Destination
		protocols    []uint32
		sources      []netip.Prefix
		seen         map[netip.Addr]struct{}
	}
	var order []string
	groups := make(map[string]*merged)
	for _, rule := range snapshot.Routes().ExitInbound() {
		destinations, protocols, err := routedDestinations(mapsession.RoutedInbound{
			Prefixes: internetDestinations, Protocol: rule.Protocol, Ports: rule.Ports})
		if err != nil {
			return nil, err
		}
		groupKey := trafficKey(destinations, protocols)
		group, exists := groups[groupKey]
		if !exists {
			group = &merged{destinations: destinations, protocols: protocols, seen: make(map[netip.Addr]struct{})}
			groups[groupKey] = group
			order = append(order, groupKey)
		}
		for _, sourceID := range rule.Sources {
			candidate, ok := candidates[sourceID]
			if !ok {
				continue
			}
			for _, source := range candidate.Addresses() {
				address := source.Addr().Unmap()
				if _, duplicate := group.seen[address]; duplicate {
					continue
				}
				group.seen[address] = struct{}{}
				group.sources = append(group.sources, netip.PrefixFrom(address, address.BitLen()))
			}
		}
	}
	grouped := make([][]*mtcpv1.FilterRule, 0, len(order))
	for _, groupKey := range order {
		group := groups[groupKey]
		var rules []*mtcpv1.FilterRule
		for start := 0; start < len(group.sources); start += sharedmtcp.MaxFilterRuleSources {
			rule := &mtcpv1.FilterRule{Destinations: group.destinations, Protocols: group.protocols}
			for _, source := range group.sources[start:min(start+sharedmtcp.MaxFilterRuleSources, len(group.sources))] {
				rule.Sources = append(rule.Sources, sharedmtcp.AppendPrefix(source))
			}
			rules = append(rules, rule)
		}
		if len(rules) > 0 {
			grouped = append(grouped, rules)
		}
	}
	rules, omitted, err := fitFilterGroups(grouped, 0, sharedmtcp.MaxFilterRules)
	if err != nil {
		return nil, err
	}
	omittedExitFilterGroups.Add(uint64(omitted)) //nolint:gosec // a count
	return rules, nil
}

// omittedExitFilterGroups counts exit traffic groups left out of an exit
// node's rules for want of room (meshtransit_mtcp_exit_filter_groups_omitted_total).
var omittedExitFilterGroups atomic.Uint64

// exitFilterOmitted reports the exit traffic groups left out: any increase
// means an exit node has more consumers than its rules hold, and some of
// them cannot reach the Internet through it.
var exitFilterOmitted = prometheus.NewCounterFunc(prometheus.CounterOpts{
	Name: "meshtransit_mtcp_exit_filter_groups_omitted_total",
	Help: "Exit traffic groups left out of an exit node's rules because they were full.",
}, func() float64 { return float64(omittedExitFilterGroups.Load()) })
