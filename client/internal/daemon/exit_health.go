package daemon

import (
	"context"
	"net/netip"
	"time"
	"unicode/utf8"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
)

type exitNodeStatusDataPlane interface {
	ExitNode() dataplane.ExitNodeStatus
}

type exitPublicDataPlane interface {
	SetExitPublicAddresses([]netip.Addr)
}

// setExitPublicAddresses hands an exit node's endpoints, as peers see them,
// to the data plane: its public ones are no Internet for its consumers.
func (s *Service) setExitPublicAddresses(candidates pathdiscovery.Set) {
	if s == nil || !s.enableExitNode || s.dataPlane == nil {
		return
	}
	endpoints := candidates.Endpoints()
	addresses := make([]netip.Addr, 0, len(endpoints))
	for _, endpoint := range endpoints {
		addresses = append(addresses, endpoint.Addr())
	}
	s.dataPlaneMu.Lock()
	defer s.dataPlaneMu.Unlock()
	if setter, supported := s.dataPlane.(exitPublicDataPlane); supported {
		setter.SetExitPublicAddresses(addresses)
	}
}

// exitCodeDNSFailed: the DNS forwarder's upstreams failed its last
// questions in a row (exit node design §8).
const exitCodeDNSFailed = "dns_failed"

// exitNodeStatus is how the data plane forwards as an exit node, degraded
// while its DNS forwarder cannot reach its upstreams.
func (s *Service) exitNodeStatus() dataplane.ExitNodeStatus {
	if s == nil || s.dataPlane == nil {
		return dataplane.ExitNodeStatus{}
	}
	s.dataPlaneMu.Lock()
	status := dataplane.ExitNodeStatus{}
	if reporter, supported := s.dataPlane.(exitNodeStatusDataPlane); supported {
		status = reporter.ExitNode()
	}
	s.dataPlaneMu.Unlock()
	// A relayed question to a zone's resolver that does not answer is the
	// exit node's own fault while its probes find no way out (DNS design
	// D1c §4.2); other failures (rules, forwarding) leave the host's own
	// sockets working.
	s.exitForwarder.SetUplinkDown(status.Health != nil && status.Health.Code == dataplane.ExitCodeEgressFailed)
	if health := status.Health; health != nil && health.State == dataplane.SiteHealthOK && s.exitForwarder.Failing() {
		degraded := *health
		degraded.State, degraded.Code = dataplane.SiteHealthDegraded, exitCodeDNSFailed
		status.Health = &degraded
	}
	return status
}

// syncExitForwarder answers consumers' DNS on the node's overlay addresses
// while the map has it serve an Exit Pool, with the pool's upstreams.
func (s *Service) syncExitForwarder(snapshot networkmap.Snapshot) {
	if s.exitForwarder == nil {
		return
	}
	if len(snapshot.ServedExits) == 0 {
		s.exitForwarder.SetRelay(nil, nil)
		s.exitForwarder.Configure(nil, nil)
		return
	}
	addresses := make([]netip.Addr, 0, len(snapshot.Self.Addresses))
	for _, prefix := range snapshot.Self.Addresses {
		addresses = append(addresses, prefix.Addr().Unmap())
	}
	// The zones' Internet resolvers consumers may ask through this exit
	// node, never into a Site it serves (DNS design D1c §4).
	var served []netip.Prefix
	for _, site := range snapshot.Served {
		served = append(served, site.Prefixes...)
	}
	s.exitForwarder.SetRelay(snapshot.ServedExits[0].DNSRelayTargets, served)
	s.exitForwarder.Configure(addresses, snapshot.ServedExits[0].DNSUpstreams)
}

// watchExitHealth hands each new exit health to the map session, until ctx
// ends: the served pool's once measured, an empty reference when the node
// serves none.
func watchExitHealth(ctx context.Context, read func() dataplane.ExitNodeStatus, poll time.Duration,
	out chan<- controlplane.RouteExitHealth,
) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	var last *controlplane.RouteExitHealth
	for {
		if health, measured := exitHealthOf(read()); measured && (last == nil || *last != health) {
			select {
			case out <- health:
				last = &health
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// exitHealthOf converts the data plane's exit health; measured is false
// while a pool is served but not measured yet.
func exitHealthOf(status dataplane.ExitNodeStatus) (controlplane.RouteExitHealth, bool) {
	if status.Pool == "" {
		return controlplane.RouteExitHealth{}, true
	}
	if status.Health == nil {
		return controlplane.RouteExitHealth{}, false
	}
	if len(status.Pool) > maximumSiteReference || !utf8.ValidString(status.Pool) {
		return controlplane.RouteExitHealth{}, true
	}
	health := controlplane.RouteExitHealth{Ref: status.Pool, State: controlplane.RouteHealthOK, Code: status.Health.Code}
	switch status.Health.State {
	case dataplane.SiteHealthDegraded:
		health.State = controlplane.RouteHealthDegraded
	case dataplane.SiteHealthFailed:
		health.State = controlplane.RouteHealthFailed
	}
	if !validHealthCode(health.Code) {
		health.Code = "unknown"
	}
	switch {
	case status.Health.IPv4 && status.Health.IPv6:
		health.Families = controlplane.ExitFamiliesBoth
	case status.Health.IPv4:
		health.Families = controlplane.ExitFamiliesV4
	case status.Health.IPv6:
		health.Families = controlplane.ExitFamiliesV6
	}
	return health, true
}

// exitForwarderFor returns the DNS forwarder of an exit node, nil for any
// other node.
func exitForwarderFor(options Options) *dnsconfig.ExitForwarder {
	if !options.EnableExitNode {
		return nil
	}
	return dnsconfig.NewExitForwarder(options.Logger, nil)
}
