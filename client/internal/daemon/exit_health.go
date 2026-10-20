package daemon

import (
	"context"
	"net/netip"
	"time"
	"unicode/utf8"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
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

// exitNodeStatus is how the data plane forwards as an exit node.
func (s *Service) exitNodeStatus() dataplane.ExitNodeStatus {
	if s == nil || s.dataPlane == nil {
		return dataplane.ExitNodeStatus{}
	}
	s.dataPlaneMu.Lock()
	defer s.dataPlaneMu.Unlock()
	if reporter, supported := s.dataPlane.(exitNodeStatusDataPlane); supported {
		return reporter.ExitNode()
	}
	return dataplane.ExitNodeStatus{}
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
