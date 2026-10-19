package dataplane

import (
	"context"
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
)

// routedRouteSetter is the helper's subnet route operation.
type routedRouteSetter interface {
	SetRoutedRoutes(context.Context, []netip.Prefix) (netadmin.RoutedResult, error)
}

// SubnetRouteStatus is what the node does with the map's subnet routes
// (mtcp-v1 §7.6).
type SubnetRouteStatus struct {
	// Requested counts the prefixes asked of the helper, Installed those it
	// installed; RefusedTotal those it refused, Refused up to 64 of them.
	Requested    int
	Installed    int
	RefusedTotal int
	Refused      []routesettings.Refusal
	// LocalConflict reports a route refused for overlapping a network the
	// host reaches itself (health code route_conflict_local).
	LocalConflict bool
	// Error is the last failure to install routes, empty after a success.
	Error string
	// UnreachableAnswered counts packets to an unreachable Site answered
	// with ICMP; UnreachableLimited those over the per-Site limit.
	UnreachableAnswered uint64
	UnreachableLimited  uint64
}

// syncRoutedLocked records the routes the map asks for and has the worker
// send them when they changed.
func (e *WireGuardEngine) syncRoutedLocked(desired []netip.Prefix) {
	setter, supported := e.opener.(routedRouteSetter)
	if !supported {
		if len(desired) != 0 && e.routedStatus.Error == "" && e.logger != nil {
			e.logger.Warn("subnet routes are not supported here", "routes", len(desired))
		}
		e.routedStatus = SubnetRouteStatus{Requested: len(desired)}
		if len(desired) != 0 {
			e.routedStatus.Error = "subnet routes are not supported on this platform"
		}
		e.filter.SetRoutedInstalled(nil)
		return
	}
	e.routed.setLocked(e, desired, helperExchange[[]netip.Prefix, netadmin.RoutedResult]{
		empty:  func(routes []netip.Prefix) bool { return len(routes) == 0 },
		equal:  slices.Equal[[]netip.Prefix],
		clone:  func(routes []netip.Prefix) []netip.Prefix { return append([]netip.Prefix{}, routes...) },
		send:   setter.SetRoutedRoutes,
		record: e.recordRoutedLocked,
		giveUp: func(err error) {
			if e.logger != nil {
				e.logger.Warn("removing subnet routes keeps failing; giving up until the next change", "error", err)
			}
			e.routedStatus = SubnetRouteStatus{}
		},
	})
}

// resetRoutedLocked forgets the routes of a closed device.
func (e *WireGuardEngine) resetRoutedLocked() {
	e.routed.resetLocked()
	e.routedStatus = SubnetRouteStatus{}
	e.filter.SetRoutedInstalled(nil)
}

// recordRoutedLocked keeps what the helper did with requested.
func (e *WireGuardEngine) recordRoutedLocked(requested []netip.Prefix, result netadmin.RoutedResult, err error) {
	previous := e.routedStatus
	status := SubnetRouteStatus{Requested: len(requested)}
	if err != nil {
		// The helper clears its routes when it fails: nothing is installed.
		status.Error = err.Error()
		status.RefusedTotal = len(requested)
		result = netadmin.RoutedResult{}
	} else {
		status.Installed = len(result.Installed)
		status.RefusedTotal = result.RefusedTotal
		status.Refused = slices.Clone(result.Refused)
		status.LocalConflict = slices.ContainsFunc(result.Refused, func(refusal routesettings.Refusal) bool {
			return refusal.Reason == routesettings.ReasonLocalConflict
		})
	}
	e.routedStatus = status
	e.filter.SetRoutedInstalled(result.Installed)
	if e.logger == nil || equalSubnetRouteStatus(previous, status) {
		return
	}
	if err != nil {
		e.logger.Warn("installing subnet routes failed", "requested", len(requested), "error", err)
		return
	}
	e.logger.Info("subnet routes applied", "requested", len(requested), "installed", status.Installed,
		"refused", status.RefusedTotal, "local_conflict", status.LocalConflict)
}

func equalSubnetRouteStatus(first, second SubnetRouteStatus) bool {
	return first.Requested == second.Requested && first.Installed == second.Installed &&
		first.RefusedTotal == second.RefusedTotal && first.Error == second.Error &&
		slices.Equal(first.Refused, second.Refused)
}

// SubnetRoutes returns what the node does with the map's subnet routes.
func (e *WireGuardEngine) SubnetRoutes() SubnetRouteStatus {
	if e == nil {
		return SubnetRouteStatus{}
	}
	e.mu.Lock()
	status := e.routedStatus
	status.Refused = slices.Clone(status.Refused)
	e.mu.Unlock()
	if e.filter != nil && e.filter.unreachable != nil {
		status.UnreachableAnswered = e.filter.unreachable.answered.Load()
		status.UnreachableLimited = e.filter.unreachable.limited.Load()
	}
	return status
}
