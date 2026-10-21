package dataplane

import (
	"context"
	"net/netip"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/underlay"
)

// exitRouteSetter is the helper's operation that sends the host's Internet
// traffic into the mesh, behind its kill switch (exit node design §6).
type exitRouteSetter interface {
	SetExitRoute(ctx context.Context, route netadmin.ExitRouteRequest) (netadmin.ExitRouting, error)
}

// ExitRouteStatus is how the node sends its Internet traffic through an exit
// node (mtcp-v1 §7.7).
type ExitRouteStatus struct {
	// Pool is the chosen pool's reference and Node the exit node used, a
	// device ID; Node is empty while none carries the traffic, which is
	// then dropped.
	Pool string
	Node string
	// IPv6 is whether IPv6 goes through the exit node; otherwise it is
	// refused.
	IPv6 bool
	// Routing is whether the helper sends the host's Internet traffic into
	// the mesh, with its kill switch; Refused (helper reason) why not.
	Routing bool
	Refused string
	// Tampered: the helper installed the exit routes again lately because
	// another program changed them (exit_rule_tampered).
	Tampered bool
	// Error is the last failure to configure the helper.
	Error string
}

// exitRouteDesired is what the helper is asked: to route the Internet into
// the mesh, and IPv6 too; dns are the exit node's resolvers.
type exitRouteDesired struct {
	use  bool
	ipv6 bool
	dns  [2]netip.Addr
}

// syncExitRouteLocked has the helper route the Internet into the mesh while
// the map's local choice names a pool, whether or not an exit node carries
// it: without one the traffic is dropped, never sent outside the mesh.
func (e *WireGuardEngine) syncExitRouteLocked(routed *routedTable) {
	desired := exitRouteDesired{}
	status := ExitRouteStatus{
		Routing: e.exitRouteStatus.Routing, Refused: e.exitRouteStatus.Refused,
		Error: e.exitRouteStatus.Error,
	}
	if routed != nil && routed.exit != nil {
		desired = exitRouteDesired{use: true, ipv6: routed.exit.ipv6, dns: exitResolverPair(routed.exit.dns)}
		status.Pool, status.IPv6 = routed.exit.pool, routed.exit.ipv6
		if routed.exit.served {
			status.Node = routed.exit.nodeRef
		}
	}
	if desired != e.exitRouteAsked {
		// A new request: what the helper said of the old one no longer
		// holds, while it is still routing (or not) as it was.
		status.Refused, status.Error = "", ""
		e.exitRouteAsked = desired
	}
	setter, supported := e.opener.(exitRouteSetter)
	if !supported {
		status.Routing, status.Refused, status.Error = false, "", ""
		if desired.use {
			status.Error = "using an exit node is not supported on this platform"
		}
		e.exitRouteStatus = status
		e.filter.SetExitRouted(false)
		return
	}
	e.exitRouteStatus = status
	// Before the helper routes anything: the client's own sockets must
	// already stay off the exit routes.
	e.followExitLocked(desired.use || status.Routing)
	e.exitRoute.setLocked(e, desired, helperExchange[exitRouteDesired, netadmin.ExitRouting]{
		empty: func(desired exitRouteDesired) bool { return !desired.use },
		equal: func(first, second exitRouteDesired) bool { return first == second },
		clone: func(desired exitRouteDesired) exitRouteDesired { return desired },
		send: func(ctx context.Context, desired exitRouteDesired) (netadmin.ExitRouting, error) {
			return setter.SetExitRoute(ctx, netadmin.ExitRouteRequest{
				Use: desired.use, IPv6: desired.ipv6, DNS: desired.dns,
			})
		},
		record: e.recordExitRouteLocked,
		giveUp: func(err error) {
			if e.logger != nil {
				e.logger.Warn("releasing the exit route keeps failing; giving up until the next change", "error", err)
			}
		},
	})
}

// exitResolverPair keeps the first IPv4 and the first IPv6 resolver.
func exitResolverPair(resolvers []netip.Addr) [2]netip.Addr {
	var pair [2]netip.Addr
	for _, address := range resolvers {
		slot := 0
		if address.Is6() {
			slot = 1
		}
		if !pair[slot].IsValid() {
			pair[slot] = address
		}
	}
	return pair
}

// recordExitRouteLocked keeps what the helper did and lets Internet packets
// reach the exit node only while the helper routes them into the mesh.
func (e *WireGuardEngine) recordExitRouteLocked(desired exitRouteDesired, result netadmin.ExitRouting, err error) {
	previous := e.exitRouteStatus
	status := previous
	status.Error = ""
	if err != nil {
		status.Error = err.Error()
		result = netadmin.ExitRouting{}
	}
	status.Routing, status.Refused, status.Tampered = result.Routing, result.Refused, result.Tampered
	e.exitRouteStatus = status
	e.filter.SetExitRouted(desired.use && result.Routing)
	e.followExitLocked(desired.use || result.Routing)
	if e.logger == nil || previous == status {
		return
	}
	if err != nil {
		e.logger.Warn("routing the Internet through the exit node failed", "pool", status.Pool, "error", err)
		return
	}
	if status.Tampered && !previous.Tampered {
		e.logger.Warn("another program changed the exit routes; the helper installed them again", "pool", status.Pool)
	}
	e.logger.Info("exit route applied", "pool", status.Pool, "exit_node", status.Node, "routing", status.Routing,
		"refused", status.Refused, "ipv6", status.IPv6, "tampered", status.Tampered)
}

// followExitLocked keeps the client's own sockets off the exit routes where
// they follow the host's routes (underlay.FollowsRoutes): bound to the
// physical path while the host routes, or is about to route, the Internet
// into the mesh. Elsewhere meshnetd keeps meshd's sockets off them, or the
// platform VPN excludes them.
func (e *WireGuardEngine) followExitLocked(bound bool) {
	if underlay.FollowsRoutes {
		underlay.SetExitBound(underlay.ExitRequested, bound)
	}
}

// resetExitRouteLocked forgets the exit route of a closed device. The
// helper keeps its kill switch: the host's Internet traffic stays dropped
// until the next device asks again or the host stops using an exit node.
func (e *WireGuardEngine) resetExitRouteLocked() {
	e.exitRoute.resetLocked()
	e.exitRouteStatus = ExitRouteStatus{}
	e.exitRouteAsked = exitRouteDesired{}
	e.filter.SetExitRouted(false)
	// The next device asks again; a kill switch the helper keeps is held
	// by root's choice (underlay.ExitChosen).
	e.followExitLocked(false)
}

// ExitRoute returns how the node sends its Internet traffic through an exit
// node.
func (e *WireGuardEngine) ExitRoute() ExitRouteStatus {
	if e == nil {
		return ExitRouteStatus{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exitRouteStatus
}
