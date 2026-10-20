package dataplane

import (
	"context"
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/shared/routedigest"
)

// servedRouteSetter is the helper's router forwarding operation.
type servedRouteSetter interface {
	SetServedRoutes(ctx context.Context, served, unmasqueraded []netip.Prefix) (netadmin.ServedResult, error)
}

// SubnetRouterStatus is what the node forwards into as a router (mtcp-v1
// §7.6).
type SubnetRouterStatus struct {
	// Sites counts the served Sites; Requested their prefixes, Served those
	// the host forwards into; RefusedTotal those it does not, Refused up to
	// 64 of them.
	Sites        int
	Requested    int
	Served       int
	RefusedTotal int
	Refused      []routesettings.Refusal
	// NotAdvertised reports a served prefix the host does not offer
	// (health prefix_not_advertised).
	NotAdvertised bool
	// Error is the last failure to forward, empty after a success.
	Error string
	// Health is each served Site's health, once measured (design §6.5).
	Health []SiteHealth
}

// syncServedLocked records the Sites the map serves through this node and
// has the worker send them when they changed.
func (e *WireGuardEngine) syncServedLocked(served []networkmap.ServedSite) {
	setter, supported := e.opener.(servedRouteSetter)
	if !supported {
		if len(served) != 0 && e.servedStatus.Error == "" && e.logger != nil {
			e.logger.Warn("subnet routers are not supported here", "sites", len(served))
		}
		e.servedStatus = SubnetRouterStatus{Sites: len(served)}
		if len(served) != 0 {
			e.servedStatus.Error = "subnet routers are not supported on this platform"
		}
		e.filter.SetServedInstalled(nil, nil)
		return
	}
	e.served.setLocked(e, served, helperExchange[[]networkmap.ServedSite, netadmin.ServedResult]{
		empty: func(sites []networkmap.ServedSite) bool { return len(sites) == 0 },
		equal: equalServedSites,
		clone: func(sites []networkmap.ServedSite) []networkmap.ServedSite {
			return append([]networkmap.ServedSite{}, sites...)
		},
		send: func(ctx context.Context, sites []networkmap.ServedSite) (netadmin.ServedResult, error) {
			prefixes, unmasqueraded := servedRequestOf(sites)
			return setter.SetServedRoutes(ctx, prefixes, unmasqueraded)
		},
		record: e.recordServedLocked,
		giveUp: func(err error) {
			if e.logger != nil {
				e.logger.Warn("stopping subnet forwarding keeps failing; giving up until the next change", "error", err)
			}
			e.servedStatus = SubnetRouterStatus{}
		},
	})
}

// resetServedLocked forgets what a closed device forwarded into.
func (e *WireGuardEngine) resetServedLocked() {
	e.stopRouterHealthLocked()
	e.served.resetLocked()
	e.servedStatus = SubnetRouterStatus{}
	e.filter.SetServedInstalled(nil, nil)
}

// servedRequestOf flattens the Sites into the prefixes to forward into and
// those whose sources keep their mesh addresses.
func servedRequestOf(sites []networkmap.ServedSite) ([]netip.Prefix, []netip.Prefix) {
	prefixes := []netip.Prefix{}
	var unmasqueraded []netip.Prefix
	for _, site := range sites {
		prefixes = append(prefixes, site.Prefixes...)
		if !site.Masquerade {
			unmasqueraded = append(unmasqueraded, site.Prefixes...)
		}
	}
	return prefixes, unmasqueraded
}

// servedEntries names the Site of each prefix the helper forwards into: the
// one whose prefix contains it (served Sites never overlap).
func servedEntries(sites []networkmap.ServedSite, installed []netip.Prefix) []routedigest.Entry {
	entries := make([]routedigest.Entry, 0, len(installed))
	for _, prefix := range installed {
		for _, site := range sites {
			if slices.ContainsFunc(site.Prefixes, func(served netip.Prefix) bool {
				return served.Bits() <= prefix.Bits() && served.Contains(prefix.Addr())
			}) {
				entries = append(entries, routedigest.Entry{SiteRef: site.Ref, Prefix: prefix, Masquerade: site.Masquerade})
				break
			}
		}
	}
	return entries
}

// recordServedLocked keeps what the helper did with requested.
func (e *WireGuardEngine) recordServedLocked(requested []networkmap.ServedSite, result netadmin.ServedResult,
	err error,
) {
	previous := e.servedStatus
	prefixes, _ := servedRequestOf(requested)
	status := SubnetRouterStatus{Sites: len(requested), Requested: len(prefixes)}
	if err != nil {
		// The helper stops forwarding when it fails: nothing is served.
		status.Error, status.RefusedTotal = err.Error(), len(prefixes)
		result = netadmin.ServedResult{}
	} else {
		status.Served, status.RefusedTotal = len(result.Installed), result.RefusedTotal
		status.Refused = slices.Clone(result.Refused)
		status.NotAdvertised = slices.ContainsFunc(result.Refused, func(refusal routesettings.Refusal) bool {
			return refusal.Reason == routesettings.ReasonNotAdvertised || refusal.Reason == routesettings.ReasonRouterOff
		})
	}
	// Health is measured on its own schedule; it keeps only Sites still
	// served.
	status.Health = slices.DeleteFunc(slices.Clone(previous.Health), func(health SiteHealth) bool {
		return !slices.ContainsFunc(requested, func(site networkmap.ServedSite) bool { return site.Ref == health.Ref })
	})
	e.servedStatus = status
	if len(result.Installed) != 0 {
		e.startRouterHealthLocked()
	}
	var local []netip.Addr
	if len(result.Installed) != 0 && e.hostAddresses != nil {
		// The router's own addresses: unknown ones only mean the kernel's
		// rules (layer 2) are the sole guard of them.
		var err error
		if local, err = e.hostAddresses(); err != nil && e.logger != nil {
			e.logger.Warn("reading the router's own addresses failed; the kernel rules alone guard them", "error", err)
		}
	}
	e.filter.SetServedInstalled(servedEntries(requested, result.Installed), local)
	e.signalEnforcementLocked()
	if e.logger == nil || equalSubnetRouterStatus(previous, status) {
		return
	}
	if err != nil {
		e.logger.Warn("forwarding into subnets failed", "sites", len(requested), "error", err)
		return
	}
	e.logger.Info("subnet forwarding applied", "sites", len(requested), "served", status.Served,
		"refused", status.RefusedTotal, "not_advertised", status.NotAdvertised)
}

func equalSubnetRouterStatus(first, second SubnetRouterStatus) bool {
	return first.Sites == second.Sites && first.Requested == second.Requested && first.Served == second.Served &&
		first.RefusedTotal == second.RefusedTotal && first.Error == second.Error &&
		slices.Equal(first.Refused, second.Refused)
}

func equalServedSites(first, second []networkmap.ServedSite) bool {
	return slices.EqualFunc(first, second, func(left, right networkmap.ServedSite) bool {
		return left.Ref == right.Ref && left.Masquerade == right.Masquerade &&
			slices.Equal(left.Prefixes, right.Prefixes) && slices.Equal(left.Probes, right.Probes)
	})
}

// signalEnforcementLocked tells the daemon the enforced policy changed
// outside a map update, such as the route digest once the helper answered.
func (e *WireGuardEngine) signalEnforcementLocked() {
	if e.enforcementChanges == nil {
		e.enforcementChanges = make(chan struct{}, 1)
	}
	select {
	case e.enforcementChanges <- struct{}{}:
	default:
	}
}

// EnforcementChanges signals a change of the enforced policy that no map
// update carried; the daemon sends the new evidence to Core.
func (e *WireGuardEngine) EnforcementChanges() <-chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.enforcementChanges == nil {
		e.enforcementChanges = make(chan struct{}, 1)
	}
	return e.enforcementChanges
}

// SubnetRouter returns what the node forwards into as a router.
func (e *WireGuardEngine) SubnetRouter() SubnetRouterStatus {
	if e == nil {
		return SubnetRouterStatus{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.servedStatus
	status.Refused = slices.Clone(status.Refused)
	status.Health = slices.Clone(status.Health)
	return status
}
