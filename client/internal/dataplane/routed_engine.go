package dataplane

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
)

const (
	// routedRefreshInterval is how often meshd asks the helper again for the
	// routes it last requested: the helper may have restarted, or changed
	// what it installs after a network or settings change.
	routedRefreshInterval = 10 * time.Second
	routedRequestTimeout  = 5 * time.Second
	// maximumWithdrawFailures bounds the retries of an empty request: a
	// helper that keeps refusing it (an older one, or one with subnet routes
	// off) most likely never installed anything.
	maximumWithdrawFailures = 3
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

// routedEngineState is the engine's view of the helper's routes. One worker
// goroutine sends every request, outside the engine's lock, so requests
// reach the helper in order and the last answer recorded is always that of
// the last request sent: the filter never admits a prefix the kernel does not
// route.
type routedEngineState struct {
	// desired is what the current map asks for; generation advances with
	// every change of desired or of the device, so an answer to an older
	// request is never recorded.
	desired    []netip.Prefix
	generation uint64
	// mayHold means the helper may hold routes on the current device: a
	// request was sent since it opened and no empty request succeeded.
	mayHold bool
	// withdrawFailures counts empty requests failed in a row.
	withdrawFailures int
	status           SubnetRouteStatus
	// wake starts or prods the worker; running is true while it runs.
	wake    chan struct{}
	running bool
	// refresh overrides routedRefreshInterval in tests.
	refresh time.Duration
}

// syncRoutedLocked records the routes the map asks for and has the worker
// send them when they changed.
func (e *WireGuardEngine) syncRoutedLocked(desired []netip.Prefix) {
	setter, supported := e.opener.(routedRouteSetter)
	if !supported {
		if len(desired) != 0 && e.routed.status.Error == "" && e.logger != nil {
			e.logger.Warn("subnet routes are not supported here", "routes", len(desired))
		}
		e.routed.status = SubnetRouteStatus{Requested: len(desired)}
		if len(desired) != 0 {
			e.routed.status.Error = "subnet routes are not supported on this platform"
		}
		e.filter.SetRoutedInstalled(nil)
		return
	}
	if slices.Equal(e.routed.desired, desired) && (len(desired) != 0 || !e.routed.mayHold) {
		return
	}
	e.routed.desired = slices.Clone(desired)
	e.routed.generation++
	e.wakeRoutedLocked(setter)
}

// wakeRoutedLocked starts the worker, or prods the running one.
func (e *WireGuardEngine) wakeRoutedLocked(setter routedRouteSetter) {
	if e.routed.wake == nil {
		e.routed.wake = make(chan struct{}, 1)
	}
	if !e.routed.running {
		e.routed.running = true
		go e.runRouted(setter, e.routed.wake)
	}
	select {
	case e.routed.wake <- struct{}{}:
	default:
	}
}

// resetRoutedLocked forgets the routes of a closed device: the helper drops
// them with the TUN, and the next device asks again. A request in flight is
// answered for a device that is gone, so its answer is never recorded.
func (e *WireGuardEngine) resetRoutedLocked() {
	e.routed.generation++
	e.routed.desired = nil
	e.routed.withdrawFailures = 0
	e.routed.status = SubnetRouteStatus{}
	e.filter.SetRoutedInstalled(nil)
	if e.routed.running {
		select {
		case e.routed.wake <- struct{}{}:
		default:
		}
	}
}

// runRouted sends the desired routes whenever they change, and again every
// routedRefreshInterval while the helper may hold some: it may have
// restarted, or changed what it installs after a network or settings
// change. It ends once the helper holds nothing and nothing is desired.
func (e *WireGuardEngine) runRouted(setter routedRouteSetter, wake <-chan struct{}) {
	e.mu.Lock()
	interval := cmp.Or(e.routed.refresh, routedRefreshInterval)
	e.mu.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	sentGeneration := uint64(0)
	for {
		e.mu.Lock()
		if e.device == nil {
			e.routed.mayHold = false
		}
		if e.device == nil || (len(e.routed.desired) == 0 && !e.routed.mayHold) {
			e.routed.running = false
			e.mu.Unlock()
			return
		}
		requested, generation := slices.Clone(e.routed.desired), e.routed.generation
		e.routed.mayHold = true
		e.mu.Unlock()
		if requested == nil {
			requested = []netip.Prefix{}
		}

		ctx, cancel := context.WithTimeout(context.Background(), routedRequestTimeout)
		result, err := setter.SetRoutedRoutes(ctx, requested)
		cancel()
		sentGeneration = generation

		e.mu.Lock()
		current := e.routed.generation == generation
		if current {
			e.recordRoutedLocked(requested, result, err)
			e.settleWithdrawalLocked(requested, err)
		}
		e.mu.Unlock()
		if !current {
			continue // a newer request is due at once
		}
		select {
		case <-wake:
			e.mu.Lock()
			unchanged := e.routed.generation == sentGeneration
			e.mu.Unlock()
			if unchanged {
				// Prodded without a change: wait for the refresh.
				select {
				case <-wake:
				case <-ticker.C:
				}
			}
		case <-ticker.C:
		}
	}
}

// settleWithdrawalLocked notes whether the helper still holds routes after
// an empty request, giving up after maximumWithdrawFailures failures.
func (e *WireGuardEngine) settleWithdrawalLocked(requested []netip.Prefix, err error) {
	if len(requested) != 0 {
		e.routed.withdrawFailures = 0
		return
	}
	if err == nil {
		e.routed.mayHold, e.routed.withdrawFailures = false, 0
		return
	}
	e.routed.withdrawFailures++
	if e.routed.withdrawFailures < maximumWithdrawFailures {
		return
	}
	if e.logger != nil {
		e.logger.Warn("removing subnet routes keeps failing; giving up until the next change",
			"attempts", e.routed.withdrawFailures, "error", err)
	}
	e.routed.mayHold, e.routed.withdrawFailures = false, 0
	e.routed.status = SubnetRouteStatus{}
}

// recordRoutedLocked keeps what the helper did with requested.
func (e *WireGuardEngine) recordRoutedLocked(requested []netip.Prefix, result netadmin.RoutedResult, err error) {
	previous := e.routed.status
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
	e.routed.status = status
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
	status := e.routed.status
	status.Refused = slices.Clone(status.Refused)
	e.mu.Unlock()
	if e.filter != nil && e.filter.unreachable != nil {
		status.UnreachableAnswered = e.filter.unreachable.answered.Load()
		status.UnreachableLimited = e.filter.unreachable.limited.Load()
	}
	return status
}
