package daemon

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/underlay"
)

// Choosing the exit node (exit node design §9): the host's root-owned
// settings name the pool, Core elects each pool's primary, and the node
// keeps the exit node it uses while that one works, as changing it changes
// the public address and cuts every connection.

// exitPreference is what the host's settings ask of exit nodes.
type exitPreference struct {
	// use is a pool reference or name, routesettings.ExitUseAuto, or empty.
	use string
	// allowManaged follows a pool Core marks managed when use is empty.
	allowManaged bool
}

// exitPreferenceOf reads the preference from settings; false when they
// cannot be read, which changes nothing: the helper keeps its kill switch
// then too.
func exitPreferenceOf(load func(string) (routesettings.Settings, error), path string,
	logger *slog.Logger,
) (exitPreference, bool) {
	settings, err := load(path)
	if err != nil {
		if logger != nil {
			logger.Warn("route settings unusable; keeping the exit choice", "error", err)
		}
		return exitPreference{}, false
	}
	noteExitChoice(settings.ExitUse)
	return exitPreference{use: settings.ExitUse, allowManaged: settings.ExitAllowManaged}, true
}

// noteExitChoice keeps the client's own sockets and lookups off the host's
// routes and resolver while root's settings name a pool, where they follow
// the host's routes (underlay.FollowsRoutes): the helper's kill switch cuts
// the host's resolver off from the start, before any map.
func noteExitChoice(use string) {
	if underlay.FollowsRoutes {
		underlay.SetExitBound(underlay.ExitChosen, use != "")
	}
}

const (
	// exitRTTSamples is how many round trips to a pool's primary auto
	// waits for, at most exitAutoMeasure after it starts choosing.
	exitRTTSamples  = 3
	exitAutoMeasure = 10 * time.Second
	// exitSilentAfter is how long every candidate of the pool auto uses
	// must be silent before it chooses another pool.
	exitSilentAfter = 10 * time.Second
	// exitStuckConnections new TCP connections through an exit node, none
	// answered for exitStuckAfter, show it no longer reaches the Internet.
	exitStuckConnections = 3
	exitStuckAfter       = 5 * time.Second
	// exitStuckAvoid is how long an exit node left as stuck is not chosen
	// again: then it is tried afresh, so a pool of one comes back.
	exitStuckAvoid = 30 * time.Second
)

// exitChoice is the exit node chosen in one control session, and since when.
type exitChoice struct {
	preference exitPreference
	// pool is the reference of the pool used; empty when the preference
	// names none or one Core does not grant.
	pool string
	// node is the exit node used (a device ID); empty while none can carry
	// the traffic, which is then dropped.
	node   string
	reason controlplane.RouteSelectionReason
	// ipv6 is whether node carries IPv6.
	ipv6 bool
	// wanted means the preference asks for an exit node: the Internet goes
	// into the mesh, through node or nowhere.
	wanted bool
	// lastSwitch, nextSwitch and backoff space the switches made because
	// an exit node stopped answering.
	lastSwitch time.Time
	nextSwitch time.Time
	backoff    time.Duration
	// pins are the approved exit nodes; pending the candidates of pool
	// waiting for approval.
	pins    *exitPins
	pending []string
	// pendingPool is a pool given the name the settings use, other than
	// the one bound to it, waiting for approval.
	pendingPool string
	// autoSince is when auto started choosing; autoSettled once it chose
	// by round trip, after which it keeps its pool.
	autoSince   time.Time
	autoSettled bool
	// activity is what the node sent through its exit node and heard back;
	// avoid is until when an exit node left as stuck is not chosen.
	activity      dataplane.ExitActivity
	activitySince time.Time
	avoid         map[string]time.Time
}

// exitSticky is what a new control session starts from, so a reconnect
// keeps the exit node in use.
type exitSticky struct {
	pool, node string
}

// seedExit starts the session's choice from the last one, with the
// host's pinned exit nodes.
func (failover *routeFailover) seedExit(preference exitPreference, sticky exitSticky, pins *exitPins) {
	failover.mu.Lock()
	defer failover.mu.Unlock()
	failover.exit = exitChoice{
		preference: preference, pool: sticky.pool, node: sticky.node, backoff: failoverBackoff, pins: pins,
		autoSince: failover.clock(), autoSettled: sticky.pool != "",
	}
	if sticky.node != "" {
		failover.exit.reason = controlplane.RouteSelectionSticky
	}
}

// setExitPreference records the settings' preference and reports whether
// the exit route changed, so the map must be applied again. A new pool or
// mode drops the exit node kept until now.
func (failover *routeFailover) setExitPreference(preference exitPreference) bool {
	if failover == nil {
		return false
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	if failover.exit.preference == preference {
		return false
	}
	before := failover.exitRouteLocked()
	failover.exit = exitChoice{
		preference: preference, backoff: failoverBackoff, pins: failover.exit.pins, autoSince: failover.clock(),
	}
	failover.chooseExitLocked(failover.clock())
	return !equalExitRoutes(before, failover.exitRouteLocked())
}

// observeExitActivity records what the node sent through its exit node.
func (failover *routeFailover) observeExitActivity(activity dataplane.ExitActivity) {
	failover.mu.Lock()
	defer failover.mu.Unlock()
	if !activity.WaitingSince.IsZero() && !activity.WaitingSince.After(failover.exit.activitySince) {
		// Evidence from before the node was last left as stuck counts no more.
		activity = dataplane.ExitActivity{Node: activity.Node}
	}
	failover.exit.activity = activity
}

// stuckLocked reports that new connections through node went unanswered:
// the exit node answers path probes but no longer reaches the Internet. A
// stuck node is avoided for exitStuckAvoid, its evidence then forgotten.
func (failover *routeFailover) stuckLocked(node string, now time.Time) bool {
	choice := &failover.exit
	if until, avoided := choice.avoid[node]; avoided {
		if now.Before(until) {
			return true
		}
		delete(choice.avoid, node)
	}
	activity := choice.activity
	stuck := activity.Node == node && activity.NewConnections >= exitStuckConnections &&
		!activity.WaitingSince.IsZero() && now.Sub(activity.WaitingSince) >= exitStuckAfter
	if stuck {
		if choice.avoid == nil {
			choice.avoid = map[string]time.Time{}
		}
		choice.avoid[node] = now.Add(exitStuckAvoid)
		choice.activity, choice.activitySince = dataplane.ExitActivity{}, now
	}
	return stuck
}

// exitPoolLocked returns the pool the preference names among those Core
// grants: by reference, else by a name only one pool has; with auto the
// one chosen by round trip (exitAutoPoolLocked); with allowManaged alone
// the first pool Core marks managed.
func (failover *routeFailover) exitPoolLocked() (networkmap.ExitPool, bool) {
	pools := failover.core.Exits
	find := func(match func(networkmap.ExitPool) bool) (networkmap.ExitPool, bool) {
		index := slices.IndexFunc(pools, match)
		if index < 0 {
			return networkmap.ExitPool{}, false
		}
		return pools[index], true
	}
	preference := failover.exit.preference
	switch {
	case preference.use == routesettings.ExitUseAuto:
		if pool, found := failover.exitAutoPoolLocked(failover.clock()); found {
			return pool, true
		}
		return find(func(pool networkmap.ExitPool) bool { return pool.Ref == failover.exit.pool })
	case preference.use != "":
		if pool, found := find(func(pool networkmap.ExitPool) bool { return pool.Ref == preference.use }); found {
			return pool, true
		}
		named := 0
		for _, pool := range pools {
			if pool.Name == preference.use {
				named++
			}
		}
		if named != 1 {
			return networkmap.ExitPool{}, false
		}
		pool, _ := find(func(pool networkmap.ExitPool) bool { return pool.Name == preference.use })
		// The name means the pool it meant at first use: another pool
		// given that name waits for approval.
		bound, wasBound := failover.exit.pins.boundPool(preference.use)
		if wasBound && bound != pool.Ref {
			failover.exit.pendingPool = pool.Ref
			return networkmap.ExitPool{}, false
		}
		if !wasBound {
			_ = failover.exit.pins.bind(preference.use, pool.Ref)
		}
		return pool, true
	case preference.allowManaged:
		return find(func(pool networkmap.ExitPool) bool { return pool.Managed })
	}
	return networkmap.ExitPool{}, false
}

// exitAutoPoolLocked keeps the pool auto uses while Core serves it and one
// of its exit nodes answers; otherwise, once the primaries of the served
// pools were measured (or exitAutoMeasure passed), it takes the one with
// the lowest round trip, pools already pinned first, and keeps it: a
// slightly faster pool is no reason to cut every connection.
func (failover *routeFailover) exitAutoPoolLocked(now time.Time) (networkmap.ExitPool, bool) {
	choice := &failover.exit
	// Once the host pinned a pool, auto chooses among pinned pools only: a
	// pool Core adds is used after an explicit choice.
	pinnedOnly := choice.pins.anyPinned()
	var served []networkmap.ExitPool
	for _, pool := range failover.core.Exits {
		if pool.Status == networkmap.ExitServed && (!pinnedOnly || failover.exitPoolPinned(pool.Ref)) {
			served = append(served, pool)
		}
	}
	if len(served) == 0 {
		return networkmap.ExitPool{}, false
	}
	index := slices.IndexFunc(served, func(pool networkmap.ExitPool) bool { return pool.Ref == choice.pool })
	if index >= 0 && choice.autoSettled && !failover.silentLocked(served[index], now) {
		return served[index], true
	}
	peers := peerIDs(failover.core)
	measured := true
	rtt := func(pool networkmap.ExitPool) time.Duration {
		samples := failover.rtts[peers[pool.Primary]]
		if len(samples) < exitRTTSamples {
			measured = false
		}
		if len(samples) == 0 {
			return time.Duration(1<<63 - 1)
		}
		sorted := slices.Clone(samples)
		slices.Sort(sorted)
		return sorted[len(sorted)/2]
	}
	best := served[0]
	bestRTT := rtt(best)
	for _, pool := range served[1:] {
		if delay := rtt(pool); delay < bestRTT {
			best, bestRTT = pool, delay
		}
	}
	if !choice.autoSettled && (measured || len(served) == 1 || now.Sub(choice.autoSince) >= exitAutoMeasure) {
		choice.autoSettled = true
	} else if !choice.autoSettled && index >= 0 {
		return served[index], true // still measuring: no switch yet
	}
	return best, true
}

func (failover *routeFailover) exitPoolPinned(pool string) bool {
	_, pinned := failover.exit.pins.approved(pool)
	return pinned
}

// silentLocked reports that no candidate of pool answered for
// exitSilentAfter, counting one that never answered from when auto started.
func (failover *routeFailover) silentLocked(pool networkmap.ExitPool, now time.Time) bool {
	peers := peerIDs(failover.core)
	for _, candidate := range pool.Candidates {
		at, answered := failover.pongs[peers[candidate.DeviceID]]
		if !answered {
			at = failover.exit.autoSince // never answered since auto started
		}
		if now.Sub(at) <= exitSilentAfter {
			return false
		}
	}
	return true
}

// chooseExitLocked chooses the pool and the exit node again and reports
// whether the exit route changed. The node in use stays while it is a
// candidate Core does not report FAILED and it answers; otherwise the
// primary when it may answer, else the first candidate that answers, else
// the first that may.
func (failover *routeFailover) chooseExitLocked(now time.Time) bool {
	before := failover.exitRouteLocked()
	choice := &failover.exit
	choice.pendingPool = ""
	pool, found := failover.exitPoolLocked()
	choice.wanted = choice.preference.use != "" || found
	if !found {
		choice.pool, choice.node, choice.reason, choice.ipv6 = "", "", controlplane.RouteSelectionNone, false
		return !equalExitRoutes(before, failover.exitRouteLocked())
	}
	if choice.pool != pool.Ref {
		choice.pool, choice.node = pool.Ref, ""
	}
	if choice.preference.use == routesettings.ExitUseAuto && !choice.autoSettled {
		// Still measuring which pool is nearest: nothing is carried, and
		// nothing pinned, until auto settles.
		choice.node, choice.reason, choice.ipv6, choice.pending = "", controlplane.RouteSelectionNone, false, nil
		return !equalExitRoutes(before, failover.exitRouteLocked())
	}
	alive, stopped := failover.livenessLocked(now)
	peers := peerIDs(failover.core)
	candidate := func(id string) (networkmap.ExitCandidate, bool) {
		index := slices.IndexFunc(pool.Candidates, func(candidate networkmap.ExitCandidate) bool {
			return candidate.DeviceID == id
		})
		if index < 0 {
			return networkmap.ExitCandidate{}, false
		}
		_, peer := peers[id]
		return pool.Candidates[index], peer
	}
	trusted := failover.trustedLocked(pool)
	usable := func(id string) bool {
		found, peer := candidate(id)
		return peer && found.State != networkmap.ExitStateFailed && (trusted == nil || slices.Contains(trusted, id))
	}
	mayCarry := func(id string) bool { return usable(id) && !stopped(id) && !failover.stuckLocked(id, now) }
	next := ""
	switch {
	case pool.Status != networkmap.ExitServed:
	case choice.node != "" && mayCarry(choice.node):
		next = choice.node
	case choice.node != "" && usable(choice.node) && now.Before(choice.nextSwitch):
		// Silent but still a working candidate: switches are spaced.
		next = choice.node
	default:
		next = failover.nextExitNodeLocked(pool, mayCarry, alive, candidate)
	}
	switch {
	case next == "":
		choice.reason = controlplane.RouteSelectionNone
	case next == pool.Primary:
		choice.reason = controlplane.RouteSelectionPrimary
	case next == choice.node && choice.reason == controlplane.RouteSelectionPrimary:
		choice.reason = controlplane.RouteSelectionSticky // Core elected another
	case next != choice.node:
		choice.reason = controlplane.RouteSelectionLocalFailover
	case choice.reason == 0 || choice.reason == controlplane.RouteSelectionNone:
		choice.reason = controlplane.RouteSelectionSticky
	}
	if next != choice.node && choice.node != "" {
		if !choice.lastSwitch.IsZero() && now.Sub(choice.lastSwitch) >= failoverStable {
			choice.backoff = failoverBackoff
		}
		choice.lastSwitch, choice.nextSwitch = now, now.Add(choice.backoff)
		choice.backoff = min(2*choice.backoff, failoverBackoffMax)
	}
	choice.node = next
	if found, _ := candidate(next); next != "" {
		choice.ipv6 = found.IPv6
	} else {
		choice.ipv6 = false
	}
	return !equalExitRoutes(before, failover.exitRouteLocked())
}

// trustedLocked returns the candidates of pool the node may use, nil for
// all of them, and records the others as pending. A host that lets the
// administrator choose trusts what Core sends; otherwise the candidates
// of the first use are pinned, those Core removes are forgotten, and a new
// one waits for approval.
func (failover *routeFailover) trustedLocked(pool networkmap.ExitPool) []string {
	choice := &failover.exit
	choice.pending = nil
	if choice.preference.allowManaged {
		return nil
	}
	candidates := make([]string, 0, len(pool.Candidates))
	for _, candidate := range pool.Candidates {
		candidates = append(candidates, candidate.DeviceID)
	}
	approved, pinned := choice.pins.approved(pool.Ref)
	if !pinned {
		approved = candidates
	}
	approved = slices.DeleteFunc(approved, func(id string) bool { return !slices.Contains(candidates, id) })
	_ = choice.pins.set(pool.Ref, approved) // kept in memory when it cannot be written
	for _, id := range candidates {
		if !slices.Contains(approved, id) {
			choice.pending = append(choice.pending, id)
		}
	}
	return approved
}

// nextExitNodeLocked picks the exit node to move to: the primary when it
// may carry, else the first candidate, in priority order, that answers and
// Core reports OK or DEGRADED, else the first that may carry.
func (failover *routeFailover) nextExitNodeLocked(pool networkmap.ExitPool, mayCarry, alive func(string) bool,
	candidate func(string) (networkmap.ExitCandidate, bool),
) string {
	if pool.Primary != "" && mayCarry(pool.Primary) {
		return pool.Primary
	}
	for _, listed := range pool.Candidates {
		found, peer := candidate(listed.DeviceID)
		if peer && (found.State == networkmap.ExitStateOK || found.State == networkmap.ExitStateDegraded) &&
			alive(listed.DeviceID) && mayCarry(listed.DeviceID) {
			return listed.DeviceID
		}
	}
	for _, listed := range pool.Candidates {
		if mayCarry(listed.DeviceID) {
			return listed.DeviceID
		}
	}
	return ""
}

// exitRouteLocked is the local choice the map carries: nil when no exit
// node is wanted.
func (failover *routeFailover) exitRouteLocked() *networkmap.ExitRoute {
	if !failover.exit.wanted {
		return nil
	}
	return &networkmap.ExitRoute{Pool: failover.exit.pool, Node: failover.exit.node, IPv6: failover.exit.ipv6}
}

func equalExitRoutes(first, second *networkmap.ExitRoute) bool {
	if first == nil || second == nil {
		return first == second
	}
	return *first == *second
}

// livenessLocked returns whether a peer answers (its last pong, direct or
// through the relay, is recent) and whether it stopped (it answered before
// and no longer does). One that never answered is neither.
func (failover *routeFailover) livenessLocked(now time.Time) (alive, stopped func(string) bool) {
	peers := peerIDs(failover.core)
	pongOf := func(stableID string) (time.Time, bool) {
		id, found := peers[stableID]
		if !found {
			return time.Time{}, false
		}
		at, answered := failover.pongs[id]
		return at, answered
	}
	alive = func(stableID string) bool {
		at, answered := pongOf(stableID)
		return answered && now.Sub(at) <= failoverAliveWithin
	}
	stopped = func(stableID string) bool {
		at, answered := pongOf(stableID)
		return answered && now.Sub(at) > failoverAliveWithin
	}
	return alive, stopped
}

// exitPeersLocked returns the candidates of the pool in use when there is
// another to fail over to: the peers to ping through the relay.
func (failover *routeFailover) exitPeersLocked() []uint64 {
	pool, found := failover.exitPoolLocked()
	if !found || len(pool.Candidates) < 2 {
		return nil
	}
	peers := peerIDs(failover.core)
	ids := make([]uint64, 0, len(pool.Candidates))
	for _, candidate := range pool.Candidates {
		if id, found := peers[candidate.DeviceID]; found {
			ids = append(ids, id)
		}
	}
	return ids
}

// ExitView is the exit node this node sends its Internet traffic to, for
// status.
type ExitView struct {
	// Use is what the host's settings ask: a pool, auto, or empty.
	Use string
	// Pool is the reference of the pool used and PoolName its name; empty
	// when the settings name a pool Core does not grant.
	Pool     string
	PoolName string
	// ExitNode is a device ID and ExitNodeName its name; empty when none
	// carries the traffic.
	ExitNode     string
	ExitNodeName string
	// Via is primary, local_failover, sticky or none.
	Via string
	// Pending are exit nodes Core added to the pool that carry no traffic
	// until a user approves them, as device IDs, with their names.
	Pending      []string
	PendingNames []string
	// PendingPool is another pool given the name the settings use, which
	// waits for approval before it is used.
	PendingPool string
}

// exitSelection returns the exit node used and why, as reported to Core
// (mtcp-v1 §7.7) and shown in status; nil when no exit node is wanted.
func (failover *routeFailover) exitSelection() (controlplane.RouteExitSelection, *ExitView, exitSticky) {
	failover.mu.Lock()
	defer failover.mu.Unlock()
	choice := failover.exit
	sticky := exitSticky{pool: choice.pool, node: choice.node}
	if !choice.wanted {
		return controlplane.RouteExitSelection{}, nil, sticky
	}
	view := &ExitView{
		Use: choice.preference.use, Pool: choice.pool, ExitNode: choice.node, Via: "none",
		Pending: slices.Clone(choice.pending), PendingPool: choice.pendingPool,
	}
	if view.Use == "" {
		view.Use = "managed"
	}
	for _, pool := range failover.core.Exits {
		if pool.Ref == choice.pool {
			view.PoolName = pool.Name
		}
	}
	for _, id := range view.Pending {
		name := id
		for _, peer := range failover.core.Peers {
			if peer.StableID == id && peer.Name != "" {
				name = peer.Name
			}
		}
		view.PendingNames = append(view.PendingNames, name)
	}
	for _, peer := range failover.core.Peers {
		if peer.StableID == choice.node {
			view.ExitNodeName = peer.Name
		}
	}
	switch choice.reason {
	case controlplane.RouteSelectionPrimary:
		view.Via = "primary"
	case controlplane.RouteSelectionLocalFailover:
		view.Via = "local_failover"
	case controlplane.RouteSelectionSticky:
		view.Via = "sticky"
	}
	report := controlplane.RouteExitSelection{Pool: choice.pool, ExitNode: choice.node, Reason: choice.reason}
	if report.ExitNode == "" {
		report.Reason = controlplane.RouteSelectionNone
	}
	return report, view, sticky
}

// watchExitPreference reads the host's exit preference every interval and,
// when it changes the exit route, has apply apply the map again, until ctx
// ends or apply fails.
func watchExitPreference(ctx context.Context, failover *routeFailover, read func() (exitPreference, bool),
	interval time.Duration, apply func() error,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		preference, known := read()
		if !known || !failover.setExitPreference(preference) {
			continue
		}
		if err := apply(); err != nil {
			return
		}
	}
}

func (s *Service) setExit(view *ExitView, sticky exitSticky) {
	s.routeSitesMu.Lock()
	defer s.routeSitesMu.Unlock()
	s.exit, s.exitSticky = view, sticky
}

// clearExit forgets the session's exit view; the sticky choice stays for
// the next session.
func (s *Service) clearExit() {
	s.routeSitesMu.Lock()
	defer s.routeSitesMu.Unlock()
	s.exit = nil
}

func (s *Service) exitSnapshot() *ExitView {
	s.routeSitesMu.Lock()
	defer s.routeSitesMu.Unlock()
	if s.exit == nil {
		return nil
	}
	view := *s.exit
	return &view
}

func (s *Service) exitStickySnapshot() exitSticky {
	s.routeSitesMu.Lock()
	defer s.routeSitesMu.Unlock()
	return s.exitSticky
}

// exitActivityDataPlane reports what the node sent through its exit node.
type exitActivityDataPlane interface {
	ExitActivity() dataplane.ExitActivity
}

type exitRouteDataPlane interface {
	ExitRoute() dataplane.ExitRouteStatus
}

// exitRouteStatus is how the data plane sends the Internet through the exit
// node.
func (s *Service) exitRouteStatus() dataplane.ExitRouteStatus {
	if s == nil || s.dataPlane == nil || !s.enableExits {
		return dataplane.ExitRouteStatus{}
	}
	s.dataPlaneMu.Lock()
	defer s.dataPlaneMu.Unlock()
	if reporter, supported := s.dataPlane.(exitRouteDataPlane); supported {
		return reporter.ExitRoute()
	}
	return dataplane.ExitRouteStatus{}
}

// ExitApproval is what approving a pool's new exit nodes did.
type ExitApproval struct {
	Pool     string
	Approved []string
}

// ErrNothingToApprove means none of the exit nodes or pools named waits
// for approval.
var ErrNothingToApprove = errors.New("daemon: nothing named waits for approval")

// ApproveExitNodes approves what ids name of what waits: exit nodes Core
// added to the pool in use (device IDs) and a pool given the name the
// settings use (its reference). Naming them keeps Core from slipping in
// another between status and approval. They are used from the next choice,
// within a second.
func (s *Service) ApproveExitNodes(_ context.Context, ids []string) (ExitApproval, error) {
	view := s.exitSnapshot()
	if view == nil || s.exitPins == nil {
		return ExitApproval{}, ErrNothingToApprove
	}
	result := ExitApproval{Pool: view.Pool}
	if view.PendingPool != "" && slices.Contains(ids, view.PendingPool) {
		if err := s.exitPins.bind(view.Use, view.PendingPool); err != nil {
			return ExitApproval{}, err
		}
		result.Pool, result.Approved = view.PendingPool, []string{view.PendingPool}
	}
	var nodes []string
	for _, id := range view.Pending {
		if slices.Contains(ids, id) {
			nodes = append(nodes, id)
		}
	}
	if len(nodes) != 0 && view.Pool != "" {
		approved, _ := s.exitPins.approved(view.Pool)
		if err := s.exitPins.set(view.Pool, append(approved, nodes...)); err != nil {
			return ExitApproval{}, err
		}
		result.Approved = append(result.Approved, nodes...)
	}
	if len(result.Approved) == 0 {
		return ExitApproval{}, ErrNothingToApprove
	}
	s.routeSitesMu.Lock()
	if s.exit != nil {
		s.exit.Pending = slices.DeleteFunc(slices.Clone(s.exit.Pending), func(id string) bool {
			return slices.Contains(nodes, id)
		})
	}
	s.routeSitesMu.Unlock()
	return result, nil
}
