package daemon

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
)

// Local router failover (design §6.3): a consumer that sends to a Site and
// hears nothing back, while its router stopped answering path probes and a
// standby of the Site still answers, sends the Site's traffic through that
// standby until Core elects again. Core's choice stays the rule; this only
// covers the time Core needs to see a router die.
const (
	// failoverSuspectAfter is how long packets to a Site may go unanswered
	// before its router is suspected.
	failoverSuspectAfter = 5 * time.Second
	// failoverAliveWithin is how recent a router's last path pong must be to
	// count it alive: direct paths are probed about every 3 seconds.
	failoverAliveWithin = 4 * time.Second
	// failoverIdleAfter is how long a Site must carry no traffic before a
	// local choice goes back to Core's, so a flow is not cut twice.
	failoverIdleAfter = time.Minute
	// failoverFollowWithin bounds how long a local choice outlives Core
	// electing another router.
	failoverFollowWithin = 5 * time.Minute
	// failoverBackoff and failoverBackoffMax space the local switches of one
	// Site; failoverStable resets the spacing.
	failoverBackoff    = 10 * time.Second
	failoverBackoffMax = 5 * time.Minute
	failoverStable     = 10 * time.Minute
	// failoverTick is how often Sites are judged.
	failoverTick = time.Second
)

// failoverSite is what is remembered of one Site with a local choice or a
// recent switch.
type failoverSite struct {
	// chosen is the router chosen locally (a StableID); empty: Core's.
	chosen string
	// coreAtChoice is Core's primary when chosen was made, and coreMovedAt
	// when Core elected another since.
	coreAtChoice string
	coreMovedAt  time.Time
	nextSwitch   time.Time
	backoff      time.Duration
	lastSwitch   time.Time
}

// routeFailover holds the local router choices of one control session. It
// is safe for concurrent use.
type routeFailover struct {
	mu    sync.Mutex
	clock func() time.Time
	// pongs is each peer's last authenticated direct path proof, and rtts
	// its last round trips (exit node design §9.2).
	pongs map[uint64]time.Time
	rtts  map[uint64][]time.Duration
	sites map[string]*failoverSite
	// core is the last map from Core, unchanged.
	core networkmap.Snapshot
	// exit is the exit node chosen (exit_choice.go); exitHeld, when it
	// reports true, holds it (a captive portal: the network under the exit
	// node is at fault, not the exit node).
	exit     exitChoice
	exitHeld func() bool
	// resolverPeers are the resolver Devices of the map's DNS zones with
	// another resolver, by mesh address, resolverOrder those peers in the
	// zones' order, askedAt their last question, pinged since when each
	// peer is pinged through the relay, livenessList the peers pinged,
	// livenessWake a nudge to ping a resolver newly asked, and
	// livenessClosed set once the session ends (dns_liveness.go).
	resolverPeers  map[netip.Addr]uint64
	resolverOrder  []uint64
	askedAt        map[uint64]time.Time
	pinged         map[uint64]time.Time
	livenessList   []uint64
	livenessWake   chan struct{}
	livenessClosed bool
	// livenessSetMu orders the lists handed to the relay
	// (syncRelayLiveness).
	livenessSetMu sync.Mutex
}

func newRouteFailover(clock func() time.Time) *routeFailover {
	return &routeFailover{
		clock: clock, pongs: map[uint64]time.Time{}, rtts: map[uint64][]time.Duration{},
		sites: map[string]*failoverSite{}, askedAt: map[uint64]time.Time{}, livenessWake: make(chan struct{}, 1),
	}
}

// routeFailoverObserver sends path proofs to the path controller and to the
// failover, without blocking either.
type routeFailoverObserver struct {
	next interface {
		ObservePath(pathdiscovery.PathObservation)
	}
	failover *routeFailover
}

func (observer routeFailoverObserver) ObservePath(observation pathdiscovery.PathObservation) {
	if observer.next != nil {
		observer.next.ObservePath(observation)
	}
	observer.failover.ObservePath(observation)
}

// ObserveRelayPong passes on that a router answered a PING through the
// relay (disco-v2 §3.2.1).
func (observer routeFailoverObserver) ObserveRelayPong(peerID uint64, at time.Time) {
	observer.failover.ObserveRelayPong(peerID, at)
}

// ObserveRelayPong records that a peer answered through the relay: it is
// up, though no direct path to it is proven. It counts like a direct pong.
func (failover *routeFailover) ObserveRelayPong(peerID uint64, at time.Time) {
	if failover == nil || peerID == 0 || at.IsZero() {
		return
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	if at.After(failover.pongs[peerID]) {
		failover.pongs[peerID] = at
	}
}

// routerPeers returns the peers that route a Site this node is sent, and
// the candidates of the exit pool it uses, the ones to ping through the
// relay when no direct path to them is proven.
func (failover *routeFailover) routerPeers() []uint64 {
	if failover == nil {
		return nil
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	peers := peerIDs(failover.core)
	var ids []uint64
	for _, route := range failover.core.Routes {
		if route.Status != networkmap.RouteServed || len(route.Candidates) < 2 {
			continue // with one router there is nothing to fail over to
		}
		for _, candidate := range route.Candidates {
			if id, found := peers[candidate]; found {
				ids = append(ids, id)
			}
		}
	}
	ids = append(ids, failover.exitPeersLocked()...)
	slices.Sort(ids)
	return slices.Compact(ids)
}

// ObservePath records that a peer answered on a direct path.
func (failover *routeFailover) ObservePath(observation pathdiscovery.PathObservation) {
	if failover == nil || observation.PeerID == 0 || observation.ObservedAt.IsZero() {
		return
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	if observation.ObservedAt.After(failover.pongs[observation.PeerID]) {
		failover.pongs[observation.PeerID] = observation.ObservedAt
	}
	if observation.RoundTrip > 0 {
		failover.rtts[observation.PeerID] = append(failover.rtts[observation.PeerID], observation.RoundTrip)
		samples := failover.rtts[observation.PeerID]
		failover.rtts[observation.PeerID] = samples[max(0, len(samples)-exitRTTSamples):]
	}
}

// effective records snapshot as Core's map and returns it with the local
// choices applied. A choice ends when its router is no longer a candidate of
// a served Site, or when Core elected it too.
func (failover *routeFailover) effective(snapshot networkmap.Snapshot) networkmap.Snapshot {
	if failover == nil {
		return snapshot
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	failover.core = snapshot
	failover.resolverPeers, failover.resolverOrder = resolverPeersOf(snapshot)
	now := failover.clock()
	peers := peerIDs(snapshot)
	for ref, site := range failover.sites {
		route, found := routeOf(snapshot, ref)
		if !found {
			delete(failover.sites, ref)
			continue
		}
		if site.chosen == "" {
			continue
		}
		_, peer := peers[site.chosen]
		if route.Status != networkmap.RouteServed || !slices.Contains(route.Candidates, site.chosen) || !peer ||
			route.Primary == site.chosen {
			site.chosen = ""
			continue
		}
		if route.Primary != site.coreAtChoice && site.coreMovedAt.IsZero() {
			site.coreMovedAt = now
		}
	}
	// Forget the proofs of peers the map no longer holds.
	current := make(map[uint64]struct{}, len(peers))
	for _, id := range peers {
		current[id] = struct{}{}
	}
	for id := range failover.pongs {
		if _, kept := current[id]; !kept {
			delete(failover.pongs, id)
		}
	}
	for id := range failover.rtts {
		if _, kept := current[id]; !kept {
			delete(failover.rtts, id)
		}
	}
	for id := range failover.askedAt {
		if !slices.Contains(failover.resolverOrder, id) {
			delete(failover.askedAt, id)
		}
	}
	failover.chooseExitLocked(now)
	return failover.applyLocked()
}

// current returns Core's last map with the local choices applied.
func (failover *routeFailover) current() networkmap.Snapshot {
	failover.mu.Lock()
	defer failover.mu.Unlock()
	return failover.applyLocked()
}

func (failover *routeFailover) applyLocked() networkmap.Snapshot {
	snapshot := failover.core
	snapshot.ExitRoute = failover.exitRouteLocked()
	changed := false
	for _, site := range failover.sites {
		if site.chosen != "" {
			changed = true
			break
		}
	}
	if !changed {
		return snapshot
	}
	routes := slices.Clone(snapshot.Routes)
	for index := range routes {
		if site := failover.sites[routes[index].Ref]; site != nil && site.chosen != "" {
			routes[index].Primary = site.chosen
		}
	}
	snapshot.Routes = routes
	return snapshot
}

// judge looks at every served Site once and reports whether a local choice
// changed, so the map must be applied again.
func (failover *routeFailover) judge(activity []dataplane.RoutedActivity) bool {
	if failover == nil {
		return false
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	now := failover.clock()
	// A router answers when its last pong (direct, or through the relay)
	// is recent, and has stopped when it answered before and no longer does.
	// One that never answered (not probed yet, or too old to answer relayed
	// pings) is neither: it is never left for silence the node cannot
	// measure.
	alive, stopped := failover.livenessLocked(now)
	changed := false
	for _, route := range failover.core.Routes {
		if route.Status != networkmap.RouteServed || route.Primary == "" {
			continue
		}
		site := failover.sites[route.Ref]
		seen := activityOf(activity, route.Ref)
		idle := now.Sub(latest(seen.LastSent, seen.LastAnswered)) >= failoverIdleAfter
		if site != nil && site.chosen != "" {
			// Back to Core's choice once that does not cut a flow: Core
			// elected another router, or its router answers again.
			back := (!site.coreMovedAt.IsZero() && (idle || now.Sub(site.coreMovedAt) >= failoverFollowWithin)) ||
				(site.coreMovedAt.IsZero() && idle && !stopped(route.Primary))
			if back {
				site.chosen, changed = "", true
			}
		}
		active := route.Primary
		if site != nil && site.chosen != "" {
			active = site.chosen
		}
		// Waiting counts from the last switch at the earliest: what the old
		// router left unanswered says nothing of the new one.
		waiting := seen.WaitingSince
		if site != nil && !waiting.IsZero() && site.lastSwitch.After(waiting) {
			waiting = site.lastSwitch
		}
		suspected := !waiting.IsZero() && now.Sub(waiting) >= failoverSuspectAfter &&
			now.Sub(seen.LastSent) < failoverSuspectAfter
		if !suspected || len(route.Candidates) < 2 || !stopped(active) {
			// A router that still answers keeps the Site: the host in the
			// Site may be the one that does not.
			continue
		}
		if site == nil {
			site = &failoverSite{backoff: failoverBackoff}
			failover.sites[route.Ref] = site
		}
		if now.Before(site.nextSwitch) {
			continue
		}
		next := ""
		for _, candidate := range route.Candidates {
			if candidate != active && alive(candidate) {
				next = candidate
				break
			}
		}
		if next == "" {
			continue // none answers: wait for Core, or for one to answer
		}
		if !site.lastSwitch.IsZero() && now.Sub(site.lastSwitch) >= failoverStable {
			site.backoff = failoverBackoff
		}
		site.chosen, site.coreAtChoice, site.coreMovedAt = next, route.Primary, time.Time{}
		if next == route.Primary {
			site.chosen = ""
		}
		site.lastSwitch, site.nextSwitch = now, now.Add(site.backoff)
		site.backoff = min(2*site.backoff, failoverBackoffMax)
		changed = true
	}
	if failover.chooseExitLocked(now) {
		changed = true
	}
	return changed
}

// choices returns the Sites routed through a router of this node's choosing,
// by reference, for status.
func (failover *routeFailover) choices() map[string]string {
	if failover == nil {
		return nil
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	chosen := map[string]string{}
	for ref, site := range failover.sites {
		if site.chosen != "" {
			chosen[ref] = site.chosen
		}
	}
	return chosen
}

func peerIDs(snapshot networkmap.Snapshot) map[string]uint64 {
	ids := make(map[string]uint64, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		ids[peer.StableID] = peer.ID
	}
	return ids
}

func routeOf(snapshot networkmap.Snapshot, ref string) (networkmap.SiteRoute, bool) {
	for _, route := range snapshot.Routes {
		if route.Ref == ref {
			return route, true
		}
	}
	return networkmap.SiteRoute{}, false
}

func activityOf(activity []dataplane.RoutedActivity, ref string) dataplane.RoutedActivity {
	for _, site := range activity {
		if site.Ref == ref {
			return site
		}
	}
	return dataplane.RoutedActivity{Ref: ref}
}

func latest(first, second time.Time) time.Time {
	if first.After(second) {
		return first
	}
	return second
}

// routedActivityDataPlane reports what this node sent to each Site and heard
// back.
type routedActivityDataPlane interface {
	RoutedActivity() []dataplane.RoutedActivity
}

// runRouteFailover judges the session's Sites every failoverTick and, when a
// local choice changed, has apply apply the map again (failover.current);
// it stops at the first failure.
func runRouteFailover(ctx context.Context, failover *routeFailover, read func() []dataplane.RoutedActivity,
	readExit func() dataplane.ExitActivity, apply func() error,
) {
	ticker := time.NewTicker(failoverTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if readExit != nil {
			failover.observeExitActivity(readExit())
		}
		if !failover.judge(read()) {
			continue
		}
		if err := apply(); err != nil {
			return
		}
	}
}

// RouteSiteView is the router this node sends one Site's traffic to, for
// status.
type RouteSiteView struct {
	Ref string
	// Name is the Site's display name; empty from an older Core.
	Name string
	// Prefixes are the Site's prefixes the rules grant: the map names a
	// Site only by its reference.
	Prefixes   []netip.Prefix
	Router     string // a device ID; empty when the Site is not served
	RouterName string
	// Via is primary, local_failover or none.
	Via string
}

// selections returns, for each Site of Core's last map, the router traffic
// goes to and why: what the node reports to Core (mtcp-v1 §8.3) and shows in
// status.
func (failover *routeFailover) selections() ([]controlplane.RouteSiteSelection, []RouteSiteView) {
	failover.mu.Lock()
	defer failover.mu.Unlock()
	names := make(map[string]string, len(failover.core.Peers))
	for _, peer := range failover.core.Peers {
		names[peer.StableID] = peer.Name
	}
	reports := make([]controlplane.RouteSiteSelection, 0, len(failover.core.Routes))
	views := make([]RouteSiteView, 0, len(failover.core.Routes))
	for _, route := range failover.core.Routes {
		report := controlplane.RouteSiteSelection{Ref: route.Ref, Reason: controlplane.RouteSelectionNone}
		view := RouteSiteView{Ref: route.Ref, Name: route.Name, Prefixes: slices.Clone(route.Prefixes), Via: "none"}
		if route.Status == networkmap.RouteServed && route.Primary != "" {
			report.Router, report.Reason, view.Via = route.Primary, controlplane.RouteSelectionPrimary, "primary"
			if site := failover.sites[route.Ref]; site != nil && site.chosen != "" {
				report.Router, report.Reason, view.Via = site.chosen, controlplane.RouteSelectionLocalFailover,
					"local_failover"
			}
			view.Router, view.RouterName = report.Router, names[report.Router]
		}
		reports = append(reports, report)
		views = append(views, view)
	}
	return reports, views
}

func (s *Service) setRouteSites(views []RouteSiteView) {
	s.routeSitesMu.Lock()
	defer s.routeSitesMu.Unlock()
	s.routeSites = slices.Clone(views)
}

func (s *Service) routeSitesSnapshot() []RouteSiteView {
	s.routeSitesMu.Lock()
	defer s.routeSitesMu.Unlock()
	return slices.Clone(s.routeSites)
}

// exitAnsweredAfter reports that the exit node in use answered after at.
func (failover *routeFailover) exitAnsweredAfter(at time.Time) bool {
	failover.mu.Lock()
	defer failover.mu.Unlock()
	id, found := peerIDs(failover.core)[failover.exit.node]
	if !found {
		return false
	}
	pong, answered := failover.pongs[id]
	return answered && pong.After(at)
}
