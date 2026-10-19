package mtcp

import (
	"context"
	"errors"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

// RouteHealthStreams stores a router's Site health (mtcp-v1 §8.3); the
// map stream service implements it when its recorder can.
type RouteHealthStreams interface {
	ReportRouteHealth(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key,
		sites []mapsession.SiteHealth) error
}

const (
	// A router reports on change and every 10 s (mtcp-v1 §14).
	routeHealthBurst = 2
	routeHealthRate  = 0.5
)

// routeHealthPacing stores a session's RouteHealthReports at most at the
// budget's rate. A report over it is kept, replacing any kept before, and
// stored when the budget allows. One store runs at a time (busy); mu is
// never held across it.
type routeHealthPacing struct {
	mu      sync.Mutex
	running sync.WaitGroup
	stopped bool
	busy    bool
	budget  rateBudget
	waiting *keptRouteHealth
	timer   endpointTimer
}

// keptRouteHealth is a report and the node key the session had when it
// arrived.
type keptRouteHealth struct {
	sites   []mapsession.SiteHealth
	nodeKey node.Key
}

var routeHealthStates = map[mtcpv1.RouteHealthReport_SiteHealth_State]mapsession.RouteHealthState{
	mtcpv1.RouteHealthReport_SiteHealth_OK:       mapsession.RouteHealthOK,
	mtcpv1.RouteHealthReport_SiteHealth_DEGRADED: mapsession.RouteHealthDegraded,
	mtcpv1.RouteHealthReport_SiteHealth_FAILED:   mapsession.RouteHealthFailed,
}

// routeHealth validates a RouteHealthReport and keeps the Sites of the
// served routes the session was sent.
func (conversation *conversation) routeHealth(report *mtcpv1.RouteHealthReport) error {
	if !conversation.session.Supports("router.health1") || !conversation.session.Supports("router.subnet.v1") {
		return Violation(mtcpv1.Error_INVALID, "route health without router.health1 and router.subnet.v1")
	}
	sites := make([]mapsession.SiteHealth, 0, len(report.GetSites()))
	for _, reported := range report.GetSites() {
		state, known := routeHealthStates[reported.GetState()]
		if !known {
			return Violation(mtcpv1.Error_INVALID, "invalid route health state")
		}
		sites = append(sites, mapsession.SiteHealth{Ref: reported.GetSiteRef(), State: state, Code: reported.GetCode()})
	}
	if !mapsession.ValidSiteHealth(sites) {
		return Violation(mtcpv1.Error_INVALID, "invalid route health report")
	}
	if _, ok := conversation.application.options.Streams.(RouteHealthStreams); !ok {
		return nil
	}
	snapshot, ok := conversation.sink.snapshot()
	if !ok {
		return nil // no map yet; the router reports again within 10 s
	}
	conversation.reportRouteHealth(servedOnly(sites, snapshot.Routes().Served()))
	return nil
}

// servedOnly keeps the Sites of served: a router reports only on what Core
// sent it, and nothing else is stored.
func servedOnly(sites []mapsession.SiteHealth, served []mapsession.ServedSite) []mapsession.SiteHealth {
	refs := make(map[string]struct{}, len(served))
	for _, site := range served {
		refs[site.Ref] = struct{}{}
	}
	kept := make([]mapsession.SiteHealth, 0, len(sites))
	for _, site := range sites {
		if _, ok := refs[site.Ref]; ok {
			kept = append(kept, site)
		}
	}
	return kept
}

// reportRouteHealth stores sites now, or keeps them until the budget allows.
func (conversation *conversation) reportRouteHealth(sites []mapsession.SiteHealth) {
	pacing := &conversation.routeHealthPacing
	pacing.mu.Lock()
	if pacing.stopped {
		pacing.mu.Unlock()
		return
	}
	pacing.waiting = &keptRouteHealth{sites: sites, nodeKey: conversation.currentKey()}
	next, ok, refused := conversation.claimRouteHealthLocked()
	pacing.mu.Unlock()
	if refused {
		conversation.application.options.Metrics.limited(limitRouteHealth)
	}
	if ok {
		conversation.storeRouteHealths(next)
	}
}

// flushRouteHealth is the timer: it stores the kept report once the budget
// allows.
func (conversation *conversation) flushRouteHealth() {
	pacing := &conversation.routeHealthPacing
	pacing.mu.Lock()
	next, ok, _ := conversation.claimRouteHealthLocked()
	pacing.mu.Unlock()
	if ok {
		conversation.storeRouteHealths(next)
	}
}

func (conversation *conversation) claimRouteHealthLocked() (kept *keptRouteHealth, ok, refused bool) {
	pacing := &conversation.routeHealthPacing
	if pacing.stopped || pacing.busy || pacing.waiting == nil {
		return nil, false, false
	}
	if wait, admitted := pacing.budget.spend(conversation.application.now(), 1); !admitted {
		delay := max(wait, time.Millisecond)
		if pacing.timer == nil {
			pacing.timer = conversation.application.routeHealthTimer(delay, conversation.flushRouteHealth)
		} else {
			pacing.timer.Reset(delay)
		}
		return nil, false, true
	}
	kept = pacing.waiting
	pacing.waiting, pacing.busy = nil, true
	pacing.running.Add(1)
	return kept, true, false
}

func (conversation *conversation) storeRouteHealths(kept *keptRouteHealth) {
	pacing := &conversation.routeHealthPacing
	for {
		conversation.storeRouteHealth(kept)
		pacing.mu.Lock()
		pacing.busy = false
		pacing.running.Done()
		next, ok, _ := conversation.claimRouteHealthLocked()
		pacing.mu.Unlock()
		if !ok {
			return
		}
		kept = next
	}
}

// storeRouteHealth stores one report made while kept.nodeKey was the
// session's key; a failure waits for the router's next report.
func (conversation *conversation) storeRouteHealth(kept *keptRouteHealth) {
	conversation.storeRouteHealthWithin(conversation.session.ctx, kept)
}

// routeHealthLastStore bounds storing the report kept when a session ends.
const routeHealthLastStore = 2 * time.Second

func (conversation *conversation) storeRouteHealthWithin(ctx context.Context, kept *keptRouteHealth) {
	streams, ok := conversation.application.options.Streams.(RouteHealthStreams)
	if !ok || !kept.nodeKey.IsValid() || kept.nodeKey != conversation.currentKey() {
		return
	}
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return
	}
	if err := streams.ReportRouteHealth(ctx, machine, kept.nodeKey, kept.sites); err != nil &&
		!errors.Is(err, context.Canceled) {
		conversation.application.options.Logger.DebugContext(ctx, "mtcp route health not stored", "error", err)
	}
}

// stopRouteHealthPacing ends the pacing when the session ends: it waits for
// a store already running, then stores a kept report once, whatever the
// budget. That is a router's last word, such as going_away when it stops
// (design §6.2): one store more per session at most.
func (conversation *conversation) stopRouteHealthPacing() {
	pacing := &conversation.routeHealthPacing
	pacing.mu.Lock()
	pacing.stopped = true
	kept := pacing.waiting
	pacing.waiting = nil
	if pacing.timer != nil {
		pacing.timer.Stop()
	}
	pacing.mu.Unlock()
	pacing.running.Wait()
	if kept != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(conversation.session.ctx), routeHealthLastStore)
		defer cancel()
		conversation.storeRouteHealthWithin(ctx, kept)
	}
}
