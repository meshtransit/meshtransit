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

// RouteSelectionStreams stores the router a node uses for each Site and
// the exit node it uses (mtcp-v1 §8.3); the map stream service implements
// it when its recorder can.
type RouteSelectionStreams interface {
	ReportRouteSelection(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key,
		sites []mapsession.SiteSelection, exit *mapsession.ExitSelection) error
}

// routeSelectionReport is what one RouteSelectionReport stores.
type routeSelectionReport struct {
	sites []mapsession.SiteSelection
	exit  *mapsession.ExitSelection
}

const (
	// A node reports on change and every 60 s (mtcp-v1 §14).
	routeSelectionBurst = 2
	routeSelectionRate  = 0.2
)

var routeSelectionReasons = map[mtcpv1.RouteSelectionReport_SiteSelection_Reason]mapsession.RouteSelectionReason{
	mtcpv1.RouteSelectionReport_SiteSelection_PRIMARY:        mapsession.RouteSelectionPrimary,
	mtcpv1.RouteSelectionReport_SiteSelection_LOCAL_FAILOVER: mapsession.RouteSelectionLocalFailover,
	mtcpv1.RouteSelectionReport_SiteSelection_NONE:           mapsession.RouteSelectionNone,
}

var exitSelectionReasons = map[mtcpv1.RouteSelectionReport_ExitSelection_Reason]mapsession.RouteSelectionReason{
	mtcpv1.RouteSelectionReport_ExitSelection_PRIMARY:        mapsession.RouteSelectionPrimary,
	mtcpv1.RouteSelectionReport_ExitSelection_LOCAL_FAILOVER: mapsession.RouteSelectionLocalFailover,
	mtcpv1.RouteSelectionReport_ExitSelection_STICKY:         mapsession.RouteSelectionSticky,
	mtcpv1.RouteSelectionReport_ExitSelection_NONE:           mapsession.RouteSelectionNone,
}

// latestPacing stores a session's reports at most at the budget's rate. A
// report over it is kept, replacing any kept before, and stored when the
// budget allows; one kept when the session ends is stored then, once. One
// store runs at a time (busy); mu is never held across it.
type latestPacing[T any] struct {
	mu      sync.Mutex
	running sync.WaitGroup
	stopped bool
	busy    bool
	budget  rateBudget
	waiting *keptReport[T]
	timer   endpointTimer
}

// keptReport is a report and the node key the session had when it arrived.
type keptReport[T any] struct {
	value   T
	nodeKey node.Key
}

// routeSelection validates a RouteSelectionReport and keeps the Sites and
// the Exit Pool of the routes the session was sent. Sites need
// routes.subnet.v1 and the exit routes.exit.v1, both routes.selection1.
func (conversation *conversation) routeSelection(report *mtcpv1.RouteSelectionReport) error {
	subnet, exits := conversation.session.Supports("routes.subnet.v1"), conversation.session.Supports("routes.exit.v1")
	if !conversation.session.Supports("routes.selection1") || (!subnet && !exits) ||
		(len(report.GetSites()) > 0 && !subnet) || (report.GetExit() != nil && !exits) {
		return Violation(mtcpv1.Error_INVALID, "route selection without routes.selection1 and the routes capability")
	}
	exit, valid := readExitSelection(report.GetExit())
	if !valid {
		return Violation(mtcpv1.Error_INVALID, "invalid exit selection")
	}
	sites := make([]mapsession.SiteSelection, 0, len(report.GetSites()))
	for _, reported := range report.GetSites() {
		reason, known := routeSelectionReasons[reported.GetReason()]
		if !known {
			return Violation(mtcpv1.Error_INVALID, "invalid route selection reason")
		}
		site := mapsession.SiteSelection{Ref: reported.GetSiteRef(), Reason: reason}
		if reported.GetRouter() != "" {
			router, err := node.ParseID(reported.GetRouter())
			if err != nil {
				return Violation(mtcpv1.Error_INVALID, "invalid route selection router")
			}
			site.Router = router
		}
		sites = append(sites, site)
	}
	if !mapsession.ValidSiteSelection(sites) {
		return Violation(mtcpv1.Error_INVALID, "invalid route selection report")
	}
	if _, ok := conversation.application.options.Streams.(RouteSelectionStreams); !ok {
		return nil
	}
	snapshot, ok := conversation.sink.snapshot()
	if !ok {
		return nil // no map yet; the node reports again on its first map
	}
	routes := snapshot.Routes()
	conversation.offerRouteSelection(selectedReport(sites, exit, routes.Sites(), routes.Exits()))
	return nil
}

// selectedReport keeps of a report what Core sent the session: its Sites'
// routers and its Exit Pool's exit node. Sites are stored even when empty:
// each report carries the whole set (mtcp-v1 §8.3).
func selectedReport(sites []mapsession.SiteSelection, exit *mapsession.ExitSelection,
	siteRoutes []mapsession.SiteRoute, exitRoutes []mapsession.ExitPoolRoute,
) routeSelectionReport {
	return routeSelectionReport{
		sites: mapsession.SelectedOnly(sites, siteRoutes),
		exit:  mapsession.SelectedExitOnly(exit, exitRoutes),
	}
}

// readExitSelection reads an absent exit selection (nil, valid), or one
// naming a pool with a known reason and an exit node, in canonical text,
// exactly when it uses one.
func readExitSelection(reported *mtcpv1.RouteSelectionReport_ExitSelection) (*mapsession.ExitSelection, bool) {
	if reported == nil {
		return nil, true
	}
	reason, known := exitSelectionReasons[reported.GetReason()]
	if !known {
		return nil, false
	}
	exit := mapsession.ExitSelection{Ref: reported.GetPoolRef(), Reason: reason}
	if reported.GetExitNode() != "" {
		exitNode, err := node.ParseID(reported.GetExitNode())
		if err != nil || exitNode.String() != reported.GetExitNode() {
			return nil, false
		}
		exit.Node = exitNode
	}
	if !mapsession.ValidExitSelection(exit) {
		return nil, false
	}
	return &exit, true
}

// offerRouteSelection stores a report now, or keeps it until the budget
// allows.
func (conversation *conversation) offerRouteSelection(report routeSelectionReport) {
	pacing := &conversation.routeSelectionPacing
	pacing.mu.Lock()
	if pacing.stopped {
		pacing.mu.Unlock()
		return
	}
	pacing.waiting = &keptReport[routeSelectionReport]{value: report, nodeKey: conversation.currentKey()}
	next, ok, refused := conversation.claimRouteSelectionLocked()
	pacing.mu.Unlock()
	if refused {
		conversation.application.options.Metrics.limited(limitRouteSelection)
	}
	if ok {
		conversation.storeRouteSelections(next)
	}
}

// flushRouteSelection is the timer: it stores the kept report once the
// budget allows.
func (conversation *conversation) flushRouteSelection() {
	pacing := &conversation.routeSelectionPacing
	pacing.mu.Lock()
	next, ok, _ := conversation.claimRouteSelectionLocked()
	pacing.mu.Unlock()
	if ok {
		conversation.storeRouteSelections(next)
	}
}

func (conversation *conversation) claimRouteSelectionLocked() (
	kept *keptReport[routeSelectionReport], ok, refused bool,
) {
	pacing := &conversation.routeSelectionPacing
	if pacing.stopped || pacing.busy || pacing.waiting == nil {
		return nil, false, false
	}
	if wait, admitted := pacing.budget.spend(conversation.application.now(), 1); !admitted {
		delay := max(wait, time.Millisecond)
		if pacing.timer == nil {
			pacing.timer = conversation.application.routeSelectionTimer(delay, conversation.flushRouteSelection)
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

func (conversation *conversation) storeRouteSelections(kept *keptReport[routeSelectionReport]) {
	pacing := &conversation.routeSelectionPacing
	for {
		conversation.storeRouteSelection(conversation.session.ctx, kept)
		pacing.mu.Lock()
		pacing.busy = false
		pacing.running.Done()
		next, ok, _ := conversation.claimRouteSelectionLocked()
		pacing.mu.Unlock()
		if !ok {
			return
		}
		kept = next
	}
}

// storeRouteSelection stores one report made while kept.nodeKey was the
// session's key; a failure waits for the node's next report.
func (conversation *conversation) storeRouteSelection(ctx context.Context,
	kept *keptReport[routeSelectionReport],
) {
	streams, ok := conversation.application.options.Streams.(RouteSelectionStreams)
	if !ok || !kept.nodeKey.IsValid() || kept.nodeKey != conversation.currentKey() {
		return
	}
	machine, err := conversation.authenticatedMachine()
	if err != nil {
		return
	}
	if err := streams.ReportRouteSelection(ctx, machine, kept.nodeKey, kept.value.sites,
		kept.value.exit); err != nil &&
		!errors.Is(err, context.Canceled) {
		conversation.application.options.Logger.DebugContext(ctx, "mtcp route selection not stored", "error", err)
	}
}

// stopRouteSelectionPacing ends the pacing when the session ends, dropping
// a kept report (the node's next session reports again, and a late store
// could land in that session's record), and waits for a store already
// running.
func (conversation *conversation) stopRouteSelectionPacing() {
	pacing := &conversation.routeSelectionPacing
	pacing.mu.Lock()
	pacing.stopped, pacing.waiting = true, nil
	if pacing.timer != nil {
		pacing.timer.Stop()
	}
	pacing.mu.Unlock()
	pacing.running.Wait()
}
