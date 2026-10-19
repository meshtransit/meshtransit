package mapsession

import (
	"context"
	"errors"
	"slices"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
)

// ErrInvalidRouteSelection reports a malformed route selection report.
var ErrInvalidRouteSelection = errors.New("map session: invalid route selection report")

// RouteSelectionReason is why a node sends a Site's traffic to a router
// (mtcp-v1 §8.3).
type RouteSelectionReason int

// The reasons of mtcp-v1 §8.3.
const (
	// RouteSelectionPrimary is the map's primary.
	RouteSelectionPrimary RouteSelectionReason = iota + 1
	// RouteSelectionLocalFailover is another candidate the node chose while
	// the primary does not answer.
	RouteSelectionLocalFailover
	// RouteSelectionNone means the Site is not served: no router.
	RouteSelectionNone
)

// SiteSelection is the router a node uses for one Site; Router is zero with
// RouteSelectionNone.
type SiteSelection struct {
	Ref    string
	Router node.ID
	Reason RouteSelectionReason
}

// ValidSiteSelection reports Sites sorted by reference and listed once,
// each with a known reason and a router exactly when it is served.
func ValidSiteSelection(sites []SiteSelection) bool {
	if len(sites) > MaximumRouteHealthSites {
		return false
	}
	previous := ""
	for index, site := range sites {
		if site.Ref == "" || len(site.Ref) > maximumSiteReference || !utf8.ValidString(site.Ref) ||
			(index > 0 && previous >= site.Ref) ||
			site.Reason < RouteSelectionPrimary || site.Reason > RouteSelectionNone ||
			(site.Reason == RouteSelectionNone) != (site.Router == node.ID{}) ||
			(site.Router != node.ID{} && !site.Router.IsValid()) {
			return false
		}
		previous = site.Ref
	}
	return true
}

// SelectedOnly keeps the Sites of routes whose router is one of their
// candidates: a node reports only on what Core sent it.
func SelectedOnly(sites []SiteSelection, routes []SiteRoute) []SiteSelection {
	byRef := make(map[string]SiteRoute, len(routes))
	for _, route := range routes {
		byRef[route.Ref] = route
	}
	kept := make([]SiteSelection, 0, len(sites))
	for _, site := range sites {
		route, found := byRef[site.Ref]
		if found && (site.Reason == RouteSelectionNone || slices.Contains(route.Candidates, site.Router)) {
			kept = append(kept, site)
		}
	}
	return kept
}

// RouteSelection is one route selection report, bound to the authenticated
// node that sent it; the recorder ties it to that node's current map
// session.
type RouteSelection struct {
	NodeKey            node.Key
	MachineFingerprint [32]byte
	Sites              []SiteSelection
	ReportedAt         time.Time
}

// RouteSelectionRecorder stores the latest route selection of a node's
// current map session. It reports false when the node has no current
// session or the session belongs to another machine.
type RouteSelectionRecorder interface {
	RecordRouteSelection(context.Context, RouteSelection) (bool, error)
}

// ReportRouteSelection stores the router of each Site a node reaches
// (mtcp-v1 §8.3). Sites must already be those of the routes the session was
// sent.
func (service *StreamService) ReportRouteSelection(ctx context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, sites []SiteSelection,
) error {
	if ctx == nil || service == nil || !machine.IsValid() {
		return ErrInvalidStreamService
	}
	recorder, ok := service.enforcement.(RouteSelectionRecorder)
	if !ok {
		return ErrEnforcementUnavailable
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil || !ValidSiteSelection(sites) {
		return ErrInvalidRouteSelection
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	stored, err := recorder.RecordRouteSelection(operationCtx, RouteSelection{
		NodeKey: identity.NodeKey(), MachineFingerprint: identity.MachineFingerprint(),
		Sites: slices.Clone(sites), ReportedAt: time.Now().UTC(),
	})
	if err != nil {
		return errors.Join(ErrEnforcementUnavailable, err)
	}
	if !stored {
		return ErrNoEnforcementStream
	}
	return nil
}
