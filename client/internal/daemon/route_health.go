package daemon

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
)

// routeHealthPoll is how often the daemon reads the router's Site health;
// the data plane measures it as often (design §6.5).
const routeHealthPoll = 2 * time.Second

// watchRouteHealth hands each new set of served Sites' health to the map
// session, until ctx ends. A router that serves Sites it has not measured
// yet sends nothing; one that serves none sends the empty set once.
func watchRouteHealth(ctx context.Context, read func() dataplane.SubnetRouterStatus, poll time.Duration,
	out chan<- []controlplane.RouteSiteHealth,
) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	var last []controlplane.RouteSiteHealth
	for {
		status := read()
		if health, measured := routeHealthOf(status); measured && (last == nil || !slices.Equal(last, health)) {
			select {
			case out <- health:
				last = health
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

// routeHealthOf converts the data plane's Site health; measured is false
// while Sites are served but not measured yet.
func routeHealthOf(status dataplane.SubnetRouterStatus) ([]controlplane.RouteSiteHealth, bool) {
	if status.Sites > 0 && len(status.Health) == 0 {
		return nil, false
	}
	health := make([]controlplane.RouteSiteHealth, 0, len(status.Health))
	for _, site := range status.Health {
		// Core refuses a report it cannot read whole (mtcp-v1 §8.3): a
		// reference it never sent is dropped, a code it cannot read is sent
		// as "unknown", and at most maximumReportedSites go.
		if site.Ref == "" || len(site.Ref) > maximumSiteReference || !utf8.ValidString(site.Ref) ||
			slices.ContainsFunc(health, func(other controlplane.RouteSiteHealth) bool { return other.Ref == site.Ref }) {
			continue
		}
		if !validHealthCode(site.Code) {
			site.Code = "unknown"
		}
		state := controlplane.RouteHealthOK
		switch site.State {
		case dataplane.SiteHealthDegraded:
			state = controlplane.RouteHealthDegraded
		case dataplane.SiteHealthFailed:
			state = controlplane.RouteHealthFailed
		}
		health = append(health, controlplane.RouteSiteHealth{Ref: site.Ref, State: state, Code: site.Code})
	}
	slices.SortFunc(health, func(first, second controlplane.RouteSiteHealth) int {
		return cmp.Compare(first.Ref, second.Ref)
	})
	return health[:min(len(health), maximumReportedSites)], true
}

const (
	// maximumReportedSites, maximumSiteReference and maximumHealthCode are
	// the bounds of one RouteHealthReport (mtcp-v1 §8.3).
	maximumReportedSites = 1024
	maximumSiteReference = 64
	maximumHealthCode    = 64
)

// validHealthCode accepts 1 to 64 lower-case letters, digits and underscores.
func validHealthCode(code string) bool {
	return code != "" && len(code) <= maximumHealthCode && strings.IndexFunc(code, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_'
	}) < 0
}
