package distribution

import (
	"time"

	"meshtransit.net/shared/policydigest"
	"meshtransit.net/shared/routedigest"
)

// RouteHealthStale is how long a router's Site health stays current without
// a new report (mtcp-v1 §8.3); older health is unknown, not failed.
const RouteHealthStale = 30 * time.Second

// RouteSummary is the route digest of the served routes of a router and
// how many entries it covers; the zero value means none was recorded, as
// for a Device that does not route.
type RouteSummary struct {
	Digest  policydigest.Digest
	Entries int
}

// IsZero reports that no route digest was recorded.
func (routes RouteSummary) IsZero() bool { return routes == RouteSummary{} }

func (routes RouteSummary) isValid() bool {
	return routes.IsZero() ||
		!routes.Digest.IsZero() && routes.Entries >= 0 && routes.Entries <= routedigest.MaximumEntries
}

// Site health states a router reports.
const (
	SiteHealthOK       = "ok"
	SiteHealthDegraded = "degraded"
	SiteHealthFailed   = "failed"
)

// SiteHealth is one served Site's health as its router measures it.
type SiteHealth struct {
	Ref   string
	State string
	Code  string
}

// ClassifyRouteEnforcement compares the route digest a router reports with
// the served routes it was last delivered, as ClassifyEnforcement does for
// its packet filter.
func ClassifyRouteEnforcement(observation Observation, now time.Time) Enforcement {
	switch {
	case !observation.Known || observation.Routes.IsZero():
		return EnforcementUnknown
	case !observation.EnforcedRoutes.IsZero() && observation.EnforcedRoutes.Digest == observation.Routes.Digest:
		return EnforcementEnforced
	case now.Sub(observation.DeliveredAt) < EnforcementGrace:
		return EnforcementApplying
	case observation.EnforcedRoutes.IsZero():
		return EnforcementNotReported
	default:
		return EnforcementMismatch
	}
}

// CurrentRouteHealth returns the router's Site health while it is current;
// false when it reported none or its last report is older than
// RouteHealthStale.
func CurrentRouteHealth(observation Observation, now time.Time) ([]SiteHealth, bool) {
	if !observation.Known || observation.RouteHealthAt.IsZero() || now.Sub(observation.RouteHealthAt) > RouteHealthStale {
		return nil, false
	}
	return append([]SiteHealth{}, observation.RouteHealth...), true
}

func validRoutes(observation Observation) bool {
	if !observation.Routes.isValid() || !observation.EnforcedRoutes.isValid() {
		return false
	}
	if observation.RouteHealthAt.IsZero() {
		return len(observation.RouteHealth) == 0
	}
	for _, site := range observation.RouteHealth {
		if site.Ref == "" || site.Code == "" ||
			(site.State != SiteHealthOK && site.State != SiteHealthDegraded && site.State != SiteHealthFailed) {
			return false
		}
	}
	return true
}
