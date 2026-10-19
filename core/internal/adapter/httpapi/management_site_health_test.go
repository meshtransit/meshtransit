package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/shared/policydigest"
)

type fakeSiteObservations struct {
	observations []distribution.Observation
	err          error
	asked        []node.ID
}

func (loader *fakeSiteObservations) LoadObservations(_ context.Context, ids []node.ID) ([]distribution.Observation, error) {
	loader.asked = ids
	return loader.observations, loader.err
}

func TestAddRouterHealthShowsEachRoutersMeasureOfTheSite(t *testing.T) {
	t.Parallel()
	siteID, _ := site.ParseID("01a1531a-a82c-7e50-afce-09a0d8d5ee84")
	first, _ := node.ParseID("01a15307-09d3-76b4-a028-3c21ee7080c0")
	second, _ := node.ParseID("01a15307-257a-74a0-a760-cba56b7804fe")
	stored := site.Site{ID: siteID, Definition: site.Definition{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}},
		Routers: []site.Router{
			{RouterAssignment: site.RouterAssignment{DeviceID: first, Priority: 10, State: site.RouterActive}},
			{RouterAssignment: site.RouterAssignment{DeviceID: second, Priority: 20, State: site.RouterActive}},
		}}
	now := time.Now()
	routes := distribution.RouteSummary{Digest: policydigest.Digest{1}, Entries: 1}
	healthy := distribution.Observation{Known: true, SessionGeneration: 1, NetworkRevision: 1,
		DeliveredAt: now.Add(-time.Hour), SeenAt: now.Add(-time.Hour), Routes: routes, EnforcedRoutes: routes,
		RouteHealth: []distribution.SiteHealth{
			{Ref: "01a1531a-aa55-7817-9cbb-d712e4710208", State: "ok", Code: "ok"},
			{Ref: siteID.String(), State: "failed", Code: "forward_blocked"},
		},
		RouteHealthAt: now.Add(-5 * time.Second)}
	stale := healthy
	stale.EnforcedRoutes = distribution.RouteSummary{Digest: policydigest.Digest{2}, Entries: 1}
	stale.RouteHealthAt = now.Add(-time.Minute)
	loader := &fakeSiteObservations{observations: []distribution.Observation{healthy, stale}}
	handler := &ManagementHandler{siteRouterObservations: loader, logger: slog.New(slog.DiscardHandler)}
	body := newSiteBody(stored)
	handler.addRouterHealth(t.Context(), &body, stored)
	if len(loader.asked) != 2 || loader.asked[0] != first || loader.asked[1] != second {
		t.Fatalf("asked for %v", loader.asked)
	}
	if got := body.Routers[0]; got.RouteEnforcement != "enforced" || got.Health == nil ||
		got.Health.State != "failed" || got.Health.Code != "forward_blocked" {
		t.Fatalf("first router = %+v %+v", got, got.Health)
	}
	// Health older than 30 s is unknown; another digest is a mismatch.
	if got := body.Routers[1]; got.RouteEnforcement != "mismatch" || got.Health != nil {
		t.Fatalf("second router = %+v", got)
	}
	// Without delivery records the Site is answered as stored.
	loader.err = errors.New("redis down")
	plain := newSiteBody(stored)
	handler.addRouterHealth(t.Context(), &plain, stored)
	if plain.Routers[0].Health != nil || plain.Routers[0].RouteEnforcement != "" {
		t.Fatalf("router without records = %+v", plain.Routers[0])
	}
}

func TestDeviceRouterItem(t *testing.T) {
	t.Parallel()
	if item := newDeviceRouterItem(distribution.Device{Observation: distribution.Observation{Known: true}}); item != nil {
		t.Fatalf("a Device that does not route has a router item: %+v", item)
	}
	reported := time.Date(2026, time.October, 19, 10, 0, 0, 0, time.UTC)
	routes := distribution.RouteSummary{Digest: policydigest.Digest{1}, Entries: 3}
	item := newDeviceRouterItem(distribution.Device{RouteEnforcement: distribution.EnforcementEnforced,
		RouteHealth: []distribution.SiteHealth{{Ref: "prod", State: "ok", Code: "ok"}},
		Observation: distribution.Observation{Known: true, Routes: routes, EnforcedRoutes: routes, RouteHealthAt: reported}})
	if item == nil || item.RouteEnforcement != "enforced" || *item.DeliveredRoutes != 3 || *item.EnforcedRoutes != 3 ||
		len(item.Sites) != 1 || item.Sites[0].SiteID != "prod" || !item.HealthReportedAt.Equal(reported) {
		t.Fatalf("router item = %+v", item)
	}
	// Stale health: the item stays, with no Sites.
	item = newDeviceRouterItem(distribution.Device{RouteEnforcement: distribution.EnforcementApplying,
		Observation: distribution.Observation{Known: true, Routes: routes, RouteHealthAt: reported}})
	if item == nil || len(item.Sites) != 0 || item.HealthReportedAt != nil || item.EnforcedRouteDigest != nil {
		t.Fatalf("stale router item = %+v", item)
	}
}
