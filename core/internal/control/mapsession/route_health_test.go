package mapsession

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/shared/routedigest"
)

type recordingRouteHealthRecorder struct {
	recordingEnforcementRecorder
	health []RouteHealth
}

func (recorder *recordingRouteHealthRecorder) RecordRouteHealth(ctx context.Context, health RouteHealth) (bool, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if _, bounded := ctx.Deadline(); !bounded {
		return false, errors.New("unbounded route health record")
	}
	if recorder.fail {
		return false, errors.New("synthetic route health store failure")
	}
	recorder.health = append(recorder.health, health)
	return !recorder.stale, nil
}

func TestValidSiteHealth(t *testing.T) {
	t.Parallel()
	ok := SiteHealth{Ref: "a", State: RouteHealthOK, Code: "ok"}
	failed := SiteHealth{Ref: "b", State: RouteHealthFailed, Code: "forward_blocked"}
	if !ValidSiteHealth(nil) || !ValidSiteHealth([]SiteHealth{ok, failed}) {
		t.Fatal("valid health was refused")
	}
	tooMany := make([]SiteHealth, MaximumRouteHealthSites+1)
	for name, sites := range map[string][]SiteHealth{
		"unsorted":      {failed, ok},
		"twice":         {ok, ok},
		"no reference":  {{State: RouteHealthOK, Code: "ok"}},
		"long ref":      {{Ref: strings.Repeat("r", 65), State: RouteHealthOK, Code: "ok"}},
		"unknown state": {{Ref: "a", State: 0, Code: "ok"}},
		"no code":       {{Ref: "a", State: RouteHealthOK}},
		"long code":     {{Ref: "a", State: RouteHealthOK, Code: strings.Repeat("c", 65)}},
		"upper case":    {{Ref: "a", State: RouteHealthOK, Code: "OK"}},
		"too many":      tooMany,
	} {
		if ValidSiteHealth(sites) {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestReportRouteHealthNeedsARecorderThatTakesIt(t *testing.T) {
	initial, _, _ := authorityDeltaSnapshotsFixture(t)
	service := newStreamServiceFixture(t, &streamSnapshotOpener{snapshots: []Snapshot{initial}}, &streamPresenceStore{})
	machine, _ := authenticatedRequestFixture(t, initial)
	sites := []SiteHealth{{Ref: "prod", State: RouteHealthFailed, Code: "probe_failed"}}
	if err := service.ReportRouteHealth(t.Context(), machine, initial.NodeKey(), sites, nil); !errors.Is(err, ErrEnforcementUnavailable) {
		t.Fatalf("without a recorder = %v", err)
	}
	enforcementOnly, err := service.WithEnforcementRecorder(&recordingEnforcementRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enforcementOnly.ReportRouteHealth(t.Context(), machine, initial.NodeKey(), sites, nil); !errors.Is(err, ErrEnforcementUnavailable) {
		t.Fatalf("with an enforcement-only recorder = %v", err)
	}
	recorder := &recordingRouteHealthRecorder{}
	recorded, err := service.WithEnforcementRecorder(recorder)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorded.ReportRouteHealth(t.Context(), machine, initial.NodeKey(), sites, nil); err != nil {
		t.Fatal(err)
	}
	if len(recorder.health) != 1 || recorder.health[0].NodeKey != initial.NodeKey() ||
		recorder.health[0].MachineFingerprint != initial.MachineKey().Fingerprint() ||
		len(recorder.health[0].Sites) != 1 || recorder.health[0].ReportedAt.IsZero() {
		t.Fatalf("stored = %+v", recorder.health)
	}
	if err := recorded.ReportRouteHealth(t.Context(), machine, initial.NodeKey(),
		[]SiteHealth{{Ref: "prod", State: RouteHealthFailed}}, nil); !errors.Is(err, ErrInvalidRouteHealth) {
		t.Fatalf("malformed health = %v", err)
	}
	if err := recorded.ReportRouteHealth(t.Context(), machine, initial.NodeKey(), nil,
		&ExitHealth{Ref: "pool", State: RouteHealthOK, Code: "ok", Families: ExitFamiliesBoth + 1}); !errors.Is(err, ErrInvalidRouteHealth) {
		t.Fatalf("malformed exit health = %v", err)
	}
	exit := &ExitHealth{Ref: "pool", State: RouteHealthDegraded, Code: "no_ipv6", Families: ExitFamiliesV4}
	if err := recorded.ReportRouteHealth(t.Context(), machine, initial.NodeKey(), nil, exit); err != nil {
		t.Fatal(err)
	}
	if last := recorder.health[len(recorder.health)-1]; last.Exit == nil || *last.Exit != *exit || last.Exit == exit {
		t.Fatalf("stored exit health = %+v", last.Exit)
	}
	served := []ServedExit{{Ref: "pool"}}
	if ServedExitOnly(exit, served) == nil || ServedExitOnly(&ExitHealth{Ref: "other"}, served) != nil ||
		ServedExitOnly(nil, served) != nil {
		t.Fatal("ServedExitOnly keeps the wrong pools")
	}
	recorder.stale = true
	if err := recorded.ReportRouteHealth(t.Context(), machine, initial.NodeKey(), sites, nil); !errors.Is(err, ErrNoEnforcementStream) {
		t.Fatalf("without a current session = %v", err)
	}
}

func TestRouteDigestOfCoversWhatARouterIsSent(t *testing.T) {
	t.Parallel()
	initial, _, _ := authorityDeltaSnapshotsFixture(t)
	fixture := newRouteFixture(t)
	router := fixture.policy(t).RoutesFor(fixture.ids[5], policyNow)
	snapshot := initial
	snapshot.routes = router
	if routes := routeDigestOf(snapshot); routes.IsValid() {
		t.Fatal("a session that did not declare router capability has a route digest")
	}
	snapshot.routeCapabilities, snapshot.routeCapabilitiesKnown = RouteCapabilities{Router: true}, true
	var entries []routedigest.Entry
	for _, site := range router.Served() {
		for _, prefix := range site.Prefixes {
			entries = append(entries, routedigest.Entry{SiteRef: site.Ref, Prefix: prefix, Masquerade: site.Masquerade})
		}
	}
	want, count, err := routedigest.Compute(entries)
	if err != nil {
		t.Fatal(err)
	}
	if routes := routeDigestOf(snapshot); routes.Digest() != want || routes.Entries() != count || count != 2 {
		t.Fatalf("routeDigestOf() = %v/%d, want %v/%d", routes.Digest(), routes.Entries(), want, count)
	}
	// A router serving nothing has the empty set's digest, not none.
	snapshot.routes = RouteView{}
	empty, _, _ := routedigest.Compute(nil)
	if routes := routeDigestOf(snapshot); routes.Digest() != empty || routes.Entries() != 0 {
		t.Fatalf("empty served = %v/%d", routes.Digest(), routes.Entries())
	}
	if delivery := deliveryOf(snapshot, FilterDigest{}, DNSDigest{}, time.Now()); delivery.Routes.Digest() != empty {
		t.Fatal("the delivery does not carry the route digest")
	}
}
