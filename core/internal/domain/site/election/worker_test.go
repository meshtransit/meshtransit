package election

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/site"
)

type manualClock struct{ now time.Time }

func (clock *manualClock) Now() time.Time { return clock.now }

// fakeSites keeps one Site's facts and records decisions as prepare would.
type fakeSites struct {
	sites    []SiteFacts
	listErr  error
	recorded []Decision
}

func (fake *fakeSites) List(_ context.Context, _ deployment.ID, after site.ID, limit int) (Page, error) {
	if fake.listErr != nil {
		return Page{}, fake.listErr
	}
	var page Page
	for _, facts := range fake.sites {
		if after.IsValid() && facts.Site.String() <= after.String() {
			continue
		}
		if len(page.Sites) == limit {
			return page, nil
		}
		page.Sites = append(page.Sites, facts)
	}
	page.Done = true
	return page, nil
}

func (fake *fakeSites) Record(_ context.Context, _ deployment.ID, decision Decision) (bool, error) {
	for index := range fake.sites {
		facts := &fake.sites[index]
		if facts.Site != decision.Site {
			continue
		}
		if facts.Generation != decision.ExpectedGeneration {
			return false, nil
		}
		fake.recorded = append(fake.recorded, decision)
		facts.Primary, facts.Generation = decision.Primary, facts.Generation+1
		return true, nil
	}
	return false, nil
}

type fakeHealth struct {
	byID map[node.ID]distribution.Observation
	err  error
}

func (fake *fakeHealth) LoadObservations(_ context.Context, ids []node.ID) ([]distribution.Observation, error) {
	if fake.err != nil {
		return nil, fake.err
	}
	loaded := make([]distribution.Observation, len(ids))
	for index, id := range ids {
		loaded[index] = fake.byID[id]
	}
	return loaded, nil
}

type harness struct {
	t       *testing.T
	clock   *manualClock
	sites   *fakeSites
	health  *fakeHealth
	worker  *Worker
	siteID  site.ID
	first   node.ID
	second  node.ID
	started time.Time
}

func newHarness(t *testing.T, failback bool) *harness {
	t.Helper()
	installation, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	siteID, err := site.ParseID("01a1531a-a82c-7e50-afce-09a0d8d5ee84")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	h := &harness{t: t, clock: &manualClock{now: started}, health: &fakeHealth{byID: map[node.ID]distribution.Observation{}},
		siteID: siteID, first: device(t, 1), second: device(t, 2), started: started}
	h.sites = &fakeSites{sites: []SiteFacts{{Site: siteID, Failback: failback, Routers: []RouterFacts{
		{Device: h.first, Priority: 10, Live: true, WorkspaceOwned: true, Covers: true},
		{Device: h.second, Priority: 20, Live: true, WorkspaceOwned: true, Covers: true},
	}}}}
	h.worker, err = New(Options{DeploymentID: installation, PollInterval: 10 * time.Second,
		OperationTimeout: time.Second}, h.sites, h.sites, h.health, h.clock,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// report makes a router report the Site in state now.
func (h *harness) report(id node.ID, state, code string) {
	at := h.clock.now
	h.health.byID[id] = distribution.Observation{Known: true, SessionGeneration: 1, NetworkRevision: 1,
		DeliveredAt: h.started, SeenAt: at, RouteHealthAt: at,
		RouteHealth: []distribution.SiteHealth{{Ref: h.siteID.String(), State: state, Code: code}}}
}

// sweep advances the clock and elects once.
func (h *harness) sweep(after time.Duration) {
	h.clock.now = h.clock.now.Add(after)
	h.worker.Sweep(context.Background())
}

func (h *harness) primary() node.ID { return h.sites.sites[0].Primary }

func (h *harness) last() Decision {
	h.t.Helper()
	if len(h.sites.recorded) == 0 {
		h.t.Fatal("nothing recorded")
	}
	return h.sites.recorded[len(h.sites.recorded)-1]
}

func TestWorkerFailsOverAndHoldsDown(t *testing.T) {
	t.Parallel()
	h := newHarness(t, true)
	h.report(h.first, distribution.SiteHealthOK, "ok")
	h.report(h.second, distribution.SiteHealthOK, "ok")
	h.sweep(0)
	if h.primary() != h.first || h.last().Reason != ReasonElected {
		t.Fatalf("first election = %+v", h.sites.recorded)
	}
	h.sweep(10 * time.Second)
	if len(h.sites.recorded) != 1 {
		t.Fatalf("an unchanged primary was recorded again: %+v", h.sites.recorded)
	}

	h.report(h.first, distribution.SiteHealthFailed, "forward_blocked")
	h.sweep(time.Second)
	if h.primary() != h.second || h.last().Reason != ReasonFailover || h.last().ExpectedGeneration != 1 {
		t.Fatalf("failover = %+v", h.sites.recorded)
	}

	// Healthy again: held down, then usable, and failback waits for its own
	// interval on top.
	h.report(h.first, distribution.SiteHealthOK, "ok")
	h.sweep(time.Second)
	h.report(h.first, distribution.SiteHealthOK, "ok")
	h.sweep(HoldDown + time.Second)
	if h.primary() != h.second {
		t.Fatal("failed back before failback")
	}
	for elapsed := time.Duration(0); elapsed <= FailbackAfter; elapsed += 10 * time.Second {
		h.report(h.first, distribution.SiteHealthOK, "ok")
		h.report(h.second, distribution.SiteHealthOK, "ok")
		h.sweep(10 * time.Second)
	}
	if h.primary() != h.first || h.last().Reason != ReasonFailback {
		t.Fatalf("failback = %+v", h.sites.recorded)
	}
}

func TestWorkerTreatsLongSilenceAsFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false)
	h.report(h.first, distribution.SiteHealthOK, "ok")
	h.sweep(0)
	h.report(h.second, distribution.SiteHealthOK, "ok")
	h.sweep(SilenceGrace) // first's report is exactly SilenceGrace old
	if h.primary() != h.first {
		t.Fatal("silence within its grace failed the router")
	}
	h.report(h.second, distribution.SiteHealthOK, "ok")
	h.sweep(time.Second)
	if h.primary() != h.first {
		t.Fatal("silence failed the router before the next sweep confirmed it")
	}
	h.report(h.second, distribution.SiteHealthOK, "ok")
	h.sweep(10 * time.Second)
	if h.primary() != h.second || h.last().Reason != ReasonFailover {
		t.Fatalf("silence = %+v", h.sites.recorded)
	}
}

func TestWorkerIgnoresRoutersThatNeverReported(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false)
	h.sweep(0)
	h.sweep(time.Hour)
	if h.primary() != h.first || len(h.sites.recorded) != 1 {
		t.Fatalf("an older client lost its Site: %+v", h.sites.recorded)
	}
}

func TestWorkerWithoutHealthKeepsTheHealthyChoice(t *testing.T) {
	t.Parallel()
	h := newHarness(t, true)
	h.report(h.first, distribution.SiteHealthFailed, "forward_blocked")
	h.report(h.second, distribution.SiteHealthOK, "ok")
	h.sweep(0)
	if h.primary() != h.second {
		t.Fatalf("first election = %+v", h.sites.recorded)
	}
	h.health.err = errors.New("redis down")
	for range 40 {
		h.sweep(10 * time.Second)
	}
	if h.primary() != h.second || len(h.sites.recorded) != 1 {
		t.Fatalf("unknown health moved the Site: %+v", h.sites.recorded)
	}
	// Authority facts still count; the router last seen failing is only the
	// best of the rest.
	h.sites.sites[0].Routers[1].Live = false
	h.sweep(10 * time.Second)
	if h.primary() != h.first || h.last().Reason != ReasonDegraded {
		t.Fatalf("an expired primary was kept: %+v", h.sites.recorded)
	}
}

func TestWorkerFailsOverWhenOneRouterOfManySitesGoesSilent(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false)
	h.sites.sites = h.sites.sites[:0]
	for index := range 25 {
		siteID, _ := site.ParseID("01a1531a-a82c-7e50-afce-09a0d8d5ee" + string("0123456789abcdef"[index>>4]) +
			string("0123456789abcdef"[index&0xf]))
		h.sites.sites = append(h.sites.sites, SiteFacts{Site: siteID, Routers: []RouterFacts{
			{Device: h.first, Priority: 10, Live: true, WorkspaceOwned: true, Covers: true},
			{Device: h.second, Priority: 20, Live: true, WorkspaceOwned: true, Covers: true},
		}})
	}
	h.report(h.first, distribution.SiteHealthOK, "ok")
	h.sweep(0)
	for range 14 {
		h.report(h.second, distribution.SiteHealthOK, "ok")
		h.sweep(10 * time.Second)
	}
	moved := 0
	for _, facts := range h.sites.sites {
		if facts.Primary == h.second {
			moved++
		}
	}
	if moved != 25 {
		t.Fatalf("%d of 25 Sites left their silent router", moved)
	}
}

func TestWorkerFreezesOnMassSilence(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false)
	// 25 Sites of two routers each, all reporting, then all silent at once.
	h.sites.sites = h.sites.sites[:0]
	base := h.clock.now
	for index := range 25 {
		siteID, _ := site.ParseID("01a1531a-a82c-7e50-afce-09a0d8d5ee" + string("0123456789abcdef"[index>>4]) +
			string("0123456789abcdef"[index&0xf]))
		first, second := device(t, byte(2*index+16)), device(t, byte(2*index+17))
		h.sites.sites = append(h.sites.sites, SiteFacts{Site: siteID, Routers: []RouterFacts{
			{Device: first, Priority: 10, Live: true, WorkspaceOwned: true, Covers: true},
			{Device: second, Priority: 20, Live: true, WorkspaceOwned: true, Covers: true},
		}})
		for _, id := range []node.ID{first, second} {
			h.health.byID[id] = distribution.Observation{Known: true, SessionGeneration: 1, NetworkRevision: 1,
				DeliveredAt: base, SeenAt: base, RouteHealthAt: base,
				RouteHealth: []distribution.SiteHealth{{Ref: siteID.String(), State: distribution.SiteHealthOK, Code: "ok"}}}
		}
	}
	h.sweep(0)
	elected := len(h.sites.recorded)
	h.sweep(SilenceGrace + time.Second)
	h.sweep(10 * time.Second)
	if len(h.sites.recorded) != elected {
		t.Fatalf("mass silence moved %d Sites", len(h.sites.recorded)-elected)
	}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := h.worker.options
	options.PollInterval = 0
	if _, err := New(options, h.sites, h.sites, h.health, h.clock, logger); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("zero poll = %v", err)
	}
	var missing *fakeSites
	if _, err := New(h.worker.options, missing, h.sites, h.health, h.clock, logger); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("nil facts = %v", err)
	}
	if err := h.worker.Shutdown(context.Background()); !errors.Is(err, ErrWorkerNotStarted) {
		t.Fatalf("shutdown before start = %v", err)
	}
	if err := h.worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.worker.Start(context.Background()); !errors.Is(err, ErrWorkerStarted) {
		t.Fatalf("second start = %v", err)
	}
	if err := h.worker.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-h.worker.Done()
}
