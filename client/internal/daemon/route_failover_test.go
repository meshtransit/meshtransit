package daemon

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
)

type failoverClock struct{ now time.Time }

func (clock *failoverClock) Now() time.Time { return clock.now }

func failoverMap(primary string) networkmap.Snapshot {
	return networkmap.Snapshot{
		Revision: 7,
		Peers:    []networkmap.Node{{ID: 11, StableID: "router-1"}, {ID: 12, StableID: "router-2"}, {ID: 13, StableID: "router-3"}},
		Routes: []networkmap.SiteRoute{{
			Ref: "prod", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")},
			Candidates: []string{"router-1", "router-2", "router-3"}, Primary: primary, Generation: 1,
			Status: networkmap.RouteServed,
		}},
	}
}

type failoverHarness struct {
	t        *testing.T
	clock    *failoverClock
	failover *routeFailover
	activity dataplane.RoutedActivity
}

func newFailoverHarness(t *testing.T) *failoverHarness {
	clock := &failoverClock{now: time.Date(2026, time.October, 19, 14, 0, 0, 0, time.UTC)}
	h := &failoverHarness{
		t: t, clock: clock, failover: newRouteFailover(clock.Now),
		activity: dataplane.RoutedActivity{Ref: "prod"},
	}
	h.failover.effective(failoverMap("router-1"))
	h.pong(11, 12, 13) // every router answered once
	return h
}

func (h *failoverHarness) pong(ids ...uint64) {
	for _, id := range ids {
		h.failover.ObservePath(pathdiscovery.PathObservation{PeerID: id, ObservedAt: h.clock.now})
	}
}

// send records traffic to the Site; answered says whether it came back.
func (h *failoverHarness) send(answered bool) {
	h.activity.LastSent = h.clock.now
	if answered {
		h.activity.LastAnswered, h.activity.WaitingSince = h.clock.now, time.Time{}
	} else if h.activity.WaitingSince.IsZero() {
		h.activity.WaitingSince = h.clock.now
	}
}

// step advances one second of traffic and probes, then judges.
func (h *failoverHarness) step(answered bool, alive ...uint64) bool {
	h.clock.now = h.clock.now.Add(time.Second)
	h.pong(alive...)
	h.send(answered)
	return h.failover.judge([]dataplane.RoutedActivity{h.activity})
}

func (h *failoverHarness) primary() string { return h.failover.current().Routes[0].Primary }

func TestRouteFailoverSwitchesFromADeadRouterToTheNextAnswering(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	for range 10 {
		if h.step(true, 11, 12, 13) {
			t.Fatal("a healthy Site switched")
		}
	}
	// router-1 stops answering probes and traffic; router-2 does not answer
	// probes either, router-3 does.
	switched := false
	for second := 1; second <= 10 && !switched; second++ {
		switched = h.step(false, 13)
		if switched && second < 5 {
			t.Fatalf("switched after %d s, before suspicion", second)
		}
	}
	if !switched || h.primary() != "router-3" {
		t.Fatalf("primary = %q, switched %t", h.primary(), switched)
	}
	if choices := h.failover.choices(); choices["prod"] != "router-3" {
		t.Fatalf("choices = %v", choices)
	}
}

func TestRouteFailoverKeepsARouterThatStillAnswers(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	// The Site's host is down, its router is fine: no answers, router pongs.
	for range 20 {
		if h.step(false, 11, 12) {
			t.Fatal("switched away from a router that answers probes")
		}
	}
	if h.primary() != "router-1" {
		t.Fatalf("primary = %q", h.primary())
	}
}

func TestRouteFailoverFollowsCore(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	for range 7 {
		h.step(false, 12)
	}
	if h.primary() != "router-2" {
		t.Fatalf("no local switch: %q", h.primary())
	}
	// Core elects router-2 as well: the local choice ends.
	h.failover.effective(failoverMap("router-2"))
	if h.primary() != "router-2" || len(h.failover.choices()) != 0 {
		t.Fatalf("after Core agreed: %q %v", h.primary(), h.failover.choices())
	}

	h = newFailoverHarness(t)
	for range 7 {
		h.step(false, 12)
	}
	// Core elects router-3; with traffic flowing the local choice stays,
	// then follows once the Site is idle.
	h.failover.effective(failoverMap("router-3"))
	for range 10 {
		h.step(true, 12, 13)
	}
	if h.primary() != "router-2" {
		t.Fatalf("a flowing Site moved: %q", h.primary())
	}
	h.clock.now = h.clock.now.Add(failoverIdleAfter)
	if !h.failover.judge([]dataplane.RoutedActivity{h.activity}) || h.primary() != "router-3" {
		t.Fatalf("an idle Site kept its local choice: %q", h.primary())
	}
}

func TestRouteFailoverReturnsWhenCoresRouterAnswersAndTheSiteIsIdle(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	for range 7 {
		h.step(false, 12)
	}
	for range 10 {
		h.step(true, 11, 12)
	}
	if h.primary() != "router-2" {
		t.Fatalf("returned while traffic flowed: %q", h.primary())
	}
	h.clock.now = h.clock.now.Add(failoverIdleAfter)
	h.pong(11)
	if !h.failover.judge([]dataplane.RoutedActivity{h.activity}) || h.primary() != "router-1" {
		t.Fatalf("did not return to Core's router: %q", h.primary())
	}
}

func TestRouteFailoverBacksOff(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	for second := 0; !h.step(false, 12); second++ {
		if second > 10 {
			t.Fatal("never switched")
		}
	}
	if h.primary() != "router-2" {
		t.Fatal("no first switch")
	}
	// router-2 dies at once too: the next switch waits for the backoff.
	switchedAt := h.clock.now
	for !h.step(false, 13) {
		if h.clock.now.Sub(switchedAt) > time.Minute {
			t.Fatal("never switched again")
		}
	}
	if waited := h.clock.now.Sub(switchedAt); waited < failoverBackoff || h.primary() != "router-3" {
		t.Fatalf("switched again after %v to %q", waited, h.primary())
	}
}

func TestRouteFailoverDropsAChoiceCoreNoLongerOffers(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	for range 7 {
		h.step(false, 12)
	}
	unserved := failoverMap("router-1")
	unserved.Routes[0].Status = networkmap.RouteUnserved
	unserved.Routes[0].Primary = ""
	if got := h.failover.effective(unserved); got.Routes[0].Primary != "" {
		t.Fatalf("an unserved Site kept a local router: %q", got.Routes[0].Primary)
	}
	if original := failoverMap("router-1"); original.Routes[0].Primary != "router-1" {
		t.Fatal("the map from Core was changed")
	}
}

func TestRouteFailoverNeverLeavesARouterItCannotMeasure(t *testing.T) {
	t.Parallel()
	clock := &failoverClock{now: time.Date(2026, time.October, 19, 14, 0, 0, 0, time.UTC)}
	h := &failoverHarness{
		t: t, clock: clock, failover: newRouteFailover(clock.Now),
		activity: dataplane.RoutedActivity{Ref: "prod"},
	}
	h.failover.effective(failoverMap("router-1"))
	// router-1 is only reached through a relay: it never pongs. Packets go
	// unanswered while router-2 answers its probes.
	for range 20 {
		if h.step(false, 12) {
			t.Fatal("left a router that was never measured")
		}
	}
	if h.primary() != "router-1" {
		t.Fatalf("primary = %q", h.primary())
	}
}

func TestRouteFailoverJudgesANewRouterFromItsOwnTime(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	for second := 0; !h.step(false, 12, 13); second++ {
		if second > 10 {
			t.Fatal("never switched")
		}
	}
	// Still unanswered (one-way traffic), but router-2 answers probes: the
	// wait before the switch is not held against it.
	for range 20 {
		if h.step(false, 12, 13) {
			t.Fatalf("left router-2, which answers: %q", h.primary())
		}
	}
}

func TestRestartExpectedOnlyForAFreshMarker(t *testing.T) {
	t.Parallel()
	now := time.Now()
	path := t.TempDir() + "/restart-expected"
	if restartExpected(path, now) || restartExpected("", now) {
		t.Fatal("a missing marker expects a restart")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !restartExpected(path, now) {
		t.Fatal("a fresh marker does not expect a restart")
	}
	if restartExpected(path, now.Add(restartMarkerFresh+time.Second)) {
		t.Fatal("an old marker still expects a restart")
	}
	clearRestartMarker(path, nil)
	if restartExpected(path, now) {
		t.Fatal("a cleared marker still expects a restart")
	}
	clearRestartMarker(path, nil) // already gone: nothing to do
}

func TestRouteFailoverReportsEachSitesRouter(t *testing.T) {
	t.Parallel()
	h := newFailoverHarness(t)
	core := failoverMap("router-1")
	core.Peers[0].Name, core.Peers[1].Name = "router-1-prod", "router-2-prod"
	core.Routes = append(core.Routes, networkmap.SiteRoute{
		Ref:      "uat",
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.36.0.0/16")}, Candidates: []string{"router-3"},
		Generation: 1, Status: networkmap.RouteUnserved,
	})
	h.failover.effective(core)
	reports, views := h.failover.selections()
	if len(reports) != 2 || reports[0] != (controlplane.RouteSiteSelection{
		Ref: "prod", Router: "router-1",
		Reason: controlplane.RouteSelectionPrimary,
	}) || reports[1].Reason != controlplane.RouteSelectionNone ||
		reports[1].Router != "" || views[0].RouterName != "router-1-prod" || views[1].Via != "none" {
		t.Fatalf("selections = %+v %+v", reports, views)
	}
	for second := 0; !h.step(false, 12, 13); second++ {
		if second > 10 {
			t.Fatal("never switched")
		}
	}
	reports, views = h.failover.selections()
	if reports[0].Router != "router-2" || reports[0].Reason != controlplane.RouteSelectionLocalFailover ||
		views[0].Via != "local_failover" || views[0].RouterName != "router-2-prod" {
		t.Fatalf("after a local switch = %+v %+v", reports, views)
	}
}
