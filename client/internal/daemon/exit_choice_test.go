package daemon

import (
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/routesettings"
)

func exitMap(primary string, states ...networkmap.ExitCandidateState) networkmap.Snapshot {
	candidates := []networkmap.ExitCandidate{
		{DeviceID: "exit-1", State: networkmap.ExitStateOK, IPv4: true, IPv6: true},
		{DeviceID: "exit-2", State: networkmap.ExitStateOK, IPv4: true},
	}
	for index, state := range states {
		candidates[index].State = state
	}
	return networkmap.Snapshot{
		Revision: 9,
		Peers:    []networkmap.Node{{ID: 21, StableID: "exit-1", Name: "fra"}, {ID: 22, StableID: "exit-2", Name: "ams"}},
		Exits: []networkmap.ExitPool{
			{Ref: "pool-a", Name: "Europe", Candidates: candidates, Primary: primary, Status: networkmap.ExitServed},
			{
				Ref: "pool-b", Name: "Office", Status: networkmap.ExitUnserved, Managed: true,
				Candidates: []networkmap.ExitCandidate{{DeviceID: "exit-2"}},
			},
		},
	}
}

type exitHarness struct {
	clock    *failoverClock
	failover *routeFailover
}

func newExitHarness(preference exitPreference, snapshot networkmap.Snapshot) *exitHarness {
	pins, _ := openExitPins("")
	clock := &failoverClock{now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	h := &exitHarness{clock: clock, failover: newRouteFailover(clock.Now)}
	h.failover.seedExit(preference, exitSticky{}, pins)
	h.failover.effective(snapshot)
	return h
}

func (h *exitHarness) route() *networkmap.ExitRoute { return h.failover.current().ExitRoute }

func (h *exitHarness) step(alive ...uint64) bool {
	h.clock.now = h.clock.now.Add(time.Second)
	for _, id := range alive {
		h.failover.ObservePath(pathdiscovery.PathObservation{PeerID: id, ObservedAt: h.clock.now})
	}
	return h.failover.judge(nil)
}

func TestExitChoicePicksThePoolTheSettingsName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		preference exitPreference
		want       *networkmap.ExitRoute
	}{
		{"none", exitPreference{}, nil},
		{"by reference", exitPreference{use: "pool-a"}, &networkmap.ExitRoute{Pool: "pool-a", Node: "exit-1", IPv6: true}},
		{"by name", exitPreference{use: "Europe"}, &networkmap.ExitRoute{Pool: "pool-a", Node: "exit-1", IPv6: true}},
		{
			"auto takes a served pool",
			exitPreference{use: routesettings.ExitUseAuto},
			&networkmap.ExitRoute{Pool: "pool-a", Node: "exit-1", IPv6: true},
		},
		// A pool not granted, or one no exit node serves, drops the
		// Internet rather than letting it out of the mesh.
		{"not granted", exitPreference{use: "elsewhere"}, &networkmap.ExitRoute{}},
		{"unserved", exitPreference{use: "pool-b"}, &networkmap.ExitRoute{Pool: "pool-b"}},
		{"managed only when allowed", exitPreference{allowManaged: true}, &networkmap.ExitRoute{Pool: "pool-b"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := newExitHarness(test.preference, exitMap("exit-1")).route()
			if !equalExitRoutes(got, test.want) {
				t.Fatalf("route = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestExitChoiceKeepsItsExitNodeWhenCoreElectsAnother(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	h.failover.effective(exitMap("exit-2"))
	if got := h.route(); got.Node != "exit-1" {
		t.Fatalf("node = %q, want the sticky exit-1", got.Node)
	}
	report, view, _ := h.failover.exitSelection()
	if report.Reason != controlplane.RouteSelectionSticky || view.Via != "sticky" || view.ExitNodeName != "fra" {
		t.Fatalf("selection = %+v %+v", report, view)
	}
}

func TestExitChoiceLeavesAFailedOrRemovedExitNode(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	// Core sees exit-1 cannot reach the Internet, though its tunnel is up.
	h.failover.effective(exitMap("exit-1", networkmap.ExitStateFailed))
	if got := h.route(); got.Node != "exit-2" || got.IPv6 {
		t.Fatalf("route = %+v, want exit-2 without IPv6", got)
	}
	report, _, _ := h.failover.exitSelection()
	if report.Reason != controlplane.RouteSelectionLocalFailover {
		t.Fatalf("reason = %v, want local failover", report.Reason)
	}
}

func TestExitChoiceFailsOverWhenTheExitNodeStopsAnswering(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	h.step(21, 22)
	for range 4 {
		if h.step(21, 22) {
			t.Fatal("a working exit node was left")
		}
	}
	changed := false
	for range 6 {
		changed = h.step(22) || changed
	}
	if !changed || h.route().Node != "exit-2" {
		t.Fatalf("changed = %t, route = %+v, want exit-2", changed, h.route())
	}
	// exit-1 answers again: the node stays where it is.
	for range 5 {
		if h.step(21, 22) {
			t.Fatal("switched back while exit-2 works")
		}
	}
}

func TestExitChoiceFollowsAChangedPreference(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{}, exitMap("exit-1"))
	if h.route() != nil {
		t.Fatal("an exit route without a preference")
	}
	if !h.failover.setExitPreference(exitPreference{use: "pool-a"}) || h.route().Node != "exit-1" {
		t.Fatalf("route = %+v after choosing pool-a", h.route())
	}
	if h.failover.setExitPreference(exitPreference{use: "pool-a"}) {
		t.Fatal("an unchanged preference changed the route")
	}
	if !h.failover.setExitPreference(exitPreference{}) || h.route() != nil {
		t.Fatal("turning the exit off kept the route")
	}
}

func TestExitChoicePingsTheCandidatesThroughTheRelay(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	if got := h.failover.routerPeers(); len(got) != 2 || got[0] != 21 || got[1] != 22 {
		t.Fatalf("relay liveness peers = %v, want 21 and 22", got)
	}
}

// A pool's exit nodes are pinned at its first use: one Core adds later
// carries nothing until approved, one it removes is forgotten, and a host
// that lets the administrator choose trusts Core.
func TestExitChoicePinsTheExitNodesOfAPool(t *testing.T) {
	t.Parallel()
	pins, err := openExitPins(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := &failoverClock{now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	failover := newRouteFailover(clock.Now)
	failover.seedExit(exitPreference{use: "pool-a"}, exitSticky{}, pins)
	first := exitMap("exit-1")
	first.Exits[0].Candidates = first.Exits[0].Candidates[:1]
	failover.effective(first)
	if got := failover.current().ExitRoute; got.Node != "exit-1" {
		t.Fatalf("route = %+v", got)
	}
	// Core adds exit-2 and makes it the only one that works.
	failover.effective(exitMap("exit-2", networkmap.ExitStateFailed))
	if got := failover.current().ExitRoute; got.Node != "" {
		t.Fatalf("an unapproved exit node carried traffic: %+v", got)
	}
	_, view, _ := failover.exitSelection()
	if len(view.Pending) != 1 || view.Pending[0] != "exit-2" || view.PendingNames[0] != "ams" {
		t.Fatalf("pending = %v %v", view.Pending, view.PendingNames)
	}
	// Approved: it carries traffic, and the pin outlives a restart.
	approved, _ := pins.approved("pool-a")
	if err := pins.set("pool-a", append(approved, "exit-2")); err != nil {
		t.Fatal(err)
	}
	failover.judge(nil)
	if got := failover.current().ExitRoute; got.Node != "exit-2" {
		t.Fatalf("route after approval = %+v", got)
	}
	reopened, err := openExitPins(pins.dir)
	if err != nil {
		t.Fatal(err)
	}
	if nodes, pinned := reopened.approved("pool-a"); !pinned || len(nodes) != 2 {
		t.Fatalf("pins after reopening = %v %t", nodes, pinned)
	}
	// Removed from the pool: forgotten, so its return needs approval again.
	failover.effective(first)
	if nodes, _ := pins.approved("pool-a"); len(nodes) != 1 || nodes[0] != "exit-1" {
		t.Fatalf("pins after a removal = %v", nodes)
	}
	// Managed exits trust Core.
	managed := newExitHarness(exitPreference{allowManaged: true}, exitMap("exit-2"))
	if _, view, _ := managed.failover.exitSelection(); len(view.Pending) != 0 {
		t.Fatalf("a managed host left exit nodes pending: %v", view.Pending)
	}
}

// Auto measures the primaries of the served pools, takes the nearest and
// keeps it, even when another becomes a little faster.
func TestExitChoiceAutoTakesTheNearestPoolAndKeepsIt(t *testing.T) {
	t.Parallel()
	snapshot := exitMap("exit-1")
	snapshot.Peers = append(snapshot.Peers, networkmap.Node{ID: 23, StableID: "exit-3", Name: "sgp"})
	snapshot.Exits[1] = networkmap.ExitPool{
		Ref: "pool-b", Name: "Asia", Status: networkmap.ExitServed, Primary: "exit-3",
		Candidates: []networkmap.ExitCandidate{{DeviceID: "exit-3", State: networkmap.ExitStateOK, IPv4: true}},
	}
	h := newExitHarness(exitPreference{use: routesettings.ExitUseAuto}, snapshot)
	rtt := func(id uint64, delay time.Duration) {
		h.failover.ObservePath(pathdiscovery.PathObservation{PeerID: id, ObservedAt: h.clock.now, RoundTrip: delay})
	}
	for range exitRTTSamples {
		h.clock.now = h.clock.now.Add(time.Second)
		rtt(21, 180*time.Millisecond)
		rtt(23, 20*time.Millisecond)
	}
	h.step()
	if got := h.route(); got.Pool != "pool-b" || got.Node != "exit-3" {
		t.Fatalf("auto chose %+v, want the nearer pool-b", got)
	}
	for range 3 {
		h.clock.now = h.clock.now.Add(time.Second)
		rtt(21, 5*time.Millisecond)
		rtt(23, 25*time.Millisecond)
	}
	h.step(21, 23)
	if got := h.route(); got.Pool != "pool-b" {
		t.Fatalf("auto left its pool for a faster one: %+v", got)
	}
}

// New connections through an exit node that go unanswered while it still
// answers probes move the node to the next candidate.
func TestExitChoiceLeavesAnExitNodeThatNoLongerReachesTheInternet(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	h.step(21, 22)
	h.failover.observeExitActivity(dataplane.ExitActivity{
		Node: "exit-1", NewConnections: 3, WaitingSince: h.clock.now,
	})
	h.step(21, 22)
	if h.route().Node != "exit-1" {
		t.Fatal("left before the connections waited long enough")
	}
	changed := false
	for range 5 {
		changed = h.step(21, 22) || changed
	}
	if !changed || h.route().Node != "exit-2" {
		t.Fatalf("route = %+v, want exit-2", h.route())
	}
}

// A pool chosen by name keeps that pool: another pool Core gives the name
// waits for approval by reference, which binds the name to it.
func TestExitChoiceBindsAPoolName(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "Europe"}, exitMap("exit-1"))
	if got := h.route(); got.Pool != "pool-a" {
		t.Fatalf("route = %+v", got)
	}
	renamed := exitMap("exit-1")
	renamed.Exits[0].Ref, renamed.Exits[1].Name = "pool-c", "Office" // pool-a gone, pool-c named Europe
	renamed.Exits[0], renamed.Exits[1] = renamed.Exits[1], renamed.Exits[0]
	h.failover.effective(renamed)
	if got := h.route(); got.Node != "" || got.Pool != "" {
		t.Fatalf("a pool renamed by Core carried traffic: %+v", got)
	}
	_, view, _ := h.failover.exitSelection()
	if view.PendingPool != "pool-c" {
		t.Fatalf("pending pool = %q", view.PendingPool)
	}
	service := &Service{exitPins: h.failover.exit.pins, exit: view}
	if _, err := service.ApproveExitNodes(t.Context(), []string{"exit-9"}); err == nil {
		t.Fatal("approving something not waiting succeeded")
	}
	if result, err := service.ApproveExitNodes(t.Context(), []string{"pool-c"}); err != nil || result.Pool != "pool-c" {
		t.Fatalf("approving the pool = %+v, %v", result, err)
	}
	h.step()
	if got := h.route(); got.Pool != "pool-c" || got.Node != "exit-1" {
		t.Fatalf("route after approval = %+v", got)
	}
}

// Once a pool is pinned, auto never moves to a pool Core adds.
func TestExitChoiceAutoKeepsToPinnedPools(t *testing.T) {
	t.Parallel()
	pins, _ := openExitPins("")
	if err := pins.set("pool-a", []string{"exit-1", "exit-2"}); err != nil {
		t.Fatal(err)
	}
	snapshot := exitMap("exit-1")
	snapshot.Exits[0].Status, snapshot.Exits[0].Primary = networkmap.ExitUnserved, ""
	snapshot.Exits[1].Status, snapshot.Exits[1].Primary = networkmap.ExitServed, "exit-2"
	clock := &failoverClock{now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	failover := newRouteFailover(clock.Now)
	failover.seedExit(exitPreference{use: routesettings.ExitUseAuto}, exitSticky{pool: "pool-a"}, pins)
	failover.effective(snapshot)
	if got := failover.current().ExitRoute; got.Pool != "pool-a" || got.Node != "" {
		t.Fatalf("auto moved to an unpinned pool: %+v", got)
	}
}

// A stuck exit node is avoided for a while, then tried again: a pool of
// one is not lost for good.
func TestExitChoiceTriesAStuckExitNodeAgain(t *testing.T) {
	t.Parallel()
	snapshot := exitMap("exit-1")
	snapshot.Exits[0].Candidates = snapshot.Exits[0].Candidates[:1]
	h := newExitHarness(exitPreference{use: "pool-a"}, snapshot)
	h.failover.observeExitActivity(dataplane.ExitActivity{Node: "exit-1", NewConnections: 3, WaitingSince: h.clock.now})
	for range 6 {
		h.step(21)
	}
	if got := h.route(); got.Node != "" {
		t.Fatalf("a stuck exit node kept the traffic: %+v", got)
	}
	// The filter's evidence goes with the exit node; old evidence counts no
	// more.
	h.failover.observeExitActivity(dataplane.ExitActivity{
		Node: "exit-1", NewConnections: 3,
		WaitingSince: h.clock.now.Add(-time.Minute),
	})
	for range int(exitStuckAvoid/time.Second) + 1 {
		h.step(21)
	}
	if got := h.route(); got.Node != "exit-1" {
		t.Fatalf("the exit node was never tried again: %+v", got)
	}
}

// An empty pin trusts nobody, also after it is written and read back.
func TestExitPinsKeepAnEmptyPinEmpty(t *testing.T) {
	t.Parallel()
	pins, err := openExitPins(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := pins.set("pool-a", nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := openExitPins(pins.dir)
	if err != nil {
		t.Fatal(err)
	}
	if nodes, pinned := reopened.approved("pool-a"); !pinned || nodes == nil || len(nodes) != 0 {
		t.Fatalf("approved = %#v, %t", nodes, pinned)
	}
}

func TestExitChoiceKeepsTheOnlyExitNodeWhenItLooksSilent(t *testing.T) {
	t.Parallel()
	single := exitMap("exit-1")
	single.Exits[0].Candidates = single.Exits[0].Candidates[:1]
	h := newExitHarness(exitPreference{use: "pool-a"}, single)
	h.step(21)
	// Its direct path proof expires (the relay may still carry it): with
	// no other candidate, dropping it would only block everything.
	for range 30 {
		h.step()
	}
	if got := h.route(); got.Node != "exit-1" {
		t.Fatalf("route = %+v, want exit-1 kept", got)
	}
	attrs := h.failover.exitLogAttrs()
	if len(attrs) != 6 || attrs[3] != "exit-1" {
		t.Fatalf("log attributes = %v", attrs)
	}
}
