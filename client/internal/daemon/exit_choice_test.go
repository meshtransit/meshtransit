package daemon

import (
	"fmt"
	"slices"
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
	// A silence a poor Wi-Fi or a reconnecting relay causes is waited out:
	// leaving changes the public address and cuts every connection.
	for range 12 {
		if h.step(22) {
			t.Fatalf("left exit-1 after a short silence: %+v", h.route())
		}
	}
	changed := false
	for range 5 {
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
	t.Cleanup(pins.settle)
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

// A primary Core adds after the pool was pinned leaves the node on the exit
// node it trusts, and status says the primary waits for approval rather
// than that it does not answer; it may be approved while no pool is used,
// and the next use takes it (TD-CLI-49).
func TestExitChoiceApprovesANewPrimaryWhileTheExitIsOff(t *testing.T) {
	t.Parallel()
	first := exitMap("exit-2")
	first.Exits[0].Candidates = first.Exits[0].Candidates[1:] // exit-2 only
	h := newExitHarness(exitPreference{use: "pool-a"}, first)
	h.failover.effective(exitMap("exit-1")) // Core adds exit-1 as primary
	h.step(21, 22)
	report, view, _ := h.failover.exitSelection()
	if h.route().Node != "exit-2" || report.Reason != controlplane.RouteSelectionSticky ||
		view.Via != "primary_unapproved" {
		t.Fatalf("route = %+v, report = %+v, via = %q", h.route(), report, view.Via)
	}

	h.failover.setExitPreference(exitPreference{})
	_, view, sticky := h.failover.exitSelection()
	service := &Service{exitPins: h.failover.exit.pins}
	service.setExit(view, sticky, h.failover.exitCandidates())
	if _, err := service.ApproveExitNodes(t.Context(), []string{"exit-9"}); err == nil {
		t.Fatal("approving an exit node of no pool succeeded")
	}
	result, err := service.ApproveExitNodes(t.Context(), []string{"exit-1"})
	if err != nil || result.Pool != "pool-a" || len(result.Approved) != 1 || result.Approved[0] != "exit-1" {
		t.Fatalf("approving while off = %+v, %v", result, err)
	}
	if _, err := service.ApproveExitNodes(t.Context(), []string{"exit-1"}); err == nil {
		t.Fatal("approving it again succeeded")
	}
	h.failover.setExitPreference(exitPreference{use: "pool-a"})
	if report, view, _ := h.failover.exitSelection(); h.route().Node != "exit-1" ||
		report.Reason != controlplane.RouteSelectionPrimary || len(view.Pending) != 0 {
		t.Fatalf("route = %+v, report = %+v, pending = %v", h.route(), report, view.Pending)
	}
}

// A pool never pinned has nothing to approve: its first use trusts every
// candidate.
func TestExitChoiceApprovesNothingInAnUnpinnedPool(t *testing.T) {
	t.Parallel()
	pins, _ := openExitPins("")
	service := &Service{exitPins: pins}
	service.setExit(nil, exitSticky{}, map[string][]string{"pool-a": {"exit-1", "exit-2"}})
	if _, err := service.ApproveExitNodes(t.Context(), []string{"exit-1"}); err == nil {
		t.Fatal("approved in a pool never pinned")
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

// spreadMap is exitMap with pool-a spread and primary assigned to this node.
func spreadMap(primary string, draining ...string) networkmap.Snapshot {
	snapshot := exitMap(primary)
	snapshot.Exits[0].Spread = true
	for index := range snapshot.Exits[0].Candidates {
		for _, id := range draining {
			if snapshot.Exits[0].Candidates[index].DeviceID == id {
				snapshot.Exits[0].Candidates[index].Draining = true
			}
		}
	}
	return snapshot
}

// TestExitChoiceMovesBackToItsAssignedExitNodeWhenIdle: in a spread pool a
// node kept on another exit node moves to the one Core assigned once
// nothing went through the exit for five minutes, not before, and only to
// one that answers; the move does not space later failovers.
func TestExitChoiceMovesBackToItsAssignedExitNodeWhenIdle(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	h.step(21, 22)
	h.failover.effective(spreadMap("exit-2"))
	if h.route().Node != "exit-1" {
		t.Fatalf("node = %q, want the sticky exit-1", h.route().Node)
	}
	// Traffic through exit-1 keeps it.
	h.clock.now = h.clock.now.Add(4 * time.Minute)
	h.failover.observeExitActivity(dataplane.ExitActivity{Node: "exit-1", LastSent: h.clock.now})
	h.clock.now = h.clock.now.Add(4 * time.Minute)
	h.step(21, 22)
	if h.route().Node != "exit-1" {
		t.Fatal("moved while a connection may still be open")
	}
	// Idle, but exit-2 does not answer: it stays.
	h.clock.now = h.clock.now.Add(2 * time.Minute)
	h.step(21)
	if h.route().Node != "exit-1" {
		t.Fatal("moved to an exit node that does not answer")
	}
	if !h.step(21, 22) || h.route().Node != "exit-2" {
		t.Fatalf("route = %+v, want exit-2 once idle", h.route())
	}
	report, _, _ := h.failover.exitSelection()
	if report.Reason != controlplane.RouteSelectionPrimary || !h.failover.exit.nextSwitch.IsZero() {
		t.Fatalf("reason %v, next switch %v", report.Reason, h.failover.exit.nextSwitch)
	}
}

// TestExitChoiceStaysStickyInAFailoverPool: a failover pool keeps the
// sticky exit node however idle, unless that node drains.
func TestExitChoiceStaysStickyInAFailoverPool(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	h.step(21, 22)
	h.failover.effective(exitMap("exit-2"))
	h.clock.now = h.clock.now.Add(time.Hour)
	h.step(21, 22)
	if h.route().Node != "exit-1" {
		t.Fatal("left a sticky exit node of a failover pool")
	}
	draining := exitMap("exit-2")
	draining.Exits[0].Candidates[0].Draining = true
	h.failover.effective(draining)
	h.step(21, 22)
	if h.route().Node != "exit-2" {
		t.Fatalf("route = %+v, want exit-2 off the draining exit-1", h.route())
	}
}

// TestExitChoiceWaitsAfterAFailedMoveBack: leaving the exit node moved back
// to within two minutes counts against it: it is not tried again for 30
// minutes.
func TestExitChoiceWaitsAfterAFailedMoveBack(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	h.step(21, 22)
	h.failover.effective(spreadMap("exit-2"))
	h.clock.now = h.clock.now.Add(6 * time.Minute)
	h.step(21, 22)
	if h.route().Node != "exit-2" {
		t.Fatalf("route = %+v, want exit-2", h.route())
	}
	// exit-2 no longer reaches the Internet: three connections unanswered.
	h.failover.observeExitActivity(dataplane.ExitActivity{
		Node: "exit-2", NewConnections: 3,
		WaitingSince: h.clock.now,
	})
	for range 6 {
		h.step(21, 22)
	}
	if h.route().Node != "exit-1" {
		t.Fatalf("route = %+v, want back on exit-1", h.route())
	}
	h.clock.now = h.clock.now.Add(10 * time.Minute)
	h.step(21, 22)
	if h.route().Node != "exit-1" {
		t.Fatal("moved back again within the wait")
	}
	h.clock.now = h.clock.now.Add(25 * time.Minute)
	h.step(21, 22)
	if h.route().Node != "exit-2" {
		t.Fatalf("route = %+v, want exit-2 after the wait", h.route())
	}
}

// TestExitChoiceGoesBackWhereItCameFrom: a move back that fails within the
// probation returns to the exit node the node came from, not to the first
// candidate.
func TestExitChoiceGoesBackWhereItCameFrom(t *testing.T) {
	t.Parallel()
	three := func(primary string) networkmap.Snapshot {
		snapshot := spreadMap(primary)
		snapshot.Peers = append(snapshot.Peers, networkmap.Node{ID: 23, StableID: "exit-3", Name: "lon"})
		snapshot.Exits[0].Candidates = append(snapshot.Exits[0].Candidates,
			networkmap.ExitCandidate{DeviceID: "exit-3", State: networkmap.ExitStateOK, IPv4: true})
		return snapshot
	}
	h := newExitHarness(exitPreference{use: "pool-a"}, three("exit-2"))
	h.step(21, 22, 23)
	if h.route().Node != "exit-2" {
		t.Fatalf("route = %+v, want exit-2", h.route())
	}
	h.failover.effective(three("exit-3"))
	h.clock.now = h.clock.now.Add(6 * time.Minute)
	h.step(21, 22, 23)
	if h.route().Node != "exit-3" {
		t.Fatalf("route = %+v, want exit-3", h.route())
	}
	h.failover.observeExitActivity(dataplane.ExitActivity{
		Node: "exit-3", NewConnections: 3,
		WaitingSince: h.clock.now,
	})
	for range 6 {
		h.step(21, 22, 23)
	}
	if h.route().Node != "exit-2" {
		t.Fatalf("route = %+v, want back on exit-2", h.route())
	}
}

// The pins a choice takes are written in the background, outside the
// failover lock, and a full store forgets the pool used longest ago.
func TestExitPinsWriteLaterAndForgetTheOldestPool(t *testing.T) {
	t.Parallel()
	pins, err := openExitPins(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for index := range maxPinnedPools {
		pins.trust(fmt.Sprintf("pool-%03d", index), []string{"exit-1"})
	}
	pins.trust("pool-000", []string{"exit-1"}) // used again: now pool-001 is the oldest
	pins.trust("pool-new", []string{"exit-2"})
	pins.settle()
	reopened, err := openExitPins(pins.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, pinned := reopened.approved("pool-new"); !pinned {
		t.Fatal("the pin written in the background was lost")
	}
	if _, pinned := reopened.approved("pool-000"); !pinned {
		t.Fatal("a pool used lately was forgotten")
	}
	if _, pinned := reopened.approved("pool-001"); pinned {
		t.Fatal("the pool used longest ago was kept")
	}
}

// An approval made while the choice prunes the same pool is never undone:
// both read and write the pins under one lock.
func TestExitPinsKeepAnApprovalMadeWhileChoosing(t *testing.T) {
	t.Parallel()
	pins, err := openExitPins(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pins.settle)
	candidates := []string{"exit-1", "exit-2"}
	pins.trust("pool-a", candidates[:1]) // pinned with exit-1 only
	for round := range 200 {
		node := fmt.Sprintf("exit-%d", round+3)
		listed := append(slices.Clone(candidates), node)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 20 {
				pins.trust("pool-a", listed)
			}
		}()
		if added, err := pins.approve("pool-a", []string{node}); err != nil || len(added) != 1 {
			t.Fatalf("approve %s = %v, %v", node, added, err)
		}
		<-done
		if trusted := pins.trust("pool-a", listed); !slices.Contains(trusted, node) {
			t.Fatalf("approval of %s undone: %v", node, trusted)
		}
	}
}

// Behind a captive portal every exit node looks silent: the node in use is
// held, and left only once the portal no longer holds the host.
func TestExitChoiceHoldsItsExitNodeBehindACaptivePortal(t *testing.T) {
	t.Parallel()
	h := newExitHarness(exitPreference{use: "pool-a"}, exitMap("exit-1"))
	held := true
	h.failover.exitHeld = func() bool { return held }
	h.step(21, 22)
	for range 30 {
		if h.step(22) {
			t.Fatalf("left exit-1 behind a portal: %+v", h.route())
		}
	}
	held = false
	if !h.step(22) || h.route().Node != "exit-2" {
		t.Fatalf("route once the portal let go = %+v", h.route())
	}
}

// The relays of a map are kept on disk for a start behind a portal, and a
// map without relays forgets nothing.
func TestCaptiveTrackerKeepsTheRelays(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tracker := newCaptiveTracker(dir)
	tracker.noteRelays(map[int]networkmap.RelayRegion{1: {ID: 1, Nodes: []networkmap.RelayNode{
		{HostName: "relay-sgp1.example", IPv4: "198.51.100.200", IPv6: "2001:db8::200"},
	}}})
	tracker.noteRelays(nil)
	reopened := newCaptiveTracker(dir).relaysSnapshot()
	if len(reopened.Addresses) != 2 || reopened.Name != "relay-sgp1.example" {
		t.Fatalf("relays after reopening = %+v", reopened)
	}
	if tracker.held() || (*captiveTracker)(nil).held() {
		t.Fatal("held with no portal")
	}
}
