package daemon

import (
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
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
	clock := &failoverClock{now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	h := &exitHarness{clock: clock, failover: newRouteFailover(clock.Now)}
	h.failover.seedExit(preference, exitSticky{})
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
