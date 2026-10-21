package daemon

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/netadmin"
)

// A window holds the exit choice and shows as open; once the tunnel was
// down during it and is back for 15 s, meshd asks the helper to close it.
// A window opened while the tunnel works stays.
func TestCaptiveTrackerFollowsTheWindow(t *testing.T) {
	t.Parallel()
	tracker := newCaptiveTracker("")
	now := time.Date(2026, time.October, 21, 23, 0, 0, 0, time.UTC)
	window := netadmin.CaptiveWindow{ID: "w1", Remaining: 2 * time.Minute, Interface: "wlan0"}
	until := now.Add(2 * time.Minute)
	follow := func(up bool) (string, bool) {
		closeWindow, open := tracker.followWindow(window, until, now, up)
		now = now.Add(time.Second)
		return closeWindow, open
	}
	if closeWindow, open := follow(true); closeWindow != "" || !open {
		t.Fatalf("window opened with the tunnel up = %q, %t", closeWindow, open)
	}
	for range 30 {
		if closeWindow, _ := follow(true); closeWindow != "" {
			t.Fatal("a window opened while the tunnel works was closed")
		}
	}
	if view := tracker.view(); view.State != captiveStateOpen || view.Interface != "wlan0" || !view.Until.Equal(until) ||
		!tracker.held() {
		t.Fatalf("view = %+v, held %t", view, tracker.held())
	}

	window.ID = "w2"
	follow(false) // behind the portal
	follow(true)  // signed in: the session is back
	for range 14 {
		if closeWindow, _ := follow(true); closeWindow != "" {
			t.Fatal("closed before the tunnel was back for 15 s")
		}
	}
	if closeWindow, _ := follow(true); closeWindow != "w2" {
		t.Fatalf("close = %q, want w2", closeWindow)
	}
	// The tunnel dropping again restarts the count.
	window.ID = "w3"
	follow(false)
	follow(true)
	follow(false)
	follow(true)
	if closeWindow, _ := follow(true); closeWindow != "" {
		t.Fatal("the count did not restart")
	}

	// The exit node answering counts as the tunnel being back.
	tracker.setExitAnswered(func(time.Time) bool { return true })
	window.ID = "w4"
	tracker.followWindow(window, until, now, false)
	if _, open := tracker.followWindow(netadmin.CaptiveWindow{}, until, now, false); open {
		t.Fatal("a window the helper no longer reports stayed open")
	}
	if view := tracker.view(); view.State != string(captive.VerdictNone) || tracker.held() {
		t.Fatalf("after the window: %+v", view)
	}
	// A window past its time is over, whatever the last answer said.
	if _, open := tracker.followWindow(window, now.Add(-time.Second), now, false); open {
		t.Fatal("a window past its time stayed open")
	}
}

func TestCaptivePortalsForASignInPage(t *testing.T) {
	t.Parallel()
	tracker := newCaptiveTracker("")
	tracker.setState(captive.State{Verdict: captive.VerdictPortal, URL: "http://10.0.0.1:8880/guest"})
	if url := tracker.portalWanted(); url != "" {
		t.Fatalf("a portal was wanted without a window: %q", url)
	}
	now := time.Now()
	tracker.followWindow(netadmin.CaptiveWindow{ID: "w1"}, now.Add(time.Minute), now, false)
	url := tracker.portalWanted()
	portals := findPortals(t.Context(), url)
	if url != "http://10.0.0.1:8880/guest" || portals != [2]netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:8880")} {
		t.Fatalf("portal of %q = %v", url, portals)
	}
	tracker.setPortals(url, portals)
	if tracker.portalWanted() != "" || tracker.portals() != portals {
		t.Fatal("the portal was not kept")
	}
	for _, page := range []string{"http://10.0.0.1/login", "https://10.0.0.1:443/", "http://100.64.0.1:8080/", "http://127.0.0.1:8080/"} {
		if got := findPortals(t.Context(), page); got != ([2]netip.AddrPort{}) {
			t.Errorf("findPortals(%q) = %v", page, got)
		}
	}
}
