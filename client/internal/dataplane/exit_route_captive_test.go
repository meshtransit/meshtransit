package dataplane

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/client/internal/netadmin"
)

// A failed exchange with the helper keeps the window meshd follows until its
// end: the helper still counts it. An answer without one closes it.
func TestExitRouteStatusKeepsTheWindowThroughAFailedExchange(t *testing.T) {
	engine := &WireGuardEngine{}
	window := netadmin.CaptiveWindow{ID: "w1", Remaining: time.Minute, Interface: "wlan0"}
	engine.recordExitRouteLocked(exitRouteDesired{}, netadmin.ExitRouting{Captive: window}, nil)
	until := engine.exitRouteStatus.CaptiveUntil
	if engine.exitRouteStatus.Captive.ID != "w1" || until.IsZero() {
		t.Fatalf("the window was not followed: %+v", engine.exitRouteStatus)
	}
	engine.recordExitRouteLocked(exitRouteDesired{}, netadmin.ExitRouting{}, errors.New("helper busy"))
	if engine.exitRouteStatus.Captive.ID != "w1" || !engine.exitRouteStatus.CaptiveUntil.Equal(until) ||
		engine.exitRouteStatus.Error == "" {
		t.Fatalf("a failed exchange lost the window: %+v", engine.exitRouteStatus)
	}
	engine.recordExitRouteLocked(exitRouteDesired{}, netadmin.ExitRouting{}, nil)
	if engine.exitRouteStatus.Captive.ID != "" || !engine.exitRouteStatus.CaptiveUntil.IsZero() {
		t.Fatalf("an answer without the window kept it: %+v", engine.exitRouteStatus)
	}
	engine.exitRouteStatus.Captive, engine.exitRouteStatus.CaptiveUntil = window, time.Now().Add(-time.Second)
	engine.recordExitRouteLocked(exitRouteDesired{}, netadmin.ExitRouting{}, errors.New("helper busy"))
	if engine.exitRouteStatus.Captive.ID != "" {
		t.Fatal("a failed exchange kept a window past its end")
	}
}
