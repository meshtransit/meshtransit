package daemon

import (
	"slices"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/netadmin"
)

// Each window that closes is kept with how it ended: closed by meshd once
// the tunnel was back, run out, or closed by root; it survives a restart,
// and goes once reported in captiveWindowSends sessions.
func TestClosedCaptiveWindowsAreKeptToReport(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tracker := newCaptiveTracker(dir)
	start := time.Now().Add(-10 * time.Minute)
	ids := []string{strings.Repeat("a1", 16), strings.Repeat("b2", 16), strings.Repeat("c3", 16)}

	// Run out: the helper still reports it at its end.
	until := start.Add(time.Minute)
	tracker.followWindow(netadmin.CaptiveWindow{ID: ids[0]}, until, start, true)
	tracker.followWindow(netadmin.CaptiveWindow{ID: ids[0]}, until, until, true)

	// Closed by meshd: the tunnel was down, then back for captiveCloseAfter.
	at := start.Add(2 * time.Minute)
	until = at.Add(5 * time.Minute)
	tracker.followWindow(netadmin.CaptiveWindow{ID: ids[1]}, until, at, false)
	tracker.followWindow(netadmin.CaptiveWindow{ID: ids[1]}, until, at.Add(time.Second), true)
	if closing, _ := tracker.followWindow(netadmin.CaptiveWindow{ID: ids[1]}, until,
		at.Add(time.Second+captiveCloseAfter), true); closing != ids[1] {
		t.Fatalf("meshd did not close the window: %q", closing)
	}
	tracker.followWindow(netadmin.CaptiveWindow{}, until, at.Add(20*time.Second), true)

	// Closed by root early, replaced by none.
	at = start.Add(4 * time.Minute)
	tracker.followWindow(netadmin.CaptiveWindow{ID: ids[2]}, at.Add(5*time.Minute), at, true)
	tracker.followWindow(netadmin.CaptiveWindow{}, at.Add(5*time.Minute), at.Add(30*time.Second), true)

	want := []controlplane.CaptiveWindow{
		{ID: ids[0], Opened: start, Closed: start.Add(time.Minute), End: controlplane.CaptiveWindowExpired},
		{
			ID: ids[1], Opened: start.Add(2 * time.Minute), Closed: start.Add(2*time.Minute + 20*time.Second),
			End: controlplane.CaptiveWindowTunnelBack,
		},
		{ID: ids[2], Opened: at, Closed: at.Add(30 * time.Second), End: controlplane.CaptiveWindowClosed},
	}
	equal := func(got []controlplane.CaptiveWindow) bool {
		return slices.EqualFunc(got, want, func(a, b controlplane.CaptiveWindow) bool {
			return a.ID == b.ID && a.Opened.Equal(b.Opened) && a.Closed.Equal(b.Closed) && a.End == b.End
		})
	}
	if got := tracker.closedWindows(); !equal(got) {
		t.Fatalf("closed windows %+v, want %+v", got, want)
	}
	reopened := newCaptiveTracker(dir)
	if got := reopened.closedWindows(); !equal(got) {
		t.Fatalf("after a restart %+v", got)
	}
	for range captiveWindowSends - 1 {
		reopened.windowsSent(ids[:1])
	}
	if got := reopened.closedWindows(); len(got) != 3 {
		t.Fatalf("a window went before its last session: %+v", got)
	}
	reopened.windowsSent(ids[:1])
	want = want[1:]
	if got := newCaptiveTracker(dir).closedWindows(); !equal(got) {
		t.Fatalf("after its last session %+v", got)
	}
}

// At most maxCaptiveWindowsKept windows are kept, the newest; windows of
// another shape or too old are not read back.
func TestClosedCaptiveWindowsAreBounded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tracker := newCaptiveTracker(dir)
	now := time.Now()
	for index := range maxCaptiveWindowsKept + 3 {
		id := strings.Repeat("0", 30) + string("0123456789abcdef"[index/16]) + string("0123456789abcdef"[index%16])
		at := now.Add(time.Duration(index) * time.Minute)
		tracker.followWindow(netadmin.CaptiveWindow{ID: id}, at.Add(5*time.Minute), at, true)
	}
	tracker.followWindow(netadmin.CaptiveWindow{}, now, now.Add(time.Hour), true)
	got := tracker.closedWindows()
	if len(got) != maxCaptiveWindowsKept || got[0].ID != strings.Repeat("0", 30)+"03" {
		t.Fatalf("kept %d windows from %+v", len(got), got[0])
	}
	tracker.mu.Lock()
	tracker.closed[0].ID = "W1"
	tracker.closed[1].Closed = now.Add(-captiveWindowKeptFor - time.Hour)
	tracker.closed[1].Opened = tracker.closed[1].Closed.Add(-time.Minute)
	tracker.writeClosedLocked()
	tracker.mu.Unlock()
	if got := newCaptiveTracker(dir).closedWindows(); len(got) != maxCaptiveWindowsKept-2 {
		t.Fatalf("read back %d windows", len(got))
	}
}

// A window meshd saw end twice, as when it lost the helper's answer for a
// moment, is kept once with its first opening and last end; one the host
// slept through ends at its own end, not on waking.
func TestClosedCaptiveWindowSeenTwiceOrSleptThrough(t *testing.T) {
	t.Parallel()
	tracker := newCaptiveTracker("")
	start := time.Now().Add(-time.Hour)
	twice, slept := strings.Repeat("d4", 16), strings.Repeat("e5", 16)
	until := start.Add(5 * time.Minute)
	tracker.followWindow(netadmin.CaptiveWindow{ID: twice}, until, start, true)
	tracker.followWindow(netadmin.CaptiveWindow{}, until, start.Add(time.Minute), true)
	tracker.followWindow(netadmin.CaptiveWindow{ID: twice}, until, start.Add(time.Minute+time.Second), true)
	tracker.followWindow(netadmin.CaptiveWindow{ID: twice}, until, until, true)

	at := start.Add(10 * time.Minute)
	tracker.followWindow(netadmin.CaptiveWindow{ID: slept}, at.Add(2*time.Minute), at, true)
	tracker.followWindow(netadmin.CaptiveWindow{ID: slept}, at.Add(2*time.Minute), at.Add(50*time.Minute), true)

	got := tracker.closedWindows()
	if len(got) != 2 || got[0].ID != twice || !got[0].Opened.Equal(start) || !got[0].Closed.Equal(until) ||
		got[0].End != controlplane.CaptiveWindowExpired {
		t.Fatalf("the window seen twice: %+v", got)
	}
	if got[1].ID != slept || !got[1].Closed.Equal(at.Add(2*time.Minute)) || got[1].End != controlplane.CaptiveWindowExpired {
		t.Fatalf("the window slept through: %+v", got[1])
	}
}
