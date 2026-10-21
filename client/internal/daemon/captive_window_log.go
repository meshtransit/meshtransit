package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/controlplane"
)

// The captive portal windows that closed, kept to report to Core for its
// audit (exit node design §17.12): kept on disk, so a window closed while
// Core was out of reach is reported in a later session, and each reported in
// up to captiveWindowSends sessions, as Core does not answer a report.

const (
	captiveWindowsFile = "captive-windows.json"
	// maxCaptiveWindowsKept bounds the windows kept; the oldest go first.
	maxCaptiveWindowsKept = 32
	// captiveWindowSends is how many sessions report a window.
	captiveWindowSends = 3
	// captiveWindowKeptFor is how long a window is kept unreported; Core
	// takes windows up to 30 days old.
	captiveWindowKeptFor = 7 * 24 * time.Hour
	// captiveWindowEndsOnTime is how close to its end a window the helper
	// closed counts as run out: meshd sees it once a second.
	captiveWindowEndsOnTime = 3 * time.Second
	// maxCaptiveWindowLength is the longest window kept: the helper's cap
	// with slack for meshd seeing it a little late, within Core's 6 minutes.
	maxCaptiveWindowLength = captive.MaximumWindow + 30*time.Second
)

// closedCaptiveWindow is a closed window as kept on disk.
type closedCaptiveWindow struct {
	ID     string                        `json:"id"`
	Opened time.Time                     `json:"opened"`
	Closed time.Time                     `json:"closed"`
	End    controlplane.CaptiveWindowEnd `json:"end"`
	Sends  int                           `json:"sends,omitempty"`
}

func (window closedCaptiveWindow) valid(now time.Time) bool {
	return captiveWindowID(window.ID) && !window.Opened.IsZero() && !window.Closed.Before(window.Opened) &&
		window.End >= controlplane.CaptiveWindowExpired && window.End <= controlplane.CaptiveWindowTunnelBack &&
		window.Closed.Sub(window.Opened) <= maxCaptiveWindowLength &&
		window.Sends < captiveWindowSends && now.Sub(window.Closed) < captiveWindowKeptFor
}

// captiveWindowID reports the helper's window ID shape: 32 lowercase hex
// digits.
func captiveWindowID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, digit := range id {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

// readClosedCaptiveWindows reads the windows kept in dir, none when it has
// none or they cannot be read.
func readClosedCaptiveWindows(dir string, now time.Time) []closedCaptiveWindow {
	if dir == "" {
		return nil
	}
	encoded, err := os.ReadFile(filepath.Join(dir, captiveWindowsFile)) //nolint:gosec // G304: the daemon's state dir
	if err != nil || len(encoded) > 16<<10 {
		return nil
	}
	var kept []closedCaptiveWindow
	if json.Unmarshal(encoded, &kept) != nil {
		return nil
	}
	kept = slices.DeleteFunc(kept, func(window closedCaptiveWindow) bool { return !window.valid(now) })
	if len(kept) > maxCaptiveWindowsKept {
		kept = kept[len(kept)-maxCaptiveWindowsKept:]
	}
	return kept
}

// noteClosedLocked keeps a window that ended at now, at the latest at its
// own end: a host that slept through it saw it end only on waking. A window
// meshd saw end before, as when it lost the helper's answer for a moment,
// is the same window: it keeps its first opening and its last end, and is
// reported again. The caller holds t.mu.
func (t *captiveTracker) noteClosedLocked(now time.Time, end controlplane.CaptiveWindowEnd) {
	if !captiveWindowID(t.window.id) || t.window.opened.IsZero() {
		return
	}
	closed := now
	if !t.window.until.IsZero() && t.window.until.Before(closed) {
		closed = t.window.until
	}
	if closed.Before(t.window.opened) {
		closed = t.window.opened
	}
	if index := slices.IndexFunc(t.closed, func(window closedCaptiveWindow) bool {
		return window.ID == t.window.id
	}); index >= 0 {
		earlier := t.closed[index]
		t.closed = slices.Delete(slices.Clone(t.closed), index, index+1)
		if earlier.Opened.Before(t.window.opened) {
			t.window.opened = earlier.Opened
		}
		if earlier.Closed.After(closed) {
			closed = earlier.Closed
		}
	}
	if closed.Sub(t.window.opened) > maxCaptiveWindowLength {
		return // not a window the helper could have kept; Core would refuse it
	}
	t.closed = append(t.closed, closedCaptiveWindow{ID: t.window.id, Opened: t.window.opened, Closed: closed, End: end})
	if len(t.closed) > maxCaptiveWindowsKept {
		t.closed = slices.Delete(t.closed, 0, len(t.closed)-maxCaptiveWindowsKept)
	}
	t.writeClosedLocked()
}

// windowEndLocked is how the followed window ended at now: closed by meshd
// once the tunnel was back, run out, or else closed. The caller holds t.mu.
func (t *captiveTracker) windowEndLocked(now time.Time) controlplane.CaptiveWindowEnd {
	switch {
	case t.window.closeAsked:
		return controlplane.CaptiveWindowTunnelBack
	case !now.Before(t.window.until.Add(-captiveWindowEndsOnTime)):
		return controlplane.CaptiveWindowExpired
	}
	return controlplane.CaptiveWindowClosed
}

// closedWindows are the closed windows still to report, oldest first.
func (t *captiveTracker) closedWindows() []controlplane.CaptiveWindow {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	windows := make([]controlplane.CaptiveWindow, 0, len(t.closed))
	for _, window := range t.closed {
		windows = append(windows, controlplane.CaptiveWindow{
			ID: window.ID, Opened: window.Opened, Closed: window.Closed, End: window.End,
		})
	}
	return windows
}

// windowsSent counts a session's report of the windows ids, forgetting each
// once reported in captiveWindowSends sessions.
func (t *captiveTracker) windowsSent(ids []string) {
	if t == nil || len(ids) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.closed[:0]
	for _, window := range t.closed {
		if slices.Contains(ids, window.ID) {
			window.Sends++
		}
		if window.Sends < captiveWindowSends {
			kept = append(kept, window)
		}
	}
	t.closed = kept
	t.writeClosedLocked()
}

// writeClosedLocked keeps the closed windows on disk; in memory only when
// they cannot be written. The caller holds t.mu.
func (t *captiveTracker) writeClosedLocked() {
	if t.dir == "" {
		return
	}
	encoded, err := json.Marshal(t.closed)
	if err != nil {
		return
	}
	_ = writeFileAtomically(filepath.Join(t.dir, captiveWindowsFile), encoded)
}

// captiveWindowsToReport lists the closed windows for the map stream; nil
// without exits, when there is nothing to report.
func (s *Service) captiveWindowsToReport() func() []controlplane.CaptiveWindow {
	if !s.enableExits || s.captive == nil {
		return nil
	}
	return s.captive.closedWindows
}
