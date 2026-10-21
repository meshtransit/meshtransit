//go:build linux || darwin

package netadmin

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"time"

	"meshtransit.net/client/internal/captive"
)

// A captive portal window (exit node design §17.4–17.6): root writes the
// window file (meshctl exit captive); the helper reads it every second,
// counts the window from then on its monotonic clock and has the exit
// route let the host's own HTTP and HTTPS, and the portal meshd found, out
// to the physical network until it ends. meshd only ever asks to close one.

// captiveWindowPoll is how often the helper reads the window file.
const captiveWindowPoll = time.Second

// openCaptiveWindow is the window the helper holds open.
type openCaptiveWindow struct {
	id string
	// until is when it ends, on the helper's monotonic clock.
	until time.Time
	// opened is the interface the last apply opened.
	opened string
}

// exitCaptive is what the exit route lets out during a window: for how much
// longer, and the portals meshd found.
type exitCaptive struct {
	Remaining time.Duration
	Portals   [2]netip.AddrPort
}

// dnsCacheFlusher empties the host resolver's cache.
type dnsCacheFlusher interface {
	FlushCaches(context.Context) error
}

// watchCaptiveWindow follows the window file until ctx ends.
func (s *Server) watchCaptiveWindow(ctx context.Context) {
	ticker := time.NewTicker(captiveWindowPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		s.pollCaptiveWindow()
		s.mu.Unlock()
	}
}

// captiveWindowPath is the window file, empty when windows are not used.
func (s *Server) captiveWindowPath() string {
	if s.exitRouteConfigurer == nil || s.routed == nil {
		return ""
	}
	return s.routed.CaptiveWindowPath
}

// pollCaptiveWindow opens a new window, and closes one root closed or whose
// time is up.
func (s *Server) pollCaptiveWindow() {
	path := s.captiveWindowPath()
	if path == "" {
		return
	}
	window, err := s.readWindow(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if s.captiveWindow != nil {
			s.closeCaptiveWindow("closed by root")
		}
		return
	case err != nil:
		// Only root writes there; a file the helper does not honour opens
		// nothing and goes.
		s.logger.Warn("ignoring the captive portal window file", "error", err)
		s.closeCaptiveWindow("invalid window file")
		return
	}
	now := s.captiveNow()
	if s.captiveWindow != nil && s.captiveWindow.id == window.ID {
		if !now.Before(s.captiveWindow.until) {
			s.closeCaptiveWindow("its time is up")
		}
		return
	}
	if refusal := s.captiveRefusal(); refusal != "" {
		s.logger.Warn("refusing the captive portal window", "reason", refusal)
		s.closeCaptiveWindow(refusal)
		return
	}
	// Opening again is a new window, from now: never added to the last.
	s.captiveWindow = &openCaptiveWindow{id: window.ID, until: now.Add(window.Duration())}
	s.exitRouteKey = ""
	s.applyExitRoute()
	if s.captiveWindow == nil {
		return
	}
	s.logger.Warn("captive portal window open: the host's HTTP and HTTPS leave outside the exit node",
		"interface", s.captiveWindow.opened, "for", window.Duration())
}

// captiveRefusal says why no window may open: root turned them off, or the
// host routes no Internet traffic into the mesh. Empty when one may.
func (s *Server) captiveRefusal() string {
	settings, err := s.loadSettings(s.routed.SettingsPath)
	if err != nil {
		return "route settings unusable"
	}
	if settings.ExitCaptiveOff {
		return "exit-captive is off"
	}
	if wanted, _ := s.exitRouteWanted(settings); !wanted || s.exitRouteKey == "" {
		return "the host does not use an exit node"
	}
	return ""
}

// closeCaptiveWindow ends the window: the file goes, so a helper that starts
// again never opens it again, the exit route closes the holes, and the host
// resolver forgets what the portal's network answered.
func (s *Server) closeCaptiveWindow(reason string) {
	if path := s.captiveWindowPath(); path != "" {
		if err := captive.CloseWindow(path); err != nil {
			s.logger.Warn("removing the captive portal window file failed", "error", err)
		}
	}
	if s.captiveWindow == nil {
		return
	}
	s.captiveWindow = nil
	s.exitRouteKey = ""
	s.applyExitRoute()
	s.flushDNSCaches()
	s.logger.Info("captive portal window closed", "reason", reason)
}

// captiveFor is what the exit route lets out now: nothing without a window.
func (s *Server) captiveFor() *exitCaptive {
	if s.captiveWindow == nil {
		return nil
	}
	remaining := s.captiveWindow.until.Sub(s.captiveNow())
	if remaining <= 0 {
		return nil
	}
	window := &exitCaptive{Remaining: remaining}
	if s.requestedExitRoute != nil {
		window.Portals = s.requestedExitRoute.CaptivePortals
	}
	return window
}

// captiveKey identifies what a window asks of the exit route, but for its
// time left.
func (s *Server) captiveKey() string {
	window := s.captiveFor()
	if window == nil {
		return "no window"
	}
	return s.captiveWindow.id + " " + window.Portals[0].String() + " " + window.Portals[1].String()
}

// captiveView is the window for meshd.
func (s *Server) captiveView() CaptiveWindow {
	window := s.captiveFor()
	if window == nil || !s.activeExitRoute.Routing {
		return CaptiveWindow{}
	}
	return CaptiveWindow{
		ID: s.captiveWindow.id, Remaining: window.Remaining.Round(time.Second), Interface: s.captiveWindow.opened,
	}
}

// closeCaptiveOnRequest closes the window meshd names: the tunnel is back.
func (s *Server) closeCaptiveOnRequest(id string) {
	if id != "" && s.captiveWindow != nil && s.captiveWindow.id == id {
		s.closeCaptiveWindow("the tunnel is back")
	}
}

// flushDNSCaches empties the host resolver's cache, when the helper manages
// one.
func (s *Server) flushDNSCaches() {
	flusher, ok := s.dns.(dnsCacheFlusher)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := flusher.FlushCaches(ctx); err != nil {
		s.logger.Warn("flushing the host's DNS cache after the captive portal window failed", "error", err)
	}
}
