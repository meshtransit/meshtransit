//go:build linux || darwin

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/routesettings"
)

// exitRouteConfigurer sends the host's Internet traffic into the mesh
// through the exit node meshd chose, behind a kill switch the helper holds
// (exit node design §6). It owns its routing table, rules and nftables
// table, also what a previous run left.
type exitRouteConfigurer interface {
	// Replace installs the kill switch, then the exit table and its rules;
	// the Internet goes into the mesh interface name when it exists, and
	// IPv6 too when ipv6; otherwise it is unreachable. allowLAN keeps the
	// host's attached private subnets out of the mesh. A captive portal
	// window, when not nil, lets the host's own HTTP and HTTPS and its
	// portals out by the physical interface of the default route, which it
	// returns, for the window's time left at most (exit node design §17.5).
	// An error leaves what it installed: once the kill switch is in, the
	// host keeps failing closed.
	Replace(name string, ipv6, allowLAN bool, window *exitCaptive) (string, error)
	// Present reports whether the kill switch is installed.
	Present() (bool, error)
	// Stamp identifies the host's interfaces and attached subnets the
	// tables follow, so a change applies the last request again.
	Stamp(name string) string
	// Clear removes the rules first and the kill switch last.
	Clear() error
}

var errExitRouteUnsupported = errors.New("netadmin: using an exit node is not supported by this helper")

// setExitRoute records what meshd asks of the exit route and reports how
// the helper routes the host.
func (s *Server) setExitRoute(connection *net.UnixConn, requested ExitRouteRequest) error {
	if s.exitRouteConfigurer == nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "exit_route_unavailable",
			Message: "this helper does not route the host through an exit node",
		}, nil)
		return errExitRouteUnsupported
	}
	if requested.Use && !s.hasActiveTUN {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "invalid_tun_state",
			Message: "tun interface is not owned by this helper generation",
		}, nil)
		return errors.New("netadmin: exit route before the tun interface")
	}
	s.requestedExitRoute = &requested
	// A window just opened or closed shows in this answer, not a second
	// later: meshd asks at once after meshctl changed it.
	s.pollCaptiveWindow()
	s.closeCaptiveOnRequest(requested.CaptiveClose)
	s.applyExitRoute()
	window := s.captiveView()
	return writeResponse(connection, response{
		Version: protocolVersion, OK: true,
		ExitRouting: s.activeExitRoute.Routing, ExitRouteRefused: s.activeExitRoute.Refused,
		ExitRouteTampered: s.activeExitRoute.Routing && s.exitTampered(),
		CaptiveWindow:     window.ID, CaptiveRemaining: int(window.Remaining / time.Second),
		CaptiveInterface: window.Interface,
	}, nil)
}

// exitRouteWanted reports whether the host's Internet goes into the mesh,
// and IPv6 too (ExitRouteWanted).
func (s *Server) exitRouteWanted(settings routesettings.Settings) (wanted, ipv6 bool) {
	return ExitRouteWanted(settings, s.requestedExitRoute)
}

// applyExitRoute routes the host as the settings and meshd's last request
// want, repeating nothing already in place. Unreadable settings change
// nothing: a failed read is no withdrawal of root's choice.
func (s *Server) applyExitRoute() {
	if s.exitRouteConfigurer == nil {
		return
	}
	settings, err := s.loadSettings(s.routed.SettingsPath)
	if err != nil {
		s.logger.Warn("route settings unusable; keeping the exit route as it is", "error", err)
		return
	}
	wanted, ipv6 := s.exitRouteWanted(settings)
	requested := s.requestedExitRoute != nil && s.requestedExitRoute.Use
	if !wanted {
		s.dropCaptiveWindow()
		if s.exitRouteKey != "" || requested {
			s.clearExitRoute()
		}
		if requested && s.activeExitRoute.Refused == "" {
			s.activeExitRoute.Refused = ExitRouteRefusedOff
		}
		return
	}
	name := ""
	if s.hasActiveTUN {
		name = s.activeName
	}
	if settings.ExitCaptiveOff {
		s.dropCaptiveWindow()
	}
	key := fmt.Sprintf("%s %t %t %s %s", name, ipv6, settings.ExitAllowLAN, s.exitRouteConfigurer.Stamp(name),
		s.captiveKey())
	if key == s.exitRouteKey {
		present, err := s.exitRouteConfigurer.Present()
		if err != nil {
			// Unknown, not changed: kept as installed until a read works.
			s.logger.Warn("checking the exit routes failed; keeping them", "error", err)
			return
		}
		if present {
			return
		}
		s.noteExitTampered()
	}
	opened, err := s.exitRouteConfigurer.Replace(name, ipv6, settings.ExitAllowLAN, s.captiveFor())
	if err != nil {
		s.logger.Warn("routing the host through the exit node failed", "error", err)
		s.activeExitRoute, s.exitRouteKey = ExitRouting{Refused: ExitRouteRefusedFailed}, ""
		return
	}
	if s.captiveWindow != nil {
		s.captiveWindow.opened = opened
	}
	s.exitRouteKey = key
	s.activeExitRoute = ExitRouting{Routing: name != ""}
}

// clearExitRoute removes the exit routes and the kill switch, whatever a
// previous run left.
func (s *Server) clearExitRoute() {
	s.activeExitRoute, s.exitRouteKey, s.exitTamperedAt = ExitRouting{}, "", time.Time{}
	if s.exitRouteConfigurer == nil {
		return
	}
	if err := s.exitRouteConfigurer.Clear(); err != nil {
		s.logger.Warn("removing the exit route failed", "error", err)
		s.activeExitRoute.Refused = ExitRouteRefusedFailed
	}
}

// stopExitRoute keeps the kill switch of a helper that stops while root's
// settings name a pool, or cannot be read: the host stays closed until the
// helper is back, or root runs meshnetd --release-exit (the package does on
// removal).
func (s *Server) stopExitRoute() {
	if s.exitRouteConfigurer == nil {
		return
	}
	settings, err := s.loadSettings(s.routed.SettingsPath)
	if err != nil || settings.ExitUse != "" {
		// The kill switch stays, without the window's holes.
		if s.captiveWindow != nil {
			s.dropCaptiveWindow()
			s.exitRouteKey = ""
			s.applyExitRoute()
		}
		return
	}
	s.clearExitRoute()
}

// checkExitRoute installs the exit route again when another tool removed
// the kill switch, such as a firewall reload flushing every table.
func (s *Server) checkExitRoute() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exitRouteConfigurer == nil || s.exitRouteKey == "" {
		return
	}
	present, err := s.exitRouteConfigurer.Present()
	if err != nil {
		s.logger.Warn("checking the exit routes failed; keeping them", "error", err)
		return
	}
	if present {
		return
	}
	s.noteExitTampered()
	s.exitRouteKey = ""
	s.applyExitRoute()
}

// exitTamperedFor is how long status reports the exit routes changed by
// another program after the helper installed them again.
const exitTamperedFor = 10 * time.Minute

// noteExitTampered records that the kill switch or the exit routes it
// installed changed under it: a firewall reload, or a program sending the
// host's traffic elsewhere (exit_rule_tampered).
func (s *Server) noteExitTampered() {
	s.logger.Warn("the exit kill switch or routes changed under the helper; installing them again")
	s.exitTamperedAt = time.Now()
}

// exitTampered reports whether the helper installed the exit routes again
// lately because they changed under it.
func (s *Server) exitTampered() bool {
	return !s.exitTamperedAt.IsZero() && time.Since(s.exitTamperedAt) < exitTamperedFor
}

// startExitRoute takes over what a previous run left: the kill switch stays
// while root's settings name a pool, and goes otherwise.
func (s *Server) startExitRoute() error {
	if s.exitRouteConfigurer == nil {
		return nil
	}
	// A window a previous run held is never opened again.
	s.dropCaptiveWindow()
	settings, err := s.loadSettings(s.routed.SettingsPath)
	if err == nil && settings.ExitUse == "" {
		return s.exitRouteConfigurer.Clear()
	}
	s.applyExitRoute()
	return nil
}

// dropCaptiveWindow forgets the window and removes its file, without
// applying the exit route again: the caller does, or clears it.
func (s *Server) dropCaptiveWindow() {
	if path := s.captiveWindowPath(); path != "" {
		if err := captive.CloseWindow(path); err != nil {
			s.logger.Warn("removing the captive portal window file failed", "error", err)
		}
	}
	if s.captiveWindow != nil {
		s.captiveWindow = nil
		s.flushDNSCaches()
		s.logger.Info("captive portal window closed", "reason", "the exit route changed")
	}
}
