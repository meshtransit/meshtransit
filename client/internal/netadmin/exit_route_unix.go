//go:build linux || darwin

package netadmin

import (
	"errors"
	"fmt"
	"net"

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
	// host's attached private subnets out of the mesh. An error leaves what
	// it installed: once the kill switch is in, the host keeps failing
	// closed.
	Replace(name string, ipv6, allowLAN bool) error
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
	s.applyExitRoute()
	return writeResponse(connection, response{
		Version: protocolVersion, OK: true,
		ExitRouting: s.activeExitRoute.Routing, ExitRouteRefused: s.activeExitRoute.Refused,
	}, nil)
}

// exitRouteWanted reports whether the host's Internet goes into the mesh,
// and IPv6 too. Root's choice of a pool holds the kill switch on its own,
// whatever meshd asks, before the first map and across restarts: neither a
// compromised meshd nor Core can lift it (exit node design §6.4). A host
// that only follows managed pools follows meshd, which follows Core.
func (s *Server) exitRouteWanted(settings routesettings.Settings) (wanted, ipv6 bool) {
	requested := s.requestedExitRoute != nil && s.requestedExitRoute.Use
	wanted = settings.ExitUse != "" || (settings.ExitAllowManaged && requested)
	return wanted, wanted && requested && s.requestedExitRoute.IPv6
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
	key := fmt.Sprintf("%s %t %t %s", name, ipv6, settings.ExitAllowLAN, s.exitRouteConfigurer.Stamp(name))
	if key == s.exitRouteKey {
		if present, err := s.exitRouteConfigurer.Present(); err == nil && present {
			return
		}
	}
	if err := s.exitRouteConfigurer.Replace(name, ipv6, settings.ExitAllowLAN); err != nil {
		s.logger.Warn("routing the host through the exit node failed", "error", err)
		s.activeExitRoute, s.exitRouteKey = ExitRouting{Refused: ExitRouteRefusedFailed}, ""
		return
	}
	s.exitRouteKey = key
	s.activeExitRoute = ExitRouting{Routing: name != ""}
}

// clearExitRoute removes the exit routes and the kill switch, whatever a
// previous run left.
func (s *Server) clearExitRoute() {
	s.activeExitRoute, s.exitRouteKey = ExitRouting{}, ""
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
	if err == nil && present {
		return
	}
	s.logger.Warn("the exit kill switch is missing; installing it again", "error", err)
	s.exitRouteKey = ""
	s.applyExitRoute()
}
