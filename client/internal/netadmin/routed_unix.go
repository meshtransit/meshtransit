//go:build linux || darwin

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/routesettings"
)

// RoutedOptions let meshnetd install subnet routes (mtcp-v1 §7.6). The
// routes go in their own routing table, which a policy rule consults for
// every user but meshd: meshd's own sockets (Control, relays, WireGuard)
// keep the main table and so never enter the mesh they carry. Each helper
// instance on a host has its own table and rule priorities.
type RoutedOptions struct {
	// SettingsPath is the root-owned local route settings file
	// (routesettings): routes are installed only as it admits.
	SettingsPath string
	// Table is the routing table of the routed routes.
	Table int
	// Priority is the policy rule priority at which every user but meshd
	// looks up Table.
	Priority int
}

// routedConfigurer installs routed routes on the data interface and clears
// what this helper installed, also what a previous run left.
type routedConfigurer interface {
	ReplaceRouted(name string, options RoutedOptions, uid uint32, current, desired []netip.Prefix) error
	Clear(options RoutedOptions, uid uint32) error
}

var errRoutedUnsupported = errors.New("netadmin: routed routes are not supported on this platform")

func validRoutedOptions(options RoutedOptions) bool {
	return options.SettingsPath != "" && options.Table > 0 && options.Table < 1<<31 &&
		(options.Table < 253 || options.Table > 255) && options.Priority > 0 && options.Priority < 32766
}

// setRouted installs the routed routes the local settings admit and
// reports those refused.
func (s *Server) setRouted(connection *net.UnixConn, requested []netip.Prefix) error {
	if s.routed == nil || s.routedConfigurer == nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "routed_routes_unavailable",
			Message: "this helper does not install subnet routes",
		}, nil)
		return errRoutedUnsupported
	}
	if !s.hasActiveTUN {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "invalid_tun_state",
			Message: "tun interface is not owned by this helper generation",
		}, nil)
		return errors.New("netadmin: routed routes before the tun interface")
	}
	accepted, refused, err := s.applyRouted(requested)
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "routed_routes_failed",
			Message: "subnet routes could not be replaced",
		}, nil)
		return err
	}
	value := response{Version: protocolVersion, OK: true, Routes: prefixStrings(accepted), RefusedTotal: len(refused)}
	for _, refusal := range refused[:min(len(refused), maximumReportedRefusals)] {
		value.Refused = append(value.Refused, routeRefusal{Prefix: refusal.Prefix.String(), Reason: refusal.Reason})
	}
	return writeResponse(connection, value, nil)
}

// applyRouted installs what the current settings admit of requested, which
// it remembers so a change of the settings applies to it at once.
func (s *Server) applyRouted(requested []netip.Prefix) ([]netip.Prefix, []routesettings.Refusal, error) {
	settings, err := s.loadSettings(s.routed.SettingsPath)
	if err != nil {
		// Unreadable or unsafe settings admit nothing: remove what is
		// installed rather than keep routes nobody may have allowed.
		s.logger.Warn("route settings unusable; removing subnet routes", "error", err)
		settings = routesettings.Settings{}
	}
	accepted, refused := routesettings.Admit(settings, requested)
	if err := s.routedConfigurer.ReplaceRouted(s.activeName, *s.routed, s.allowedUID, s.activeRouted,
		accepted); err != nil {
		// What is installed is now unknown: clear it all, so the next try
		// starts from an empty table instead of a stale view.
		if clearErr := s.routedConfigurer.Clear(*s.routed, s.allowedUID); clearErr != nil {
			err = errors.Join(err, clearErr)
		}
		s.activeRouted, s.requestedRouted = nil, slices.Clone(requested)
		return nil, nil, fmt.Errorf("netadmin: replacing routed routes: %w", err)
	}
	s.activeRouted, s.requestedRouted = slices.Clone(accepted), slices.Clone(requested)
	return accepted, refused, nil
}
