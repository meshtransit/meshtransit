//go:build linux || darwin

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"meshtransit.net/client/internal/routesettings"
)

// servedConfigurer forwards into served prefixes on the host (design §8.1,
// §8.2). It owns the host's forwarding settings it changed and its table.
type servedConfigurer interface {
	// ReplaceServed returns what it forwards into and the entries the host
	// cannot serve; an error means the host's state is unknown.
	ReplaceServed(name string, self []netip.Prefix, mtu int, entries []routesettings.ServedEntry) (
		[]routesettings.ServedEntry, []routesettings.Refusal, error)
	// Present reports whether the rules are still installed.
	Present() (bool, error)
	Clear() error
}

var errServedUnsupported = errors.New("netadmin: subnet routers are not supported on this platform")

// setServed forwards into the served prefixes the local settings admit and
// reports those refused.
func (s *Server) setServed(connection *net.UnixConn, requested servedRequest) error {
	if s.routed == nil || s.servedConfigurer == nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "served_routes_unavailable",
			Message: "this helper does not forward into subnets",
		}, nil)
		return errServedUnsupported
	}
	if !s.hasActiveTUN {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "invalid_tun_state",
			Message: "tun interface is not owned by this helper generation",
		}, nil)
		return errors.New("netadmin: served routes before the tun interface")
	}
	installed, refused, err := s.applyServed(requested)
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "served_routes_failed",
			Message: "subnet forwarding could not be replaced",
		}, nil)
		return err
	}
	prefixes := make([]netip.Prefix, 0, len(installed))
	for _, entry := range installed {
		prefixes = append(prefixes, entry.Prefix)
	}
	value := response{Version: protocolVersion, OK: true, Routes: prefixStrings(prefixes), RefusedTotal: len(refused)}
	for _, refusal := range refused[:min(len(refused), maximumReportedRefusals)] {
		value.Refused = append(value.Refused, routeRefusal{Prefix: refusal.Prefix.String(), Reason: refusal.Reason})
	}
	return writeResponse(connection, value, nil)
}

// applyServed forwards into what the current settings admit of requested,
// which it remembers so a change of the settings applies to it at once.
func (s *Server) applyServed(requested servedRequest) ([]routesettings.ServedEntry, []routesettings.Refusal, error) {
	settings, err := s.loadSettings(s.routed.SettingsPath)
	if err != nil {
		// Unreadable or unsafe settings serve nothing.
		s.logger.Warn("route settings unusable; forwarding into no subnets", "error", err)
		settings = routesettings.Settings{}
	}
	plain := make(map[netip.Prefix]struct{}, len(requested.Unmasqueraded))
	for _, prefix := range requested.Unmasqueraded {
		plain[prefix] = struct{}{}
	}
	entries := make([]routesettings.ServedEntry, 0, len(requested.Prefixes))
	for _, prefix := range requested.Prefixes {
		_, unmasqueraded := plain[prefix]
		entries = append(entries, routesettings.ServedEntry{Prefix: prefix, Masquerade: !unmasqueraded})
	}
	admitted, refused := routesettings.AdmitServed(settings, entries)
	installed, failed, err := s.servedConfigurer.ReplaceServed(s.activeName, s.activeTUN.Addresses, s.mtu, admitted)
	if err != nil {
		// What is installed is now unknown: forward into nothing.
		if clearErr := s.servedConfigurer.Clear(); clearErr != nil {
			err = errors.Join(err, clearErr)
		}
		s.activeServed, s.requestedServed = nil, &requested
		return nil, nil, fmt.Errorf("netadmin: replacing served routes: %w", err)
	}
	s.activeServed, s.requestedServed = installed, &requested
	return installed, append(refused, failed...), nil
}

// clearServed stops forwarding, as when the TUN is replaced or the helper
// stops.
func (s *Server) clearServed() {
	if s.servedConfigurer == nil {
		return
	}
	if err := s.servedConfigurer.Clear(); err != nil {
		s.logger.Warn("clearing subnet forwarding failed", "error", err)
	}
	s.activeServed, s.requestedServed = nil, nil
}
