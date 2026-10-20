//go:build linux || darwin

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/routesettings"
)

// servedConfigurer forwards into served prefixes on the host (design §8.1,
// §8.2). It owns the host's forwarding settings it changed and its table.
type servedConfigurer interface {
	// ReplaceServed returns what it forwards into and the entries the host
	// cannot serve; with exit it also forwards to the Internet as an exit
	// node. An error means the host's state is unknown.
	ReplaceServed(name string, self []netip.Prefix, mtu int, entries []routesettings.ServedEntry,
		exit *exitForwarding) ([]routesettings.ServedEntry, []routesettings.Refusal, error)
	// Present reports whether the rules are still installed.
	Present() (bool, error)
	// Problems reports what keeps the installed forwarding from working:
	// ProblemRulesMissing, ProblemForwardingOff; none when nothing is
	// installed.
	Problems() []string
	// SelfTestPackets counts the self-test packets that left towards a
	// Site since the table was installed; false when it cannot be read.
	SelfTestPackets() (uint64, bool)
	// Conntrack returns the kernel's connection tracking use, 0 and 0 when
	// it does not report it.
	Conntrack() (count, maximum int)
	Clear() error
}

var errServedUnsupported = errors.New("netadmin: subnet routers are not supported on this platform")

// exitForwarding is how the host forwards as an exit node: the limits the
// host's settings leave of Core's, and the host addresses meshd learned that
// are no Internet.
type exitForwarding struct {
	ConntrackPerConsumer int
	SMTP                 bool
	Excluded             []netip.Prefix
}

// exitForwardingOf narrows what meshd asks with the host's settings: nil
// unless asked and exit mode is on.
func exitForwardingOf(settings routesettings.Settings, requested *ExitRequest) (*exitForwarding, ExitServing) {
	if requested == nil || !requested.Serve {
		return nil, ExitServing{}
	}
	if !settings.ExitMode {
		return nil, ExitServing{Refused: ExitRefusedOff}
	}
	exit := &exitForwarding{
		ConntrackPerConsumer: settings.ExitConntrackLimit(requested.ConntrackPerConsumer),
		SMTP:                 settings.ExitSMTP(requested.SMTP), Excluded: slices.Clone(requested.Excluded),
	}
	return exit, ExitServing{
		Serving: true, ConntrackPerConsumer: exit.ConntrackPerConsumer, SMTP: exit.SMTP,
		MaxConsumers: settings.ExitConsumerLimit(),
	}
}

// setServedExit forwards as an exit node while the local settings allow it,
// or stops, and reports how.
func (s *Server) setServedExit(connection *net.UnixConn, requested ExitRequest) error {
	if s.routed == nil || s.servedConfigurer == nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "served_routes_unavailable",
			Message: "this helper does not forward as an exit node",
		}, nil)
		return errServedUnsupported
	}
	if !s.hasActiveTUN {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "invalid_tun_state",
			Message: "tun interface is not owned by this helper generation",
		}, nil)
		return errors.New("netadmin: exit forwarding before the tun interface")
	}
	s.requestedExit = &requested
	served := servedRequest{}
	if s.requestedServed != nil {
		served = *s.requestedServed
	}
	if _, _, err := s.applyForwarding(served); err != nil {
		s.logger.Warn("exit forwarding could not be replaced", "error", err)
	}
	return writeResponse(connection, exitResponse(response{Version: protocolVersion, OK: true}, s.activeExit), nil)
}

func exitResponse(value response, exit ExitServing) response {
	value.ExitServing, value.ExitConntrack, value.ExitSMTP = exit.Serving, exit.ConntrackPerConsumer, exit.SMTP
	value.ExitMaxConsumers, value.ExitRefused = exit.MaxConsumers, exit.Refused
	return value
}

// servedRepairInterval bounds how often a health check installs the router
// again to repair it.
const servedRepairInterval = 10 * time.Second

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
	installed, refused, err := s.applyForwarding(requested)
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

// applyForwarding forwards into what the current settings admit of
// requested, and as an exit node when meshd asked and the settings allow
// it; it remembers both so a change of the settings applies at once.
func (s *Server) applyForwarding(requested servedRequest) ([]routesettings.ServedEntry, []routesettings.Refusal, error) {
	settings, err := s.loadSettings(s.routed.SettingsPath)
	if err != nil {
		// Unreadable or unsafe settings serve nothing.
		s.logger.Warn("route settings unusable; forwarding into no subnets and as no exit node", "error", err)
		settings = routesettings.Settings{}
	}
	exit, exitServing := exitForwardingOf(settings, s.requestedExit)
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
	installed, failed, err := s.servedConfigurer.ReplaceServed(s.activeName, s.activeTUN.Addresses, s.mtu, admitted,
		exit)
	if err != nil {
		// What is installed is now unknown: forward into nothing.
		if clearErr := s.servedConfigurer.Clear(); clearErr != nil {
			err = errors.Join(err, clearErr)
		}
		s.activeServed, s.requestedServed, s.servedRefused, s.servedFailed = nil, &requested, nil, true
		s.activeExit = ExitServing{}
		if exit != nil {
			s.activeExit.Refused = ExitRefusedFailed
		}
		return nil, nil, fmt.Errorf("netadmin: replacing served routes: %w", err)
	}
	refused = append(refused, failed...)
	s.activeServed, s.requestedServed, s.servedRefused, s.servedFailed = installed, &requested, refused, false
	s.activeExit = exitServing
	return installed, refused, nil
}

// forwarding reports whether meshd asked for any forwarding.
func (s *Server) forwarding() bool { return s.requestedServed != nil || s.requestedExit != nil }

// forwardingRequest is the served routes meshd last asked for, none before.
func (s *Server) forwardingRequest() servedRequest {
	if s.requestedServed == nil {
		return servedRequest{}
	}
	return *s.requestedServed
}

// checkServed reports the router's health (design §6.5). A missing table or
// forwarding something turned off is repaired once first, so only what the
// helper cannot fix is reported.
func (s *Server) checkServed(connection *net.UnixConn) error {
	if s.routed == nil || s.servedConfigurer == nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion, Code: "served_routes_unavailable",
			Message: "this helper does not forward into subnets",
		}, nil)
		return errServedUnsupported
	}
	value := response{Version: protocolVersion, OK: true, Routes: []string{}}
	if s.hasActiveTUN && s.forwarding() {
		// At most one repair every servedRepairInterval, however often
		// meshd asks.
		broken := s.servedFailed || ((len(s.activeServed) != 0 || s.activeExit.Serving) &&
			len(s.servedConfigurer.Problems()) != 0)
		if now := time.Now(); broken && now.Sub(s.servedRepaired) >= servedRepairInterval {
			s.servedRepaired = now
			if _, _, err := s.applyForwarding(s.forwardingRequest()); err != nil {
				s.logger.Warn("repairing subnet forwarding failed", "error", err)
			}
		}
		prefixes := make([]netip.Prefix, 0, len(s.activeServed))
		for _, entry := range s.activeServed {
			prefixes = append(prefixes, entry.Prefix)
		}
		value.Routes, value.RefusedTotal = prefixStrings(prefixes), len(s.servedRefused)
		for _, refusal := range s.servedRefused[:min(len(s.servedRefused), maximumReportedRefusals)] {
			value.Refused = append(value.Refused, routeRefusal{Prefix: refusal.Prefix.String(), Reason: refusal.Reason})
		}
		value.Problems = s.servedConfigurer.Problems()
		if s.servedFailed {
			value.Problems = append(value.Problems, ProblemInstallFailed)
		}
		slices.Sort(value.Problems)
		value.Problems = slices.Compact(value.Problems)
		if packets, known := s.servedConfigurer.SelfTestPackets(); known {
			value.SelfTestPackets = &packets
		}
	}
	value.ConntrackCount, value.ConntrackMax = s.servedConfigurer.Conntrack()
	return writeResponse(connection, exitResponse(value, s.activeExit), nil)
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
	s.activeServed, s.requestedServed, s.servedRefused, s.servedFailed = nil, nil, nil, false
	s.requestedExit, s.activeExit = nil, ExitServing{}
}
