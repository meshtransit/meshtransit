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

// RoutedOptions let meshnetd install subnet routes (mtcp-v1 §7.6). On Linux
// the routes go in their own routing table, which a policy rule consults for
// every user but meshd: meshd's own sockets (Control, relays, WireGuard)
// keep the main table and so never enter the mesh they carry. Each helper
// instance on a host has its own table and rule priorities. macOS has one
// table and no such rule: the routes go there, marked, and meshd keeps its
// sockets off them itself; Table, Priority, NftTable and StatePath stay
// unset.
type RoutedOptions struct {
	// SettingsPath is the root-owned local route settings file
	// (routesettings): routes are installed only as it admits.
	SettingsPath string
	// Table is the routing table of the routed routes.
	Table int
	// Priority is the policy rule priority at which every user but meshd
	// looks up Table.
	Priority int
	// NftTable, when set, lets the host forward as a subnet router: the
	// name of the helper's own inet nftables table. StatePath records the
	// host forwarding settings the helper changed.
	NftTable  string
	StatePath string
}

// routedState is what the routed table holds: routes to the mesh
// interface, and throw routes that send single hosts inside them (system
// resolvers) back to the host's own routing.
type routedState struct {
	Routes []netip.Prefix
	Throws []netip.Prefix
}

// routedConfigurer installs routed routes on the data interface and clears
// what this helper installed, also what a previous run left.
type routedConfigurer interface {
	// ReplaceRouted returns what is installed and the routes the kernel
	// refused; an error means the table's state is unknown.
	ReplaceRouted(name string, options RoutedOptions, uid uint32, current, desired routedState) (
		routedState, []routesettings.Refusal, error)
	Clear(options RoutedOptions, uid uint32) error
}

var errRoutedUnsupported = errors.New("netadmin: routed routes are not supported on this platform")

func validRoutedOptions(options RoutedOptions) bool {
	return options.SettingsPath != "" && validPlatformRoutedOptions(options)
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
	// Never a route into the mesh's own unique local blocks: meshd does not
	// decide that either.
	accepted, reserved := routesettings.WithoutMesh(accepted,
		append(slices.Clone(s.activeTUN.Addresses), s.activeTUN.Routes...))
	refused = append(refused, reserved...)
	desired := routedState{Routes: accepted}
	if len(accepted) > 0 {
		local, err := s.hostRouting.LocalRoutes(s.activeName)
		if err != nil {
			// The host's networks are unknown: no route may risk them.
			s.logger.Warn("reading local routes failed; installing no subnet routes", "error", err)
			for _, route := range accepted {
				refused = append(refused, routesettings.Refusal{Prefix: route, Reason: routesettings.ReasonLocalConflict})
			}
			accepted = []netip.Prefix{}
		} else {
			var conflicts []routesettings.Refusal
			accepted, conflicts = WithoutLocalConflicts(accepted, local)
			refused = append(refused, conflicts...)
		}
		desired = routedState{Routes: accepted, Throws: PinnedResolvers(accepted, s.hostRouting.Resolvers())}
	}
	installed, failed, err := s.routedConfigurer.ReplaceRouted(s.activeName, *s.routed, s.allowedUID,
		s.activeRouted, desired)
	if err != nil {
		// What is installed is now unknown: clear it all, so the next try
		// starts from an empty table instead of a stale view.
		if clearErr := s.routedConfigurer.Clear(*s.routed, s.allowedUID); clearErr != nil {
			err = errors.Join(err, clearErr)
		}
		s.activeRouted, s.requestedRouted = routedState{}, slices.Clone(requested)
		return nil, nil, fmt.Errorf("netadmin: replacing routed routes: %w", err)
	}
	s.activeRouted = routedState{Routes: slices.Clone(installed.Routes), Throws: slices.Clone(installed.Throws)}
	s.requestedRouted = slices.Clone(requested)
	return installed.Routes, append(refused, failed...), nil
}

// withoutUnpinned drops each route containing a resolver whose pin the
// kernel refused, with the pin's reason.
func withoutUnpinned(routes []netip.Prefix, failedPins []routesettings.Refusal) ([]netip.Prefix, []routesettings.Refusal) {
	if len(failedPins) == 0 {
		return routes, nil
	}
	kept := make([]netip.Prefix, 0, len(routes))
	var refused []routesettings.Refusal
	for _, route := range routes {
		index := slices.IndexFunc(failedPins, func(pin routesettings.Refusal) bool { return route.Contains(pin.Prefix.Addr()) })
		if index >= 0 {
			refused = append(refused, routesettings.Refusal{Prefix: route, Reason: failedPins[index].Reason})
			continue
		}
		kept = append(kept, route)
	}
	return kept, refused
}

// prefixIntersection returns the prefixes of left also in right, in left's
// order.
func prefixIntersection(left, right []netip.Prefix) []netip.Prefix {
	return prefixDifference(left, prefixDifference(left, right))
}

// hostRouting reads what the local route checks need from the host.
type hostRouting interface {
	// LocalRoutes returns the main table's routes other than default routes
	// and those on the mesh interface.
	LocalRoutes(meshInterface string) ([]LocalRoute, error)
	// Resolvers returns the system DNS servers learned from the physical
	// network.
	Resolvers() []netip.Addr
}
