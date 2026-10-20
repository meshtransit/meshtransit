//go:build windows

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/winnet"
)

// maximumReportedRefusals matches what the helper reports elsewhere.
const maximumReportedRefusals = 64

// SetRoutedRoutes installs on the adapter the subnet routes the local
// settings admit (mtcp-v1 §7.6). Windows has no helper: the service itself
// does what meshnetd does on Linux and macOS, reading the settings again on
// every request, so a change of them or of the host's networks applies at
// the next (at most 10 s). A route overlapping a network the host reaches
// itself, or holding a system resolver, is refused as a local conflict:
// Windows gets no resolver pins. On a failure no subnet route stays.
func (o *WindowsTUNOpener) SetRoutedRoutes(_ context.Context, requested []netip.Prefix) (netadmin.RoutedResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.luid == 0 {
		return netadmin.RoutedResult{}, errors.New("dataplane: the Wintun adapter is not open")
	}
	settings, err := routesettings.Load(o.routeSettings)
	if err != nil {
		// Unusable settings admit nothing.
		settings = routesettings.Settings{}
	}
	accepted, refused := routesettings.Admit(settings, requested)
	if len(accepted) > 0 {
		accepted, refused = o.withoutLocalConflicts(accepted, refused)
	}
	failed, err := winnet.ReplaceRoutesReporting(o.luid, routeUnion(o.overlay, accepted))
	if err != nil {
		// What is installed is unknown: take every subnet route off.
		_, clearErr := winnet.ReplaceRoutesReporting(o.luid, o.overlay)
		o.routed = nil

		return netadmin.RoutedResult{}, fmt.Errorf("dataplane: replacing subnet routes: %w", errors.Join(err, clearErr))
	}
	installed := make([]netip.Prefix, 0, len(accepted))
	for _, route := range accepted {
		if slices.Contains(failed, route) {
			refused = append(refused, routesettings.Refusal{Prefix: route, Reason: routesettings.ReasonInstallFailed})
			continue
		}
		installed = append(installed, route)
	}
	o.routed = installed
	result := netadmin.RoutedResult{Installed: slices.Clone(installed), RefusedTotal: len(refused)}
	result.Refused = slices.Clone(refused[:min(len(refused), maximumReportedRefusals)])

	return result, nil
}

// withoutLocalConflicts refuses the routes that would take over a network the
// host reaches itself or a resolver it uses. Unknown host routes refuse all.
func (o *WindowsTUNOpener) withoutLocalConflicts(accepted []netip.Prefix, refused []routesettings.Refusal) (
	[]netip.Prefix, []routesettings.Refusal,
) {
	local, err := winnet.LocalRoutes(o.luid)
	resolvers, resolverErr := winnet.Resolvers(o.luid)
	if err != nil || resolverErr != nil {
		for _, route := range accepted {
			refused = append(refused, routesettings.Refusal{Prefix: route, Reason: routesettings.ReasonLocalConflict})
		}

		return []netip.Prefix{}, refused
	}
	kept, conflicts := netadmin.WithoutLocalConflicts(accepted, local)
	refused = append(refused, conflicts...)
	withoutResolvers := kept[:0:0]
	for _, route := range kept {
		if slices.ContainsFunc(resolvers, route.Contains) {
			refused = append(refused, routesettings.Refusal{Prefix: route, Reason: routesettings.ReasonLocalConflict})
			continue
		}
		withoutResolvers = append(withoutResolvers, route)
	}

	return withoutResolvers, refused
}
