package mobile

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
)

// maximumReportedRefusals matches what the desktop helper reports.
const maximumReportedRefusals = 64

// SetRoutedRoutes puts on the VPN interface the subnet routes the app's
// settings admit (mtcp-v1 §7.6), refusing those that overlap a network the
// device is attached to (local_conflict): Android sends a Site's traffic to
// the VPN only for the routes its interface has. An interface cannot change
// its routes in place, so a change makes a new one and the running device
// moves to it. The settings and attached networks are read again on every
// request, which the data plane repeats every 10 seconds. The app's own
// sockets are excluded from the VPN (protect), so subnet routes never carry
// them.
func (opener *platformTUN) SetRoutedRoutes(ctx context.Context, requested []netip.Prefix) (netadmin.RoutedResult, error) {
	opener.change.Lock()
	defer opener.change.Unlock()
	settings, err := loadRouteSettings(opener.routeSettings)
	if err != nil {
		opener.logger.Warn("subnet route settings unusable; installing none", "error", err)
		settings = routesettings.Settings{}
	}
	accepted, refused := routesettings.Admit(settings, requested)
	if len(accepted) > 0 {
		var conflicts []routesettings.Refusal
		accepted, conflicts = netadmin.WithoutLocalConflicts(accepted, opener.attachedNetworks())
		refused = append(refused, conflicts...)
		accepted, conflicts = opener.withoutNetworkServers(accepted)
		refused = append(refused, conflicts...)
	}
	opener.mu.Lock()
	current, addresses, routes, installed := opener.open, opener.addresses, opener.routes, opener.routed
	opener.mu.Unlock()
	if current == nil || current.isClosed() {
		return netadmin.RoutedResult{}, fmt.Errorf("%w: no open TUN for subnet routes", errNoTUN)
	}
	if !slices.Equal(installed, accepted) {
		if err := current.Replace(func() (tun.Device, error) {
			return opener.openDevice(ctx, addresses, routes, accepted)
		}); err != nil {
			return netadmin.RoutedResult{}, fmt.Errorf("mobile: changing subnet routes: %w", err)
		}
		opener.mu.Lock()
		if opener.open == current {
			opener.routed = slices.Clone(accepted)
		}
		opener.mu.Unlock()
	}
	result := netadmin.RoutedResult{Installed: slices.Clone(accepted), RefusedTotal: len(refused)}
	result.Refused = slices.Clone(refused[:min(len(refused), maximumReportedRefusals)])
	return result, nil
}

// attachedNetworks returns the networks of the addresses the platform last
// reported with their prefix length.
func (opener *platformTUN) attachedNetworks() []netadmin.LocalRoute {
	if opener.hosts == nil {
		return nil
	}
	networks := opener.hosts.attached()
	local := make([]netadmin.LocalRoute, 0, len(networks))
	for _, network := range networks {
		if network.Addr().IsLinkLocalUnicast() || network.Addr().IsLoopback() || network.Bits() == 0 {
			continue
		}
		local = append(local, netadmin.LocalRoute{Prefix: network, Connected: true})
	}
	return local
}

// withoutNetworkServers refuses each route containing a DNS server or
// gateway of the physical networks: protect() keeps only the app's own
// sockets out of the VPN, not the system's queries or a carrier's services.
func (opener *platformTUN) withoutNetworkServers(routes []netip.Prefix) ([]netip.Prefix, []routesettings.Refusal) {
	if opener.hosts == nil {
		return routes, nil
	}
	servers := opener.hosts.networkServers()
	kept := make([]netip.Prefix, 0, len(routes))
	var refused []routesettings.Refusal
	for _, route := range routes {
		if slices.ContainsFunc(servers, route.Contains) {
			refused = append(refused, routesettings.Refusal{Prefix: route, Reason: routesettings.ReasonLocalConflict})
			continue
		}
		kept = append(kept, route)
	}
	return kept, refused
}

// validateRoutedConfig keeps subnet routes on the interface to canonical
// prefixes the route settings could admit: never the default route, a
// loopback, link-local or multicast range, or the overlay frame.
func validateRoutedConfig(routed []netip.Prefix) error {
	for _, prefix := range routed {
		if prefix != prefix.Masked() || routesettings.Usable(prefix) != "" {
			return fmt.Errorf("%w: %s is not a subnet route", errNoTUN, prefix)
		}
	}
	return nil
}
