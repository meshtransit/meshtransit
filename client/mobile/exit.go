package mobile

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/overlayframe"
)

// maximumExitRoutes bounds the routes the Internet takes on the interface:
// 0/0 and ::/0 split around at most 64 excluded LAN subnets.
const maximumExitRoutes = 4096

// exitSinkholeResolver is the network address of the overlay frame's
// CGNAT range: never a node's, so queries sent to it go nowhere.
var exitSinkholeResolver = netip.MustParseAddr("100.64.0.0")

// mobileExit is what the VPN interface carries for an exit node: the
// Internet's routes and the exit node's resolvers.
type mobileExit struct {
	routes []netip.Prefix
	dns    []netip.Addr
}

func (exit mobileExit) equal(other mobileExit) bool {
	return slices.Equal(exit.routes, other.routes) && slices.Equal(exit.dns, other.dns)
}

// validate keeps the exit's resolvers inside the overlay frame, reached
// through the mesh like the rest: never a resolver outside it, which would
// send the device's names around the exit node.
func (exit mobileExit) validate() error {
	if len(exit.routes) > maximumExitRoutes {
		return fmt.Errorf("%w: %d exit routes", errNoTUN, len(exit.routes))
	}
	for _, prefix := range exit.routes {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return fmt.Errorf("%w: %s is not an exit route", errNoTUN, prefix)
		}
	}
	for _, address := range exit.dns {
		if !overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) {
			return fmt.Errorf("%w: exit resolver %s is outside the mesh", errNoTUN, address)
		}
	}
	return nil
}

// SetExitRoute sends the device's Internet traffic into the VPN interface,
// as the app's settings and the data plane's request want
// (netadmin.ExitRouteWanted): 0/0 and ::/0, less the attached private
// subnets when the LAN is allowed, with the exit node's resolvers as the
// interface's DNS servers (exit node design §6.1, §7.1). IPv6 always goes
// in: without an exit node that carries it, the data plane refuses it. The
// app's own sockets are excluded from the VPN (protect). Android holds no
// kill switch of the app's: "Block connections without VPN" in its
// always-on VPN settings does that. An interface cannot change in place,
// so a change makes a new one and the running device moves to it.
func (opener *platformTUN) SetExitRoute(ctx context.Context, requested netadmin.ExitRouteRequest) (
	netadmin.ExitRouting, error,
) {
	opener.change.Lock()
	defer opener.change.Unlock()
	settings, err := loadRouteSettings(opener.routeSettings)
	if err != nil {
		// A failed read is no withdrawal of the person's choice.
		return netadmin.ExitRouting{}, fmt.Errorf("mobile: reading exit settings: %w", err)
	}
	wanted, _ := netadmin.ExitRouteWanted(settings, &requested)
	desired := mobileExit{}
	if wanted {
		var lan []netip.Prefix
		if settings.ExitAllowLAN {
			lan = opener.exitLAN()
		}
		desired.routes = internetRoutes(lan)
		for _, address := range requested.DNS {
			if address.IsValid() {
				desired.dns = append(desired.dns, address)
			}
		}
		if len(desired.dns) == 0 {
			// No exit node answers names yet: a resolver nothing answers,
			// inside the mesh, rather than the network's, which Android
			// would otherwise use.
			desired.dns = []netip.Addr{exitSinkholeResolver}
		}
	}
	opener.mu.Lock()
	current, addresses, routes, routed, installed, wantedDNS := opener.open, opener.addresses, opener.routes,
		opener.routed, opener.exit, opener.dnsWanted
	opener.mu.Unlock()
	result := netadmin.ExitRouting{Routing: wanted}
	if requested.Use && !wanted {
		result.Refused = netadmin.ExitRouteRefusedOff
	}
	if current == nil || current.isClosed() {
		opener.mu.Lock()
		opener.exit = desired
		opener.mu.Unlock()
		opener.exitRouted.Store(len(desired.routes) != 0)
		return netadmin.ExitRouting{Refused: result.Refused}, nil
	}
	if installed.equal(desired) || (opener.answer != nil && slices.Equal(installed.routes, desired.routes)) {
		// With the in-process resolver the interface's DNS is always it: a
		// new exit node alone changes nothing on the interface.
		opener.mu.Lock()
		if opener.open == current {
			opener.exit = desired
		}
		opener.mu.Unlock()
		return result, nil
	}
	if len(desired.routes) != 0 {
		// Before the routes: no name may leave outside the mesh once the
		// Internet goes into it.
		opener.exitRouted.Store(true)
	}
	if err := current.Replace(func() (tun.Device, error) {
		return opener.openDevice(ctx, addresses, routes, routed, desired, wantedDNS)
	}); err != nil {
		opener.exitRouted.Store(len(installed.routes) != 0)
		return netadmin.ExitRouting{Refused: netadmin.ExitRouteRefusedFailed},
			fmt.Errorf("mobile: changing the exit route: %w", err)
	}
	opener.exitRouted.Store(len(desired.routes) != 0)
	opener.recordInstalled(current, desired)
	opener.mu.Lock()
	if opener.open == current {
		opener.exit = desired
	}
	opener.mu.Unlock()
	return result, nil
}

// exitLAN returns the attached private subnets and link-local multicast the
// LAN keeps out of the VPN when allowed (exit node design §6.2).
func (opener *platformTUN) exitLAN() []netip.Prefix {
	var lan []netip.Prefix
	if opener.hosts != nil {
		for _, network := range opener.hosts.attached() {
			network = network.Masked()
			if netadmin.ExitLANSubnet(network) && !slices.Contains(lan, network) {
				lan = append(lan, network)
			}
		}
	}
	return append(lan, netadmin.ExitLANMulticast...)
}

// internetRoutes returns 0/0 and ::/0 less excluded, as the fewest
// prefixes that cover the rest.
func internetRoutes(excluded []netip.Prefix) []netip.Prefix {
	var routes []netip.Prefix
	for _, universe := range []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	} {
		routes = appendWithout(routes, universe, excluded)
	}
	return routes
}

// appendWithout appends prefix less every excluded prefix it overlaps.
func appendWithout(routes []netip.Prefix, prefix netip.Prefix, excluded []netip.Prefix) []netip.Prefix {
	overlapping := false
	for _, out := range excluded {
		if !out.IsValid() || out.Addr().Is4() != prefix.Addr().Is4() || !out.Overlaps(prefix) {
			continue
		}
		if out.Bits() <= prefix.Bits() {
			return routes // excluded whole
		}
		overlapping = true
	}
	if !overlapping {
		return append(routes, prefix)
	}
	low, high := halves(prefix)
	return appendWithout(appendWithout(routes, low, excluded), high, excluded)
}

// halves splits prefix into its two prefixes one bit longer.
func halves(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits() + 1
	low := netip.PrefixFrom(prefix.Addr(), bits)
	raw := prefix.Addr().AsSlice()
	raw[prefix.Bits()/8] |= 0x80 >> (prefix.Bits() % 8)
	high, _ := netip.AddrFromSlice(raw)
	return low, netip.PrefixFrom(high, bits)
}

// SetExitNode sets the Exit Pool the device sends its Internet traffic
// through: a pool's name or reference, "auto" for the nearest pool granted,
// or "" for none; allowLAN keeps the attached private networks reachable
// outside the VPN. The change applies within 10 seconds while connected,
// and is kept.
func (engine *Engine) SetExitNode(pool string, allowLAN bool) (err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return errEngineClosed
	}
	settings, err := loadRouteSettings(engine.routeSettings)
	if err != nil {
		return err // never overwrite settings it cannot read
	}
	settings.ExitUse, settings.ExitAllowLAN = strings.TrimSpace(pool), allowLAN
	return saveRouteSettings(engine.routeSettings, settings)
}

// ExitNode returns the Exit Pool the device uses, "" for none.
func (engine *Engine) ExitNode() (pool string, err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return "", errEngineClosed
	}
	settings, err := loadRouteSettings(engine.routeSettings)
	return settings.ExitUse, err
}

// ExitAllowsLAN reports whether the attached private networks stay
// reachable outside the VPN while an exit node is used.
func (engine *Engine) ExitAllowsLAN() (allowed bool, err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return false, errEngineClosed
	}
	settings, err := loadRouteSettings(engine.routeSettings)
	return settings.ExitAllowLAN, err
}

// ApproveExitNodes approves the exit nodes or pool the status lists as
// waiting (comma-separated IDs), and returns the IDs approved,
// comma-separated. Naming them keeps Core from slipping in another between
// status and approval.
func (engine *Engine) ApproveExitNodes(ids string) (approved string, err error) {
	defer recoverPanic(&err)
	var names []string
	for _, id := range strings.Split(ids, ",") {
		if id = strings.TrimSpace(id); id != "" {
			names = append(names, id)
		}
	}
	err = engine.act(func(ctx context.Context) error {
		result, approveErr := engine.service.ApproveExitNodes(ctx, names)
		approved = strings.Join(result.Approved, ",")
		return approveErr
	})
	return approved, err
}
