//go:build windows

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/underlay"
	"meshtransit.net/client/internal/winfw"
	"meshtransit.net/client/internal/winnet"
)

// windowsExitRoutes send the host's Internet traffic into the adapter
// (exit node design §6.1): halves of each family, more specific than any
// default route. A more specific route still wins, which the kill switch
// answers: what leaves by another interface is dropped (§6.3).
var windowsExitRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
}

// SetExitRoute routes the host's Internet traffic into the adapter behind
// the WFP kill switch, as the local settings and meshd's request want
// (netadmin.ExitRouteWanted): the service does what meshnetd does on Linux.
// The settings are read again on every request.
func (o *WindowsTUNOpener) SetExitRoute(_ context.Context, requested netadmin.ExitRouteRequest) (
	netadmin.ExitRouting, error,
) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.exitRequest = &requested
	// A window just opened or closed shows in this answer, not a second
	// later: meshd asks at once after meshctl changed it.
	o.pollCaptiveLocked(time.Now())
	if o.captive != nil && requested.CaptiveClose == o.captive.id {
		// The tunnel is back: the window has done its work.
		o.closeCaptiveLocked()
		_ = captive.CloseWindow(o.captivePath)
	}
	routing, err := o.applyExitLocked()
	o.followPortalLocked(time.Now())
	routing.Captive = o.captiveView(time.Now())
	return routing, err
}

// applyExitLocked brings the kill switch and the exit routes to what the
// settings and meshd's last request want. Unreadable settings change
// nothing: a failed read is no withdrawal of root's choice.
func (o *WindowsTUNOpener) applyExitLocked() (netadmin.ExitRouting, error) {
	settings, err := routesettings.Load(o.routeSettings)
	if err != nil {
		return o.exitRouting, fmt.Errorf("dataplane: reading route settings: %w", err)
	}
	wanted, _ := netadmin.ExitRouteWanted(settings, o.exitRequest)
	asked := o.exitRequest != nil && o.exitRequest.Use
	if !wanted {
		if o.captive != nil {
			o.closeCaptiveLocked()
			_ = captive.CloseWindow(o.captivePath)
		}
		err := o.clearExitLocked()
		o.exitRouting = netadmin.ExitRouting{}
		if asked {
			o.exitRouting.Refused = netadmin.ExitRouteRefusedOff
		}
		if err != nil {
			o.exitRouting.Refused = netadmin.ExitRouteRefusedFailed
		}
		return o.exitRouting, err
	}
	config := winfw.Config{Adapter: o.luid}
	if settings.ExitAllowLAN {
		config.LAN = windowsExitLAN(o.luid)
	}
	// The service's own sockets leave the host's routes and resolver before
	// the kill switch cuts them off, whoever asked for it: meshd or root's
	// settings.
	underlay.SetExitBound(underlay.ExitHeld, true)
	o.killSwitchUnknown = true
	// The kill switch first: no route sends anything anywhere before the
	// host is closed.
	if err := winfw.Enable(config); err != nil {
		o.exitRouting = netadmin.ExitRouting{Refused: netadmin.ExitRouteRefusedFailed}
		return o.exitRouting, errors.Join(fmt.Errorf("dataplane: installing the kill switch: %w", err),
			o.setExitRoutesLocked(false))
	}
	if o.luid == 0 {
		// Closed until an adapter opens and carries the traffic.
		o.exitRouting = netadmin.ExitRouting{}
		return o.exitRouting, nil
	}
	if err := o.setExitRoutesLocked(true); err != nil {
		o.exitRouting = netadmin.ExitRouting{Refused: netadmin.ExitRouteRefusedFailed}
		return o.exitRouting, err
	}
	o.exitRouting = netadmin.ExitRouting{Routing: true}
	return o.exitRouting, nil
}

// clearExitLocked takes the exit routes off the adapter and lifts the kill
// switch; the service's sockets follow the host's routes again once both
// are gone.
func (o *WindowsTUNOpener) clearExitLocked() error {
	err := o.setExitRoutesLocked(false)
	if o.killSwitchUnknown {
		if disableErr := winfw.Disable(); disableErr != nil {
			err = errors.Join(err, disableErr)
		} else {
			o.killSwitchUnknown = false
		}
	}
	if err == nil {
		underlay.SetExitBound(underlay.ExitHeld, false)
	}
	return err
}

// setExitRoutesLocked installs or removes the exit routes with the
// adapter's others. IPv6 ones may fail on an adapter without IPv6: the
// kill switch then drops IPv6 to the Internet.
func (o *WindowsTUNOpener) setExitRoutesLocked(routed bool) error {
	if o.exitRouted == routed && !routed {
		return nil
	}
	o.exitRouted = routed
	if o.luid == 0 {
		return nil
	}
	failed, err := winnet.ReplaceRoutesReporting(o.luid, o.adapterRoutesLocked(o.routed))
	if err != nil {
		return fmt.Errorf("dataplane: replacing the exit routes: %w", err)
	}
	if routed && o.captive == nil && slices.ContainsFunc(failed, func(route netip.Prefix) bool {
		return route.Addr().Is4() && slices.Contains(windowsExitRoutes, route)
	}) {
		return errors.New("dataplane: adding the IPv4 exit routes failed")
	}
	return nil
}

// adapterRoutesLocked returns the adapter's routes: per-peer, the subnet
// routes given and the exit routes while they are installed.
func (o *WindowsTUNOpener) adapterRoutesLocked(routed []netip.Prefix) []netip.Prefix {
	routes := routeUnion(o.overlay, routed)
	if o.exitRouted && o.captive == nil {
		routes = routeUnion(routes, windowsExitRoutes)
	}
	return routes
}

// windowsExitLAN returns the LAN the kill switch lets through when the
// settings allow it: the private subnets of the host's own addresses and
// link-local multicast (exit node design §6.2).
func windowsExitLAN(adapter uint64) []netip.Prefix {
	subnets, err := winnet.AttachedSubnets(adapter)
	if err != nil {
		return nil
	}
	lan := make([]netip.Prefix, 0, len(subnets)+len(netadmin.ExitLANMulticast))
	for _, subnet := range subnets {
		if netadmin.ExitLANSubnet(subnet) {
			lan = append(lan, subnet)
		}
	}
	return append(lan, netadmin.ExitLANMulticast...)
}

// startExit applies the settings when the service starts, before any
// adapter: a host whose settings name a pool is closed at once, and a kill
// switch an earlier run left is lifted when they name none.
func (o *WindowsTUNOpener) startExit() {
	o.mu.Lock()
	defer o.mu.Unlock()
	// A window an earlier run held is never opened again; its child sees
	// the file gone and ends.
	if o.captivePath != "" {
		_ = captive.CloseWindow(o.captivePath)
	}
	_, _ = o.applyExitLocked()
}

// ReleaseWindowsExit lifts the kill switch of a stopping service unless the
// settings name a pool, or cannot be read: the host then stays closed until
// the service is back, or an administrator runs "meshd release-exit".
func ReleaseWindowsExit(settingsPath string) error {
	settings, err := routesettings.Load(settingsPath)
	if err != nil {
		return fmt.Errorf("dataplane: keeping the exit kill switch: the route settings are unreadable: %w", err)
	}
	if settings.ExitUse != "" {
		return nil
	}
	return winfw.Disable()
}
