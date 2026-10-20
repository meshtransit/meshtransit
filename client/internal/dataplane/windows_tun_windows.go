//go:build windows

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/winadapter"
	"meshtransit.net/client/internal/winnet"
)

// windowsTUNMTU matches meshnetd's MTU on Linux and macOS.
const windowsTUNMTU = 1280

var setTunnelType sync.Once

// WindowsTUNOpener opens the MeshTransit Wintun adapter inside the service
// and configures it: a Wintun session cannot be handed to another process,
// so there is no privileged helper on Windows.
type WindowsTUNOpener struct {
	// routeSettings is the subnet route settings file only SYSTEM and
	// administrators write (routesettings).
	routeSettings string
	// mu serializes every change of the adapter's routes: overlay are the
	// per-peer routes, routed the subnet routes installed (SetRoutedRoutes).
	mu        sync.Mutex
	luid      uint64
	addresses []netip.Prefix
	overlay   []netip.Prefix
	routed    []netip.Prefix
}

// NewWindowsTUNOpener returns an opener for the service's adapter that
// installs the subnet routes routeSettings admits.
func NewWindowsTUNOpener(routeSettings string) *WindowsTUNOpener {
	setTunnelType.Do(func() { tun.WintunTunnelType = winadapter.Name })

	return &WindowsTUNOpener{routeSettings: routeSettings}
}

// OpenTUN creates the adapter and gives it exactly the map's addresses and
// per-peer routes. Closing the returned device removes the adapter.
func (o *WindowsTUNOpener) OpenTUN(_ context.Context, config netadmin.TUNConfig) (netadmin.TUN, error) {
	if err := validateOverlayPrefixes(config.Addresses, config.Routes); err != nil {
		return netadmin.TUN{}, err
	}
	guid := winadapter.GUID
	device, err := tun.CreateTUNWithRequestedGUID(winadapter.Name, &guid, windowsTUNMTU)
	if err != nil {
		return netadmin.TUN{}, fmt.Errorf("dataplane: creating the Wintun adapter: %w", err)
	}
	native, ok := device.(*tun.NativeTun)
	if !ok {
		_ = device.Close()

		return netadmin.TUN{}, errors.New("dataplane: unexpected Wintun device type")
	}
	luid := native.LUID()
	if err := winnet.Configure(luid, windowsTUNMTU, config.Addresses, config.Routes); err != nil {
		_ = device.Close()

		return netadmin.TUN{}, err
	}
	// Failing closed is deliberate: an adapter that registers itself would
	// put mesh addresses into the LAN's DNS.
	if err := winnet.Quiet(luid); err != nil {
		_ = device.Close()

		return netadmin.TUN{}, err
	}
	o.mu.Lock()
	// A new adapter carries no subnet routes: the old one's left with it.
	o.luid, o.overlay, o.routed = luid, slices.Clone(config.Routes), nil
	o.addresses = slices.Clone(config.Addresses)
	o.mu.Unlock()

	return netadmin.TUN{
		Device:    device,
		Name:      winadapter.Name,
		MTU:       windowsTUNMTU,
		Addresses: slices.Clone(config.Addresses),
		Routes:    slices.Clone(config.Routes),
	}, nil
}

// ConfigureTUNRoutes replaces the open adapter's per-peer routes.
func (o *WindowsTUNOpener) ConfigureTUNRoutes(_ context.Context, config netadmin.TUNConfig) error {
	if err := validateOverlayPrefixes(config.Addresses, config.Routes); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.luid == 0 {
		return errors.New("dataplane: the Wintun adapter is not open")
	}
	failed, err := winnet.ReplaceRoutesReporting(o.luid, routeUnion(config.Routes, o.routed))
	o.overlay = slices.Clone(config.Routes)
	for _, route := range failed {
		if slices.Contains(config.Routes, route) {
			err = errors.Join(err, fmt.Errorf("dataplane: adding route %s failed", route))
		}
	}

	return err
}

// routeUnion returns the adapter's routes: per-peer and subnet ones.
func routeUnion(overlay, routed []netip.Prefix) []netip.Prefix {
	union := slices.Clone(overlay)
	for _, route := range routed {
		if !slices.Contains(union, route) {
			union = append(union, route)
		}
	}

	return union
}

// validateOverlayPrefixes checks what meshd would configure: host addresses,
// and routes that are canonical prefixes (aggregated peer addresses) lying
// wholly inside the safe overlay frame and covering no own address.
func validateOverlayPrefixes(addresses, routes []netip.Prefix) error {
	for _, prefix := range addresses {
		if !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() || prefix != prefix.Masked() ||
			!netadmin.WithinSafeOverlayFrame(prefix) {
			return fmt.Errorf("dataplane: %s is not an overlay host prefix", prefix)
		}
	}
	for _, prefix := range routes {
		if !prefix.IsValid() || prefix != prefix.Masked() || !netadmin.WithinSafeOverlayFrame(prefix) ||
			slices.ContainsFunc(addresses, prefix.Overlaps) {
			return fmt.Errorf("dataplane: %s is not an overlay route", prefix)
		}
	}

	return nil
}
