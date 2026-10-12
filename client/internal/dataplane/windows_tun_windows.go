//go:build windows

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/winnet"
)

const (
	// windowsAdapterName names the Wintun adapter in Network Connections.
	windowsAdapterName = "MeshTransit"
	// windowsTUNMTU matches meshnetd's MTU on Linux and macOS.
	windowsTUNMTU = 1280
)

// windowsAdapterGUID keeps one adapter identity across restarts, so Windows
// does not list a new network for every start.
var windowsAdapterGUID = windows.GUID{
	Data1: 0x6d657368, Data2: 0x7472, Data3: 0x616e,
	Data4: [8]byte{0x73, 0x69, 0x74, 0x00, 0x00, 0x00, 0x00, 0x01},
}

var setTunnelType sync.Once

// WindowsTUNOpener opens the MeshTransit Wintun adapter inside the service
// and configures it: a Wintun session cannot be handed to another process,
// so there is no privileged helper on Windows.
type WindowsTUNOpener struct {
	mu   sync.Mutex
	luid uint64
}

// NewWindowsTUNOpener returns an opener for the service's adapter.
func NewWindowsTUNOpener() *WindowsTUNOpener {
	setTunnelType.Do(func() { tun.WintunTunnelType = windowsAdapterName })

	return &WindowsTUNOpener{}
}

// OpenTUN creates the adapter and gives it exactly the map's addresses and
// per-peer routes. Closing the returned device removes the adapter.
func (o *WindowsTUNOpener) OpenTUN(_ context.Context, config netadmin.TUNConfig) (netadmin.TUN, error) {
	if err := validateOverlayHostPrefixes(config.Addresses, config.Routes); err != nil {
		return netadmin.TUN{}, err
	}
	guid := windowsAdapterGUID
	device, err := tun.CreateTUNWithRequestedGUID(windowsAdapterName, &guid, windowsTUNMTU)
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
	o.mu.Lock()
	o.luid = luid
	o.mu.Unlock()

	return netadmin.TUN{
		Device:    device,
		Name:      windowsAdapterName,
		MTU:       windowsTUNMTU,
		Addresses: slices.Clone(config.Addresses),
		Routes:    slices.Clone(config.Routes),
	}, nil
}

// ConfigureTUNRoutes replaces the open adapter's per-peer routes.
func (o *WindowsTUNOpener) ConfigureTUNRoutes(_ context.Context, config netadmin.TUNConfig) error {
	if err := validateOverlayHostPrefixes(config.Addresses, config.Routes); err != nil {
		return err
	}
	o.mu.Lock()
	luid := o.luid
	o.mu.Unlock()
	if luid == 0 {
		return errors.New("dataplane: the Wintun adapter is not open")
	}

	return winnet.ReplaceRoutes(luid, config.Routes)
}

// validateOverlayHostPrefixes accepts only canonical host prefixes inside the
// overlay frame meshnetd enforces on Linux and macOS.
func validateOverlayHostPrefixes(groups ...[]netip.Prefix) error {
	for _, group := range groups {
		for _, prefix := range group {
			if !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() || prefix != prefix.Masked() ||
				!netadmin.WithinSafeOverlayFrame(prefix) {
				return fmt.Errorf("dataplane: %s is not an overlay host prefix", prefix)
			}
		}
	}

	return nil
}
