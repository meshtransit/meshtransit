package mobile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/overlayframe"
)

// tunName names the platform TUN in status and logs; the platform owns the
// real interface name.
const tunName = "mobile-tun"

// maxStandardDescriptor is stderr, the highest descriptor a process starts
// with; a TUN descriptor is always above it.
const maxStandardDescriptor = 2

// errNoTUN reports that the platform gave no usable TUN.
var errNoTUN = errors.New("mobile: platform TUN unavailable")

// adoptTUN turns a descriptor into a WireGuard TUN device; tests replace it.
type adoptTUN func(file *os.File, mtu int, logger *slog.Logger) (tun.Device, error)

// platformTUN opens TUN devices through the app's TunProvider for the data
// plane (dataplane's tun opener) and changes their routes in place
// (dataplane's tun route configurer).
type platformTUN struct {
	provider TunProvider
	mtu      int
	logger   *slog.Logger
	adopt    adoptTUN
	// routeSettings is the app's subnet route settings file, and hosts the
	// device's attached networks the platform last reported.
	routeSettings string
	hosts         *hostAddressList

	// change serializes every change of the interface: the data plane's
	// and the subnet route worker's.
	change sync.Mutex
	mu     sync.Mutex
	open   *replaceableTUN // the TUN last given to the data plane
	// The open TUN's interface has the stable overlay routes and the
	// subnet routes installed, and the addresses it was opened with.
	addresses []netip.Prefix
	routes    []netip.Prefix
	routed    []netip.Prefix
	// exit is what the interface carries for an exit node (SetExitRoute).
	exit mobileExit
}

func newPlatformTUN(provider TunProvider, mtu int, logger *slog.Logger, routeSettings string,
	hosts *hostAddressList,
) *platformTUN {
	return &platformTUN{
		provider: provider, mtu: mtu, logger: logger, adopt: dataplane.AdoptTUN, routeSettings: routeSettings,
		hosts: hosts,
	}
}

// OpenTUN asks the platform for a TUN configured with exactly the addresses
// and routes of the current map. The platform cannot be cancelled mid-call;
// a context already done is honoured before calling it.
func (opener *platformTUN) OpenTUN(ctx context.Context, config netadmin.TUNConfig) (netadmin.TUN, error) {
	opener.change.Lock()
	defer opener.change.Unlock()
	routes := stableRoutes(config.Routes)
	opener.mu.Lock()
	exit := opener.exit
	opener.mu.Unlock()
	// An exit route in use stays: the Internet never leaves outside the
	// mesh while a new interface comes up.
	device, err := opener.openDevice(ctx, config.Addresses, routes, nil, exit)
	if err != nil {
		return netadmin.TUN{}, err
	}
	replaceable := newReplaceableTUN(device, opener.mtu, opener.logger)
	opener.mu.Lock()
	// A new interface carries no subnet routes: the data plane asks again.
	opener.open, opener.routes, opener.routed = replaceable, routes, nil
	opener.addresses = slices.Clone(config.Addresses)
	opener.mu.Unlock()
	return netadmin.TUN{
		Device:    replaceable,
		Name:      tunName,
		MTU:       opener.mtu,
		Addresses: append([]netip.Prefix(nil), config.Addresses...),
		Routes:    append([]netip.Prefix(nil), config.Routes...),
	}, nil
}

// ConfigureTUNRoutes gives the open TUN the map's new routes; the addresses
// are unchanged (the data plane rebuilds the TUN when they change). When
// the stable routes are the same, as for most peers joining or leaving,
// nothing changes. Otherwise the platform makes a new interface for them
// and the running device moves to it. On an error the old interface stays
// and the data plane rebuilds.
func (opener *platformTUN) ConfigureTUNRoutes(ctx context.Context, config netadmin.TUNConfig) error {
	opener.change.Lock()
	defer opener.change.Unlock()
	routes := stableRoutes(config.Routes)
	opener.mu.Lock()
	current, unchanged, routed, exit := opener.open, slices.Equal(opener.routes, routes), opener.routed, opener.exit
	opener.mu.Unlock()
	if current == nil || current.isClosed() {
		return fmt.Errorf("%w: no open TUN to change", errNoTUN)
	}
	if unchanged {
		return nil
	}
	if err := current.Replace(func() (tun.Device, error) {
		return opener.openDevice(ctx, config.Addresses, routes, routed, exit)
	}); err != nil {
		return err
	}
	opener.mu.Lock()
	if opener.open == current {
		opener.routes, opener.addresses = routes, slices.Clone(config.Addresses)
	}
	opener.mu.Unlock()
	return nil
}

// openDevice asks the platform for a configured interface and adopts its
// descriptor.
func (opener *platformTUN) openDevice(ctx context.Context, addresses, routes, routed []netip.Prefix,
	exit mobileExit,
) (tun.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: no addresses", errNoTUN)
	}
	if err := validateOverlayConfig(addresses, routes); err != nil {
		return nil, err
	}
	if err := validateRoutedConfig(routed); err != nil {
		return nil, err
	}
	if err := exit.validate(); err != nil {
		return nil, err
	}
	interfaceRoutes := slices.Clone(routes)
	for _, prefix := range slices.Concat(routed, exit.routes) {
		if !slices.Contains(interfaceRoutes, prefix) {
			interfaceRoutes = append(interfaceRoutes, prefix)
		}
	}
	fd, err := opener.provider.OpenTUN(joinPrefixes(addresses), joinPrefixes(interfaceRoutes),
		joinAddresses(exit.dns), opener.mtu)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoTUN, err)
	}
	if fd <= maxStandardDescriptor {
		// Never adopt (and later close) stdin, stdout or stderr.
		return nil, fmt.Errorf("%w: invalid descriptor", errNoTUN)
	}
	file := os.NewFile(uintptr(fd), tunName)
	if file == nil {
		return nil, fmt.Errorf("%w: invalid descriptor", errNoTUN)
	}
	device, err := opener.adopt(file, opener.mtu, opener.logger)
	if err != nil {
		// adopt closed the descriptor, tearing the unused interface down.
		return nil, fmt.Errorf("%w: %w", errNoTUN, err)
	}
	return device, nil
}

// joinPrefixes writes prefixes as the comma-separated CIDR list TunProvider
// receives.
func joinPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		values = append(values, prefix.String())
	}
	return strings.Join(values, ",")
}

// joinAddresses writes addresses as the comma-separated list TunProvider
// receives.
func joinAddresses(addresses []netip.Addr) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return strings.Join(values, ",")
}

// validateOverlayConfig keeps the platform VPN interface inside the overlay
// frame, as the desktop helper does: host addresses and routes of the overlay
// and alias ranges only. A map that asks for a LAN, a public range or the
// default route never reaches VpnService.
func validateOverlayConfig(addresses, routes []netip.Prefix) error {
	for _, prefix := range addresses {
		if prefix.Bits() != prefix.Addr().BitLen() || !overlayframe.Contains(prefix) {
			return fmt.Errorf("%w: %s is not an overlay host address", errNoTUN, prefix)
		}
	}
	for _, prefix := range routes {
		if prefix != prefix.Masked() || !overlayframe.Contains(prefix) {
			return fmt.Errorf("%w: %s is not an overlay route", errNoTUN, prefix)
		}
	}
	return nil
}
