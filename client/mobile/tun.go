package mobile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/netadmin"
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

	mu   sync.Mutex
	open *replaceableTUN // the TUN last given to the data plane
}

func newPlatformTUN(provider TunProvider, mtu int, logger *slog.Logger) *platformTUN {
	return &platformTUN{provider: provider, mtu: mtu, logger: logger, adopt: dataplane.AdoptTUN}
}

// OpenTUN asks the platform for a TUN configured with exactly the addresses
// and routes of the current map. The platform cannot be cancelled mid-call;
// a context already done is honoured before calling it.
func (opener *platformTUN) OpenTUN(ctx context.Context, config netadmin.TUNConfig) (netadmin.TUN, error) {
	device, err := opener.openDevice(ctx, config)
	if err != nil {
		return netadmin.TUN{}, err
	}
	replaceable := newReplaceableTUN(device, opener.mtu, opener.logger)
	opener.mu.Lock()
	opener.open = replaceable
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
// are unchanged (the data plane rebuilds the TUN when they change). The
// platform makes a new interface for them and the running device moves to
// it. On an error the old interface stays and the data plane rebuilds.
func (opener *platformTUN) ConfigureTUNRoutes(ctx context.Context, config netadmin.TUNConfig) error {
	opener.mu.Lock()
	current := opener.open
	opener.mu.Unlock()
	if current == nil || current.isClosed() {
		return fmt.Errorf("%w: no open TUN to change", errNoTUN)
	}
	return current.Replace(func() (tun.Device, error) { return opener.openDevice(ctx, config) })
}

// openDevice asks the platform for a configured interface and adopts its
// descriptor.
func (opener *platformTUN) openDevice(ctx context.Context, config netadmin.TUNConfig) (tun.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(config.Addresses) == 0 {
		return nil, fmt.Errorf("%w: no addresses", errNoTUN)
	}
	fd, err := opener.provider.OpenTUN(joinPrefixes(config.Addresses), joinPrefixes(config.Routes), opener.mtu)
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
