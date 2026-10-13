package mobile

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

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

// platformTUN opens TUN devices through the app's TunProvider for the data
// plane (dataplane's tun opener).
type platformTUN struct {
	provider TunProvider
	mtu      int
}

// OpenTUN asks the platform for a TUN configured with exactly the addresses
// and routes of the current map. The platform cannot be cancelled mid-call;
// a context already done is honoured before calling it.
func (opener platformTUN) OpenTUN(ctx context.Context, config netadmin.TUNConfig) (netadmin.TUN, error) {
	if err := ctx.Err(); err != nil {
		return netadmin.TUN{}, err
	}
	if len(config.Addresses) == 0 {
		return netadmin.TUN{}, fmt.Errorf("%w: no addresses", errNoTUN)
	}
	fd, err := opener.provider.OpenTUN(joinPrefixes(config.Addresses), joinPrefixes(config.Routes), opener.mtu)
	if err != nil {
		return netadmin.TUN{}, fmt.Errorf("%w: %w", errNoTUN, err)
	}
	if fd <= maxStandardDescriptor {
		// Never adopt (and later close) stdin, stdout or stderr.
		return netadmin.TUN{}, fmt.Errorf("%w: invalid descriptor", errNoTUN)
	}
	file := os.NewFile(uintptr(fd), tunName)
	if file == nil {
		return netadmin.TUN{}, fmt.Errorf("%w: invalid descriptor", errNoTUN)
	}
	return netadmin.TUN{
		File:      file,
		Name:      tunName,
		MTU:       opener.mtu,
		Addresses: append([]netip.Prefix(nil), config.Addresses...),
		Routes:    append([]netip.Prefix(nil), config.Routes...),
	}, nil
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
