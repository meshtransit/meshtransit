package mobile

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
)

// maxHostAddresses bounds the addresses the platform may report.
const maxHostAddresses = 64

// hostAddressList holds the device's network addresses the platform last
// reported (SetHostAddresses); the data plane reads it for its endpoint
// candidates.
type hostAddressList struct {
	current atomic.Pointer[[]netip.Addr]
}

func (list *hostAddressList) load() []netip.Addr {
	if addresses := list.current.Load(); addresses != nil {
		return *addresses
	}
	return nil
}

// parseHostAddresses reads a comma-separated list of IP addresses; an
// address may carry its prefix length ("192.168.1.20/24"), as Android's
// LinkAddress writes it.
func parseHostAddresses(value string) ([]netip.Addr, error) {
	addresses := []netip.Addr{}
	for entry := range strings.SplitSeq(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(addresses) == maxHostAddresses {
			return nil, fmt.Errorf("%w: more than %d host addresses", errInvalidConfig, maxHostAddresses)
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			addresses = append(addresses, prefix.Addr())
			continue
		}
		address, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not an IP address", errInvalidConfig, entry)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}
