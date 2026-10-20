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
	// networks are the attached networks of the addresses reported with
	// their prefix length, which subnet routes must not take over.
	networks atomic.Pointer[[]netip.Prefix]
	// servers are the DNS servers and gateways of the physical networks
	// (SetHostServers): a subnet route containing one would take the
	// system's own traffic to it into the VPN.
	servers atomic.Pointer[[]netip.Addr]
}

func (list *hostAddressList) networkServers() []netip.Addr {
	if servers := list.servers.Load(); servers != nil {
		return *servers
	}
	return nil
}

func (list *hostAddressList) attached() []netip.Prefix {
	if networks := list.networks.Load(); networks != nil {
		return *networks
	}
	return nil
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
func parseHostAddresses(value string) ([]netip.Addr, []netip.Prefix, error) {
	addresses := []netip.Addr{}
	networks := []netip.Prefix{}
	for entry := range strings.SplitSeq(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(addresses) == maxHostAddresses {
			return nil, nil, fmt.Errorf("%w: more than %d host addresses", errInvalidConfig, maxHostAddresses)
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			addresses = append(addresses, prefix.Addr())
			networks = append(networks, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %q is not an IP address", errInvalidConfig, entry)
		}
		addresses = append(addresses, address)
	}
	return addresses, networks, nil
}
