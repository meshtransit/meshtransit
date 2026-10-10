//go:build linux

package dataplane

import (
	"math"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ipv6AddressStates reads the kernel's flags for the host's IPv6 addresses.
// A failure returns nil: every address then counts as stable.
func ipv6AddressStates() map[netip.Addr]ipv6AddressState {
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil
	}
	states := make(map[netip.Addr]ipv6AddressState, len(addresses))
	for _, address := range addresses {
		if address.IPNet == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			continue
		}
		preferred := int64(address.PreferedLft)
		if address.PreferedLft < 0 || int64(address.PreferedLft) == math.MaxUint32 {
			preferred = -1 // INFINITY_LIFE_TIME
		}
		states[ip] = ipv6AddressState{
			temporary: address.Flags&unix.IFA_F_TEMPORARY != 0,
			unusable:  address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED|unix.IFA_F_DEPRECATED) != 0,
			preferred: preferred,
		}
	}

	return states
}
