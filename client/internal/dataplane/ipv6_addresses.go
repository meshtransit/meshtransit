package dataplane

import (
	"cmp"
	"net/netip"
	"slices"
)

// maxIPv6HostAddresses bounds the IPv6 host candidates. A host has one
// stable global address per prefix and maybe a unique-local one; more are
// privacy rotations or stale prefixes that only crowd out better candidates.
const maxIPv6HostAddresses = 4

// ipv6AddressState is what the kernel knows about an IPv6 address.
type ipv6AddressState struct {
	temporary bool  // RFC 8981 privacy address
	unusable  bool  // tentative, duplicate or deprecated: not to be offered
	preferred int64 // preferred lifetime in seconds; negative means forever
}

// selectIPv6HostAddresses drops IPv6 addresses peers should not use and
// orders the rest: stable global addresses, then one temporary global
// address only when no stable one exists, then unique-local addresses, at
// most maxIPv6HostAddresses. IPv4 addresses pass through unchanged. states
// holds the kernel's view; an address without one counts as stable.
func selectIPv6HostAddresses(addresses []netip.Addr, states map[netip.Addr]ipv6AddressState) []netip.Addr {
	var ipv4, stable, temporary, local []netip.Addr
	for _, address := range addresses {
		if !address.Is6() {
			ipv4 = append(ipv4, address)

			continue
		}
		state := states[address]
		switch {
		case state.unusable:
		case address.IsPrivate():
			local = append(local, address)
		case state.temporary:
			temporary = append(temporary, address)
		default:
			stable = append(stable, address)
		}
	}
	slices.SortFunc(stable, netip.Addr.Compare)
	slices.SortFunc(local, netip.Addr.Compare)
	selected := stable
	if len(stable) == 0 && len(temporary) != 0 {
		// The longest-lived privacy address is the one the kernel uses.
		newest := slices.MaxFunc(temporary, func(a, b netip.Addr) int {
			return cmp.Compare(lifetime(states[a]), lifetime(states[b]))
		})
		selected = append(selected, newest)
	}
	selected = append(selected, local...)
	if len(selected) > maxIPv6HostAddresses {
		selected = selected[:maxIPv6HostAddresses]
	}

	return append(ipv4, selected...)
}

func lifetime(state ipv6AddressState) int64 {
	if state.preferred < 0 {
		return 1 << 62
	}

	return state.preferred
}
