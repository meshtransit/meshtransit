package mobile

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/underlay"
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

// onAttachedNetwork reports whether address is on a network the device is
// attached to: a private resolver there is asked over it.
func (list *hostAddressList) onAttachedNetwork(address netip.Addr) bool {
	return slices.ContainsFunc(list.attached(), func(network netip.Prefix) bool { return network.Contains(address) })
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

const (
	// maxResolversPerNetwork and maxResolverNetworks bound the networks'
	// DNS servers MeshTransit's resolver asks (DNS design D4 §3.5).
	maxResolversPerNetwork = 3
	maxResolverNetworks    = 3
)

// parseHostResolvers reads SetHostResolvers' list, keeping the servers a
// socket of the client can ask: never a link-local one (its zone is lost),
// a loopback, multicast or unspecified address, one in the mesh, or the
// resolver itself.
func parseHostResolvers(value string) ([]underlay.NetworkResolver, error) {
	resolvers := []underlay.NetworkResolver{}
	perNetwork := map[int64]int{}
	for entry := range strings.SplitSeq(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		addressText, networkText, hasNetwork := strings.Cut(entry, "@")
		address, err := netip.ParseAddr(strings.TrimSpace(addressText))
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not an IP address", errInvalidConfig, entry)
		}
		var network int64
		if hasNetwork {
			network, err = strconv.ParseInt(strings.TrimSpace(networkText), 10, 64)
			if err != nil || network < 0 {
				return nil, fmt.Errorf("%w: %q has no network handle", errInvalidConfig, entry)
			}
		}
		address = address.Unmap().WithZone("")
		if !usableHostResolver(address) {
			continue
		}
		if _, seen := perNetwork[network]; !seen && len(perNetwork) == maxResolverNetworks {
			continue
		}
		if perNetwork[network] == maxResolversPerNetwork {
			continue
		}
		resolver := underlay.NetworkResolver{Address: netip.AddrPortFrom(address, dnsPort), Network: network}
		if slices.Contains(resolvers, resolver) {
			continue
		}
		perNetwork[network]++
		resolvers = append(resolvers, resolver)
	}
	return resolvers, nil
}

func usableHostResolver(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() &&
		!address.IsLinkLocalUnicast() && address != resolverAddress &&
		!overlayframe.Contains(netip.PrefixFrom(address, address.BitLen()))
}
