package dataplane

import (
	"fmt"
	"net"
	"net/netip"
)

// meshOverlayPrefixes are the ranges MeshTransit assigns inside Workspaces.
// A host interface address in them belongs to a mesh client on this host,
// possibly one enrolled in another Network, and is never an underlay path.
var meshOverlayPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// hostInterface is the subset of an interface that endpoint discovery reads.
type hostInterface struct {
	name      string
	flags     net.Flags
	addresses []net.Addr
}

func localHostAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("dataplane: listing host interfaces: %w", err)
	}
	observed := make([]hostInterface, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		interfaceAddresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		observed = append(observed, hostInterface{
			name:      networkInterface.Name,
			flags:     networkInterface.Flags,
			addresses: interfaceAddresses,
		})
	}

	return selectIPv6HostAddresses(usableHostAddresses(observed), ipv6AddressStates()), nil
}

// usableHostAddresses keeps addresses a peer could reach over the underlay.
// Point-to-point interfaces are tunnels: this client's TUN, another mesh
// client's TUN or DNS link on the same host, or another VPN. Advertising
// their addresses would publish other Networks' overlay addresses to peers
// and send probes to unreachable destinations.
func usableHostAddresses(interfaces []hostInterface) []netip.Addr {
	addresses := make([]netip.Addr, 0, len(interfaces)*2)
	for _, networkInterface := range interfaces {
		if networkInterface.flags&net.FlagUp == 0 ||
			networkInterface.flags&net.FlagLoopback != 0 ||
			networkInterface.flags&net.FlagPointToPoint != 0 {
			continue
		}
		for _, rawAddress := range networkInterface.addresses {
			address, valid := hostAddress(rawAddress)
			if valid && !meshOverlayAddress(address) {
				addresses = append(addresses, address)
			}
		}
	}

	return addresses
}

func meshOverlayAddress(address netip.Addr) bool {
	for _, prefix := range meshOverlayPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}

	return false
}

func hostAddress(raw net.Addr) (netip.Addr, bool) {
	var value net.IP
	switch address := raw.(type) {
	case *net.IPNet:
		value = address.IP
	case *net.IPAddr:
		if address.Zone != "" {
			return netip.Addr{}, false
		}
		value = address.IP
	default:
		return netip.Addr{}, false
	}
	parsed, valid := netip.AddrFromSlice(value)
	if !valid {
		return netip.Addr{}, false
	}

	return parsed.Unmap(), true
}
