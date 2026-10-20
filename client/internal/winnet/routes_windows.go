//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/netadmin"
)

// maximumLocalRoutes bounds the host routes subnet routes are checked
// against. A host with more installs none.
const maximumLocalRoutes = 16384

// ErrTooManyLocalRoutes reports a host whose routes are too many to check
// subnet routes against cheaply.
var ErrTooManyLocalRoutes = errors.New("winnet: too many local routes to check subnet routes against")

// LocalRoutes returns the host's routes but default routes, those on the
// adapter, loopback and Windows' own host routes: an on-link route (no next
// hop) is an attached network.
func LocalRoutes(adapter uint64) ([]netadmin.LocalRoute, error) {
	var local []netadmin.LocalRoute
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			return nil, fmt.Errorf("winnet: reading routes: %w", err)
		}
		for i := range rows {
			row := &rows[i]
			prefix := row.DestinationPrefix.Prefix()
			// Windows' own host routes (an address, its subnet's broadcast)
			// lie inside the attached network listed with them, and
			// loopback is never a subnet route's to take.
			if uint64(row.InterfaceLUID) == adapter || !prefix.IsValid() || prefix.Bits() == 0 ||
				prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() ||
				row.Protocol == winipcfg.RouteProtocolLocal && prefix.IsSingleIP() ||
				prefix.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
				continue
			}
			if len(local) == maximumLocalRoutes {
				return nil, ErrTooManyLocalRoutes
			}
			local = append(local, netadmin.LocalRoute{
				Prefix: prefix.Masked(), Connected: row.NextHop.Addr().IsUnspecified(),
			})
		}
	}

	return local, nil
}

// Resolvers returns the DNS servers of every adapter but this one.
func Resolvers(adapter uint64) ([]netip.Addr, error) {
	addresses, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagSkipUnicast|
		winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipFriendlyName)
	if err != nil {
		return nil, fmt.Errorf("winnet: reading adapters: %w", err)
	}
	var resolvers []netip.Addr
	for _, entry := range addresses {
		if uint64(entry.LUID) == adapter {
			continue
		}
		for server := entry.FirstDNSServerAddress; server != nil; server = server.Next {
			address, ok := netip.AddrFromSlice(server.Address.IP())
			if !ok {
				continue
			}
			address = address.Unmap().WithZone("")
			if address.IsLoopback() || address.IsUnspecified() {
				continue
			}
			resolvers = append(resolvers, address)
		}
	}

	return resolvers, nil
}

// maximumAttachedSubnets bounds the subnets AttachedSubnets returns.
const maximumAttachedSubnets = 64

// AttachedSubnets returns the subnets of the addresses of every interface
// but this adapter and loopback, masked and without repeats: the networks
// the host reaches itself, read from its addresses rather than its routes.
func AttachedSubnets(adapter uint64) ([]netip.Prefix, error) {
	var subnets []netip.Prefix
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("winnet: reading addresses: %w", err)
	}
	for i := range rows {
		row := &rows[i]
		address := row.Address.Addr().Unmap().WithZone("")
		if uint64(row.InterfaceLUID) == adapter || !address.IsValid() || address.IsLoopback() {
			continue
		}
		prefix, err := address.Prefix(int(row.OnLinkPrefixLength))
		if err != nil || slices.Contains(subnets, prefix) {
			continue
		}
		subnets = append(subnets, prefix)
		if len(subnets) == maximumAttachedSubnets {
			break
		}
	}

	return subnets, nil
}
