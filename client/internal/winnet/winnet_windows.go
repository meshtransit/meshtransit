//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Configure gives the adapter exactly addresses (host prefixes), on-link
// routes to routes, and mtu for every address family it uses.
func Configure(luid uint64, mtu int, addresses, routes []netip.Prefix) error {
	if mtu < 1280 || mtu > 9000 {
		return fmt.Errorf("winnet: mtu %d is outside 1280-9000", mtu)
	}
	adapter := winipcfg.LUID(luid)
	if err := adapter.SetIPAddresses(addresses); err != nil {
		return fmt.Errorf("winnet: setting adapter addresses: %w", err)
	}
	for _, family := range families(addresses) {
		if err := setMTU(adapter, family, mtu); err != nil {
			return err
		}
	}

	return ReplaceRoutes(luid, routes)
}

// ReplaceRoutes makes routes the adapter's only on-link routes that
// MeshTransit manages. It leaves the routes Windows derives from the
// adapter's addresses (protocol Local: the address's host route, its subnet,
// broadcast and multicast) in place, because without the host route Windows
// drops every packet sent to the adapter's own address as not locally
// destined. winipcfg's SetRoutes flushes those too, so it is not used.
func ReplaceRoutes(luid uint64, routes []netip.Prefix) error {
	missing := make(map[netip.Prefix]struct{}, len(routes))
	for _, route := range routes {
		if !route.IsValid() || route != route.Masked() {
			return fmt.Errorf("winnet: route %s is not a canonical prefix", route)
		}
		missing[route] = struct{}{}
	}
	adapter := winipcfg.LUID(luid)
	var errs []error
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			return fmt.Errorf("winnet: reading routes: %w", err)
		}
		for i := range rows {
			row := &rows[i]
			if row.InterfaceLUID != adapter || row.Protocol != winipcfg.RouteProtocolNetMgmt {
				continue
			}
			destination := row.DestinationPrefix.Prefix()
			if _, wanted := missing[destination]; wanted && row.NextHop.Addr().IsUnspecified() {
				delete(missing, destination)
				continue
			}
			if err := row.Delete(); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				errs = append(errs, fmt.Errorf("winnet: removing route %s: %w", destination, err))
			}
		}
	}
	for route := range missing {
		nextHop := netip.IPv4Unspecified()
		if route.Addr().Is6() {
			nextHop = netip.IPv6Unspecified()
		}
		if err := adapter.AddRoute(route, nextHop, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			errs = append(errs, fmt.Errorf("winnet: adding route %s: %w", route, err))
		}
	}

	return errors.Join(errs...)
}

// Index returns the adapter's interface index, which other Windows APIs and
// net.Interface use.
func Index(luid uint64) (uint32, error) {
	row, err := winipcfg.LUID(luid).Interface()
	if err != nil {
		return 0, fmt.Errorf("winnet: reading the adapter: %w", err)
	}

	return row.InterfaceIndex, nil
}

func setMTU(adapter winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	row, err := adapter.IPInterface(family)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil // the family is not bound to the adapter
	}
	if err != nil {
		return fmt.Errorf("winnet: reading the adapter interface: %w", err)
	}
	row.NLMTU = uint32(mtu) //nolint:gosec // Bounded to 1280-9000 above.
	if err := row.Set(); err != nil {
		return fmt.Errorf("winnet: setting the adapter mtu: %w", err)
	}

	return nil
}

func families(addresses []netip.Prefix) []winipcfg.AddressFamily {
	var hasV4, hasV6 bool
	for _, address := range addresses {
		hasV4 = hasV4 || address.Addr().Is4()
		hasV6 = hasV6 || address.Addr().Is6()
	}
	var result []winipcfg.AddressFamily
	if hasV4 {
		result = append(result, windows.AF_INET)
	}
	if hasV6 {
		result = append(result, windows.AF_INET6)
	}

	return result
}

// netbiosDisabled is NetbiosOptions' "disable NetBIOS over TCP/IP".
const netbiosDisabled = 2

// Quiet stops Windows from announcing the adapter: no dynamic DNS
// registration of its addresses (which would put mesh addresses into the
// LAN's DNS) and no NetBIOS over TCP/IP on it.
func Quiet(luid uint64) error {
	guid, err := winipcfg.LUID(luid).GUID()
	if err != nil {
		return fmt.Errorf("winnet: reading adapter GUID: %w", err)
	}
	for _, family := range []uint64{0, winipcfg.DnsInterfaceSettingsFlagIPv6} {
		settings := &winipcfg.DnsInterfaceSettings{
			Version: winipcfg.DnsInterfaceSettingsVersion1,
			Flags: family | winipcfg.DnsInterfaceSettingsFlagRegistrationEnabled |
				winipcfg.DnsInterfaceSettingsFlagRegisterAdapterName,
		}
		if err := winipcfg.SetInterfaceDnsSettings(*guid, settings); err != nil {
			return fmt.Errorf("winnet: turning off DNS registration: %w", err)
		}
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_`+guid.String(), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("winnet: opening NetBIOS settings: %w", err)
	}
	defer func() { _ = key.Close() }()
	if err := key.SetDWordValue("NetbiosOptions", netbiosDisabled); err != nil {
		return fmt.Errorf("winnet: turning off NetBIOS: %w", err)
	}

	return nil
}
