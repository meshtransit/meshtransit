package netadmin

import (
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/routesettings"
)

// The private ranges a LAN may use (exit node design §6.2).
var exitLANRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// ExitLANMulticast is the link-local multicast (mDNS, SSDP) a LAN uses
// when allowed.
var ExitLANMulticast = []netip.Prefix{netip.MustParsePrefix("224.0.0.0/24"), netip.MustParsePrefix("ff02::/16")}

// ExitLANSubnet admits a private attached subnet, IPv4 /16 or longer or
// IPv6 /64: never a public one, which a rogue DHCP server could hand out to
// pull traffic out of the mesh.
func ExitLANSubnet(prefix netip.Prefix) bool {
	if !slices.ContainsFunc(exitLANRanges, func(private netip.Prefix) bool {
		return private.Bits() <= prefix.Bits() && private.Contains(prefix.Addr())
	}) {
		return false
	}
	if prefix.Addr().Is4() {
		return prefix.Bits() >= 16
	}
	return prefix.Bits() == 64
}

// ExitRouteWanted reports whether the host's Internet goes into the mesh,
// and IPv6 too, given root's settings and meshd's last request (nil for
// none). Root's choice of a pool holds the kill switch on its own, whatever
// meshd asks, before the first map and across restarts: neither a
// compromised meshd nor Core can lift it (exit node design §6.4). A host
// that only follows managed pools follows meshd, which follows Core.
func ExitRouteWanted(settings routesettings.Settings, requested *ExitRouteRequest) (wanted, ipv6 bool) {
	asked := requested != nil && requested.Use
	wanted = settings.ExitUse != "" || (settings.ExitAllowManaged && asked)
	return wanted, wanted && asked && requested.IPv6
}
