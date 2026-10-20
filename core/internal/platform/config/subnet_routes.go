package config

import (
	"net/netip"
	"slices"
)

// envSubnetRoutes turns subnet routes on for the deployment: Access Rules
// may name Sites, and maps carry routes (mtcp-v1 §7.6). Off by default.
// Every role reads it so that the roles that compile policy and the roles
// that encode maps always agree.
const envSubnetRoutes = "MESHTRANSIT_SUBNET_ROUTES_ENABLED"

func loadSubnetRoutes(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envSubnetRoutes, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envSubnetRoutes)
	}
}

// envSiteDenied names the addresses no Site may cover: the ones clients
// dial, such as Core's public endpoint, its load balancers and the relays
// (design: subnet routers §4.3). A route there would carry a client's own
// Control or relay traffic into the mesh. Maps leave such prefixes out as
// well, also when relays change after a Site was saved.
const envSiteDenied = "MESHTRANSIT_SITE_DENIED_CIDRS"

func loadSiteDenied(lookup LookupFunc) ([]netip.Prefix, error) {
	denied, err := parseTrustedProxyPrefixes(valueOrDefault(lookup, envSiteDenied, ""))
	if err != nil || slices.ContainsFunc(denied, func(prefix netip.Prefix) bool {
		return prefix.Bits() == 0 || prefix.Addr().Is4In6()
	}) {
		return nil, settingError(envSiteDenied)
	}
	return denied, nil
}
