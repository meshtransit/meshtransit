//go:build (!linux && !windows && !darwin) || android || ios

package underlay

import (
	"net"
	"net/netip"
)

// resolver is the system resolver here: no kill switch of the helper's
// stands between the client and the host's resolver.
func resolver() *net.Resolver { return nil }

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver { return net.DefaultResolver }

// NetworkResolvers returns the resolvers of the host's networks: none known
// here, so a captive portal window keeps names on the exit node's resolver.
func NetworkResolvers() []netip.AddrPort { return nil }
