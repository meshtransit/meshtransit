//go:build (!linux && !windows && !darwin) || android || ios

package underlay

import "net"

// resolver is the system resolver here: no kill switch of the helper's
// stands between the client and the host's resolver.
func resolver() *net.Resolver { return nil }

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver { return net.DefaultResolver }
