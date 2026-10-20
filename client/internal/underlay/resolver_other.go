//go:build !linux || android

package underlay

import "net"

// resolver is the system resolver here: no kill switch of the helper's
// stands between the client and the host's resolver.
func resolver() *net.Resolver { return nil }
