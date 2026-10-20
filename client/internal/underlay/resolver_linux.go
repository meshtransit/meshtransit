//go:build linux && !android

package underlay

import "net"

// resolver is the resolver of the client's own dials: on Linux the one that
// asks systemd-resolved's upstreams directly (upstreamResolver).
func resolver() *net.Resolver { return upstreamResolver }
