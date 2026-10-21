//go:build (linux && !android) || (darwin && !ios)

package underlay

import "net/netip"

// testNet is TEST-NET-1, where MeshTransit's own resolver listens: never a
// resolver of the host's networks.
var testNet = netip.MustParsePrefix("192.0.2.0/24")
