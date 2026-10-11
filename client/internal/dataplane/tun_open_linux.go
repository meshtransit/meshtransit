package dataplane

import "golang.zx2c4.com/wireguard/tun"

// openInheritedTUN wraps the helper's TUN descriptor without the netlink
// monitor, which needs privileges meshd does not have.
var openInheritedTUN inheritedTUNOpener = tun.CreateUnmonitoredTUNFromFD
