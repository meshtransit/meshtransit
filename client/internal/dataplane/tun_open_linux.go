package dataplane

import (
	"log/slog"

	"golang.zx2c4.com/wireguard/tun"
)

// openInheritedTUN wraps the helper's TUN descriptor without the netlink
// monitor, which needs privileges meshd does not have.
var openInheritedTUN inheritedTUNOpener = tun.CreateUnmonitoredTUNFromFD

// inheritedTUNOpenerFor returns the Linux opener; it has nothing to log.
func inheritedTUNOpenerFor(*slog.Logger) inheritedTUNOpener { return openInheritedTUN }
