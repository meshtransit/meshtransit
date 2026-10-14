package dataplane

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// openInheritedTUN wraps the helper's TUN descriptor without the netlink
// monitor, which needs privileges meshd does not have (and which Android
// forbids apps).
var openInheritedTUN inheritedTUNOpener = openUnmonitoredTUN

// inheritedTUNOpenerFor returns the Linux opener; it has nothing to log.
func inheritedTUNOpenerFor(*slog.Logger) inheritedTUNOpener { return openInheritedTUN }

// openUnmonitoredTUN calls tun.CreateUnmonitoredTUNFromFD, which wraps the
// descriptor in an os.File before it can fail and, when it fails, leaves
// that file to its finalizer. Its one earlier failure, setting the
// descriptor nonblocking, happens here first; every later failure reports
// errDescriptorTaken, so the caller does not close the descriptor a second
// time (the finalizer could then close whatever reused the number).
func openUnmonitoredTUN(descriptor int) (tun.Device, string, error) {
	if err := unix.SetNonblock(descriptor, true); err != nil {
		return nil, "", fmt.Errorf("setting the tun nonblocking: %w", err)
	}
	device, name, err := tun.CreateUnmonitoredTUNFromFD(descriptor)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errDescriptorTaken, err)
	}
	return device, name, nil
}
