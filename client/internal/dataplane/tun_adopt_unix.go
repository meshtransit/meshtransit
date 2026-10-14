//go:build linux || darwin

package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
)

// acquireTUN adopts the TUN descriptor meshnetd opened for meshd, or takes
// the device a mobile platform's VPN interface gave the app (client/mobile).
func acquireTUN(tunValue netadmin.TUN, logger *slog.Logger) (tun.Device, error) {
	if tunValue.Device != nil {
		return inProcessTUN(tunValue)
	}

	return adoptPrivilegedTUNDescriptor(tunValue.File, tunValue.MTU, inheritedTUNOpenerFor(logger))
}

// AdoptTUN wraps a TUN descriptor configured outside meshd, such as by a
// mobile platform's VPN API, in a WireGuard TUN device of the given MTU. It
// takes file: file is closed whether or not it succeeds.
func AdoptTUN(file *os.File, mtu int, logger *slog.Logger) (tun.Device, error) {
	device, err := adoptPrivilegedTUNDescriptor(file, mtu, inheritedTUNOpenerFor(logger))
	if err != nil && file != nil {
		_ = file.Close()
	}
	return device, err
}

// inheritedTUNOpener wraps a descriptor in a TUN device. On failure the
// caller closes the descriptor, unless the error is errDescriptorTaken.
type inheritedTUNOpener func(int) (tun.Device, string, error)

// errDescriptorTaken reports an opener failure after the opener took the
// descriptor: something else (an os.File's finalizer) will close it.
var errDescriptorTaken = errors.New("dataplane: the tun opener kept the descriptor")

// adoptPrivilegedTUNDescriptor transfers a helper-configured TUN descriptor
// into the unprivileged packet engine without attempting privileged link
// changes. The duplicate gives the WireGuard adapter sole descriptor ownership.
func adoptPrivilegedTUNDescriptor(
	file *os.File,
	expectedMTU int,
	open inheritedTUNOpener,
) (tun.Device, error) {
	if file == nil || expectedMTU < 1280 || expectedMTU > 9000 {
		return nil, errors.New("dataplane: inherited tun metadata is invalid")
	}
	if open == nil {
		return nil, errors.New("dataplane: inherited tun opener is required")
	}

	descriptor, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: duplicating inherited tun descriptor: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = unix.Close(descriptor)

		return nil, fmt.Errorf("dataplane: transferring inherited tun descriptor: %w", err)
	}

	tunDevice, actualName, err := open(descriptor)
	if err != nil {
		switch {
		case tunDevice != nil:
			_ = tunDevice.Close()
		case !errors.Is(err, errDescriptorTaken):
			_ = unix.Close(descriptor)
		}

		return nil, fmt.Errorf("dataplane: opening inherited tun descriptor: %w", err)
	}
	if tunDevice == nil {
		_ = unix.Close(descriptor)

		return nil, errors.New("dataplane: inherited tun opener returned no device")
	}
	if actualName == "" {
		_ = tunDevice.Close()

		return nil, errors.New("dataplane: inherited tun name is empty")
	}
	actualMTU, err := tunDevice.MTU()
	if err != nil {
		_ = tunDevice.Close()

		return nil, fmt.Errorf("dataplane: reading inherited tun mtu: %w", err)
	}
	if actualMTU != expectedMTU {
		_ = tunDevice.Close()

		return nil, errors.New("dataplane: inherited tun mtu does not match helper response")
	}

	return tunDevice, nil
}
