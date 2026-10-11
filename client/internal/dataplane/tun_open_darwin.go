package dataplane

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// openInheritedTUN wraps the helper's utun descriptor. The MTU argument is
// zero because setting it needs root; meshnetd already set it and
// adoptPrivilegedTUNDescriptor checks the value. The route listener
// wireguard-go starts needs no privileges.
//
// wireguard-go closes the file it is given when it fails, while the caller
// closes descriptor on failure, so the device gets its own duplicate.
func openInheritedTUN(descriptor int) (tun.Device, string, error) {
	duplicate, err := unix.Dup(descriptor)
	if err != nil {
		return nil, "", fmt.Errorf("dataplane: duplicating utun descriptor: %w", err)
	}
	unix.CloseOnExec(duplicate)
	file := os.NewFile(uintptr(duplicate), "meshnetd-utun")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, "", errors.New("dataplane: invalid utun descriptor")
	}
	device, err := tun.CreateTUNFromFile(file, 0)
	if err != nil {
		return nil, "", err
	}
	name, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", err
	}
	_ = unix.Close(descriptor)
	return device, name, nil
}
