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
	return newManagedUpTUN(device), name, nil
}

// managedUpTUN hides the up and down events wireguard-go derives from routing
// messages, as Linux's unmonitored TUN does: meshd brings the device up itself
// and rebuilds it when it must. Without this, a late "down" message for a
// destroyed utun whose index the new one reused stopped the new device and
// closed its UDP socket, over and over.
type managedUpTUN struct {
	tun.Device
	events chan tun.Event
}

func newManagedUpTUN(inner tun.Device) *managedUpTUN {
	wrapped := &managedUpTUN{Device: inner, events: make(chan tun.Event, 10)}
	go func() {
		defer close(wrapped.events)
		for event := range inner.Events() {
			if event &^= tun.EventUp | tun.EventDown; event != 0 {
				wrapped.events <- event
			}
		}
	}()
	return wrapped
}

func (t *managedUpTUN) Events() <-chan tun.Event { return t.events }
