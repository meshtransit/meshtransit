package mobile

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// replaceableTUN is the TUN device the data plane runs on in an Engine.
//
// A mobile VPN interface cannot change its routes in place: Android makes a
// new interface, with a new descriptor, for every route change. Replace
// moves the running WireGuard device onto the new descriptor, so peers keep
// their sessions and paths instead of the data plane being rebuilt.
//
// A read or write that was using the replaced device when it closed moves
// to the new one; packets in flight at that moment are lost, as they would
// be on any route change. wireguard-go stops the whole device on a TUN read
// error, so no read error is reported while a replacement is under way: the
// platform may tear the old interface down before it hands over the new one.
type replaceableTUN struct {
	mtu    int
	batch  int
	logger *slog.Logger
	events chan tun.Event // never sent on: the Engine brings the device up

	mu         sync.RWMutex
	current    tun.Device
	generation uint64
	replacing  chan struct{} // closed when the replacement under way ends
	closed     bool
}

var _ tun.Device = (*replaceableTUN)(nil)

func newReplaceableTUN(device tun.Device, mtu int, logger *slog.Logger) *replaceableTUN {
	return &replaceableTUN{
		mtu: mtu, batch: device.BatchSize(), logger: logger, events: make(chan tun.Event), current: device,
	}
}

// active returns the device to use now and its generation.
func (replaceable *replaceableTUN) active() (tun.Device, uint64, error) {
	replaceable.mu.RLock()
	defer replaceable.mu.RUnlock()
	if replaceable.closed {
		return nil, 0, os.ErrClosed
	}
	return replaceable.current, replaceable.generation, nil
}

// moved reports whether the device of generation was replaced, waiting for
// a replacement under way to end first.
func (replaceable *replaceableTUN) moved(generation uint64) bool {
	replaceable.mu.RLock()
	replacing := replaceable.replacing
	replaceable.mu.RUnlock()
	if replacing != nil {
		<-replacing
	}
	replaceable.mu.RLock()
	defer replaceable.mu.RUnlock()
	return !replaceable.closed && replaceable.generation != generation
}

func (replaceable *replaceableTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	for {
		device, generation, err := replaceable.active()
		if err != nil {
			return 0, err
		}
		count, err := device.Read(buffers, sizes, offset)
		if err == nil || !replaceable.moved(generation) {
			return count, err
		}
	}
}

func (replaceable *replaceableTUN) Write(buffers [][]byte, offset int) (int, error) {
	device, generation, err := replaceable.active()
	if err != nil {
		return 0, err
	}
	count, err := device.Write(buffers, offset)
	if err == nil || !replaceable.moved(generation) {
		return count, err
	}
	// The device closed under this write: the packets go to the new one.
	device, _, err = replaceable.active()
	if err != nil {
		return 0, err
	}
	return device.Write(buffers, offset)
}

// Replace opens the next device with open and makes it the device in use,
// then closes the previous one. The next device must have the same MTU and
// batch size, which the running WireGuard device was sized for. When open
// or the check fails, the previous device stays in use.
func (replaceable *replaceableTUN) Replace(open func() (tun.Device, error)) error {
	replacing, err := replaceable.beginReplace()
	if err != nil {
		return err
	}
	defer close(replacing)
	next, err := open()
	if err == nil && next == nil {
		err = errors.New("mobile: no replacement TUN")
	}
	if err == nil {
		if err = replaceable.compatible(next); err != nil {
			_ = next.Close()
		}
	}
	replaceable.mu.Lock()
	replaceable.replacing = nil
	if err != nil || replaceable.closed {
		replaceable.mu.Unlock()
		if err == nil {
			_ = next.Close()
			err = os.ErrClosed
		}
		return err
	}
	previous := replaceable.current
	replaceable.current = next
	replaceable.generation++
	replaceable.mu.Unlock()
	// Closing wakes a read still waiting on the previous device. The next
	// device is already in use, so a close error changes nothing.
	if closeErr := previous.Close(); closeErr != nil && replaceable.logger != nil {
		replaceable.logger.Warn("closing the replaced TUN failed", "error", closeErr)
	}
	return nil
}

// beginReplace marks a replacement under way; only one runs at a time.
func (replaceable *replaceableTUN) beginReplace() (chan struct{}, error) {
	replaceable.mu.Lock()
	defer replaceable.mu.Unlock()
	if replaceable.closed {
		return nil, os.ErrClosed
	}
	if replaceable.replacing != nil {
		return nil, errors.New("mobile: a TUN replacement is already under way")
	}
	replaceable.replacing = make(chan struct{})
	return replaceable.replacing, nil
}

func (replaceable *replaceableTUN) compatible(next tun.Device) error {
	if batch := next.BatchSize(); batch != replaceable.batch {
		return fmt.Errorf("mobile: replacement TUN batch size %d differs from %d", batch, replaceable.batch)
	}
	mtu, err := next.MTU()
	if err != nil {
		return fmt.Errorf("mobile: reading the replacement TUN mtu: %w", err)
	}
	if mtu != replaceable.mtu {
		return fmt.Errorf("mobile: replacement TUN mtu %d differs from %d", mtu, replaceable.mtu)
	}
	return nil
}

// Close closes the device in use; Close again does nothing.
func (replaceable *replaceableTUN) Close() error {
	replaceable.mu.Lock()
	if replaceable.closed {
		replaceable.mu.Unlock()
		return nil
	}
	replaceable.closed = true
	current := replaceable.current
	replaceable.mu.Unlock()
	close(replaceable.events)
	return current.Close()
}

func (replaceable *replaceableTUN) isClosed() bool {
	replaceable.mu.RLock()
	defer replaceable.mu.RUnlock()
	return replaceable.closed
}

func (replaceable *replaceableTUN) File() *os.File {
	device, _, err := replaceable.active()
	if err != nil {
		return nil
	}
	return device.File()
}

func (replaceable *replaceableTUN) MTU() (int, error) { return replaceable.mtu, nil }

func (replaceable *replaceableTUN) Name() (string, error) {
	device, _, err := replaceable.active()
	if err != nil {
		return "", err
	}
	return device.Name()
}

func (replaceable *replaceableTUN) Events() <-chan tun.Event { return replaceable.events }

func (replaceable *replaceableTUN) BatchSize() int { return replaceable.batch }
