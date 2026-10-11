package dataplane

import (
	"context"
	"os"
	"testing"
	"time"

	"meshtransit.net/client/internal/relay"
)

// stoppingFakeDevice closes done on Close, like WireGuard's own device, and
// lets a test stop it as WireGuard does after a TUN read error.
type stoppingFakeDevice struct {
	*fakeWireGuardDevice
	done chan struct{}
}

func (d *stoppingFakeDevice) Done() <-chan struct{} { return d.done }

func (d *stoppingFakeDevice) Close() {
	d.fakeWireGuardDevice.Close()
	d.stop()
}

func (d *stoppingFakeDevice) stop() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

type stoppingFakeFactory struct {
	devices []*stoppingFakeDevice
}

func (f *stoppingFakeFactory) New(
	context.Context, *os.File, int, *policyFilter, PacketObserver, *relay.Config,
) (wireGuardDevice, error) {
	device := &stoppingFakeDevice{fakeWireGuardDevice: &fakeWireGuardDevice{}, done: make(chan struct{})}
	f.devices = append(f.devices, device)

	return device, nil
}

func TestWireGuardEngineSignalsAndRebuildsADeviceThatStoppedOnItsOwn(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &wireGuardTUNOpener{}
	factory := &stoppingFakeFactory{}
	engine, err := newWireGuardEngine(opener, 41641, factory, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	factory.devices[0].stop()
	select {
	case <-engine.DeviceStops():
	case <-time.After(5 * time.Second):
		t.Fatal("no device stop signal")
	}

	// The same map is compatible, but must not keep the stopped device.
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if len(factory.devices) != 2 || opener.calls != 2 || factory.devices[1].upCalls != 1 {
		t.Fatalf("devices=%d opens=%d, want a rebuilt device", len(factory.devices), opener.calls)
	}
	if factory.devices[0].closeCalls != 1 {
		t.Fatalf("stopped device close calls = %d, want 1", factory.devices[0].closeCalls)
	}
}

func TestWireGuardEngineDoesNotSignalAnIntendedClose(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	factory := &stoppingFakeFactory{}
	engine, err := newWireGuardEngine(&wireGuardTUNOpener{}, 41641, factory, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-engine.DeviceStops():
		t.Fatal("an intended Close signalled a device stop")
	case <-time.After(100 * time.Millisecond):
	}
}
