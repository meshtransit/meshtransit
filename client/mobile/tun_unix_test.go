//go:build unix

package mobile

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
)

// last reports the arguments of the latest OpenTUN call. Only the Unix tests
// read them back, so it lives here to keep Windows lint clean.
func (tun *fakeTUN) last() (addresses, routes string, mtu int) {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	return tun.addresses, tun.routes, tun.mtu
}

// routesValue and dnsValue report the routes and DNS servers of the
// latest OpenTUN call.
func (tun *fakeTUN) routesValue() string {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	return tun.routes
}

func (tun *fakeTUN) dnsValue() string {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	return tun.dns
}

// fakeDevice is a TUN device whose packets come from a channel.
type fakeDevice struct {
	mtu, batch int
	file       *os.File
	packets    chan []byte
	reading    chan struct{} // receives once per Read that starts waiting
	broken     chan struct{} // closed: reads fail, as on a torn-down interface
	breakOnce  sync.Once
	closed     chan struct{}
	closeOnce  sync.Once
}

func newFakeDevice(file *os.File, mtu int) *fakeDevice {
	return &fakeDevice{
		mtu: mtu, batch: 1, file: file, packets: make(chan []byte, 4), reading: make(chan struct{}, 64),
		broken: make(chan struct{}), closed: make(chan struct{}),
	}
}

func (device *fakeDevice) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	select {
	case device.reading <- struct{}{}:
	default:
	}
	select {
	case packet := <-device.packets:
		sizes[0] = copy(buffers[0][offset:], packet)
		return 1, nil
	case <-device.broken:
		return 0, errors.New("interface torn down")
	case <-device.closed:
		return 0, os.ErrClosed
	}
}

// breakReads makes reads fail without closing the device.
func (device *fakeDevice) breakReads() { device.breakOnce.Do(func() { close(device.broken) }) }

func (device *fakeDevice) Write(buffers [][]byte, _ int) (int, error) {
	select {
	case <-device.closed:
		return 0, os.ErrClosed
	default:
		return len(buffers), nil
	}
}

func (device *fakeDevice) Close() error {
	device.closeOnce.Do(func() {
		close(device.closed)
		if device.file != nil {
			_ = device.file.Close()
		}
	})
	return nil
}

func (device *fakeDevice) isClosed() bool {
	select {
	case <-device.closed:
		return true
	default:
		return false
	}
}

func (device *fakeDevice) File() *os.File           { return device.file }
func (device *fakeDevice) MTU() (int, error)        { return device.mtu, nil }
func (device *fakeDevice) Name() (string, error)    { return "tun0", nil }
func (device *fakeDevice) Events() <-chan tun.Event { return nil }
func (device *fakeDevice) BatchSize() int           { return device.batch }

// platformFixture serves fresh descriptors (dups of a pipe) to platformTUN
// and records the devices it adopts.
type platformFixture struct {
	t        *testing.T
	provider *fakeTUN
	pipe     *os.File

	mu      sync.Mutex
	devices []*fakeDevice
}

func newPlatformFixture(t *testing.T) (*platformFixture, *platformTUN) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	fixture := &platformFixture{t: t, pipe: reader}
	fixture.provider = &fakeTUN{}
	fixture.provider.next = fixture.freshDescriptor
	opener := newPlatformTUN(fixture.provider, DefaultMTU, slog.New(slog.DiscardHandler),
		filepath.Join(t.TempDir(), routeSettingsFile), &hostAddressList{})
	opener.adopt = func(file *os.File, mtu int, _ *slog.Logger) (tun.Device, error) {
		device := newFakeDevice(file, mtu)
		fixture.mu.Lock()
		fixture.devices = append(fixture.devices, device)
		fixture.mu.Unlock()
		return device, nil
	}
	return fixture, opener
}

// freshDescriptor gives a new descriptor the engine owns, as the platform must.
func (fixture *platformFixture) freshDescriptor() (int, error) {
	fd, err := syscall.Dup(int(fixture.pipe.Fd()))
	if err != nil {
		fixture.t.Fatal(err)
	}
	return fd, nil
}

func (fixture *platformFixture) device(index int) *fakeDevice {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.devices[index]
}

var (
	testAddresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32"), netip.MustParsePrefix("fd07::5/128")}
	testRoutes    = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
)

func TestPlatformTUNPassesTheMapsConfiguration(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatalf("OpenTUN() error = %v", err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	addresses, routes, mtu := fixture.provider.last()
	if addresses != "100.64.0.5/32,fd07::5/128" || routes != "100.64.0.0/10" || mtu != DefaultMTU {
		t.Fatalf("platform got %q %q %d", addresses, routes, mtu)
	}
	deviceMTU, _ := opened.Device.MTU()
	if opened.File != nil || opened.Device == nil || opened.MTU != DefaultMTU || deviceMTU != DefaultMTU ||
		len(opened.Addresses) != 2 || len(opened.Routes) != 1 {
		t.Fatalf("OpenTUN() = %+v", opened)
	}
}

func TestPlatformTUNChangesRoutesWithoutANewDevice(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	// A read waits on the first interface while the routes change.
	read := make(chan error, 1)
	go func() {
		buffers, sizes := [][]byte{make([]byte, 64)}, []int{0}
		_, err := opened.Device.Read(buffers, sizes, 0)
		if err == nil && string(buffers[0][:sizes[0]]) != "after" {
			err = errors.New("read the wrong packet")
		}
		read <- err
	}()
	<-fixture.device(0).reading
	wider := append([]netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}, testRoutes...)
	if err := opener.ConfigureTUNRoutes(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: wider}); err != nil {
		t.Fatalf("ConfigureTUNRoutes() error = %v", err)
	}
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/10,198.18.0.0/15" {
		t.Fatalf("platform got routes %q", routes)
	}
	if !fixture.device(0).isClosed() {
		t.Fatal("the first interface stayed open")
	}
	fixture.device(1).packets <- []byte("after")
	select {
	case err := <-read:
		if err != nil {
			t.Fatalf("Read() across the change error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read() did not move to the new interface")
	}
}

func TestPlatformTUNRouteChangeNeedsAnOpenTUN(t *testing.T) {
	t.Parallel()
	_, opener := newPlatformFixture(t)
	config := netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes}
	if err := opener.ConfigureTUNRoutes(t.Context(), config); !errors.Is(err, errNoTUN) {
		t.Fatalf("ConfigureTUNRoutes() before OpenTUN error = %v", err)
	}
	opened, err := opener.OpenTUN(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	_ = opened.Device.Close()
	if err := opener.ConfigureTUNRoutes(t.Context(), config); !errors.Is(err, errNoTUN) {
		t.Fatalf("ConfigureTUNRoutes() after Close error = %v", err)
	}
}

func TestPlatformTUNFailsClosed(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for name, test := range map[string]struct {
		ctx    context.Context
		tun    *fakeTUN
		adopt  error
		config netadmin.TUNConfig
	}{
		"platform error":    {ctx: t.Context(), tun: &fakeTUN{err: errors.New("no permission")}, config: netadmin.TUNConfig{Addresses: testAddresses}},
		"negative fd":       {ctx: t.Context(), tun: &fakeTUN{fd: -1}, config: netadmin.TUNConfig{Addresses: testAddresses}},
		"stdin":             {ctx: t.Context(), tun: &fakeTUN{fd: 0}, config: netadmin.TUNConfig{Addresses: testAddresses}},
		"stderr":            {ctx: t.Context(), tun: &fakeTUN{fd: 2}, config: netadmin.TUNConfig{Addresses: testAddresses}},
		"no addresses":      {ctx: t.Context(), tun: &fakeTUN{}},
		"context cancelled": {ctx: canceled, tun: &fakeTUN{}, config: netadmin.TUNConfig{Addresses: testAddresses}},
		"not a TUN":         {ctx: t.Context(), adopt: errors.New("not a tun")},
		"LAN route": {ctx: t.Context(), tun: &fakeTUN{}, config: netadmin.TUNConfig{
			Addresses: testAddresses, Routes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		}},
		"default route": {ctx: t.Context(), tun: &fakeTUN{}, config: netadmin.TUNConfig{
			Addresses: testAddresses, Routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
		"route wider than the frame": {ctx: t.Context(), tun: &fakeTUN{}, config: netadmin.TUNConfig{
			Addresses: testAddresses, Routes: []netip.Prefix{netip.MustParsePrefix("100.0.0.0/8")},
		}},
		"public address": {ctx: t.Context(), tun: &fakeTUN{}, config: netadmin.TUNConfig{
			Addresses: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
		}},
		"address that is not a host": {ctx: t.Context(), tun: &fakeTUN{}, config: netadmin.TUNConfig{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, opener := newPlatformFixture(t)
			if test.tun != nil {
				opener.provider = test.tun
			}
			if test.adopt != nil {
				opener.adopt = func(file *os.File, _ int, _ *slog.Logger) (tun.Device, error) {
					_ = file.Close()
					return nil, test.adopt
				}
				test.config.Addresses = testAddresses
			}
			if _, err := opener.OpenTUN(test.ctx, test.config); !errors.Is(err, errNoTUN) && !errors.Is(err, context.Canceled) {
				t.Fatalf("OpenTUN() error = %v, want errNoTUN", err)
			}
		})
	}
}

func TestReplaceableTUNRefusesAnIncompatibleDevice(t *testing.T) {
	t.Parallel()
	first := newFakeDevice(nil, DefaultMTU)
	replaceable := newReplaceableTUN(first, DefaultMTU, nil)
	t.Cleanup(func() { _ = replaceable.Close() })
	otherMTU := newFakeDevice(nil, 1400)
	if err := replaceable.Replace(opens(otherMTU)); err == nil || !otherMTU.isClosed() {
		t.Fatalf("Replace(mtu 1400) error = %v, closed = %t", err, otherMTU.isClosed())
	}
	otherBatch := newFakeDevice(nil, DefaultMTU)
	otherBatch.batch = 8
	if err := replaceable.Replace(opens(otherBatch)); err == nil || !otherBatch.isClosed() {
		t.Fatalf("Replace(batch 8) error = %v, closed = %t", err, otherBatch.isClosed())
	}
	if err := replaceable.Replace(func() (tun.Device, error) { return nil, errors.New("no interface") }); err == nil {
		t.Fatal("Replace() succeeded without a device")
	}
	if first.isClosed() {
		t.Fatal("a failed Replace closed the device in use")
	}
}

func TestReplaceableTUNAfterClose(t *testing.T) {
	t.Parallel()
	first := newFakeDevice(nil, DefaultMTU)
	replaceable := newReplaceableTUN(first, DefaultMTU, nil)
	if err := replaceable.Close(); err != nil || !first.isClosed() {
		t.Fatalf("Close() error = %v, device closed = %t", err, first.isClosed())
	}
	if err := replaceable.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := replaceable.Read([][]byte{make([]byte, 8)}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read() after Close error = %v", err)
	}
	if _, err := replaceable.Write([][]byte{make([]byte, 8)}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write() after Close error = %v", err)
	}
	next := newFakeDevice(nil, DefaultMTU)
	if err := replaceable.Replace(opens(next)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Replace() after Close error = %v", err)
	}
	if _, ok := <-replaceable.Events(); ok {
		t.Fatal("Events() stayed open after Close")
	}
}

func opens(device tun.Device) func() (tun.Device, error) {
	return func() (tun.Device, error) { return device, nil }
}

func TestReplaceableTUNReadSurvivesTheOldInterfaceFailingFirst(t *testing.T) {
	t.Parallel()
	first := newFakeDevice(nil, DefaultMTU)
	replaceable := newReplaceableTUN(first, DefaultMTU, nil)
	t.Cleanup(func() { _ = replaceable.Close() })
	read := make(chan error, 1)
	go func() {
		buffers, sizes := [][]byte{make([]byte, 64)}, []int{0}
		_, err := replaceable.Read(buffers, sizes, 0)
		read <- err
	}()
	<-first.reading
	second := newFakeDevice(nil, DefaultMTU)
	second.packets <- []byte("after")
	// The platform tears the old interface down while it builds the new one.
	err := replaceable.Replace(func() (tun.Device, error) {
		first.breakReads()
		time.Sleep(20 * time.Millisecond) // the failed read must wait, not return
		return second, nil
	})
	if err != nil {
		t.Fatalf("Replace() error = %v", err)
	}
	if err := <-read; err != nil {
		t.Fatalf("Read() during the replacement error = %v; wireguard-go would stop the device", err)
	}
}

func TestReplaceableTUNWriteMovesToTheNewDevice(t *testing.T) {
	t.Parallel()
	first := newFakeDevice(nil, DefaultMTU)
	replaceable := newReplaceableTUN(first, DefaultMTU, nil)
	t.Cleanup(func() { _ = replaceable.Close() })
	if err := replaceable.Replace(opens(newFakeDevice(nil, DefaultMTU))); err != nil {
		t.Fatal(err)
	}
	if count, err := replaceable.Write([][]byte{make([]byte, 8)}, 0); err != nil || count != 1 {
		t.Fatalf("Write() after Replace = %d, %v", count, err)
	}
}

// TestReplaceableTUNUnderConcurrentUse is for the race detector: readers,
// writers, replacements and Close at once must not race, hang or panic.
func TestReplaceableTUNUnderConcurrentUse(t *testing.T) {
	t.Parallel()
	replaceable := newReplaceableTUN(newFakeDevice(nil, DefaultMTU), DefaultMTU, nil)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			buffers, sizes := [][]byte{make([]byte, 64)}, []int{0}
			for {
				if _, err := replaceable.Read(buffers, sizes, 0); errors.Is(err, os.ErrClosed) {
					return
				}
			}
		})
		group.Go(func() {
			for {
				if _, err := replaceable.Write([][]byte{make([]byte, 8)}, 0); errors.Is(err, os.ErrClosed) {
					return
				}
			}
		})
	}
	for range 50 {
		next := newFakeDevice(nil, DefaultMTU)
		next.packets <- []byte("packet")
		if err := replaceable.Replace(opens(next)); err != nil {
			t.Fatalf("Replace() error = %v", err)
		}
	}
	if err := replaceable.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readers or writers hung after Close")
	}
}

// TestPlatformTUNKeepsItsInterfaceWhenPeersComeAndGo changes the peers within
// one Network's block: the stable routes do not change, so the platform is
// not asked for a new interface.
func TestPlatformTUNKeepsItsInterfaceWhenPeersComeAndGo(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{
		Addresses: testAddresses,
		Routes:    prefixes("100.64.0.2/32", "100.64.0.3/32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/16" {
		t.Fatalf("platform got routes %q", routes)
	}
	if err := opener.ConfigureTUNRoutes(t.Context(), netadmin.TUNConfig{
		Addresses: testAddresses,
		Routes:    prefixes("100.64.0.2/32", "100.64.0.7/32", "100.64.0.8/32"),
	}); err != nil {
		t.Fatal(err)
	}
	if fixture.device(0).isClosed() {
		t.Fatal("a peer joining in the same block rebuilt the interface")
	}
}

// A route change outside the overlay frame never reaches the platform: the
// open interface keeps its routes and the data plane rebuilds.
func TestPlatformTUNRefusesRouteChangesOutsideTheFrame(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	lan := append([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, testRoutes...)
	if err := opener.ConfigureTUNRoutes(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: lan}); !errors.Is(err, errNoTUN) {
		t.Fatalf("ConfigureTUNRoutes() error = %v, want errNoTUN", err)
	}
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/10" {
		t.Fatalf("platform got routes %q", routes)
	}
	if fixture.device(0).isClosed() {
		t.Fatal("a refused change closed the open interface")
	}
}
