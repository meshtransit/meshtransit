package meshgw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"meshtransit.net/client/internal/netadmin"
)

var (
	gatewayAddr = netip.MustParseAddr("100.64.0.10")
	clientAddr  = netip.MustParseAddr("100.64.0.20")
)

func gatewayConfig(addrs ...netip.Addr) netadmin.TUNConfig {
	config := netadmin.TUNConfig{Routes: []netip.Prefix{netip.MustParsePrefix("100.64.0.20/32")}}
	for _, addr := range addrs {
		config.Addresses = append(config.Addresses, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return config
}

func newTestStacks(t *testing.T) *Stacks {
	t.Helper()
	stacks := NewStacks(netstackMTU, DefaultTCPBuffers(), slog.New(slog.DiscardHandler))
	t.Cleanup(func() { _ = stacks.Close() })
	return stacks
}

func openTUN(t *testing.T, stacks *Stacks, config netadmin.TUNConfig) tun.Device {
	t.Helper()
	opened, err := stacks.OpenTUN(t.Context(), config)
	if err != nil {
		t.Fatalf("OpenTUN() error = %v", err)
	}
	return opened.Device
}

// wire joins the gateway, through whichever TUN the data plane holds now,
// to a client stack, as the encrypted path would. attach swaps the TUN.
type wire struct {
	t       *testing.T
	client  tun.Device
	current atomic.Pointer[tun.Device]
	pumps   sync.WaitGroup
}

func newWire(t *testing.T, client tun.Device) *wire {
	t.Helper()
	w := &wire{t: t, client: client}
	w.pumps.Add(1)
	go func() {
		defer w.pumps.Done()
		w.fromClient()
	}()
	t.Cleanup(func() {
		_ = client.Close()
		if device := w.current.Load(); device != nil {
			_ = (*device).Close()
		}
		w.pumps.Wait()
	})
	return w
}

// attach gives the wire a gateway TUN: its packets go to the client, and
// the client's go to it, until it closes.
func (w *wire) attach(device tun.Device) {
	w.current.Store(&device)
	w.pumps.Add(1)
	go func() {
		defer w.pumps.Done()
		pumpUntilClosed(device, w.client)
	}()
}

func (w *wire) fromClient() {
	bufs := [][]byte{make([]byte, pumpOffset+netstackMTU+1)}
	sizes := []int{0}
	for {
		n, err := w.client.Read(bufs, sizes, pumpOffset)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if device := w.current.Load(); device != nil {
			// A TUN closed between packets drops this one, as a real
			// rebuild would; TCP sends it again.
			_, _ = (*device).Write([][]byte{bufs[0][:pumpOffset+sizes[0]]}, pumpOffset)
		}
	}
}

func pumpUntilClosed(from, to tun.Device) {
	bufs := [][]byte{make([]byte, pumpOffset+netstackMTU+1)}
	sizes := []int{0}
	for {
		n, err := from.Read(bufs, sizes, pumpOffset)
		if err != nil {
			return
		}
		if n == 1 {
			_, _ = to.Write([][]byte{bufs[0][:pumpOffset+sizes[0]]}, pumpOffset)
		}
	}
}

func newClient(t *testing.T) (tun.Device, *netstack.Net) {
	t.Helper()
	device, network, err := netstack.CreateNetTUN([]netip.Addr{clientAddr}, nil, netstackMTU)
	if err != nil {
		t.Fatalf("CreateNetTUN() error = %v", err)
	}
	return device, network
}

// echoOnce accepts one connection on the gateway's current stack and echoes
// it until the client closes.
func echoOnce(t *testing.T, stacks *Stacks) {
	t.Helper()
	current, ok := stacks.Current()
	if !ok {
		t.Fatal("Current() found no stack")
	}
	listener, err := current.Net.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()
}

func roundTrip(t *testing.T, conn io.ReadWriter, message string) {
	t.Helper()
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("Write(%q) error = %v", message, err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull(%q) error = %v", message, err)
	}
	if string(got) != message {
		t.Fatalf("echoed %q, want %q", got, message)
	}
}

// The data plane closes and reopens its TUN when the relays change or the
// device rebuilds. With the same addresses the gateway keeps its stack, so
// a connection open across the swap carries on.
func TestStacksKeepConnectionsAcrossReopens(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	clientDevice, clientNet := newClient(t)
	w := newWire(t, clientDevice)
	first := openTUN(t, stacks, gatewayConfig(gatewayAddr))
	w.attach(first)
	echoOnce(t, stacks)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := clientNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	roundTrip(t, conn, "before")

	for i := range 3 {
		if err := first.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		// Peer changes only change routes, which a netstack ignores.
		config := gatewayConfig(gatewayAddr)
		config.Routes = append(config.Routes, netip.MustParsePrefix("100.64.0.30/32"))
		if err := stacks.ConfigureTUNRoutes(t.Context(), config); err != nil {
			t.Fatalf("ConfigureTUNRoutes() error = %v", err)
		}
		first = openTUN(t, stacks, config)
		w.attach(first)
		roundTrip(t, conn, "after reopen "+string(rune('a'+i)))
	}
}

// A new address set is a new stack: the old one retires, and its
// listeners stop, so the forwarder knows to bind again.
func TestStacksReplaceTheStackWhenAddressesChange(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	_ = openTUN(t, stacks, gatewayConfig(gatewayAddr))
	before, ok := stacks.Current()
	if !ok || len(before.Addresses) != 1 || before.Addresses[0] != gatewayAddr {
		t.Fatalf("Current() = %+v, %v", before, ok)
	}
	listener, err := before.Net.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()
	select {
	case <-stacks.Changes():
	default:
	}

	moved := netip.MustParseAddr("100.64.0.11")
	_ = openTUN(t, stacks, gatewayConfig(moved))
	select {
	case <-stacks.Changes():
	case <-time.After(5 * time.Second):
		t.Fatal("no change was signalled")
	}
	select {
	case <-before.Retired:
	case <-time.After(5 * time.Second):
		t.Fatal("the old stack did not retire")
	}
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("Accept() on a retired stack succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept() on a retired stack still blocks")
	}
	after, ok := stacks.Current()
	if !ok || len(after.Addresses) != 1 || after.Addresses[0] != moved {
		t.Fatalf("Current() after the change = %+v, %v", after, ok)
	}

	// Reopening with the same addresses is no change.
	_ = openTUN(t, stacks, gatewayConfig(moved))
	select {
	case <-stacks.Changes():
		t.Fatal("a reopen over the same stack signalled a change")
	default:
	}
}

// A closed TUN ends the data plane's read and refuses writes, and its events
// end, as wireguard-go expects of any TUN.
func TestStacksTUNCloses(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	device := openTUN(t, stacks, gatewayConfig(gatewayAddr))
	if event := <-device.Events(); event != tun.EventUp {
		t.Fatalf("first event = %v, want EventUp", event)
	}
	read := make(chan error, 1)
	go func() {
		_, err := device.Read([][]byte{make([]byte, netstackMTU)}, []int{0}, 0)
		read <- err
	}()
	if err := device.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	select {
	case err := <-read:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read() after Close error = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read() still blocks after Close")
	}
	if _, err := device.Write([][]byte{make([]byte, 40)}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write() after Close error = %v, want os.ErrClosed", err)
	}
	if _, open := <-device.Events(); open {
		t.Fatal("events still open after Close")
	}
}

// OpenTUN reports exactly the map's addresses and routes, as the data plane
// checks, and refuses a map without addresses or a closed opener.
func TestStacksOpenTUNEchoesTheMap(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	config := gatewayConfig(gatewayAddr, netip.MustParseAddr("fd7a:115c:a1e0::10"))
	opened, err := stacks.OpenTUN(t.Context(), config)
	if err != nil {
		t.Fatalf("OpenTUN() error = %v", err)
	}
	if opened.Device == nil || opened.File != nil || opened.Name == "" || opened.MTU != netstackMTU {
		t.Fatalf("OpenTUN() = %+v", opened)
	}
	if !equalPrefixes(opened.Addresses, config.Addresses) || !equalPrefixes(opened.Routes, config.Routes) {
		t.Fatalf("OpenTUN() addresses %v routes %v, want the map's", opened.Addresses, opened.Routes)
	}
	config.Addresses[0] = netip.MustParsePrefix("100.64.9.9/32")
	if opened.Addresses[0] == config.Addresses[0] {
		t.Fatal("OpenTUN() kept the caller's slice")
	}

	if _, err := stacks.OpenTUN(t.Context(), netadmin.TUNConfig{}); err == nil {
		t.Fatal("OpenTUN() without addresses succeeded")
	}
	if err := stacks.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := stacks.OpenTUN(t.Context(), gatewayConfig(gatewayAddr)); err == nil {
		t.Fatal("OpenTUN() after Close succeeded")
	}
	if _, ok := stacks.Current(); ok {
		t.Fatal("Current() after Close found a stack")
	}
}

// Closing stacks while traffic flows ends every goroutine without a panic:
// the stack's one reader runs until the stack is closed (TD-CLI-74).
func TestStacksCloseUnderTrafficLeaksNothing(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for range 10 {
		closeUnderTraffic(t)
	}
}

func closeUnderTraffic(t *testing.T) {
	t.Helper()
	stacks := NewStacks(netstackMTU, DefaultTCPBuffers(), slog.New(slog.DiscardHandler))
	clientDevice, clientNet := newClient(t)
	w := &wire{t: t, client: clientDevice}
	w.pumps.Add(1)
	go func() {
		defer w.pumps.Done()
		w.fromClient()
	}()
	w.attach(openTUN(t, stacks, gatewayConfig(gatewayAddr)))
	current, _ := stacks.Current()
	listener, err := current.Net.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort() error = %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		chunk := bytes.Repeat([]byte{'x'}, 16<<10)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		for {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)

	if err := stacks.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_ = listener.Close()
	_ = conn.Close()
	<-sent
	<-served
	_ = clientDevice.Close()
	w.pumps.Wait()
}

func equalPrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A generation nobody reads fills up and drops what the stack sends, counted,
// without stalling the stack; once the data plane holds the next generation,
// traffic flows again.
func TestStacksDropRatherThanStall(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	stuck := openTUN(t, stacks, gatewayConfig(gatewayAddr))
	current, _ := stacks.Current()
	conn, err := current.Net.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(clientAddr, 9))
	if err != nil {
		t.Fatalf("DialUDPAddrPort() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	for range generationQueue + 64 {
		if _, err := conn.Write([]byte("datagram")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for stacks.Dropped() < 64 {
		if time.Now().After(deadline) {
			t.Fatalf("Dropped() = %d, want at least 64", stacks.Dropped())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := stuck.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	clientDevice, clientNet := newClient(t)
	w := newWire(t, clientDevice)
	w.attach(openTUN(t, stacks, gatewayConfig(gatewayAddr)))
	echoOnce(t, stacks)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tcp, err := clientNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatalf("Dial() after the stall error = %v", err)
	}
	defer func() { _ = tcp.Close() }()
	if err := tcp.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	roundTrip(t, tcp, "after the stall")
}
