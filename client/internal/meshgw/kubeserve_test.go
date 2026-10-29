package meshgw

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// greetingServer greets each connection and holds it until its context
// ends, as kubeproxy.Server closes its connections with Serve's context.
type greetingServer struct{}

func (greetingServer) Serve(ctx context.Context, listener net.Listener) error {
	var conns sync.Map
	stop := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		conns.Range(func(conn, _ any) bool {
			if held, ok := conn.(net.Conn); ok {
				_ = held.Close()
			}
			return true
		})
	})
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil
		}
		conns.Store(conn, struct{}{})
		_, _ = conn.Write([]byte("hi\n"))
	}
}

// The listener serves only while Open allows it, and closing it closes the
// connections it took (K1b design §3).
func TestKubeProxyListenerOpensAndCloses(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	clientDevice, clientNet := newClient(t)
	w := newWire(t, clientDevice)
	w.attach(openTUN(t, stacks, gatewayConfig(gatewayAddr)))
	var open atomic.Bool
	listener := &KubeProxyListener{
		Stacks: stacks, Port: 443, Server: greetingServer{},
		Open: func() (bool, string) {
			if !open.Load() {
				return false, "no valid certificate"
			}
			return true, ""
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- listener.Run(ctx) }()
	t.Cleanup(func() { stop(); <-done })
	waitFor := func(what string, condition func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !condition(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	dial := func() (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		return clientNet.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(gatewayAddr, 443))
	}

	waitFor("no closed reason", func() bool { return listener.ClosedReason() == "no valid certificate" })
	if conn, err := dial(); err == nil {
		_ = conn.Close()
		t.Fatal("connected while closed")
	}

	open.Store(true)
	waitFor("never listening", listener.Listening)
	if listener.ClosedReason() != "" {
		t.Fatalf("closed reason %q while listening", listener.ClosedReason())
	}
	conn, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || line != "hi\n" {
		t.Fatalf("%q, %v", line, err)
	}

	open.Store(false)
	waitFor("still listening", func() bool { return !listener.Listening() })
	if _, err := reader.ReadString('\n'); err == nil {
		t.Fatal("a connection outlived the listener")
	}
}

// The replica serves with a valid certificate and a map confirmed within
// staleAfter.
func TestKubeOpen(t *testing.T) {
	t.Parallel()
	var valid atomic.Bool
	var fresh atomic.Pointer[time.Time]
	never := time.Time{}
	fresh.Store(&never)
	open := kubeOpen(func() (*tls.Certificate, bool) { return nil, valid.Load() },
		func() time.Time { return *fresh.Load() }, 5*time.Minute)
	if ok, why := open(); ok || why != "no valid certificate" {
		t.Fatalf("%t %q", ok, why)
	}
	valid.Store(true)
	if ok, why := open(); ok || why != "map not confirmed within 5m0s" {
		t.Fatalf("never confirmed: %t %q", ok, why)
	}
	old := time.Now().Add(-6 * time.Minute)
	fresh.Store(&old)
	if ok, _ := open(); ok {
		t.Fatal("open on a stale map")
	}
	now := time.Now()
	fresh.Store(&now)
	if ok, why := open(); !ok || why != "" {
		t.Fatalf("%t %q", ok, why)
	}
}

// An address that cannot listen is tried again while the others serve on,
// and readiness hears of it (review b5b M2, M3).
func TestKubeProxyListenerRetriesAnAddress(t *testing.T) {
	t.Parallel()
	second := netip.MustParseAddr("100.64.0.11")
	stacks := newTestStacks(t)
	clientDevice, clientNet := newClient(t)
	w := newWire(t, clientDevice)
	w.attach(openTUN(t, stacks, gatewayConfig(gatewayAddr, second)))
	stack, _ := stacks.Current()
	taken, err := stack.Net.ListenTCPAddrPort(netip.AddrPortFrom(second, 443))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = taken.Close() })
	listener := &KubeProxyListener{
		Stacks: stacks, Port: 443, Server: greetingServer{},
		Open: func() (bool, string) { return true, "" }, Logger: slog.New(slog.DiscardHandler),
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- listener.Run(ctx) }()
	t.Cleanup(func() { stop(); <-done })
	waitFor := func(what string, condition func() bool) {
		t.Helper()
		for deadline := time.Now().Add(8 * time.Second); !condition(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	waitFor("no bind failure", listener.BindFailing)
	if listener.Listening() {
		t.Fatal("listening with an address down")
	}
	dialCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	conn, err := clientNet.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(gatewayAddr, 443))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || line != "hi\n" {
		t.Fatalf("%q, %v", line, err)
	}

	_ = taken.Close()
	waitFor("never listening on both", listener.Listening)
	if listener.BindFailing() {
		t.Fatal("still failing once both listen")
	}
	// The first address's connection lived through the retries.
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var timeout net.Error
	if _, err := reader.ReadString('\n'); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("the first connection ended: %v", err)
	}
}
