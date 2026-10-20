//go:build !ios

package underlay

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A socket to an address inside a recorded subnet route is bound to the
// interface the host routes that address through: loopback here, so the test
// needs no network. Not parallel: the recorded routes are process-wide.
func TestControlBindsRoutedDestinationToPhysicalInterface(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatalf("InterfaceByName(lo0) error = %v", err)
	}

	SetRouted([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	t.Cleanup(func() { SetRouted(nil) })
	connection, err := Dialer(5*time.Second).DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		t.Fatalf("connection is %T", connection)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn() error = %v", err)
	}
	var bound int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		bound, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF)
	}); err != nil || optionErr != nil {
		t.Fatalf("reading IP_BOUND_IF: %v, %v", err, optionErr)
	}
	if bound != loopback.Index {
		t.Fatalf("IP_BOUND_IF = %d, want lo0 (%d)", bound, loopback.Index)
	}
}

// Outside every recorded route a socket stays unbound.
func TestControlLeavesOtherDestinationsUnbound(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	SetRouted([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	t.Cleanup(func() { SetRouted(nil) })
	connection, err := Dialer(5*time.Second).DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		t.Fatalf("connection is %T", connection)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn() error = %v", err)
	}
	var bound int
	_ = raw.Control(func(fd uintptr) { bound, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF) })
	if bound != 0 {
		t.Fatalf("IP_BOUND_IF = %d, want unbound", bound)
	}
}
