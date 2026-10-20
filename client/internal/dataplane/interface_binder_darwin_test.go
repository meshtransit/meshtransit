//go:build darwin && !ios

package dataplane

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPortBinderBindsTheSocketsOnItsPort(t *testing.T) {
	socket, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	other, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	local, ok := socket.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("not a UDP address")
	}
	binder := portBinder{port: local.AddrPort().Port()}
	if err := binder.BindSocketToInterface4(uint32(loopback.Index), false); err != nil { //nolint:gosec // an index
		t.Fatal(err)
	}
	boundIf := func(connection *net.UDPConn) int {
		raw, err := connection.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		value := -1
		_ = raw.Control(func(fd uintptr) { value, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF) })
		return value
	}
	if got := boundIf(socket); got != loopback.Index {
		t.Fatalf("bound interface = %d, want %d", got, loopback.Index)
	}
	if got := boundIf(other); got != 0 {
		t.Fatalf("a socket on another port was bound to %d", got)
	}
	if err := binder.BindSocketToInterface4(0, false); err != nil || boundIf(socket) != 0 {
		t.Fatalf("unbinding: %v, bound to %d", err, boundIf(socket))
	}
	if err := binder.BindSocketToInterface6(1, false); err == nil {
		t.Fatal("an IPv6 bind found no socket yet succeeded")
	}
}
