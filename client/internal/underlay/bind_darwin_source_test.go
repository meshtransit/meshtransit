//go:build darwin && !ios

package underlay

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBindSourceBindsAnUnboundSocketOnce(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	loopback := netip.MustParseAddr("127.0.0.1")
	if err := bindSource(fd, loopback); err != nil {
		t.Fatalf("bindSource() = %v", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	local, ok := bound.(*unix.SockaddrInet4)
	if !ok || local.Addr != loopback.As4() || local.Port == 0 {
		t.Fatalf("bound to %+v, want 127.0.0.1 and a port", bound)
	}
	// A bound socket keeps its address: no second bind, no error.
	if err := bindSource(fd, netip.MustParseAddr("127.0.0.2")); err != nil {
		t.Fatalf("bindSource() on a bound socket = %v", err)
	}
}
