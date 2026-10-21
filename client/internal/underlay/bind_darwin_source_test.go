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

func TestPickSourcePrefersAStableUsableAddress(t *testing.T) {
	stable := netip.MustParseAddr("2001:db8::1")
	temporary := netip.MustParseAddr("2001:db8::2")
	deprecated := netip.MustParseAddr("2001:db8::3")
	tentative := netip.MustParseAddr("2001:db8::4")
	unique := netip.MustParseAddr("fd00::5")
	translated := netip.MustParseAddr("2001:db8::6")
	unread := netip.MustParseAddr("2001:db8::7")
	flags := map[netip.Addr]uint32{
		temporary: in6IffTemporary, deprecated: 0x10, tentative: 0x2, stable: in6IffSecured, translated: 0x1000,
	}
	read := func(address netip.Addr) (uint32, error) {
		if address == unread {
			return 0, unix.EADDRNOTAVAIL
		}
		return flags[address], nil
	}
	for _, test := range []struct {
		name        string
		candidates  []netip.Addr
		destination string
		want        netip.Addr
	}{
		{"stable over temporary", []netip.Addr{deprecated, temporary, tentative, stable}, "2001:db8:1::9", stable},
		{"temporary before deprecated", []netip.Addr{deprecated, temporary}, "2001:db8:1::9", temporary},
		{"deprecated when nothing else", []netip.Addr{tentative, deprecated, translated}, "2001:db8:1::9", deprecated},
		{"never tentative or CLAT46", []netip.Addr{tentative, translated}, "2001:db8:1::9", netip.Addr{}},
		{"unread flags rank as temporary", []netip.Addr{unread, stable}, "2001:db8:1::9", stable},
		{"unread flags before deprecated", []netip.Addr{deprecated, unread}, "2001:db8:1::9", unread},
		{"no unique local to the Internet", []netip.Addr{unique}, "2001:db8:1::9", netip.Addr{}},
		{"unique local to a unique local", []netip.Addr{stable, unique}, "fd00::9", unique},
		{"a global one when no unique local", []netip.Addr{stable}, "fd00::9", stable},
	} {
		if got, _ := pickSource(test.candidates, netip.MustParseAddr(test.destination), read); got != test.want {
			t.Errorf("%s: pickSource() = %v, want %v", test.name, got, test.want)
		}
	}
	ipv4 := netip.MustParseAddr("192.168.1.10")
	if got, ok := pickSource([]netip.Addr{stable, ipv4}, netip.MustParseAddr("203.0.113.1"), read); !ok || got != ipv4 {
		t.Errorf("pickSource() for IPv4 = %v", got)
	}
}

func TestIPv6AddressFlagsReadsTheKernel(t *testing.T) {
	flags, err := ipv6AddressFlags("lo0", netip.MustParseAddr("::1"))
	if err != nil {
		t.Fatalf("ipv6AddressFlags(lo0, ::1) = %v", err)
	}
	if flags&in6IffUnusable != 0 {
		t.Fatalf("::1 flags %#x look unusable", flags)
	}
	if _, err := ipv6AddressFlags("lo0", netip.MustParseAddr("2001:db8::77")); err == nil {
		t.Fatal("an address the interface lacks must fail")
	}
}
