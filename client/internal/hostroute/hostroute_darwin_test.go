package hostroute

import (
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestMaskLength(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		mask       []byte
		bits       int
		want       int
		contiguous bool
	}{
		{[]byte{0, 0, 0, 0}, 32, 0, true},
		{[]byte{255, 255, 128, 0}, 32, 17, true},
		{[]byte{255, 255, 255, 255}, 32, 32, true},
		{[]byte{255, 0, 255, 0}, 32, 0, false},
		{[]byte{254, 1, 0, 0}, 32, 0, false},
		{append([]byte{255, 255, 255, 255, 255, 255, 255, 255}, make([]byte, 8)...), 128, 64, true},
	} {
		got, contiguous := maskLength(test.mask, test.bits)
		if contiguous != test.contiguous || (contiguous && got != test.want) {
			t.Errorf("maskLength(%v) = %d, %t; want %d, %t", test.mask, got, contiguous, test.want, test.contiguous)
		}
	}
}

func message(flags, index int, destination, gateway, mask route.Addr) *route.RouteMessage {
	addresses := []route.Addr{unix.RTAX_DST: destination, unix.RTAX_GATEWAY: gateway}
	if mask != nil {
		addresses = append(addresses, mask)
	}
	return &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET, Flags: flags, Index: index, Addrs: addresses}
}

func v4(a, b, c, d byte) *route.Inet4Addr { return &route.Inet4Addr{IP: [4]byte{a, b, c, d}} }

func TestParseAndPhysical(t *testing.T) {
	t.Parallel()
	up := unix.RTF_UP | unix.RTF_STATIC
	messages := []route.Message{
		// default via 192.168.35.1 on en0 (index 14)
		message(up|unix.RTF_GATEWAY, 14, v4(0, 0, 0, 0), v4(192, 168, 35, 1), v4(0, 0, 0, 0)),
		// attached 192.168.35.0/24
		message(up, 14, v4(192, 168, 35, 0), &route.LinkAddr{Index: 14}, v4(255, 255, 255, 0)),
		// cloned host entry, ignored
		message(up|unix.RTF_HOST|unix.RTF_LLINFO|unix.RTF_WASCLONED, 14, v4(192, 168, 35, 7), &route.LinkAddr{Index: 14}, nil),
		// a subnet route meshnetd installed on utun (index 30)
		message(up|Mark, 30, v4(10, 35, 0, 0), &route.LinkAddr{Index: 30}, v4(255, 255, 128, 0)),
		// a scoped default on another interface, ignored
		message(up|unix.RTF_GATEWAY|unix.RTF_IFSCOPE, 15, v4(0, 0, 0, 0), v4(172, 16, 0, 1), v4(0, 0, 0, 0)),
	}
	table := Parse(messages)
	if len(table) != len(messages) {
		t.Fatalf("Parse() kept %d routes, want %d", len(table), len(messages))
	}
	if table[3].Prefix != netip.MustParsePrefix("10.35.0.0/17") || !table[3].Owned() {
		t.Fatalf("subnet route parsed as %+v", table[3])
	}
	if table[2].Prefix != netip.MustParsePrefix("192.168.35.7/32") || !table[2].Cloned() || table[2].Owned() {
		t.Fatalf("cloned route parsed as %+v", table[2])
	}

	path, found := Physical(table, nil, netip.MustParseAddr("10.35.0.4"))
	if !found || path.Index != 14 || path.Prefix.Bits() != 0 {
		t.Fatalf("Physical(10.35.0.4) = %+v, %t; want the default route on en0", path, found)
	}
	path, found = Physical(table, nil, netip.MustParseAddr("192.168.35.7"))
	if !found || path.Prefix != netip.MustParsePrefix("192.168.35.0/24") {
		t.Fatalf("Physical(192.168.35.7) = %+v, %t; want the attached network", path, found)
	}
	if links := MeshLinks(table); len(links) != 1 || links[0] != 30 {
		t.Fatalf("MeshLinks() = %v, want [30]", links)
	}
	if _, found := Physical(table, []int{14}, netip.MustParseAddr("10.35.0.4")); found {
		t.Fatal("Physical() skipping en0 still found a route")
	}
}

// The host's own table parses without root.
func TestReadHostTable(t *testing.T) {
	t.Parallel()
	table, err := Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if _, found := Physical(table, nil, netip.MustParseAddr("127.0.0.1")); !found {
		t.Fatal("no route to 127.0.0.1 in the host table")
	}
}

// A default route on the mesh utun (an exit node) never wins: the socket
// would be bound into the mesh.
func TestPhysicalSkipsMeshDefault(t *testing.T) {
	t.Parallel()
	up := unix.RTF_UP | unix.RTF_STATIC
	table := Parse([]route.Message{
		message(up|unix.RTF_GATEWAY, 14, v4(0, 0, 0, 0), v4(192, 168, 35, 1), v4(0, 0, 0, 0)),
		message(up, 30, v4(0, 0, 0, 0), &route.LinkAddr{Index: 30}, v4(128, 0, 0, 0)),
		message(up|Mark, 30, v4(10, 35, 0, 0), &route.LinkAddr{Index: 30}, v4(255, 255, 128, 0)),
	})
	path, found := Physical(table, MeshLinks(table), netip.MustParseAddr("10.35.0.4"))
	if !found || path.Index != 14 {
		t.Fatalf("Physical() = %+v, %t; want en0", path, found)
	}
}

func TestSameGateway(t *testing.T) {
	t.Parallel()
	if !SameGateway(v4(192, 168, 1, 1), v4(192, 168, 1, 1)) || SameGateway(v4(192, 168, 1, 1), v4(192, 168, 1, 2)) ||
		SameGateway(v4(192, 168, 1, 1), &route.LinkAddr{Index: 4}) ||
		!SameGateway(&route.LinkAddr{Index: 4}, &route.LinkAddr{Index: 4}) ||
		SameGateway(&route.Inet6Addr{ZoneID: 4}, &route.Inet6Addr{ZoneID: 5}) {
		t.Fatal("SameGateway() compared wrongly")
	}
}
