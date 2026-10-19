//go:build linux || darwin

package netadmin

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"meshtransit.net/client/internal/routesettings"
)

func TestWithoutLocalConflicts(t *testing.T) {
	t.Parallel()
	local := []localRoute{
		{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Connected: true},
		{Prefix: netip.MustParsePrefix("10.30.5.0/24")},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		{Prefix: netip.MustParsePrefix("fd00:1::/64"), Connected: true},
	}
	tests := []struct {
		route    string
		conflict bool
	}{
		{"192.168.0.0/16", true},   // covers the attached LAN
		{"192.168.1.128/25", true}, // inside the attached LAN
		{"192.168.2.0/24", false},  // beside it
		{"10.30.0.0/16", true},     // a more specific host route inside
		{"10.30.5.0/24", true},     // equal to a route another path already serves
		{"10.20.0.0/16", false},    // only a wider route, such as another VPN's
		{"fd00:1::/48", true},
		{"fd00:2::/64", false},
	}
	for _, test := range tests {
		route := netip.MustParsePrefix(test.route)
		kept, refused := withoutLocalConflicts([]netip.Prefix{route}, local)
		if got := len(refused) == 1; got != test.conflict || len(kept)+len(refused) != 1 {
			t.Errorf("withoutLocalConflicts(%s) kept %v refused %v, want conflict %t", route, kept, refused, test.conflict)
			continue
		}
		if test.conflict && refused[0].Reason != routesettings.ReasonLocalConflict {
			t.Errorf("reason = %q", refused[0].Reason)
		}
	}
}

func TestPinnedResolvers(t *testing.T) {
	t.Parallel()
	routes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00:1::/64")}
	resolvers := []netip.Addr{
		netip.MustParseAddr("10.20.0.53"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("10.20.0.53"),
		netip.MustParseAddr("::ffff:10.20.0.54"), netip.MustParseAddr("fd00:1::53"),
		{},
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.53/32"), netip.MustParsePrefix("10.20.0.54/32"),
		netip.MustParsePrefix("fd00:1::53/128"),
	}
	if got := pinnedResolvers(routes, resolvers); !slices.Equal(got, want) {
		t.Fatalf("pinnedResolvers() = %v, want %v", got, want)
	}
	if got := pinnedResolvers(nil, resolvers); len(got) != 0 {
		t.Fatalf("pinnedResolvers(no routes) = %v", got)
	}
}

func TestReadResolvers(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	first := filepath.Join(directory, "resolv.conf")
	second := filepath.Join(directory, "upstream.conf")
	if err := os.WriteFile(first, []byte("# stub\nnameserver 127.0.0.53\noptions edns0\nsearch lan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("nameserver 10.20.0.53\nnameserver fe80::1%eth0\nnameserver bogus\nnameserver\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readResolvers([]string{first, filepath.Join(directory, "missing"), second})
	want := []netip.Addr{netip.MustParseAddr("10.20.0.53"), netip.MustParseAddr("fe80::1")}
	if !slices.Equal(got, want) {
		t.Fatalf("readResolvers() = %v, want %v", got, want)
	}
}
