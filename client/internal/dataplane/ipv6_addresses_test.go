package dataplane

import (
	"net/netip"
	"slices"
	"testing"
)

func addrs(values ...string) []netip.Addr {
	out := make([]netip.Addr, len(values))
	for i, value := range values {
		out[i] = netip.MustParseAddr(value)
	}
	return out
}

func TestSelectIPv6HostAddresses(t *testing.T) {
	t.Parallel()
	stable := netip.MustParseAddr("2001:db8:1::10")
	temporaryOld := netip.MustParseAddr("2001:db8:1:0:aaaa::1")
	temporaryNew := netip.MustParseAddr("2001:db8:1:0:bbbb::1")
	deprecated := netip.MustParseAddr("2001:db8:2::10")
	tentative := netip.MustParseAddr("2001:db8:3::10")
	local := netip.MustParseAddr("fd12:3456::10")
	states := map[netip.Addr]ipv6AddressState{
		stable:       {preferred: -1},
		temporaryOld: {temporary: true, preferred: 600},
		temporaryNew: {temporary: true, preferred: 80000},
		deprecated:   {unusable: true},
		tentative:    {unusable: true},
	}
	for _, tt := range []struct {
		name  string
		input []netip.Addr
		want  []netip.Addr
	}{
		{
			name:  "stable wins over privacy addresses; unusable ones are dropped",
			input: []netip.Addr{temporaryOld, deprecated, local, stable, temporaryNew, tentative, netip.MustParseAddr("192.168.1.10")},
			want:  addrs("192.168.1.10", "2001:db8:1::10", "fd12:3456::10"),
		},
		{
			name:  "only privacy addresses: the longest-lived one",
			input: []netip.Addr{temporaryOld, temporaryNew},
			want:  []netip.Addr{temporaryNew},
		},
		{
			name:  "unknown state counts as stable and the list is bounded",
			input: addrs("2001:db8:9::5", "2001:db8:9::4", "2001:db8:9::3", "2001:db8:9::2", "2001:db8:9::1", "fd00::1"),
			want:  addrs("2001:db8:9::1", "2001:db8:9::2", "2001:db8:9::3", "2001:db8:9::4"),
		},
	} {
		if got := selectIPv6HostAddresses(tt.input, states); !slices.Equal(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
