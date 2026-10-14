package mobile

import (
	"net/netip"
	"slices"
	"testing"
)

func prefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for index, value := range values {
		out[index] = netip.MustParsePrefix(value)
	}
	return out
}

func TestStableRoutesWidenOverlayRoutesToTheirBlock(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct{ routes, want []netip.Prefix }{
		"peers of one Network": {
			routes: prefixes("100.64.0.2/32", "100.64.0.9/32", "fd07:d4de:9d87:1::2/128"),
			want:   prefixes("100.64.0.0/16", "fd07:d4de:9d87:1::/64"),
		},
		"a shared Device in another block": {
			routes: prefixes("100.64.0.2/32", "100.65.3.4/32"),
			want:   prefixes("100.64.0.0/15"),
		},
		"wider routes stay": {
			routes: prefixes("100.64.0.0/10"),
			want:   prefixes("100.64.0.0/10"),
		},
		"a LAN or carrier route stays exact": {
			routes: prefixes("10.20.0.5/32", "100.63.255.1/32", "fc00::5/128"),
			want:   prefixes("10.20.0.5/32", "100.63.255.1/32", "fc00::5/128"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := stableRoutes(test.routes); !slices.Equal(got, test.want) {
				t.Fatalf("stableRoutes(%v) = %v, want %v", test.routes, got, test.want)
			}
		})
	}
}
