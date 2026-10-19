package networkmap

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestValidateRoutes(t *testing.T) {
	t.Parallel()
	valid := func() []SiteRoute {
		return []SiteRoute{
			{
				Ref: "a", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("2001:db8::/48")},
				Candidates: []string{"r1", "r2"}, Primary: "r1", Generation: 3, Status: RouteServed,
			},
			{
				Ref: "b", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}, Candidates: []string{"r3"},
				Status: RouteUnserved,
			},
		}
	}
	if err := validateRoutes(valid(), "self"); err != nil {
		t.Fatalf("valid routes: %v", err)
	}
	if err := validateRoutes(nil, "self"); err != nil {
		t.Fatalf("no routes: %v", err)
	}
	for name, change := range map[string]func([]SiteRoute) []SiteRoute{
		"out of order":    func(routes []SiteRoute) []SiteRoute { return []SiteRoute{routes[1], routes[0]} },
		"listed twice":    func(routes []SiteRoute) []SiteRoute { routes[1].Ref = "a"; return routes },
		"empty reference": func(routes []SiteRoute) []SiteRoute { routes[0].Ref = ""; return routes },
		"long reference":  func(routes []SiteRoute) []SiteRoute { routes[1].Ref = strings.Repeat("x", 65); return routes },
		"host bits": func(routes []SiteRoute) []SiteRoute {
			routes[1].Prefixes[0] = netip.MustParsePrefix("10.30.0.1/16")
			return routes
		},
		"default route": func(routes []SiteRoute) []SiteRoute {
			routes[1].Prefixes[0] = netip.MustParsePrefix("0.0.0.0/0")
			return routes
		},
		"prefixes unsorted":  func(routes []SiteRoute) []SiteRoute { slices.Reverse(routes[0].Prefixes); return routes },
		"no prefixes":        func(routes []SiteRoute) []SiteRoute { routes[1].Prefixes = nil; return routes },
		"self candidate":     func(routes []SiteRoute) []SiteRoute { routes[1].Candidates = []string{"self"}; return routes },
		"duplicate":          func(routes []SiteRoute) []SiteRoute { routes[0].Candidates = []string{"r1", "r1"}; return routes },
		"primary elsewhere":  func(routes []SiteRoute) []SiteRoute { routes[0].Primary = "r9"; return routes },
		"served unprimaried": func(routes []SiteRoute) []SiteRoute { routes[1].Status = RouteServed; return routes },
		"unknown status":     func(routes []SiteRoute) []SiteRoute { routes[1].Status = RouteStatusUnknown; return routes },
		"IPv4-mapped": func(routes []SiteRoute) []SiteRoute {
			routes[1].Prefixes[0] = netip.MustParsePrefix("::ffff:10.30.0.0/112")
			return routes
		},
	} {
		if err := validateRoutes(change(valid()), "self"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestEffectiveStatusMarksOverlapAsConflict(t *testing.T) {
	t.Parallel()
	routes := []SiteRoute{
		{Ref: "a", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Status: RouteServed},
		{Ref: "b", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Status: RouteServed},
		{Ref: "c", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}, Status: RouteServed},
	}
	if got := EffectiveStatus(routes); !slices.Equal(got, []RouteStatus{RouteConflict, RouteConflict, RouteServed}) {
		t.Fatalf("EffectiveStatus() = %v", got)
	}
}

func TestEffectiveStatusMatchesPairwiseOverlap(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(7, 11)) //nolint:gosec // G404: repeatable test inputs
	octets := [4]byte{0, 1, 2, 3}
	for round := range 200 {
		routes := make([]SiteRoute, 1+random.IntN(12))
		for index := range routes {
			routes[index].Status = RouteServed
			for range 1 + random.IntN(4) {
				bits := 8 + random.IntN(17)
				address := netip.AddrFrom4([4]byte{10, octets[random.IntN(4)], octets[random.IntN(4)], 0})
				routes[index].Prefixes = append(routes[index].Prefixes, netip.PrefixFrom(address, bits).Masked())
			}
		}
		want := make([]RouteStatus, len(routes))
		for index := range routes {
			want[index] = RouteServed
		}
		for first := range routes {
			for second := first + 1; second < len(routes); second++ {
				if overlaps(routes[first].Prefixes, routes[second].Prefixes) {
					want[first], want[second] = RouteConflict, RouteConflict
				}
			}
		}
		if got := EffectiveStatus(routes); !slices.Equal(got, want) {
			t.Fatalf("round %d: EffectiveStatus() = %v, want %v for %+v", round, got, want, routes)
		}
	}
}

// overlaps is the pairwise check EffectiveStatus replaces.
func overlaps(first, second []netip.Prefix) bool {
	return slices.ContainsFunc(first, func(prefix netip.Prefix) bool {
		return slices.ContainsFunc(second, prefix.Overlaps)
	})
}
