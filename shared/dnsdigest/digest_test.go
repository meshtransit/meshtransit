package dnsdigest

import (
	"errors"
	"net/netip"
	"testing"
)

func testRoutes() []Route {
	return []Route{
		{Suffix: "073438549244.296056403058.mesh.internal"},
		{Suffix: "corp.internal", FailOpen: true, Resolvers: []Resolver{
			{Address: netip.MustParseAddr("100.64.0.21"), Port: 5335},
			{Address: netip.MustParseAddr("192.0.2.53")},
		}},
		{Suffix: ".", Unavailable: true},
	}
}

// The vector in docs/protocol/dns-digest-v1.md §4.
func TestComputeVector(t *testing.T) {
	t.Parallel()
	digest, routes, err := Compute(testRoutes(), []string{"073438549244.296056403058.mesh.internal", "corp.internal"})
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:e0ade8e76caf31f2f615616fa198aeb45a96511e0161cb2d055923f995c63504"
	if digest.String() != want || routes != 3 {
		t.Fatalf("digest = %s over %d routes, want %s over 3", digest, routes, want)
	}
}

// Route order does not change the digest; resolver order, ports, failure
// modes and search domain order do. Port 0 is 53 and an IPv4-mapped address
// is the IPv4 address.
func TestComputeIsCanonical(t *testing.T) {
	t.Parallel()
	search := []string{"corp.internal"}
	base, _, err := Compute(testRoutes(), search)
	if err != nil {
		t.Fatal(err)
	}
	reversed := testRoutes()
	reversed[0], reversed[2] = reversed[2], reversed[0]
	same := testRoutes()
	same[1].Resolvers[1].Port = 53
	same[1].Resolvers[0].Address = netip.MustParseAddr("::ffff:100.64.0.21")
	for name, routes := range map[string][]Route{"reordered": reversed, "spelled otherwise": same} {
		if digest, _, err := Compute(routes, search); err != nil || digest != base {
			t.Errorf("%s: %s, %v", name, digest, err)
		}
	}
	changes := map[string]func([]Route) ([]Route, []string){
		"resolver order": func(routes []Route) ([]Route, []string) {
			resolvers := routes[1].Resolvers
			resolvers[0], resolvers[1] = resolvers[1], resolvers[0]
			return routes, search
		},
		"port":      func(routes []Route) ([]Route, []string) { routes[1].Resolvers[0].Port = 5336; return routes, search },
		"fail open": func(routes []Route) ([]Route, []string) { routes[1].FailOpen = false; return routes, search },
		"available": func(routes []Route) ([]Route, []string) {
			routes[2].Unavailable = false
			return routes, search
		},
		"search": func(routes []Route) ([]Route, []string) {
			return routes, []string{"corp.internal", "073438549244.296056403058.mesh.internal"}
		},
		"route gone": func(routes []Route) ([]Route, []string) { return routes[:2], search },
	}
	for name, change := range changes {
		routes, domains := change(testRoutes())
		if digest, _, err := Compute(routes, domains); err != nil || digest == base {
			t.Errorf("%s: digest unchanged (%v)", name, err)
		}
	}
}

func TestComputeRefusesWhatItCannotRepresent(t *testing.T) {
	t.Parallel()
	five := make([]Resolver, MaximumResolvers+1)
	for index := range five {
		five[index] = Resolver{Address: netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)})}
	}
	for name, routes := range map[string][]Route{
		"duplicate suffix":        {{Suffix: "corp.internal"}, {Suffix: "corp.internal", FailOpen: true}},
		"upper case":              {{Suffix: "Corp.internal"}},
		"trailing dot":            {{Suffix: "corp.internal."}},
		"empty label":             {{Suffix: "corp..internal"}},
		"unavailable with one":    {{Suffix: "corp", Unavailable: true, Resolvers: five[:1]}},
		"too many resolvers":      {{Suffix: "corp", Resolvers: five}},
		"invalid resolver":        {{Suffix: "corp", Resolvers: []Resolver{{}}}},
		"resolver with a zone id": {{Suffix: "corp", Resolvers: []Resolver{{Address: netip.MustParseAddr("fe80::1%eth0")}}}},
	} {
		if _, _, err := Compute(routes, nil); !errors.Is(err, ErrInvalidRoute) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := Compute(nil, []string{"."}); !errors.Is(err, ErrInvalidRoute) {
		t.Errorf("root as a search domain: %v", err)
	}
	if _, _, err := Compute(make([]Route, MaximumRoutes+1), nil); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too many routes: %v", err)
	}
}

// The empty configuration has a digest of its own, never the zero value.
func TestComputeEmpty(t *testing.T) {
	t.Parallel()
	digest, routes, err := Compute(nil, nil)
	if err != nil || routes != 0 || digest.IsZero() {
		t.Fatalf("empty = %s, %d, %v", digest, routes, err)
	}
}
