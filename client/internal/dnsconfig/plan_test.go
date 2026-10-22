package dnsconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"meshtransit.net/client/internal/networkmap"
)

func TestCompileMeshDNSPlan(t *testing.T) {
	t.Parallel()

	snapshot := dnsSnapshot()
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !plan.Enabled || plan.Revision != 7 {
		t.Fatalf("plan state = %#v", plan)
	}
	if len(plan.Hosts) != 3 || plan.Hosts[0].Name != "node-a.example.mesh" ||
		plan.Hosts[1].Name != "node-b.example.mesh" ||
		plan.Hosts[2].Name != "service.example.mesh" {
		t.Fatalf("hosts = %#v", plan.Hosts)
	}
	if len(plan.Hosts[0].Addresses) != 2 || !plan.Hosts[0].Addresses[0].Is4() ||
		!plan.Hosts[0].Addresses[1].Is6() {
		t.Fatalf("node-a addresses = %#v", plan.Hosts[0].Addresses)
	}
	// Every record of the node's own zone answers PTR, the service too.
	if len(plan.Reverse) != 4 || plan.Reverse[0].Address != netip.MustParseAddr("100.64.0.1") ||
		plan.Reverse[0].Name != "node-a.example.mesh" {
		t.Fatalf("reverse = %#v", plan.Reverse)
	}

	snapshot.DNS.Routes[0].Suffix = "mutated.example"
	snapshot.DNS.Records[0].Name = "mutated.example"
	if plan.Routes[1].Suffix != "example.mesh" || plan.Hosts[2].Name != "service.example.mesh" {
		t.Fatalf("compiled plan aliases caller state: %#v", plan)
	}
}

func TestCompileAddsLocalRouteForExtraRecord(t *testing.T) {
	t.Parallel()

	snapshot := dnsSnapshot()
	snapshot.DNS.Records = append(snapshot.DNS.Records, networkmap.DNSRecord{
		Name:    "outside.example.net",
		Type:    networkmap.DNSRecordA,
		Address: netip.MustParseAddr("192.0.2.20"),
	})
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !locallyAuthoritative(plan.Routes, "outside.example.net") {
		t.Fatalf("routes do not cover extra record: %#v", plan.Routes)
	}
}

func TestCompileRejectsAmbiguousOrUnroutedZoneNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*networkmap.Snapshot)
	}{
		{
			name: "duplicate record address",
			mutate: func(snapshot *networkmap.Snapshot) {
				snapshot.DNS.Records = append(snapshot.DNS.Records, snapshot.DNS.Records[0])
			},
		},
		{
			name: "node route forwarded externally",
			mutate: func(snapshot *networkmap.Snapshot) {
				snapshot.DNS.Routes[1].Resolvers = []networkmap.DNSResolver{{
					Address: netip.MustParseAddrPort("1.1.1.1:53"),
				}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			snapshot := dnsSnapshot()
			test.mutate(&snapshot)
			if _, err := Compile(snapshot); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Compile() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCompileWithoutDNS(t *testing.T) {
	t.Parallel()

	plan, err := Compile(networkmap.Snapshot{Revision: 9})
	if err != nil || plan.Enabled || plan.Revision != 9 {
		t.Fatalf("Compile() = %#v, %v", plan, err)
	}
}

func TestCompileDoesNotEnableFallbackOnlyPlan(t *testing.T) {
	t.Parallel()

	snapshot := networkmap.Snapshot{
		Revision: 10,
		DNS: &networkmap.DNSConfig{FallbackResolvers: []networkmap.DNSResolver{{
			Address: netip.MustParseAddrPort("1.1.1.1:53"),
		}}},
	}
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if plan.Enabled {
		t.Fatal("fallback-only plan enabled the local resolver")
	}
	if len(plan.DefaultResolvers) != 0 ||
		len(plan.FallbackResolvers) != 1 ||
		plan.FallbackResolvers[0] != netip.MustParseAddrPort("1.1.1.1:53") {
		t.Fatalf("fallback-only plan = %#v", plan)
	}
}

func dnsSnapshot() networkmap.Snapshot {
	return networkmap.Snapshot{
		Revision: 7,
		Self: networkmap.Node{
			ID:   1,
			Name: "Node-A.Example.Mesh.",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd07:d4de:9d87::1/128"),
			},
		},
		Peers: []networkmap.Node{{
			ID:        2,
			Name:      "node-b.example.mesh.",
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		}},
		DNS: &networkmap.DNSConfig{
			FallbackResolvers: []networkmap.DNSResolver{{
				Address: netip.MustParseAddrPort("1.1.1.1:53"),
			}},
			Routes: []networkmap.DNSRoute{
				{Suffix: "64.100.in-addr.arpa", Resolvers: []networkmap.DNSResolver{}},
				{Suffix: "example.mesh", Resolvers: []networkmap.DNSResolver{}},
			},
			SearchDomains: []string{"example.mesh"},
			Records: []networkmap.DNSRecord{
				{Name: "service.example.mesh", Type: networkmap.DNSRecordA, Address: netip.MustParseAddr("100.64.0.10")},
				{Name: "node-a.example.mesh", Type: networkmap.DNSRecordA, Address: netip.MustParseAddr("100.64.0.1")},
				{
					Name: "node-a.example.mesh", Type: networkmap.DNSRecordAAAA,
					Address: netip.MustParseAddr("fd07:d4de:9d87::1"),
				},
				{Name: "node-b.example.mesh", Type: networkmap.DNSRecordA, Address: netip.MustParseAddr("100.64.0.2")},
			},
		},
	}
}

// Shared names are routed by one shared.mesh route however many there are,
// so a Device importing many shares stays within the host's route limits.
func TestCompileRoutesSharedNamesAsOneZone(t *testing.T) {
	t.Parallel()

	snapshot := dnsSnapshot()
	for index := range 300 {
		snapshot.DNS.Records = append(snapshot.DNS.Records, networkmap.DNSRecord{
			Name:    fmt.Sprintf("share%d.ws01.net01.shared.mesh", index),
			Type:    networkmap.DNSRecordA,
			Address: netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)}),
		})
	}
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	shared := 0
	for _, route := range plan.Routes {
		if dnsSuffixContains(sharedZone, route.Suffix) {
			shared++
			if route.Suffix != sharedZone || len(route.Resolvers) != 0 {
				t.Fatalf("shared route = %#v, want one local %s route", route, sharedZone)
			}
		}
	}
	if shared != 1 {
		t.Fatalf("plan has %d shared routes, want 1: %#v", shared, plan.Routes)
	}
	if !locallyAuthoritative(plan.Routes, "unknown.ws01.net01.shared.mesh") {
		t.Fatal("an unknown shared name would leave the mesh resolver")
	}
}

// A shared.mesh route Core configures itself is kept; names under it need no
// route of their own: the node answers them, and asks the route's resolvers
// for anything else (DNS design D2 §5.2).
func TestCompileKeepsACoreSharedRoute(t *testing.T) {
	t.Parallel()

	snapshot := dnsSnapshot()
	snapshot.DNS.Routes = append(snapshot.DNS.Routes, networkmap.DNSRoute{
		Suffix:    sharedZone,
		Resolvers: []networkmap.DNSResolver{{Address: netip.MustParseAddrPort("192.0.2.53:53")}},
	})
	snapshot.DNS.Records = append(snapshot.DNS.Records, networkmap.DNSRecord{
		Name:    "db.ws01.net01.shared.mesh",
		Type:    networkmap.DNSRecordA,
		Address: netip.MustParseAddr("198.18.0.5"),
	})
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	routes := 0
	for _, route := range plan.Routes {
		if route.Suffix == sharedZone {
			routes++
			if len(route.Resolvers) != 1 {
				t.Fatalf("Core's shared.mesh route lost its resolver: %#v", route)
			}
		}
	}
	if _, found := findHost(plan.Hosts, "db.ws01.net01.shared.mesh"); routes != 1 || !found ||
		hasRouteSuffix(plan.Routes, "db.ws01.net01.shared.mesh") {
		t.Fatalf("routes = %#v", plan.Routes)
	}
}

// coreSnapshot is a map as Core sends it: Device names in the Network's
// zone with their records, the suffix answered locally, the zone searched,
// and share names under shared.<suffix>.
func coreSnapshot() networkmap.Snapshot {
	const zone = "000000000101.000000000201.mesh.internal"
	return networkmap.Snapshot{
		Revision: 11,
		Self: networkmap.Node{
			ID: 1, Name: "laptop." + zone + ".",
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers: []networkmap.Node{
			{ID: 2, Name: "server." + zone + ".", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}},
			{
				ID: 3, Name: "db.000000000301.000000000401.shared.mesh.internal.",
				Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.5/32")},
			},
		},
		DNS: &networkmap.DNSConfig{
			Routes:        []networkmap.DNSRoute{{Suffix: "mesh.internal", Resolvers: []networkmap.DNSResolver{}}},
			SearchDomains: []string{zone},
			Records: []networkmap.DNSRecord{
				{Name: "laptop." + zone, Type: networkmap.DNSRecordA, Address: netip.MustParseAddr("100.64.0.1")},
				{Name: "server." + zone, Type: networkmap.DNSRecordA, Address: netip.MustParseAddr("100.64.0.2")},
				{
					Name: "db.000000000301.000000000401.shared.mesh.internal", Type: networkmap.DNSRecordA,
					Address: netip.MustParseAddr("198.18.0.5"),
				},
			},
		},
	}
}

// TestCompileDerivesPointersFromTheNetworkZone: Core sends no pointer
// records; the node answers PTR for the records of its own Network's zone
// (the zone its own name is in), never for share names.
func TestCompileDerivesPointersFromTheNetworkZone(t *testing.T) {
	t.Parallel()

	plan, err := Compile(coreSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	const zone = "000000000101.000000000201.mesh.internal"
	want := []Reverse{
		{Address: netip.MustParseAddr("100.64.0.1"), Name: "laptop." + zone},
		{Address: netip.MustParseAddr("100.64.0.2"), Name: "server." + zone},
	}
	if len(plan.Reverse) != len(want) || plan.Reverse[0] != want[0] || plan.Reverse[1] != want[1] {
		t.Fatalf("reverse = %#v, want %#v", plan.Reverse, want)
	}
	if !plan.Enabled || len(plan.Routes) != 1 || plan.Routes[0].Suffix != "mesh.internal" ||
		len(plan.Routes[0].Resolvers) != 0 || len(plan.SearchDomains) != 1 || plan.SearchDomains[0] != zone {
		t.Fatalf("plan = %#v", plan)
	}
	for _, name := range []string{"laptop." + zone, "db.000000000301.000000000401.shared.mesh.internal", "unknown." + zone} {
		if !locallyAuthoritative(plan.Routes, name) {
			t.Fatalf("%s would leave the mesh resolver", name)
		}
	}
}

// An older Core's share names under shared.mesh still get their one local
// route next to a current Core's suffix route.
func TestCompileKeepsTheSharedMeshFallbackBesideTheSuffixRoute(t *testing.T) {
	t.Parallel()

	snapshot := coreSnapshot()
	snapshot.DNS.Records = append(snapshot.DNS.Records, networkmap.DNSRecord{
		Name: "old.000000000301.000000000401.shared.mesh", Type: networkmap.DNSRecordA,
		Address: netip.MustParseAddr("198.18.0.6"),
	})
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(plan.Routes) != 2 || plan.Routes[0].Suffix != "mesh.internal" || plan.Routes[1].Suffix != sharedZone ||
		len(plan.Reverse) != 2 {
		t.Fatalf("routes = %#v, reverse = %#v", plan.Routes, plan.Reverse)
	}
}

// A locally answered route for the root or an Internet suffix from control
// would hide names the host resolves elsewhere: it is skipped, not fatal. A
// private single label (an nxdomain zone) is kept.
func TestCompileSkipsLocalRoutesForTheRootAndInternetSuffixes(t *testing.T) {
	t.Parallel()

	snapshot := coreSnapshot()
	snapshot.DNS.Routes = append(snapshot.DNS.Routes,
		networkmap.DNSRoute{Suffix: ".", Resolvers: []networkmap.DNSResolver{}},
		networkmap.DNSRoute{Suffix: "com", Resolvers: []networkmap.DNSResolver{}},
		networkmap.DNSRoute{Suffix: "co.uk", Resolvers: []networkmap.DNSResolver{}},
		networkmap.DNSRoute{Suffix: "lan", Resolvers: []networkmap.DNSResolver{}},
		networkmap.DNSRoute{Suffix: "corp", Resolvers: []networkmap.DNSResolver{{Address: netip.MustParseAddrPort("192.0.2.53:53")}}},
	)
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if plan.IgnoredRoutes != 3 || len(plan.Routes) != 3 || plan.Routes[0].Suffix != "corp" ||
		plan.Routes[1].Suffix != "lan" || !plan.Routes[1].local() ||
		plan.Routes[2].Suffix != "mesh.internal" || locallyAuthoritative(plan.Routes, "www.example.com") {
		t.Fatalf("routes = %#v, ignored %d", plan.Routes, plan.IgnoredRoutes)
	}
}

// A forward zone's route stays even on a single label: one that fails closed
// keeps its route unavailable, so its names never fall to the host's DNS;
// one that fails open with no resolver left, like a zone that leaves its
// names to the host, is not routed to the node at all.
func TestCompileKeepsForwardZoneRoutes(t *testing.T) {
	t.Parallel()

	snapshot := coreSnapshot()
	snapshot.DNS.Routes = append(snapshot.DNS.Routes,
		networkmap.DNSRoute{Suffix: "lab", Unavailable: true},
		networkmap.DNSRoute{Suffix: "open", Unavailable: true, FailOpen: true},
		networkmap.DNSRoute{Suffix: "corp", Resolvers: []networkmap.DNSResolver{
			{Address: netip.MustParseAddrPort("100.64.0.7:5335")},
		}},
	)
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	lab, found := mostSpecificRoute(plan.Routes, "wiki.lab")
	if !found || lab.Suffix != "lab" || !lab.Unavailable || lab.FailOpen || lab.local() ||
		locallyAuthoritative(plan.Routes, "wiki.lab") || plan.IgnoredRoutes != 0 ||
		hasRouteSuffix(plan.Routes, "open") {
		t.Fatalf("routes = %#v, ignored %d", plan.Routes, plan.IgnoredRoutes)
	}
	if cloned := clonePlan(plan); !slices.EqualFunc(cloned.Routes, plan.Routes, func(left, right Route) bool {
		return left.Suffix == right.Suffix && left.Unavailable == right.Unavailable &&
			left.FailOpen == right.FailOpen && slices.Equal(left.Resolvers, right.Resolvers)
	}) {
		t.Fatal("a cloned plan loses route modes")
	}
}
