package dnsconfig

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/meshtransit/meshtransit/client/internal/networkmap"
)

func TestCompileMagicDNSPlan(t *testing.T) {
	t.Parallel()

	snapshot := dnsSnapshot()
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !plan.Enabled || !plan.Proxied || plan.Revision != 7 {
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
	if len(plan.Reverse) != 3 || plan.Reverse[0].Address != netip.MustParseAddr("100.64.0.1") {
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

func TestCompileRejectsAmbiguousOrUnroutedNodeNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*networkmap.Snapshot)
	}{
		{
			name: "duplicate node name",
			mutate: func(snapshot *networkmap.Snapshot) {
				snapshot.Peers[0].Name = snapshot.Self.Name
			},
		},
		{
			name: "extra record shadows node",
			mutate: func(snapshot *networkmap.Snapshot) {
				snapshot.DNS.Records[0].Name = "node-a.example.mesh"
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
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
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
			Proxied:       true,
			Records: []networkmap.DNSRecord{{
				Name:    "service.example.mesh",
				Type:    networkmap.DNSRecordA,
				Address: netip.MustParseAddr("100.64.0.10"),
			}},
		},
	}
}
