package networkmap

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestValidateAndClone(t *testing.T) {
	t.Parallel()

	snapshot := validSnapshot()
	snapshot.Peers[0].AllowedIPs = append(
		snapshot.Peers[0].AllowedIPs,
		netip.MustParsePrefix("100.64.1.0/24"),
		netip.MustParsePrefix("fd00:1::/64"),
	)
	validated, err := ValidateAndClone(snapshot, time.Now())
	if err != nil {
		t.Fatalf("ValidateAndClone() error = %v", err)
	}

	snapshot.Peers[0].Addresses[0] = netip.MustParsePrefix("100.64.0.99/32")
	snapshot.Policy[0].Sources[0].Kind = "corrupted"
	snapshot.Relays[1] = RelayRegion{ID: 1}
	snapshot.DNS.Routes[0].Resolvers = append(
		snapshot.DNS.Routes[0].Resolvers,
		DNSResolver{Address: netip.MustParseAddrPort("9.9.9.9:53")},
	)
	snapshot.DNS.Records[0].Name = "corrupted.example.mesh"
	if got := validated.Peers[0].Addresses[0]; got != netip.MustParsePrefix("100.64.0.2/32") {
		t.Fatalf("validated peer address changed through caller alias: %s", got)
	}
	if got := validated.Policy[0].Sources[0].Kind; got != SelectorPrefix {
		t.Fatalf("validated policy changed through caller alias: %s", got)
	}
	if got := len(validated.Relays[1].Nodes); got != 1 {
		t.Fatalf("validated relay nodes changed through caller alias: %d", got)
	}
	if got := len(validated.DNS.Routes[0].Resolvers); got != 0 {
		t.Fatalf("validated dns route changed through caller alias: %d resolvers", got)
	}
	if got := validated.DNS.Records[0].Name; got != "service.example.mesh" {
		t.Fatalf("validated dns record changed through caller alias: %q", got)
	}
}

func TestValidateAndClone_RejectsUnsafeSnapshots(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{
			name: "unauthorized self",
			mutate: func(snapshot *Snapshot) {
				snapshot.Self.MachineAuthorized = false
			},
		},
		{
			name: "expired self",
			mutate: func(snapshot *Snapshot) {
				snapshot.Self.KeyExpiry = time.Now().Add(-time.Minute)
			},
		},
		{
			name: "explicitly expired self",
			mutate: func(snapshot *Snapshot) {
				snapshot.Self.Expired = true
			},
		},
		{
			name: "peer address outside the overlay frame",
			mutate: func(snapshot *Snapshot) {
				lan := netip.MustParsePrefix("192.168.1.20/32")
				snapshot.Peers[0].Addresses = []netip.Prefix{lan}
				snapshot.Peers[0].AllowedIPs = []netip.Prefix{lan}
			},
		},
		{
			name: "peer allowed prefix outside the overlay frame",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].AllowedIPs = append(snapshot.Peers[0].AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
			},
		},
		{
			name: "peer allowed prefix wider than the overlay frame",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].AllowedIPs = append(snapshot.Peers[0].AllowedIPs, netip.MustParsePrefix("100.0.0.0/8"))
			},
		},
		{
			name: "self address outside the overlay frame",
			mutate: func(snapshot *Snapshot) {
				public := netip.MustParsePrefix("203.0.113.7/32")
				snapshot.Self.Addresses = []netip.Prefix{public}
				snapshot.Self.AllowedIPs = []netip.Prefix{public}
			},
		},
		{
			name: "duplicate peer address",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].Addresses = append([]netip.Prefix(nil), snapshot.Self.Addresses...)
				snapshot.Peers[0].AllowedIPs = append([]netip.Prefix(nil), snapshot.Self.Addresses...)
			},
		},
		{
			name: "unallowed direct address",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
			},
		},
		{
			name: "unspecified endpoint",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:443")}
			},
		},
		{
			name: "loopback endpoint",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:443")}
			},
		},
		{
			name: "capability control character",
			mutate: func(snapshot *Snapshot) {
				snapshot.Policy[0].Sources[0] = Selector{
					Kind:       SelectorCapability,
					Capability: "admin\x00role",
				}
			},
		},
		{
			name: "capability destination",
			mutate: func(snapshot *Snapshot) {
				snapshot.Policy[0].Destinations[0].Selector = Selector{
					Kind:       SelectorCapability,
					Capability: "example:cap",
				}
			},
		},
		{
			name: "relay id mismatch",
			mutate: func(snapshot *Snapshot) {
				region := snapshot.Relays[1]
				region.ID = 2
				snapshot.Relays[1] = region
			},
		},
		{
			name: "relay ip family mismatch",
			mutate: func(snapshot *Snapshot) {
				region := snapshot.Relays[1]
				region.Nodes[0].IPv4 = "2001:db8::1"
				snapshot.Relays[1] = region
			},
		},
		{
			name: "relay link local ip",
			mutate: func(snapshot *Snapshot) {
				region := snapshot.Relays[1]
				region.Nodes[0].IPv6 = "fe80::1"
				snapshot.Relays[1] = region
			},
		},
		{
			name: "peer mapped endpoint",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].Endpoints = []netip.AddrPort{
					netip.MustParseAddrPort("[::ffff:192.0.2.10]:41641"),
				}
			},
		},
		{
			name: "peer link local endpoint",
			mutate: func(snapshot *Snapshot) {
				snapshot.Peers[0].Endpoints = []netip.AddrPort{
					netip.MustParseAddrPort("169.254.1.1:41641"),
				}
			},
		},
		{
			name: "peer duplicate endpoint",
			mutate: func(snapshot *Snapshot) {
				endpoint := netip.MustParseAddrPort("192.0.2.10:41641")
				snapshot.Peers[0].Endpoints = []netip.AddrPort{endpoint, endpoint}
			},
		},
		{
			name: "loopback dns resolver",
			mutate: func(snapshot *Snapshot) {
				snapshot.DNS.FallbackResolvers[0].Address = netip.MustParseAddrPort("127.0.0.1:53")
			},
		},
		{
			name: "nonstandard dns resolver port",
			mutate: func(snapshot *Snapshot) {
				snapshot.DNS.FallbackResolvers[0].Address = netip.MustParseAddrPort("1.1.1.1:5353")
			},
		},
		{
			name: "duplicate dns route",
			mutate: func(snapshot *Snapshot) {
				snapshot.DNS.Routes = append(snapshot.DNS.Routes, snapshot.DNS.Routes[0])
			},
		},
		{
			name: "noncanonical dns route",
			mutate: func(snapshot *Snapshot) {
				snapshot.DNS.Routes[0].Suffix = "Example.Mesh"
			},
		},
		{
			name: "dns record type mismatch",
			mutate: func(snapshot *Snapshot) {
				snapshot.DNS.Records[0].Type = DNSRecordAAAA
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			snapshot := validSnapshot()
			test.mutate(&snapshot)
			if _, err := ValidateAndClone(snapshot, time.Now()); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ValidateAndClone() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func validSnapshot() Snapshot {
	selfAddress := netip.MustParsePrefix("100.64.0.1/32")
	peerAddress := netip.MustParsePrefix("100.64.0.2/32")

	return Snapshot{
		Revision:    1,
		NetworkName: "example.mesh",
		Self: Node{
			ID:                1,
			StableID:          "self-stable-id",
			Name:              "self.example.mesh.",
			PublicKey:         "nodekey:0101010101010101010101010101010101010101010101010101010101010101",
			DiscoveryKey:      "discokey:0101010101010101010101010101010101010101010101010101010101010101",
			Addresses:         []netip.Prefix{selfAddress},
			AllowedIPs:        []netip.Prefix{selfAddress},
			MachineAuthorized: true,
		},
		Peers: []Node{{
			ID:                2,
			StableID:          "peer-stable-id",
			Name:              "peer.example.mesh.",
			PublicKey:         "nodekey:0202020202020202020202020202020202020202020202020202020202020202",
			DiscoveryKey:      "discokey:0202020202020202020202020202020202020202020202020202020202020202",
			Addresses:         []netip.Prefix{peerAddress},
			AllowedIPs:        []netip.Prefix{peerAddress},
			MachineAuthorized: true,
		}},
		Policy: []Rule{{
			Sources: []Selector{{Kind: SelectorPrefix, Prefix: peerAddress}},
			Destinations: []Destination{{
				Selector: Selector{Kind: SelectorPrefix, Prefix: selfAddress},
				PortFrom: 22,
				PortTo:   22,
			}},
			Protocols: []uint8{6},
		}},
		Relays: map[int]RelayRegion{
			1: {
				ID:   1,
				Code: "sgp",
				Name: "Singapore",
				Nodes: []RelayNode{{
					Name:      "1a",
					HostName:  "relay.example.com",
					STUNPort:  3478,
					RelayPort: 443,
				}},
			},
		},
		DNS: &DNSConfig{
			FallbackResolvers: []DNSResolver{{
				Address: netip.MustParseAddrPort("1.1.1.1:53"),
			}},
			Routes: []DNSRoute{
				{Suffix: "example.mesh", Resolvers: []DNSResolver{}},
				{Suffix: "64.100.in-addr.arpa", Resolvers: []DNSResolver{}},
			},
			SearchDomains: []string{"example.mesh"},
			Records: []DNSRecord{{
				Name:    "service.example.mesh",
				Type:    DNSRecordA,
				Address: netip.MustParseAddr("100.64.0.10"),
			}},
		},
	}
}

// TestValidateAndClone_BoundsDNSRecords: a map carries at most 50,000 address
// records (mtcp-v1 §7.3): an A and an AAAA record for self and 10,000 peers
// plus 10,000 shares fit.
func TestValidateAndClone_BoundsDNSRecords(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		count int
		valid bool
	}{{count: 50_000, valid: true}, {count: 50_001}} {
		snapshot := validSnapshot()
		records := make([]DNSRecord, test.count)
		for index := range records {
			address := [16]byte{0: 0xfd, 13: byte(index >> 16), 14: byte(index >> 8), 15: byte(index)}
			records[index] = DNSRecord{
				Name: "service.example.mesh", Type: DNSRecordAAAA,
				Address: netip.AddrFrom16(address),
			}
		}
		snapshot.DNS.Records = records
		_, err := ValidateAndClone(snapshot, time.Now())
		if (err == nil) != test.valid {
			t.Fatalf("%d records: error = %v, valid %v", test.count, err, test.valid)
		}
	}
}
