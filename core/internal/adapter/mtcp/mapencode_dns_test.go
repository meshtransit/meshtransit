package mtcp

import (
	"net/netip"
	"slices"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// TestEncodeSnapshotCarriesDNSZones: Device 702 asks corp.internal of
// Device 701 on port 5335 (a rule admits UDP to it) and then 1.1.1.1, and
// lab.lan of Device 703, which no rule admits it to: that route is
// unavailable and fails open. corp.internal follows the Network's zone as a
// search domain (mtcp-v1 §7.3).
func TestEncodeSnapshotCarriesDNSZones(t *testing.T) {
	t.Parallel()
	consumer := exitSnapshotFixtureWith(t, 702, func(params *mapsession.NetworkPolicyParams) {
		params.ExitPools, params.ExitNodes, params.ExitRules = nil, nil, nil
		ids := map[int64]node.ID{}
		for _, device := range params.Devices {
			ids[device.Device] = device.NodeID
		}
		params.Rules = []mapsession.NetworkPolicyRule{{
			ID:         must(policy.ParseRuleID("01890f00-0000-7000-8000-000000000902")),
			SourceKind: mapsession.SelectorDevice, SourceRef: 702, DestinationKind: mapsession.SelectorDevice,
			DestinationRef: 701, Protocol: policy.ProtocolUDP,
			Ports: []policy.PortRange{must(policy.NewPortRange(5335, 5335))},
		}}
		params.DNSZones = []mapsession.DNSZone{
			{Zone: 1, Domain: "corp.internal", OtherNames: mapsession.DNSOtherForward, SearchPosition: 1,
				Resolvers: []mapsession.DNSZoneResolver{
					{Device: 701, NodeID: ids[701], Eligible: true, Port: 5335},
					{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}},
			{Zone: 2, Domain: "lab.lan", OtherNames: mapsession.DNSOtherForward, FailOpen: true,
				Resolvers: []mapsession.DNSZoneResolver{
					{Device: 703, NodeID: ids[703], Eligible: true, Port: 53}}},
		}
	})
	message, err := encodeSnapshot(consumer, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	dns := message.GetDns()
	routes := dns.GetRoutes()
	if len(routes) != 3 || routes[0].GetSuffix() != "mesh.internal" || routes[1].GetSuffix() != "corp.internal" ||
		routes[1].GetUnavailable() || routes[1].GetFailOpen() || routes[2].GetSuffix() != "lab.lan" ||
		!routes[2].GetUnavailable() || !routes[2].GetFailOpen() || len(routes[2].GetResolvers()) != 0 {
		t.Fatalf("routes = %v", routes)
	}
	resolvers := routes[1].GetResolvers()
	first, _ := netip.AddrFromSlice(resolvers[0].GetIp())
	second, _ := netip.AddrFromSlice(resolvers[1].GetIp())
	if len(resolvers) != 2 || first != netip.MustParseAddr("100.64.0.1") || resolvers[0].GetPort() != 5335 ||
		second != netip.MustParseAddr("1.1.1.1") || resolvers[1].GetPort() != 0 {
		t.Fatalf("corp.internal resolvers = %v", resolvers)
	}
	if search := dns.GetSearchDomains(); !slices.Equal(search,
		[]string{"000000000101.000000000201.mesh.internal", "corp.internal"}) {
		t.Fatalf("search domains = %v", search)
	}
}

// TestEncodeSnapshotCarriesTheRootZone: the root zone is a route "."
// with its resolvers and failure mode (mtcp-v1 §7.3, dns.root1), never a
// search domain.
func TestEncodeSnapshotCarriesTheRootZone(t *testing.T) {
	t.Parallel()
	consumer := exitSnapshotFixtureWith(t, 702, func(params *mapsession.NetworkPolicyParams) {
		params.ExitPools, params.ExitNodes, params.ExitRules = nil, nil, nil
		params.DNSZones = []mapsession.DNSZone{
			{Zone: 1, Domain: ".", OtherNames: mapsession.DNSOtherForward, FailOpen: true,
				Resolvers: []mapsession.DNSZoneResolver{{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}},
		}
	})
	message, err := encodeSnapshot(consumer, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	dns := message.GetDns()
	routes := dns.GetRoutes()
	if len(routes) != 2 || routes[1].GetSuffix() != "." || routes[1].GetUnavailable() || !routes[1].GetFailOpen() ||
		len(routes[1].GetResolvers()) != 1 || slices.Contains(dns.GetSearchDomains(), ".") {
		t.Fatalf("routes = %v, search domains = %v", routes, dns.GetSearchDomains())
	}
}

// TestEncodeSnapshotCarriesDNSNames: zone corp.lan answers its other names
// NXDOMAIN (the node's own route, as the mesh suffix) and corp.com leaves
// them to the host (unavailable, failing open); a name to the Device itself
// answers its mesh address (a peer's comes from the map's peer, see
// mapsession); a CNAME is a CNAME record (mtcp-v1 §7.3).
func TestEncodeSnapshotCarriesDNSNames(t *testing.T) {
	t.Parallel()
	consumer := exitSnapshotFixtureWith(t, 702, func(params *mapsession.NetworkPolicyParams) {
		params.ExitPools, params.ExitNodes, params.ExitRules = nil, nil, nil
		ids := map[int64]node.ID{}
		for _, device := range params.Devices {
			ids[device.Device] = device.NodeID
		}
		params.Rules = []mapsession.NetworkPolicyRule{{
			ID:         must(policy.ParseRuleID("01890f00-0000-7000-8000-000000000902")),
			SourceKind: mapsession.SelectorDevice, SourceRef: 702, DestinationKind: mapsession.SelectorDevice,
			DestinationRef: 701, Protocol: policy.ProtocolTCP,
			Ports: []policy.PortRange{must(policy.NewPortRange(443, 443))},
		}}
		params.DNSZones = []mapsession.DNSZone{
			{Zone: 1, Domain: "corp.lan", OtherNames: mapsession.DNSOtherNXDomain, FailOpen: true},
			{Zone: 2, Domain: "corp.com", OtherNames: mapsession.DNSOtherHost, FailOpen: true},
		}
		params.DNSNames = []mapsession.DNSName{
			{Zone: 1, FQDN: "git.corp.lan", Device: 702, NodeID: ids[702]},
			{Zone: 2, FQDN: "wiki.corp.com", CNAME: "corp.atlassian.net"},
		}
	})
	message, err := encodeSnapshot(consumer, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	dns := message.GetDns()
	routes := dns.GetRoutes()
	if len(routes) != 3 || routes[1].GetSuffix() != "corp.com" || !routes[1].GetUnavailable() ||
		!routes[1].GetFailOpen() || routes[2].GetSuffix() != "corp.lan" || routes[2].GetUnavailable() ||
		routes[2].GetFailOpen() || len(routes[2].GetResolvers()) != 0 {
		t.Fatalf("routes = %v", routes)
	}
	var git, wiki bool
	for _, record := range dns.GetRecords() {
		switch record.GetName() {
		case "git.corp.lan":
			address, _ := netip.AddrFromSlice(record.GetValue())
			git = git || (record.GetType() == mtcpv1.DnsRecord_A && address == netip.MustParseAddr("100.64.0.2"))
		case "wiki.corp.com":
			wiki = record.GetType() == mtcpv1.DnsRecord_CNAME && record.GetTarget() == "corp.atlassian.net" &&
				len(record.GetValue()) == 0
		}
	}
	if !git || !wiki {
		t.Fatalf("records = %v", dns.GetRecords())
	}
}
