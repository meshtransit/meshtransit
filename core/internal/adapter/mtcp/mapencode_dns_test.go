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
			{Zone: 1, Domain: "corp.internal", SearchPosition: 1, Resolvers: []mapsession.DNSZoneResolver{
				{Device: 701, NodeID: ids[701], Eligible: true, Port: 5335},
				{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}},
			{Zone: 2, Domain: "lab.lan", FailOpen: true, Resolvers: []mapsession.DNSZoneResolver{
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
