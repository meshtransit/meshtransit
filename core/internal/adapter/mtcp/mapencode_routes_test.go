package mtcp

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// routeSnapshotFixture is the map of Device 701, which routes Site "hq"
// (10.20.0.0/16) for Device 702 (tcp/443 to 10.20.5.0/24) and reaches Site
// "lab" (10.30.0.0/16, ICMP) through Device 703.
func routeSnapshotFixture(t *testing.T) mapsession.Snapshot {
	t.Helper()
	scope := snapshotFixture(t, 1).Scope()
	now := time.Date(2026, time.September, 14, 4, 0, 0, 0, time.UTC)
	ids := map[int64]node.ID{}
	var devices []mapsession.PolicyDevice
	for _, device := range []int64{701, 702, 703} {
		ids[device] = must(node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", device)))
		devices = append(devices, mapsession.PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: now.Add(time.Hour)})
	}
	https := must(policy.NewPortRange(443, 443))
	networkPolicy := must(mapsession.NewNetworkPolicy(mapsession.NetworkPolicyParams{
		Scope: scope, Revision: 5, ReleaseActive: true, Devices: devices,
		Members:       []mapsession.SelectorMember{{Kind: mapsession.SelectorDeviceGroup, Selector: 10, Device: 702}},
		RouteRevision: 9, RoutePeerLimit: 10_000,
		Sites: []mapsession.RouteSite{
			{Site: 1, Ref: "hq", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Masquerade: true,
				Probes: []mapsession.RouteProbe{{Address: netip.MustParseAddr("10.20.0.1"), TCP: true, Port: 22}}},
			{Site: 2, Ref: "lab", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}},
		},
		RouteRouters: []mapsession.RouteRouter{
			{Site: 1, Device: 701, NodeID: ids[701], Active: true, WorkspaceOwned: true,
				Offered: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}},
			{Site: 2, Device: 703, NodeID: ids[703], Active: true, WorkspaceOwned: true,
				Offered: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}},
		},
		RouteRules: []mapsession.RouteRule{
			{ID: must(policy.ParseRuleID("01890f00-0000-7000-8000-000000000901")), SourceKind: mapsession.SelectorDeviceGroup,
				SourceRef: 10, Site: 1, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.5.0/24")},
				Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{https}},
			{ID: must(policy.ParseRuleID("01890f00-0000-7000-8000-000000000902")), SourceKind: mapsession.SelectorDevice,
				SourceRef: 701, Site: 2, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
				Protocol: policy.ProtocolICMP},
		},
	}))
	peers := []mapsession.PeerCandidate{
		peerFixture(t, scope, ids[702].String(), 702, "100.64.0.2", 2),
		peerFixture(t, scope, ids[703].String(), 703, "100.64.0.3", 3),
	}
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	return must(mapsession.NewSnapshot(mapsession.SnapshotParams{
		Scope: scope, NetworkName: must(network.ParseDisplayName("Development Mesh")),
		NetworkRevision: 7, RecoveryEpoch: 2, SessionGeneration: 3, NumericNodeID: 701, NumericOwnerID: 11,
		NodeID: ids[701], Hostname: must(node.ParseHostname("node-one.example")),
		DNSLabel: must(node.ParseDNSLabel("node-one")), WorkspaceCode: must(identity.ParseDisplayCode("000000000101")),
		NetworkCode: must(identity.ParseDisplayCode("000000000201")),
		MachineKey:  must(node.NewMachineKey([32]byte{1})), NodeKey: must(node.NewKey([32]byte{1, 2, 3})),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}, CreatedAt: createdAt,
		KeyExpiry: createdAt.Add(24 * time.Hour), PeerCandidates: peers,
		PacketPolicy:   must(policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: 5, Rules: []policy.Rule{}})),
		Routes:         networkPolicy.RoutesFor(ids[701], now),
		RelayDirectory: relayDirectoryFixture(t),
	}))
}

func TestEncodeSnapshotCarriesRoutes(t *testing.T) {
	t.Parallel()
	snapshot := routeSnapshotFixture(t)
	if peers := snapshot.AuthorizedPeers(); len(peers) != 2 {
		t.Fatalf("routes made %d peers, want the consumer and the router", len(peers))
	}
	message, err := encodeSnapshot(snapshot, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	routes := message.GetRoutes().GetSites()
	if len(routes) != 1 || routes[0].GetSiteRef() != "lab" || routes[0].GetStatus() != mtcpv1.SiteRoute_SERVED ||
		routes[0].GetPrimary() != "01890f00-0000-7000-8000-000000000703" || routes[0].GetGeneration() != 9 ||
		!slices.Equal(routes[0].GetCandidates(), []string{"01890f00-0000-7000-8000-000000000703"}) {
		t.Fatalf("routes = %v", message.GetRoutes())
	}
	served := message.GetServed().GetSites()
	if len(served) != 1 || served[0].GetSiteRef() != "hq" || !served[0].GetMasquerade() ||
		len(served[0].GetProbes()) != 1 || served[0].GetProbes()[0].GetKind() != mtcpv1.RouteProbe_TCP ||
		served[0].GetProbes()[0].GetPort() != 22 {
		t.Fatalf("served = %v", message.GetServed())
	}
	want := &mtcpv1.FilterRule{
		Sources: []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.2/32"))},
		Destinations: []*mtcpv1.Destination{{Prefix: sharedmtcp.AppendPrefix(netip.MustParsePrefix("10.20.5.0/24")),
			Ports: []*mtcpv1.PortRange{{First: 443, Last: 443}}}},
		Protocols: []uint32{6},
	}
	if rules := message.GetPacketFilter().GetRules(); len(rules) != 1 || !proto.Equal(rules[0], want) {
		t.Fatalf("filter = %v", message.GetPacketFilter())
	}
	digest, err := PacketFilterDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if expected, grants, err := sharedmtcp.FilterDigest(message.GetPacketFilter()); err != nil ||
		digest.Digest() != expected || digest.Grants() != grants {
		t.Fatalf("digest %v, want %v (%v)", digest.Digest(), expected, err)
	}
}

func TestRoutedDestinationsUseTheFamiliesOfICMP(t *testing.T) {
	t.Parallel()
	destinations, protocols, err := routedDestinations(mapsession.RoutedInbound{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/48"), netip.MustParsePrefix("10.0.0.0/8")},
		Protocol: policy.ProtocolICMP,
	})
	if err != nil || len(destinations) != 2 || !slices.Equal(protocols, []uint32{1, 58}) {
		t.Fatalf("destinations %v, protocols %v, error %v", destinations, protocols, err)
	}
	if _, _, err := routedDestinations(mapsession.RoutedInbound{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Protocol: policy.ProtocolTCP,
	}); err == nil {
		t.Fatal("TCP without ports was encoded")
	}
	if encodeRoutes(mapsession.RouteView{}, endpointFilter{}) != nil ||
		encodeServed(mapsession.RouteView{}, endpointFilter{}) != nil {
		t.Fatal("an empty view encoded routes")
	}
}

// A Site prefix holding an address clients dial (the operator's denied
// ranges, a relay) is left out of both maps: a route there would carry a
// client's own Control or relay traffic into the mesh. A Site left with no
// prefix is left out.
func TestEncodeSnapshotLeavesOutPrefixesHoldingDialedAddresses(t *testing.T) {
	t.Parallel()
	snapshot := routeSnapshotFixture(t)
	denied := []netip.Prefix{netip.MustParsePrefix("10.30.7.0/24"), netip.MustParsePrefix("10.20.0.10/32")}
	message, err := encodeSnapshot(snapshot, &mtcpv1.View{Epoch: 1, Seq: 1}, false, denied, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	if message.GetRoutes() != nil || message.GetServed() != nil {
		t.Fatalf("routes = %v, served = %v", message.GetRoutes(), message.GetServed())
	}
	filter := endpointFilter{relays: []netip.Addr{netip.MustParseAddr("10.30.1.1")}}
	for _, test := range []struct {
		prefix string
		want   bool
	}{
		{"10.30.0.0/16", true},
		{"10.30.2.0/24", false},
		{"10.31.0.0/16", false},
	} {
		if got := filter.coversDialed(netip.MustParsePrefix(test.prefix)); got != test.want {
			t.Errorf("coversDialed(%s) = %t", test.prefix, got)
		}
	}
	kept := filter.routable([]netip.Prefix{netip.MustParsePrefix("10.30.0.0/16"), netip.MustParsePrefix("10.31.0.0/16")})
	if !slices.Equal(kept, []netip.Prefix{netip.MustParsePrefix("10.31.0.0/16")}) {
		t.Fatalf("routable() = %v", kept)
	}
}
