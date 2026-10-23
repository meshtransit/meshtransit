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

// exitSnapshotFixture is the map of self in a Network where Devices 701
// (priority 1) and 703 (priority 2) are the exit nodes of pool "p-main",
// and group 10 = {702} may reach the Internet through it over TCP 443.
func exitSnapshotFixture(t *testing.T, self int64) mapsession.Snapshot {
	t.Helper()
	return exitSnapshotFixtureWith(t, self, nil)
}

// exitSnapshotFixtureWith is exitSnapshotFixture with the policy changed
// first.
func exitSnapshotFixtureWith(t *testing.T, self int64, change func(*mapsession.NetworkPolicyParams)) mapsession.Snapshot {
	t.Helper()
	scope := snapshotFixture(t, 1).Scope()
	now := time.Date(2026, time.October, 20, 4, 0, 0, 0, time.UTC)
	ids := map[int64]node.ID{}
	var devices []mapsession.PolicyDevice
	for _, device := range []int64{701, 702, 703} {
		ids[device] = must(node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", device)))
		devices = append(devices, mapsession.PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: now.Add(time.Hour)})
	}
	https := must(policy.NewPortRange(443, 443))
	params := mapsession.NetworkPolicyParams{
		Scope: scope, Revision: 5, ReleaseActive: true, Devices: devices,
		Members:       []mapsession.SelectorMember{{Kind: mapsession.SelectorDeviceGroup, Selector: 10, Device: 702}},
		RouteRevision: 9, RoutePeerLimit: 10_000,
		DNSZones: []mapsession.DNSZone{
			{Zone: 1, Domain: "corp.example", OtherNames: mapsession.DNSOtherForward,
				Resolvers: []mapsession.DNSZoneResolver{{Address: netip.MustParseAddr("9.9.9.9"), Port: 53}}},
			{Zone: 2, Domain: "hr.example", OtherNames: mapsession.DNSOtherForward, Groups: []int64{10},
				Resolvers: []mapsession.DNSZoneResolver{{Address: netip.MustParseAddr("8.8.4.4"), Port: 53}}},
		},
		ExitPools: []mapsession.ExitPool{{Pool: 1, Ref: "p-main", Name: "Main", ConntrackPerConsumer: 4096,
			DNSUpstreams: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			Probes:       []mapsession.ExitProbe{{Address: netip.MustParseAddr("9.9.9.9"), Port: 443}}}},
		ExitNodes: []mapsession.ExitNode{
			{Pool: 1, Device: 701, NodeID: ids[701], Priority: 1, Active: true, WorkspaceOwned: true, Offered: true},
			{Pool: 1, Device: 703, NodeID: ids[703], Priority: 2, Active: true, WorkspaceOwned: true, Offered: true},
		},
		ExitRules: []mapsession.ExitRule{{ID: must(policy.ParseRuleID("01890f00-0000-7000-8000-000000000901")),
			SourceKind: mapsession.SelectorDeviceGroup, SourceRef: 10, Pool: 1, Protocol: policy.ProtocolTCP,
			Ports: []policy.PortRange{https}}},
	}
	if change != nil {
		change(&params)
	}
	networkPolicy := must(mapsession.NewNetworkPolicy(params))
	var peers []mapsession.PeerCandidate
	for _, device := range []int64{701, 702, 703} {
		if device != self {
			peers = append(peers, peerFixture(t, scope, ids[device].String(), device,
				fmt.Sprintf("100.64.0.%d", device-700), byte(device-700))) //nolint:gosec // 1 to 3
		}
	}
	createdAt := time.Date(2026, time.October, 20, 3, 0, 0, 0, time.UTC)
	return must(mapsession.NewSnapshot(mapsession.SnapshotParams{
		Scope: scope, NetworkName: must(network.ParseDisplayName("Development Mesh")),
		NetworkRevision: 7, RecoveryEpoch: 2, SessionGeneration: 3, NumericNodeID: self, NumericOwnerID: 11,
		NodeID: ids[self], Hostname: must(node.ParseHostname("node-one.example")),
		DNSLabel: must(node.ParseDNSLabel("node-one")), WorkspaceCode: must(identity.ParseDisplayCode("000000000101")),
		NetworkCode: must(identity.ParseDisplayCode("000000000201")),
		MachineKey:  must(node.NewMachineKey([32]byte{1})), NodeKey: must(node.NewKey([32]byte{1, 2, 3})),
		Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", self-700))}, CreatedAt: createdAt,
		KeyExpiry: createdAt.Add(24 * time.Hour), PeerCandidates: peers,
		PacketPolicy:   must(policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: 5, Rules: []policy.Rule{}})),
		Routes:         networkPolicy.RoutesFor(ids[self], now),
		RelayDirectory: relayDirectoryFixture(t),
	}))
}

// TestEncodeSnapshotCarriesSpreadExitPools: a spread pool's map says so,
// names the consumer's own exit node as primary, in its own candidate order,
// and marks draining exit nodes.
func TestEncodeSnapshotCarriesSpreadExitPools(t *testing.T) {
	t.Parallel()
	consumer := exitSnapshotFixtureWith(t, 702, func(params *mapsession.NetworkPolicyParams) {
		params.ExitPools[0].Spread, params.ExitPools[0].Serving = true, []int64{703}
		params.ExitNodes[0].Active = false // 701 drains
	})
	message, err := encodeSnapshot(consumer, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	pools := message.GetExits().GetPools()
	if len(pools) != 1 || pools[0].GetMode() != mtcpv1.ExitPool_SPREAD ||
		pools[0].GetPrimary() != "01890f00-0000-7000-8000-000000000703" {
		t.Fatalf("spread exits = %v", message.GetExits())
	}
	candidates := pools[0].GetCandidates()
	if len(candidates) != 2 || !candidates[0].GetDraining() || candidates[1].GetDraining() {
		t.Fatalf("spread candidates = %v", candidates)
	}
	failover, err := encodeSnapshot(exitSnapshotFixture(t, 702), &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil,
		dnsname.Default())
	if err != nil || failover.GetExits().GetPools()[0].GetMode() != mtcpv1.ExitPool_FAILOVER {
		t.Fatalf("failover mode = %v, %v", failover.GetExits(), err)
	}
}

// TestEncodeSnapshotCarriesCaptiveOff: a pool that turns captive portal
// windows off says so in its consumers' maps; others do not.
func TestEncodeSnapshotCarriesCaptiveOff(t *testing.T) {
	t.Parallel()
	consumer := exitSnapshotFixtureWith(t, 702, func(params *mapsession.NetworkPolicyParams) {
		params.ExitPools[0].CaptiveOff = true
	})
	message, err := encodeSnapshot(consumer, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil || !message.GetExits().GetPools()[0].GetCaptiveOff() {
		t.Fatalf("captive off = %v, %v", message.GetExits(), err)
	}
	allowed, err := encodeSnapshot(exitSnapshotFixture(t, 702), &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil,
		dnsname.Default())
	if err != nil || allowed.GetExits().GetPools()[0].GetCaptiveOff() {
		t.Fatalf("captive allowed = %v, %v", allowed.GetExits(), err)
	}
}

func TestEncodeSnapshotCarriesExitPools(t *testing.T) {
	t.Parallel()
	consumer := exitSnapshotFixture(t, 702)
	if peers := consumer.AuthorizedPeers(); len(peers) != 2 {
		t.Fatalf("a consumer's exit nodes made %d peers, want 2", len(peers))
	}
	message, err := encodeSnapshot(consumer, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	pools := message.GetExits().GetPools()
	if len(pools) != 1 || pools[0].GetPoolRef() != "p-main" || pools[0].GetName() != "Main" ||
		pools[0].GetStatus() != mtcpv1.ExitPool_SERVED || pools[0].GetGeneration() != 9 ||
		pools[0].GetPrimary() != "01890f00-0000-7000-8000-000000000701" || len(pools[0].GetCandidates()) != 2 {
		t.Fatalf("exits = %v", message.GetExits())
	}
	first := pools[0].GetCandidates()[0]
	if first.GetDeviceId() != "01890f00-0000-7000-8000-000000000701" ||
		netip.AddrFrom4([4]byte(first.GetDnsIpv4())) != netip.MustParseAddr("100.64.0.1") ||
		first.GetState() != mtcpv1.ExitCandidate_STATE_UNSPECIFIED {
		t.Fatalf("first candidate = %v", first)
	}
	if message.GetServedExits() != nil || len(message.GetPacketFilter().GetRules()) != 0 {
		t.Fatalf("a consumer got served exits %v or filter %v", message.GetServedExits(), message.GetPacketFilter())
	}

	exitNode := exitSnapshotFixture(t, 701)
	message, err = encodeSnapshot(exitNode, &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	if message.GetExits() != nil {
		t.Fatalf("an exit node got its own pool: %v", message.GetExits())
	}
	served := message.GetServedExits().GetPools()
	if len(served) != 1 || served[0].GetPoolRef() != "p-main" || served[0].GetConntrackPerConsumer() != 4096 ||
		served[0].GetSmtpAllowed() || len(served[0].GetProbes()) != 1 || served[0].GetProbes()[0].GetPort() != 443 ||
		len(served[0].GetDnsUpstreams()) != 1 || len(served[0].GetDnsRelayTargets()) != 1 ||
		!slices.Equal(served[0].GetDnsRelayTargets()[0], []byte{9, 9, 9, 9}) {
		t.Fatalf("served exits = %v", message.GetServedExits())
	}
	// A zone sent to some Groups: its resolver for their consumers only.
	scopes := served[0].GetDnsRelayScopes()
	if len(scopes) != 1 || len(scopes[0].GetTargets()) != 1 || !slices.Equal(scopes[0].GetTargets()[0], []byte{8, 8, 4, 4}) ||
		len(scopes[0].GetSources()) != 1 ||
		!proto.Equal(scopes[0].GetSources()[0], sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.2/32"))) {
		t.Fatalf("relay scopes = %v", scopes)
	}
	ports := []*mtcpv1.PortRange{{First: 443, Last: 443}}
	want := &mtcpv1.FilterRule{
		Sources: []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.2/32"))},
		Destinations: []*mtcpv1.Destination{
			{Prefix: sharedmtcp.AppendPrefix(netip.MustParsePrefix("0.0.0.0/0")), Ports: ports},
			{Prefix: sharedmtcp.AppendPrefix(netip.MustParsePrefix("::/0")), Ports: ports},
		},
		Protocols: []uint32{6},
	}
	if rules := served[0].GetRules(); len(rules) != 1 || !proto.Equal(rules[0], want) {
		t.Fatalf("exit rules = %v", served[0].GetRules())
	}
	// Exit rules stay out of the packet filter: 0/0 opens the exit path
	// only, never the node's own addresses.
	if rules := message.GetPacketFilter().GetRules(); len(rules) != 0 {
		t.Fatalf("exit rules reached the packet filter: %v", rules)
	}
	if !slices.ContainsFunc(exitNode.AuthorizedPeers(), func(peer mapsession.PeerCandidate) bool {
		return peer.NodeID().String() == "01890f00-0000-7000-8000-000000000702"
	}) {
		t.Fatal("an exit node's consumer is no peer")
	}
	if encodeExits(routeSnapshotFixture(t)) != nil {
		t.Fatal("a map without pools encoded exits")
	}
	if served, err := encodeServedExits(routeSnapshotFixture(t)); err != nil || served != nil {
		t.Fatalf("a map without a served pool encoded %v, %v", served, err)
	}
}

// A Device of an unmanaged Device Group gets an empty DNS configuration; the
// others keep their zones (DNS design D5b).
func TestEncodeSnapshotLeavesUnmanagedDevicesWithoutDNS(t *testing.T) {
	t.Parallel()
	managed, err := encodeSnapshot(exitSnapshotFixture(t, 702), &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil,
		dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(managed.GetDns().GetRoutes()) < 2 {
		t.Fatalf("managed DNS = %v", managed.GetDns())
	}
	unmanaged, err := encodeSnapshot(exitSnapshotFixtureWith(t, 702, func(params *mapsession.NetworkPolicyParams) {
		params.DNSUnmanagedGroups = []int64{10}
	}), &mtcpv1.View{Epoch: 1, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	if dns := unmanaged.GetDns(); dns == nil || len(dns.GetRoutes()) != 0 || len(dns.GetRecords()) != 0 ||
		len(dns.GetSearchDomains()) != 0 {
		t.Fatalf("unmanaged DNS = %v", dns)
	}
}
