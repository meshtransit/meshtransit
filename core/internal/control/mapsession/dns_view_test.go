package mapsession

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

func mustLabel(t *testing.T, value string) node.DNSLabel {
	t.Helper()
	label, err := node.ParseDNSLabel(value)
	if err != nil {
		t.Fatal(err)
	}
	return label
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// namedSnapshot is snapshotFixture with naming facts and one same-Network
// peer (label peer-9) that a rule pairs with self, plus one unpaired
// candidate (label peer-8) the map must not name.
func namedSnapshot(t *testing.T) Snapshot {
	t.Helper()
	base := snapshotFixture(t)
	paired := peerCandidateParamsFixture(t, base, "01890f00-0000-7000-8000-000000000709", 9)
	paired.DNSLabel = mustLabel(t, "peer-9")
	paired.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32"), netip.MustParsePrefix("fd00::9/128")}
	unpaired := peerCandidateParamsFixture(t, base, "01890f00-0000-7000-8000-000000000708", 8)
	unpaired.DNSLabel = mustLabel(t, "peer-8")
	rule := must(policy.NewRule(policy.RuleParams{ID: policyRuleID(t, 1), Scope: base.Scope(),
		SourceNodeID: paired.NodeID, DestinationNodeID: base.NodeID(), Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{must(policy.NewPortRange(22, 22))}}))
	params := base.params()
	params.DNSLabel = mustLabel(t, "node-1")
	params.WorkspaceCode, params.NetworkCode = identity.DisplayCode("000000000101"), identity.DisplayCode("000000000201")
	params.PeerCandidates = []PeerCandidate{must(NewPeerCandidate(paired)), must(NewPeerCandidate(unpaired))}
	params.PacketPolicy = must(policy.NewSnapshot(policy.SnapshotParams{Scope: base.Scope(), Revision: 5,
		Rules: []policy.Rule{rule}}))
	return must(NewSnapshot(params))
}

func TestDNSViewNamesSelfAndSameNetworkPeers(t *testing.T) {
	t.Parallel()
	view, err := namedSnapshot(t).DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	const zone = "000000000101.000000000201.mesh.internal"
	if view.SelfName() != "node-1."+zone || view.SearchDomain() != zone || view.LocalSuffix() != "mesh.internal" {
		t.Fatalf("self %q, search %q, local %q", view.SelfName(), view.SearchDomain(), view.LocalSuffix())
	}
	peer, found := view.PeerName(must(node.ParseID("01890f00-0000-7000-8000-000000000709")))
	if !found || peer != "peer-9."+zone {
		t.Fatalf("peer name = %q, %v", peer, found)
	}
	if _, found := view.PeerName(must(node.ParseID("01890f00-0000-7000-8000-000000000708"))); found {
		t.Fatal("an unauthorized candidate is named")
	}
	records := view.Records()
	want := []DNSRecord{
		{Name: "node-1." + zone, Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
		{Name: "peer-9." + zone, Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr("fd00::9")}},
	}
	if !slices.EqualFunc(records, want, func(left, right DNSRecord) bool {
		return left.Name == right.Name && slices.Equal(left.Addresses, right.Addresses)
	}) {
		t.Fatalf("records = %+v, want %+v", records, want)
	}
	records[0].Addresses[0] = netip.MustParseAddr("192.0.2.1")
	if view.Records()[0].Addresses[0] != want[0].Addresses[0] {
		t.Fatal("records are not caller-owned copies")
	}
}

func TestDNSViewWithoutNamingFactsPublishesNoDeviceNames(t *testing.T) {
	t.Parallel()
	view, err := snapshotFixture(t).DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	if view.SelfName() != "node-1.example" || view.SearchDomain() != "" || len(view.Records()) != 0 {
		t.Fatalf("view = %+v", view)
	}
	if _, err := (Snapshot{}).DNSView(dnsname.Default()); err == nil {
		t.Fatal("an invalid snapshot has a view")
	}
}

func TestDNSViewNamesOtherNetworkPeersOnlyByShare(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := deviceAliasFixture(t)
	name := func(snapshot Snapshot, label string, workspaceCode string) Snapshot {
		params := snapshot.params()
		params.DNSLabel = mustLabel(t, label)
		params.WorkspaceCode, params.NetworkCode = identity.DisplayCode(workspaceCode), identity.DisplayCode("000000000999")
		return must(NewSnapshot(params))
	}
	provider, consumer = name(provider, "provider-host", "000000000101"), name(consumer, "consumer-host", "000000000102")
	access := evidence.Authority.Endpoint.AccessName().String()
	for _, self := range []Snapshot{provider, consumer} {
		projection := must(NewDirectDeviceProjection(deviceAliasProjectionParams(t, self, provider, consumer, evidence)))
		mapped := must(self.WithDirectDeviceProjections([]DirectDeviceProjection{projection}))
		view, err := mapped.DNSView(dnsname.Default())
		if err != nil {
			t.Fatal(err)
		}
		peerName, found := view.PeerName(projection.Peer().NodeID())
		other := "provider-host"
		if self.Scope() == provider.Scope() {
			other = "consumer-host"
		}
		for _, record := range view.Records() {
			if strings.Contains(record.Name, other) {
				t.Fatalf("a record names the other Network's Device: %+v", record)
			}
		}
		if strings.Contains(peerName, "host") || strings.Contains(peerName, projection.Peer().Hostname().String()) {
			t.Fatalf("peer name %q leaks the other Network's names", peerName)
		}
		if self.Scope() == provider.Scope() {
			if !found || !strings.HasSuffix(peerName, ".invalid") || len(view.Records()) != 1 {
				t.Fatalf("provider names its consumer %q with records %+v", peerName, view.Records())
			}
			continue
		}
		wantShare := dnsname.Default().SharedName(access)
		if !found || peerName != wantShare {
			t.Fatalf("consumer names its provider %q, want %q", peerName, wantShare)
		}
		records := view.Records()
		if len(records) != 2 || records[0].Name != "consumer-host.000000000102.000000000999.mesh.internal" ||
			records[1].Name != wantShare {
			t.Fatalf("consumer records = %+v", records)
		}
	}
}

// TestDNSViewLeavesUnlabeledDevicesUnnamed: a Device of the Network the
// store gave no label never fails the map; it gets no name or record.
func TestDNSViewLeavesUnlabeledDevicesUnnamed(t *testing.T) {
	t.Parallel()
	named := namedSnapshot(t)
	params := named.params()
	params.DNSLabel = node.DNSLabel{}
	candidates := named.candidates.list()
	unlabeled := candidates[1].params() // peer-9, the authorized one (sorted by ID)
	unlabeled.DNSLabel = node.DNSLabel{}
	params.PeerCandidates = []PeerCandidate{candidates[0], must(NewPeerCandidate(unlabeled))}
	snapshot := must(NewSnapshot(params))
	view, err := snapshot.DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := view.PeerName(unlabeled.NodeID)
	if len(view.Records()) != 0 || view.Unnamed() != 2 || view.SelfName() != snapshot.Hostname().String() ||
		peer != unlabeled.Hostname.String() || view.SearchDomain() == "" {
		t.Fatalf("view = %+v, peer %q", view, peer)
	}
}

// TestDNSViewDropsConflictingAndExcessRecords: a name already taken and
// records past MaximumDNSRecords addresses are left out in a fixed order,
// never failing the map.
func TestDNSViewDropsConflictingAndExcessRecords(t *testing.T) {
	t.Parallel()
	address := func(index int) netip.Addr {
		value := netip.MustParseAddr("10.0.0.0")
		for range index {
			value = value.Next()
		}
		return value
	}
	candidates := []DNSRecord{
		{Name: "self.zone", Addresses: []netip.Addr{address(1)}},
		{Name: "db.shared.mesh.internal", Addresses: []netip.Addr{address(2)}},
		{Name: "db.shared.mesh.internal", Addresses: []netip.Addr{address(3)}},
	}
	next := address(10)
	for index := range MaximumDNSRecords - 1 {
		candidates = append(candidates, DNSRecord{Name: "share-" + strconv.Itoa(index), Addresses: []netip.Addr{next}})
		next = next.Next()
	}
	var view DNSView
	view.keep(candidates)
	if len(view.records) != MaximumDNSRecords || view.dropped != 2 ||
		view.records[1].Addresses[0] != address(2) || view.records[len(view.records)-1].Name != "share-49997" {
		t.Fatalf("kept %d records, dropped %d, second %+v, last %+v", len(view.records), view.dropped,
			view.records[1], view.records[len(view.records)-1])
	}
}
