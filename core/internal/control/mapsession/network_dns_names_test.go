package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/node"
)

// newDNSNamesFixture adds to dnsFixture zone 902 corp.lan, nxdomain, sent to
// every Device, and zone 903 corp.com, host, sent to group 10, with names:
//   - git.corp.lan -> Device 7 (group 10 reaches it over UDP 5335);
//   - nas.corp.lan -> Device 8 (Device 4 over UDP, group 10 over TCP);
//   - one.corp.lan -> Device 1 (no rule reaches it but its own);
//   - four.corp.lan -> Device 4 (Device 8 is reached by it, never reaches it);
//   - printer.corp.lan -> 10.0.5.20;
//   - wiki.corp.lan CNAME git.corp.lan, docs.corp.lan CNAME wiki.corp.lan,
//     help.corp.lan CNAME support.example.com;
//   - www.corp.com -> 192.0.2.80.
func newDNSNamesFixture(t *testing.T) *dnsFixture {
	t.Helper()
	fixture := newDNSFixture(t)
	ids := fixture.ids
	fixture.params.DNSZones = append(fixture.params.DNSZones,
		DNSZone{Zone: 902, Domain: "corp.lan", OtherNames: DNSOtherNXDomain, FailOpen: true},
		DNSZone{Zone: 903, Domain: "corp.com", OtherNames: DNSOtherHost, FailOpen: true, Groups: []int64{10}})
	device := func(fqdn string, ref int64) DNSName {
		return DNSName{Zone: 902, FQDN: fqdn, Device: ref, NodeID: ids[ref]}
	}
	fixture.params.DNSNames = []DNSName{
		device("git.corp.lan", 7), device("nas.corp.lan", 8), device("one.corp.lan", 1), device("four.corp.lan", 4),
		{Zone: 902, FQDN: "printer.corp.lan", Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.20")}},
		{Zone: 902, FQDN: "wiki.corp.lan", CNAME: "git.corp.lan"},
		{Zone: 902, FQDN: "docs.corp.lan", CNAME: "wiki.corp.lan"},
		{Zone: 902, FQDN: "help.corp.lan", CNAME: "support.example.com"},
		{Zone: 903, FQDN: "www.corp.com", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.80")}},
	}
	return fixture
}

func nameList(names []DNSNameRoute) []string {
	fqdns := make([]string, 0, len(names))
	for _, name := range names {
		fqdns = append(fqdns, name.FQDN)
	}
	return fqdns
}

func TestRoutesForDNSNames(t *testing.T) {
	t.Parallel()
	fixture := newDNSNamesFixture(t)
	ids := fixture.ids
	networkPolicy := fixture.policy(t)

	// A member of group 10 reaches Devices 7 and 8: their names, the CNAME
	// chain to git, its own name; both new zones with their kinds.
	member := networkPolicy.RoutesFor(ids[1], policyNow)
	if names := nameList(member.DNSNames()); !slices.Equal(names, []string{"docs.corp.lan", "git.corp.lan",
		"help.corp.lan", "nas.corp.lan", "one.corp.lan", "printer.corp.lan", "wiki.corp.lan", "www.corp.com"}) {
		t.Fatalf("member names = %v", names)
	}
	if targets := member.NameTargets(); !slices.Equal(targets, sortedIDs(ids[7], ids[8])) {
		t.Fatalf("member name targets = %v", targets)
	}
	kinds := map[string]DNSOtherNames{}
	for _, zone := range member.DNSZones() {
		kinds[zone.Domain] = zone.OtherNames
	}
	if kinds["corp.lan"] != DNSOtherNXDomain || kinds["corp.com"] != DNSOtherHost ||
		kinds["corp.internal"] != DNSOtherForward {
		t.Fatalf("member zone kinds = %v", kinds)
	}
	// Device 4 reaches only Device 8: git and the CNAMEs that end at it are
	// hidden, and corp.com is not sent to it.
	if names := nameList(networkPolicy.RoutesFor(ids[4], policyNow).DNSNames()); !slices.Equal(names,
		[]string{"four.corp.lan", "help.corp.lan", "nas.corp.lan", "printer.corp.lan"}) {
		t.Fatalf("Device 4 names = %v", names)
	}
	// Device 8 is reached by Device 4 but reaches nothing: a rule the other
	// way is not enough.
	if names := nameList(networkPolicy.RoutesFor(ids[8], policyNow).DNSNames()); !slices.Equal(names,
		[]string{"help.corp.lan", "nas.corp.lan", "printer.corp.lan"}) {
		t.Fatalf("Device 8 names = %v", names)
	}
	// Without dns.records1: no names, forward zones only.
	stripped := member.ForCapabilities(RouteCapabilities{DNSForward: true})
	if len(stripped.DNSNames()) != 0 || len(stripped.NameTargets()) != 0 || len(stripped.DNSZones()) != 2 {
		t.Fatalf("without dns.records1 = %+v", stripped.DNSZones())
	}
	if !member.ForCapabilities(RouteCapabilities{DNSForward: true, DNSRecords: true}).Equal(member) ||
		!networkPolicy.Equal(newDNSNamesFixture(t).policy(t)) {
		t.Fatal("views or policies with names compare wrongly")
	}
}

func TestRoutesForDNSNamesFollowTime(t *testing.T) {
	t.Parallel()
	ids := newDNSNamesFixture(t).ids
	names := func(t *testing.T, self int64, change func(*NetworkPolicyParams)) []string {
		t.Helper()
		fixture := newDNSNamesFixture(t)
		change(&fixture.params)
		return nameList(fixture.policy(t).RoutesFor(ids[self], policyNow).DNSNames())
	}
	// Device 2's membership of group 10 lapsed: it reaches neither 7 nor 8,
	// and corp.com is no longer sent to it.
	lapsed := names(t, 2, func(params *NetworkPolicyParams) {
		params.Members[1].ValidUntil = policyNow.Add(-time.Minute)
	})
	if !slices.Equal(lapsed, []string{"help.corp.lan", "printer.corp.lan"}) {
		t.Errorf("lapsed member names = %v", lapsed)
	}
	// Device 7 is offline: its name goes.
	if offline := names(t, 1, func(params *NetworkPolicyParams) { params.Devices[6].ExpiresAt = policyNow }); slices.Contains(offline, "git.corp.lan") || slices.Contains(offline, "wiki.corp.lan") {
		t.Errorf("an offline target's names = %v", offline)
	}
	// A target Device that is gone answers nothing.
	gone := names(t, 1, func(params *NetworkPolicyParams) { params.DNSNames[0].Device = 0 })
	if slices.Contains(gone, "git.corp.lan") {
		t.Errorf("a gone target's name = %v", gone)
	}
}

func TestNewNetworkPolicyRefusesInvalidDNSNames(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*NetworkPolicyParams){
		"unknown zone":    func(params *NetworkPolicyParams) { params.DNSNames[0].Zone = 999 },
		"outside zone":    func(params *NetworkPolicyParams) { params.DNSNames[0].FQDN = "git.corp.internal.lan" },
		"twice":           func(params *NetworkPolicyParams) { params.DNSNames[1].FQDN = params.DNSNames[0].FQDN },
		"two targets":     func(params *NetworkPolicyParams) { params.DNSNames[0].CNAME = "a.example.com" },
		"no target":       func(params *NetworkPolicyParams) { params.DNSNames[4].Addresses = nil },
		"CNAME to itself": func(params *NetworkPolicyParams) { params.DNSNames[5].CNAME = "wiki.corp.lan" },
		"resolvers on a host zone": func(params *NetworkPolicyParams) {
			params.DNSZones[3].Resolvers = params.DNSZones[0].Resolvers
		},
		"no kind": func(params *NetworkPolicyParams) { params.DNSZones[2].OtherNames = DNSOtherUnknown },
	} {
		fixture := newDNSNamesFixture(t)
		change(&fixture.params)
		if _, err := NewNetworkPolicy(fixture.params); !errors.Is(err, ErrInvalidNetworkPolicy) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A limited map keeps the Devices names point at after shares and before
// online peers.
func TestPeerRankKeepsNameTargetsAfterShares(t *testing.T) {
	t.Parallel()
	snapshot := namedSnapshot(t)
	target, _ := node.ParseID("01890f00-0000-7000-8000-000000000709")
	shared := map[node.ID]struct{}{}
	routed := map[node.ID]struct{}{}
	named := map[node.ID]struct{}{target: {}}
	peer := PeerCandidate{nodeID: target}
	if rank := snapshot.peerRank(peer, shared, routed, named); rank != 1 {
		t.Fatalf("a name target ranks %d", rank)
	}
	shared[target] = struct{}{}
	if rank := snapshot.peerRank(peer, shared, routed, named); rank != 0 {
		t.Fatalf("a shared name target ranks %d", rank)
	}
	if rank := snapshot.peerRank(PeerCandidate{}, map[node.ID]struct{}{}, routed, map[node.ID]struct{}{}); rank != 3 {
		t.Fatalf("another offline peer ranks %d", rank)
	}
}

func TestDNSViewAdminNames(t *testing.T) {
	t.Parallel()
	base := namedSnapshot(t)
	peer, _ := node.ParseID("01890f00-0000-7000-8000-000000000709")
	missing, _ := node.ParseID("01890f00-0000-7000-8000-00000000070a")
	params := base.params()
	params.Routes = RouteView{
		nameTable: []DNSNameRoute{
			{FQDN: "gone.corp.lan", NodeID: missing},
			{FQDN: "nas.corp.lan", NodeID: peer},
			{FQDN: "printer.corp.lan", Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.20")}},
			{FQDN: "wiki.corp.lan", CNAME: "corp.atlassian.net"},
		},
		dnsNames:    []int32{0, 1, 2, 3},
		nameTargets: []node.ID{peer, missing},
	}
	view, err := must(NewSnapshot(params)).DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	records := map[string][]netip.Addr{}
	for _, record := range view.Records() {
		records[record.Name] = record.Addresses
	}
	// A name to a Device answers both its mesh addresses.
	if !slices.Equal(records["nas.corp.lan"], []netip.Addr{netip.MustParseAddr("100.64.0.9"),
		netip.MustParseAddr("fd00::9")}) ||
		!slices.Equal(records["printer.corp.lan"], []netip.Addr{netip.MustParseAddr("10.0.5.20")}) ||
		records["gone.corp.lan"] != nil {
		t.Fatalf("records = %v", records)
	}
	if aliases := view.Aliases(); !slices.Equal(aliases, []DNSAlias{{Name: "wiki.corp.lan",
		Target: "corp.atlassian.net"}}) {
		t.Fatalf("aliases = %v", aliases)
	}
	if view.Dropped() < 1 {
		t.Fatalf("a name whose Device the map lacks was not counted as dropped (%d)", view.Dropped())
	}
}
