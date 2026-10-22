package mapsession

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/sharing"
)

func zoneDomains(zones []DNSZoneRoute) []string {
	domains := make([]string, 0, len(zones))
	for _, zone := range zones {
		domains = append(domains, zone.Domain)
	}
	return domains
}

// Service names (DNS design D3 §4): a share name reaches every Device its
// zone is sent to, the map's projection deciding the rest; a CNAME to one
// is hidden with it. A zone kind host whose only name is its apex sends no
// route of its own where another zone the Device receives holds it.
func TestRoutesForShareNamesAndOneNameZones(t *testing.T) {
	t.Parallel()
	fixture := newDNSNamesFixture(t)
	ids := fixture.ids
	app := must(sharing.ParseImportedResourceID("01890f00-0000-7000-8000-00000000b001"))
	public := must(sharing.ParseImportedResourceID("01890f00-0000-7000-8000-00000000b002"))
	vip := must(sharing.ParseImportedResourceID("01890f00-0000-7000-8000-00000000b003"))
	host := func(zone int64, domain string, groups ...int64) DNSZone {
		return DNSZone{Zone: zone, Domain: domain, OtherNames: DNSOtherHost, FailOpen: true, Groups: groups}
	}
	fixture.params.DNSZones = append(fixture.params.DNSZones,
		host(904, "app.corp.lan"),        // one name, under corp.lan: every Device receives both
		host(905, "app.example.org"),     // one name, under no other zone
		host(906, "pair.corp.lan"),       // two names: keeps its route (TD-CORE-83)
		host(907, "shop.corp.com"),       // one name, under corp.com, which only group 10 receives
		host(908, "vip.example.net", 10), // one share name only group 10 receives
	)
	address := []netip.Addr{netip.MustParseAddr("10.0.6.1")}
	fixture.params.DNSNames = append(fixture.params.DNSNames,
		DNSName{Zone: 904, FQDN: "app.corp.lan", Share: app},
		DNSName{Zone: 905, FQDN: "app.example.org", Share: public},
		DNSName{Zone: 906, FQDN: "a.pair.corp.lan", Addresses: address},
		DNSName{Zone: 906, FQDN: "b.pair.corp.lan", Addresses: address},
		DNSName{Zone: 907, FQDN: "shop.corp.com", Addresses: address},
		DNSName{Zone: 908, FQDN: "vip.example.net", Share: vip},
		DNSName{Zone: 902, FQDN: "portal.corp.lan", CNAME: "app.corp.lan"},
		DNSName{Zone: 902, FQDN: "vip.corp.lan", CNAME: "vip.example.net"},
	)
	networkPolicy := fixture.policy(t)

	member := networkPolicy.RoutesFor(ids[1], policyNow)
	if zones := zoneDomains(member.DNSZones()); !slices.Equal(zones, []string{"app.example.org", "corp.com",
		"corp.internal", "corp.lan", "lab.lan", "pair.corp.lan", "vip.example.net"}) {
		t.Fatalf("member zones = %v", zones)
	}
	names := nameList(member.DNSNames())
	for _, want := range []string{"app.corp.lan", "app.example.org", "portal.corp.lan", "shop.corp.com",
		"vip.corp.lan", "vip.example.net"} {
		if !slices.Contains(names, want) {
			t.Errorf("member names %v lack %s", names, want)
		}
	}
	for _, name := range member.DNSNames() {
		if (name.FQDN == "app.corp.lan") != (name.Share == app) || name.Share.IsValid() && name.NodeID.IsValid() {
			t.Errorf("member name %+v", name)
		}
	}
	// A share adds no peer: the projection already holds its provider.
	if targets := member.NameTargets(); !slices.Equal(targets, sortedIDs(ids[7], ids[8])) {
		t.Fatalf("member name targets = %v", targets)
	}

	// Device 4 does not receive corp.com, so shop.corp.com keeps its route;
	// nor vip.example.net, so the CNAME to it is hidden too.
	other := networkPolicy.RoutesFor(ids[4], policyNow)
	if zones := zoneDomains(other.DNSZones()); !slices.Equal(zones, []string{"app.example.org", "corp.lan",
		"lab.lan", "pair.corp.lan", "shop.corp.com"}) {
		t.Fatalf("Device 4 zones = %v", zones)
	}
	names = nameList(other.DNSNames())
	if slices.Contains(names, "vip.example.net") || slices.Contains(names, "vip.corp.lan") ||
		!slices.Contains(names, "app.corp.lan") || !slices.Contains(names, "portal.corp.lan") {
		t.Fatalf("Device 4 names = %v", names)
	}
	if !networkPolicy.Equal(networkPolicy) || networkPolicy.Equal(newDNSNamesFixture(t).policy(t)) {
		t.Fatal("policies with share names compare wrongly")
	}
}

func TestNewNetworkPolicyRefusesInvalidShareNames(t *testing.T) {
	t.Parallel()
	share := must(sharing.ParseImportedResourceID("01890f00-0000-7000-8000-00000000b001"))
	for name, change := range map[string]func(*DNSName){
		"and a Device":    func(value *DNSName) { value.NodeID, value.Device = policyNodeID(t, 7), 7 },
		"and addresses":   func(value *DNSName) { value.Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.1")} },
		"and a CNAME":     func(value *DNSName) { value.CNAME = "a.example.com" },
		"and a gone ref":  func(value *DNSName) { value.Device = 3 },
		"outside a zone":  func(value *DNSName) { value.FQDN = "app.example.org" },
		"in the root one": func(value *DNSName) { value.Zone = 0 },
	} {
		fixture := newDNSNamesFixture(t)
		value := DNSName{Zone: 902, FQDN: "app.corp.lan", Share: share}
		change(&value)
		fixture.params.DNSNames = append(fixture.params.DNSNames, value)
		if _, err := NewNetworkPolicy(fixture.params); !errors.Is(err, ErrInvalidNetworkPolicy) {
			t.Errorf("a share name %s: %v", name, err)
		}
	}
}

// A share name answers the alias of the map's projection of the share, and
// nothing without one; a CNAME whose chain reaches it follows it.
func TestDNSViewShareNamesAnswerTheProjectedAlias(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := deviceAliasFixture(t)
	projection := must(NewDirectDeviceProjection(deviceAliasProjectionParams(t, consumer, provider, consumer, evidence)))
	mapped := must(consumer.WithDirectDeviceProjections([]DirectDeviceProjection{projection}))
	share := evidence.Authority.Contract.ImportedResourceID()
	other := must(sharing.ParseImportedResourceID("01890f00-0000-7000-8000-00000000b009"))
	routes := RouteView{
		nameTable: []DNSNameRoute{
			{FQDN: "app.corp.com", Share: share},
			{FQDN: "docs.corp.com", CNAME: "docs.example.net"},
			{FQDN: "gone.corp.com", Share: other},
			{FQDN: "old.corp.com", CNAME: "gone.corp.com"},
			{FQDN: "stale.corp.com", CNAME: "old.corp.com"},
			{FQDN: "www.corp.com", CNAME: "app.corp.com"},
		},
		dnsNames: []int32{0, 1, 2, 3, 4, 5},
	}
	view := func(t *testing.T, snapshot Snapshot) DNSView {
		t.Helper()
		params := snapshot.params()
		params.Routes = routes
		view, err := must(NewSnapshot(params)).DNSView(dnsname.Default())
		if err != nil {
			t.Fatal(err)
		}
		return view
	}
	names := func(view DNSView) (map[string][]netip.Addr, []string) {
		records := map[string][]netip.Addr{}
		for _, record := range view.Records() {
			records[record.Name] = record.Addresses
		}
		var aliases []string
		for _, alias := range view.Aliases() {
			aliases = append(aliases, alias.Name)
		}
		return records, aliases
	}

	imported := view(t, mapped)
	records, aliases := names(imported)
	if !slices.Equal(records["app.corp.com"], []netip.Addr{netip.MustParseAddr("100.96.0.1"),
		netip.MustParseAddr("fd00:feed::1")}) || records["gone.corp.com"] != nil {
		t.Fatalf("records = %v", records)
	}
	if !slices.Equal(aliases, []string{"docs.corp.com", "www.corp.com"}) {
		t.Fatalf("aliases = %v", aliases)
	}
	// A share the map does not project is no degradation: no rule reaches it.
	if imported.Dropped() != 0 || imported.OverBudget() != 0 {
		t.Fatalf("dropped = %d, over budget = %d", imported.Dropped(), imported.OverBudget())
	}

	// Without the projection (no rule to the share, an ended contract) the
	// share's name and the CNAME to it go.
	records, aliases = names(view(t, consumer))
	if records["app.corp.com"] != nil || !slices.Equal(aliases, []string{"docs.corp.com"}) {
		t.Fatalf("without the projection: records = %v, aliases = %v", records, aliases)
	}
	// The provider's map never answers the consumer's names.
	records, _ = names(view(t, must(provider.WithDirectDeviceProjections([]DirectDeviceProjection{
		must(NewDirectDeviceProjection(deviceAliasProjectionParams(t, provider, provider, consumer, evidence))),
	}))))
	if records["app.corp.com"] != nil {
		t.Fatalf("the provider's map answers a consumer name: %v", records)
	}
}

// clientDNSRoutes.cost follows the client (dnsconfig splitHostZones,
// routeNames, buildResolvedConfig): each case gives the domains the client's
// helper gets.
func TestClientDNSRoutesCost(t *testing.T) {
	t.Parallel()
	many := func(count int, format string) []string {
		values := make([]string, count)
		for index := range values {
			values[index] = fmt.Sprintf(format, index)
		}
		return values
	}
	for name, test := range map[string]struct {
		config clientDNSRoutes
		names  []string
		want   int
	}{
		// corp.com is split: a, b and the name with no zone get routes; the
		// name an nxdomain zone holds inside it costs nothing.
		"split": {clientDNSRoutes{routes: []string{"mesh.internal", "x.corp.com"}, host: []string{"corp.com"}},
			[]string{"a.corp.com", "b.corp.com", "y.x.corp.com", "free.example.org"}, 5},
		// Covered by a route, or a search domain: routed whole, its names
		// cost nothing.
		"covered": {clientDNSRoutes{routes: []string{"mesh.internal", "corp.com"}, host: []string{"app.corp.com"}},
			[]string{"app.corp.com"}, 3},
		"searched": {clientDNSRoutes{routes: []string{"mesh.internal"}, search: []string{"corp.com"},
			host: []string{"corp.com"}}, []string{"a.corp.com", "b.corp.com"}, 2},
		// More names than the client's budget: routed whole.
		"past the client's budget": {clientDNSRoutes{routes: []string{"mesh.internal"}, host: []string{"corp.com"}},
			many(300, "n%d.corp.com"), 2},
		// The client's budget goes negative: every such zone is routed whole,
		// even one whose names the Device does not see.
		"no names, budget gone": {clientDNSRoutes{routes: append([]string{"mesh.internal"}, many(200, "z%d.lan")...),
			search: []string{"net.mesh.internal"}, host: many(55, "h%d.example.org")}, nil, 257},
		"no names, budget left": {clientDNSRoutes{routes: []string{"mesh.internal"},
			host: many(5, "h%d.example.org")}, nil, 1},
	} {
		if got, _ := test.config.cost(test.names); got != test.want {
			t.Errorf("%s: %d domains, want %d", name, got, test.want)
		}
	}
}

// The route budget of one map (DNS design D3 §4.3) keeps what the client
// routes within its helper's bounds, following the client: a zone leaving
// its other names to the host costs one route when the client routes it
// whole, and its names one each when it splits it.
func TestDNSViewKeepsRoutesWithinBudget(t *testing.T) {
	t.Parallel()
	base := namedSnapshot(t)
	view := func(t *testing.T, zones []DNSZoneRoute, table []DNSNameRoute) DNSView {
		t.Helper()
		slices.SortFunc(zones, func(left, right DNSZoneRoute) int { return strings.Compare(left.Domain, right.Domain) })
		slices.SortFunc(table, func(left, right DNSNameRoute) int { return strings.Compare(left.FQDN, right.FQDN) })
		positions := make([]int32, len(table))
		for index := range positions {
			positions[index] = int32(index)
		}
		params := base.params()
		params.Routes = RouteView{dnsZones: zones, nameTable: table, dnsNames: positions}
		view, err := must(NewSnapshot(params)).DNSView(dnsname.Default())
		if err != nil {
			t.Fatal(err)
		}
		return view
	}
	routed := func(view DNSView) (int, int) {
		config := clientDNSRoutes{search: view.SearchDomains()}
		if view.LocalSuffix() != "" {
			config.routes = append(config.routes, view.LocalSuffix())
		}
		for _, zone := range view.Zones() {
			if zone.leavesToHost() {
				config.host = append(config.host, zone.Domain)
			} else {
				config.routes = append(config.routes, zone.Domain)
			}
		}
		var names []string
		for _, record := range view.Records() {
			names = append(names, record.Name)
		}
		for _, alias := range view.Aliases() {
			names = append(names, alias.Name)
		}
		return config.cost(names)
	}
	address := []netip.Addr{netip.MustParseAddr("10.0.6.1")}

	// 200 zones routed whole and 55 host zones whose names the Device does
	// not see: the client routes each host zone whole, 257 domains with the
	// mesh names. The last host zones go.
	var zones []DNSZoneRoute
	for index := range 200 {
		zones = append(zones, DNSZoneRoute{Domain: fmt.Sprintf("z%03d.lan", index), OtherNames: DNSOtherNXDomain})
	}
	for index := range 55 {
		zones = append(zones, DNSZoneRoute{Domain: fmt.Sprintf("h%02d.example.org", index), OtherNames: DNSOtherHost,
			FailOpen: true})
	}
	crowded := view(t, zones, nil)
	if domains, bytes := routed(crowded); domains > maximumDNSRouteDomains || bytes > maximumDNSRouteBytes ||
		crowded.OverBudget() != 257-maximumDNSRouteDomains || len(crowded.Zones()) != 255-crowded.OverBudget() ||
		slices.ContainsFunc(crowded.Zones(), func(zone DNSForwardZone) bool { return zone.Domain == "h54.example.org" }) {
		t.Fatalf("%d domains in %d bytes, %d zones, over budget %d", domains, bytes, len(crowded.Zones()),
			crowded.OverBudget())
	}

	// A forward zone that fails open lost its resolvers and holds 300 names:
	// the client routes it whole, so every name stays.
	var table []DNSNameRoute
	for index := range 300 {
		table = append(table, DNSNameRoute{FQDN: fmt.Sprintf("n%03d.corp.com", index), Addresses: address})
	}
	whole := view(t, []DNSZoneRoute{{Domain: "corp.com", OtherNames: DNSOtherForward, FailOpen: true}}, table)
	if len(whole.Records()) != 2+300 || whole.OverBudget() != 0 {
		t.Fatalf("a zone the client routes whole kept %d records, over budget %d", len(whole.Records()),
			whole.OverBudget())
	}

	// A host zone of 100 long names the client splits: their routes pass
	// the bytes, so the last names by name go, whole; a name an nxdomain
	// zone holds stays.
	label := strings.Repeat("a", 60)
	table = []DNSNameRoute{{FQDN: "x.z.corp.com", Addresses: address}, {FQDN: "w.corp.com", CNAME: "x.z.corp.com"}}
	for index := range 100 {
		table = append(table, DNSNameRoute{FQDN: fmt.Sprintf("%s.%s.%s.n%03d.corp.com", label, label, label, index),
			Addresses: address})
	}
	split := view(t, []DNSZoneRoute{{Domain: "corp.com", OtherNames: DNSOtherHost, FailOpen: true},
		{Domain: "z.corp.com", OtherNames: DNSOtherNXDomain}}, table)
	kept := map[string]bool{}
	for _, record := range split.Records() {
		kept[record.Name] = true
	}
	long := func(index int) string { return fmt.Sprintf("%s.%s.%s.n%03d.corp.com", label, label, label, index) }
	domains, bytes := routed(split)
	// The long names sort first, then w.corp.com: the CNAME is past the
	// budget too.
	if domains > maximumDNSRouteDomains || bytes > maximumDNSRouteBytes || !kept["x.z.corp.com"] ||
		!kept[long(0)] || kept[long(99)] || len(split.Aliases()) != 0 ||
		split.OverBudget() != 100-(len(kept)-3)+1 {
		t.Fatalf("%d domains in %d bytes, over budget %d, kept %d", domains, bytes, split.OverBudget(), len(kept))
	}
	// One more name would not have fitted.
	names := []string{"x.z.corp.com"}
	for index := range len(kept) - 3 + 1 {
		names = append(names, long(index))
	}
	config := clientDNSRoutes{routes: []string{split.LocalSuffix(), "z.corp.com"}, search: split.SearchDomains(),
		host: []string{"corp.com"}}
	if config.fits(names) {
		t.Fatal("the budget left out a name that fits")
	}
}

func TestDNSViewDropsZonesPastTheRouteBudget(t *testing.T) {
	t.Parallel()
	base := namedSnapshot(t)
	label := strings.Repeat("a", 60)
	long := func(index int) string {
		return fmt.Sprintf("%s.%s.%s.z%03d.lan", label, label, label, index)
	}
	var zones []DNSZoneRoute
	for index := range 100 {
		zones = append(zones, DNSZoneRoute{Domain: long(index), OtherNames: DNSOtherNXDomain})
	}
	zones[99].SearchPosition = 1
	address := []netip.Addr{netip.MustParseAddr("10.0.6.1")}
	params := base.params()
	params.Routes = RouteView{dnsZones: zones, nameTable: []DNSNameRoute{
		{FQDN: "www." + long(0), Addresses: address}, {FQDN: "www." + long(99), Addresses: address},
	}, dnsNames: []int32{0, 1}}
	view, err := must(NewSnapshot(params)).DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	bytes := len(view.LocalSuffix())
	for _, domain := range view.SearchDomains() {
		bytes += len(domain)
	}
	for _, zone := range view.Zones() {
		bytes += len(zone.Domain)
	}
	if bytes > maximumDNSRouteBytes || len(view.Zones()) == 100 || len(view.Zones()) < 60 {
		t.Fatalf("%d zones in %d bytes", len(view.Zones()), bytes)
	}
	// The last zone is past the budget: its search domain and its name go
	// with it; the first zone keeps its name.
	if slices.Contains(view.SearchDomains(), long(99)) {
		t.Fatalf("search domains = %v", view.SearchDomains())
	}
	records := map[string]bool{}
	for _, record := range view.Records() {
		records[record.Name] = true
	}
	if !records["www."+long(0)] || records["www."+long(99)] {
		t.Fatalf("records = %v", records)
	}
	if view.OverBudget() != 100-len(view.Zones())+1 {
		t.Fatalf("over budget = %d with %d zones", view.OverBudget(), len(view.Zones()))
	}
}
