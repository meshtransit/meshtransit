package dnsconfig

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/underlay"
)

// The root zone becomes Plan.Root, outside the routes the host routes by
// domain; with it the plan routes every name, unavailable or not, so the
// host sends the resolver every name (DNS design D1b §4).
func TestCompileTakesTheRootZone(t *testing.T) {
	t.Parallel()
	resolver := netip.MustParseAddrPort("100.64.0.21:5335")
	for name, root := range map[string]networkmap.DNSRoute{
		"forwarded":   {Suffix: ".", Resolvers: []networkmap.DNSResolver{{Address: resolver}}, FailOpen: true},
		"unavailable": {Suffix: ".", Resolvers: []networkmap.DNSResolver{}, Unavailable: true},
	} {
		snapshot := dnsSnapshot()
		snapshot.DNS.Routes = append(slices.Clone(snapshot.DNS.Routes), root)
		plan, err := Compile(snapshot)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if plan.Root == nil || plan.Root.Unavailable != root.Unavailable || plan.Root.FailOpen != root.FailOpen ||
			slices.ContainsFunc(plan.Routes, func(route Route) bool { return route.Suffix == "." }) ||
			!plan.RoutesAllNames() || !plan.Enabled || MatchDomains(plan) != nil {
			t.Fatalf("%s: plan %+v", name, plan)
		}
		config, err := buildResolvedConfig(plan, netadmin.DNSEndpoint{})
		if err != nil || !config.DefaultRoute || !slices.Contains(config.RouteDomains, ".") {
			t.Fatalf("%s: host config %+v, %v", name, config, err)
		}
		if cloned := clonePlan(plan); cloned.Root == plan.Root ||
			(len(plan.Root.Resolvers) != 0 && &cloned.Root.Resolvers[0] == &plan.Root.Resolvers[0]) {
			t.Fatalf("%s: clone shares the root", name)
		}
	}
	// A root the node would answer itself hides every name: ignored.
	snapshot := dnsSnapshot()
	snapshot.DNS.Routes = append(slices.Clone(snapshot.DNS.Routes),
		networkmap.DNSRoute{Suffix: ".", Resolvers: []networkmap.DNSResolver{}})
	if plan, err := Compile(snapshot); err != nil || plan.Root != nil || plan.IgnoredRoutes != 1 {
		t.Fatalf("local root: %+v, %v", plan, err)
	}
}

func rootPlan(root Route) Plan {
	return Plan{Enabled: true, Root: &root, Routes: []Route{{Suffix: "corp.internal", Resolvers: []netip.AddrPort{}}}}
}

// Names no route holds go to the root zone's resolvers, which fail as the
// zone says; names a route holds stay with it.
func TestResolverEngineAsksTheRootZone(t *testing.T) {
	t.Parallel()
	root := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.90"), false)
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.91"), false)
	engine := zoneEngine(t, network.address)
	plan := rootPlan(Route{Suffix: ".", Resolvers: []netip.AddrPort{root.address}})
	if got := firstA(t, resolveName(t, engine, plan, "www.example.com.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.90") || network.asked.Load() != 0 {
		t.Fatalf("answer %s, network asked %d", got, network.asked.Load())
	}
	if message := resolveName(t, engine, plan, "nope.corp.internal.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeNameError || root.asked.Load() != 1 {
		t.Fatalf("a name a route holds = %v, root asked %d", message.RCode, root.asked.Load())
	}
	closed := rootPlan(Route{Suffix: ".", Unavailable: true})
	if message := resolveName(t, engine, closed, "www.example.com.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeServerFailure || network.asked.Load() != 0 {
		t.Fatalf("closed, unavailable root = %v, network asked %d", message.RCode, network.asked.Load())
	}
	open := rootPlan(Route{Suffix: ".", Unavailable: true, FailOpen: true})
	if got := firstA(t, resolveName(t, engine, open, "www.example.com.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.91") {
		t.Fatalf("open, unavailable root answered %s", got)
	}
}

// With a root zone the node answers a few names itself, so applications
// keep to it: Firefox's canary, DNS resolver discovery, Private Relay
// (DNS design D1b §5.5).
func TestResolverEngineAnswersItsOwnNamesWithARootZone(t *testing.T) {
	t.Parallel()
	root := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.92"), false)
	engine := zoneEngine(t)
	plan := rootPlan(Route{Suffix: ".", Resolvers: []netip.AddrPort{root.address}})
	for name, want := range map[string]dnsmessage.RCode{
		"use-application-dns.net.": dnsmessage.RCodeNameError, "resolver.arpa.": dnsmessage.RCodeSuccess,
		"_dns.resolver.arpa.": dnsmessage.RCodeSuccess,
		"mask.icloud.com.":    dnsmessage.RCodeNameError, "MASK-H2.icloud.com.": dnsmessage.RCodeNameError,
	} {
		recordType := dnsmessage.TypeA
		if name == "_dns.resolver.arpa." {
			recordType = dnsmessage.TypeSVCB
		}
		message := resolveName(t, engine, plan, name, recordType)
		if message.RCode != want || len(message.Answers) != 0 {
			t.Errorf("%s = %v %v", name, message.RCode, message.Answers)
		}
	}
	if root.asked.Load() != 0 {
		t.Fatalf("the root zone was asked %d times", root.asked.Load())
	}
	// Without a root zone they are ordinary names.
	if message := resolveName(t, engine, Plan{Enabled: true, Root: nil}, "use-application-dns.net.",
		dnsmessage.TypeA); message.RCode == dnsmessage.RCodeNameError {
		t.Fatal("the canary is answered without a root zone")
	}
}

// MeshTransit's own infrastructure is asked of the network, never of the
// root zone, which may filter it (DNS design D1b §5.8): exact names only.
func TestResolverEngineLeavesInfrastructureToTheNetwork(t *testing.T) {
	t.Parallel()
	root := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.93"), false)
	engine := zoneEngine(t, network.address)
	engine.setInfrastructureNames([]string{"Control.MeshTransit.net.", "relay-sgp1.meshtransit.net"})
	plan := rootPlan(Route{Suffix: ".", Resolvers: []netip.AddrPort{root.address}})
	for _, name := range []string{"control.meshtransit.net.", "relay-sgp1.meshtransit.net."} {
		if got := firstA(t, resolveName(t, engine, plan, name, dnsmessage.TypeA)); got != netip.MustParseAddr("192.0.2.93") {
			t.Fatalf("%s answered %s", name, got)
		}
	}
	if root.asked.Load() != 0 {
		t.Fatal("the root zone was asked for infrastructure")
	}
	if message := resolveName(t, engine, plan, "x.control.meshtransit.net.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeRefused || root.asked.Load() != 1 {
		t.Fatalf("a name under the control host = %v", message.RCode)
	}
}

// The reverse names of mesh and private addresses never go to the root
// zone's resolvers or an exit node (DNS design D1b §5.7).
func TestResolverEngineKeepsPrivateReverseNames(t *testing.T) {
	t.Parallel()
	for _, withExit := range []bool{false, true} {
		t.Run(fmt.Sprintf("exit %t", withExit), func(t *testing.T) {
			t.Parallel()
			root := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.94"), false)
			network := startCountingUpstream(t, dnsmessage.RCodeNameError, netip.Addr{}, false)
			exit := startCountingUpstream(t, dnsmessage.RCodeNameError, netip.Addr{}, false)
			engine := zoneEngine(t, network.address)
			plan := rootPlan(Route{Suffix: ".", Resolvers: []netip.AddrPort{root.address}})
			if withExit {
				plan.Exit = &ExitDNS{Resolvers: []netip.AddrPort{exit.address}, IPv6: true}
			}
			for _, name := range []string{"5.1.168.192.in-addr.arpa.", "9.0.64.100.in-addr.arpa."} {
				if message := resolveName(t, engine, plan, name, dnsmessage.TypePTR); message.RCode !=
					dnsmessage.RCodeNameError {
					t.Errorf("%s = %v", name, message.RCode)
				}
			}
			wantNetwork := int32(1)
			if withExit {
				wantNetwork = 0
			}
			if root.asked.Load() != 0 || exit.asked.Load() != 0 || network.asked.Load() != wantNetwork {
				t.Fatalf("root %d, exit %d, network %d", root.asked.Load(), exit.asked.Load(), network.asked.Load())
			}
			// A public address's reverse name is the root zone's.
			resolveName(t, engine, plan, "8.8.8.8.in-addr.arpa.", dnsmessage.TypePTR)
			if root.asked.Load() != 1 && !withExit {
				t.Fatalf("public reverse name asked the root %d times", root.asked.Load())
			}
		})
	}
	// With only the Network's own resolvers, reverse names keep going to
	// them: an office DNS may hold the LAN's reverse zone.
	office := startCountingUpstream(t, dnsmessage.RCodeNameError, netip.Addr{}, false)
	plan := Plan{Enabled: true, DefaultResolvers: []netip.AddrPort{office.address}}
	resolveName(t, zoneEngine(t), plan, "5.1.168.192.in-addr.arpa.", dnsmessage.TypePTR)
	if office.asked.Load() != 1 {
		t.Fatalf("the Network's resolvers were asked %d times for a LAN reverse name", office.asked.Load())
	}
}

// While an exit node is in use the root zone's resolver Devices keep their
// place, with the exit node's forwarder after them; AAAA without IPv6 at the
// exit node has no data at once; a captive portal window wins over a root
// zone that fails closed (DNS design D1b §5.2, Q6).
func TestResolverEngineRootZoneWithAnExitNode(t *testing.T) {
	t.Parallel()
	device := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.95"), false)
	exit := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.96"), false)
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.97"), false)
	engine := zoneEngine(t, network.address)
	plan := rootPlan(Route{Suffix: ".", Resolvers: []netip.AddrPort{device.address}})
	plan.Exit = &ExitDNS{Resolvers: []netip.AddrPort{exit.address}}
	// The test listener is on 127.0.0.1, a private address: it keeps its
	// place as a resolver Device would.
	if got := firstA(t, resolveName(t, engine, plan, "www.example.com.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.95") {
		t.Fatalf("answer %s", got)
	}
	if message := resolveName(t, engine, plan, "www.example.com.", dnsmessage.TypeAAAA); message.RCode !=
		dnsmessage.RCodeSuccess || len(message.Answers) != 0 || device.asked.Load() != 1 {
		t.Fatalf("AAAA without IPv6 = %v %v, device asked %d", message.RCode, message.Answers, device.asked.Load())
	}
	closed := rootPlan(Route{Suffix: ".", Unavailable: true})
	closed.Exit = plan.Exit
	engine.captive.Store(true)
	if got := firstA(t, resolveName(t, engine, closed, "portal.hotel.example.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.97") {
		t.Fatalf("captive window with a closed root answered %s", got)
	}
}

// Resolver health: never asked is idle; an answer is ok with its time;
// SERVFAIL or REFUSED is refusing; a breaker that skips it is broken; a
// resolver Device that stopped answering pings is stopped. The root zone's
// resolvers come first, each once.
func TestResolverHealth(t *testing.T) {
	t.Parallel()
	good := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.98"), false)
	refusing := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	idle := netip.MustParseAddrPort("192.0.2.200:53")
	stopped := netip.MustParseAddrPort("100.64.0.77:53")
	engine := zoneEngine(t)
	engine.setLiveness(&fakeLiveness{stopped: map[netip.Addr]bool{stopped.Addr(): true}})
	plan := Plan{
		Enabled: true,
		Root:    &Route{Suffix: ".", Resolvers: []netip.AddrPort{good.address, idle}},
		Routes: []Route{
			{Suffix: "corp.internal", Resolvers: []netip.AddrPort{refusing.address, stopped, good.address}},
			{Suffix: "dead.internal", Resolvers: []netip.AddrPort{deadResolver}},
		},
	}
	resolveName(t, engine, plan, "www.example.com.", dnsmessage.TypeA)
	resolveName(t, engine, Plan{Enabled: true, Routes: []Route{{
		Suffix:    "corp.internal",
		Resolvers: []netip.AddrPort{refusing.address},
	}}}, "a.corp.internal.", dnsmessage.TypeA)
	for range breakerFailures {
		resolveName(t, engine, plan, "a.dead.internal.", dnsmessage.TypeA)
	}
	health := engine.resolverHealth(plan, maximumReportedResolvers)
	states := make([]controlplane.ResolverState, 0, len(health))
	for _, resolver := range health {
		states = append(states, resolver.State)
	}
	want := []controlplane.ResolverState{
		controlplane.ResolverOK, controlplane.ResolverIdle,
		controlplane.ResolverRefusing, controlplane.ResolverStopped, controlplane.ResolverBroken,
	}
	if !slices.Equal(states, want) || health[0].Resolver != good.address || health[0].LastOK.IsZero() ||
		!health[1].LastOK.IsZero() {
		t.Fatalf("health = %+v", health)
	}
	if limited := engine.resolverHealth(plan, 2); len(limited) != 2 {
		t.Fatalf("bounded health = %+v", limited)
	}
	// A resolver that leaves the plan is idle again when it comes back.
	engine.adoptHealth(Plan{Enabled: true, Routes: []Route{
		{Suffix: "corp.internal", Resolvers: []netip.AddrPort{refusing.address}},
	}})
	if health := engine.resolverHealth(plan, maximumReportedResolvers); health[0].State != controlplane.ResolverIdle ||
		!health[0].LastOK.IsZero() || health[2].State != controlplane.ResolverRefusing {
		t.Fatalf("health after the root left = %+v", health)
	}
}

type unusedOpener struct{}

func (unusedOpener) OpenDNS(context.Context) (netadmin.DNSLink, error) {
	return netadmin.DNSLink{}, errors.New("unused")
}

// While root's settings name a pool and the plan has no exit node yet, the
// desktop resolver sends no question out through the host's network: an
// open root zone that lost its resolvers answers SERVFAIL, except in a
// captive portal window (DNS design D1b §5.4). Not parallel: the choice is
// the process's.
func TestServerKeepsQuestionsInWhileAPoolIsChosen(t *testing.T) {
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.89"), false)
	server, err := NewServer(unusedOpener{})
	if err != nil {
		t.Fatal(err)
	}
	server.engine.networkResolvers = func() []netip.AddrPort { return []netip.AddrPort{network.address} }
	open := rootPlan(Route{Suffix: ".", Unavailable: true, FailOpen: true})
	underlay.SetExitChosen(true)
	t.Cleanup(func() { underlay.SetExitChosen(false) })
	if message := resolveName(t, server.engine, open, "www.example.com.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeServerFailure || network.asked.Load() != 0 {
		t.Fatalf("pool chosen = %v, network asked %d", message.RCode, network.asked.Load())
	}
	server.engine.captive.Store(true)
	if got := firstA(t, resolveName(t, server.engine, open, "portal.hotel.example.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.89") {
		t.Fatalf("captive window answered %s", got)
	}
	server.engine.captive.Store(false)
	underlay.SetExitChosen(false)
	if got := firstA(t, resolveName(t, server.engine, open, "www.example.com.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.89") {
		t.Fatalf("no pool chosen answered %s", got)
	}
}

// A CNAME out of the mesh is chased through the root zone, except to
// MeshTransit's own infrastructure, which stays with the network (DNS design
// D1b §5.1, §5.8).
func TestResolverEngineChasesThroughTheRootZone(t *testing.T) {
	t.Parallel()
	root := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.87"), false)
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.88"), false)
	plan, engine := namesPlan(t, network.address)
	plan.Root = &Route{Suffix: ".", Resolvers: []netip.AddrPort{root.address}}
	help := resolveName(t, engine, plan, "help.corp.lan.", dnsmessage.TypeA)
	if summary := answerSummary(help); len(summary) != 2 || summary[1] != "support.example.com A 192.0.2.87" ||
		network.asked.Load() != 0 {
		t.Fatalf("chase through the root = %v, network asked %d", summary, network.asked.Load())
	}
	engine.setInfrastructureNames([]string{"support.example.com"})
	help = resolveName(t, engine, plan, "help.corp.lan.", dnsmessage.TypeA)
	if summary := answerSummary(help); len(summary) != 2 || summary[1] != "support.example.com A 192.0.2.88" ||
		root.asked.Load() != 1 {
		t.Fatalf("chase to infrastructure = %v, root asked %d", summary, root.asked.Load())
	}
}
