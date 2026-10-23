package dnsconfig

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// zoneResolverX is the Internet resolver of the zones these tests ask
// through an exit node.
var zoneResolverX = netip.MustParseAddrPort("9.9.9.9:53")

// startRelayingExit runs an exit node's forwarder on loopback that relays
// to listed, asking x in their place, and answers other questions from
// system; it returns the forwarder's address.
func startRelayingExit(t *testing.T, x, system netip.AddrPort, listed ...string) netip.AddrPort {
	t.Helper()
	forwarder := relayForwarder(t, x, listed...)
	forwarder.local = func() []netip.Prefix { return nil }
	forwarder.port = 0
	if system.IsValid() {
		resolvConf := filepath.Join(t.TempDir(), "resolv.conf")
		if err := os.WriteFile(resolvConf, []byte("nameserver 127.0.0.1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		forwarder.resolvConf, forwarder.upstreamPort = resolvConf, system.Port()
	}
	forwarder.Configure([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil)
	t.Cleanup(forwarder.Close)
	forwarder.lifecycle.Lock()
	defer forwarder.lifecycle.Unlock()
	return netip.MustParseAddrPort(forwarder.udp[0].LocalAddr().String())
}

// exitZonePlan is a plan using the exit node's forwarder at via, with one
// zone corp.example whose resolver is X.
func exitZonePlan(via netip.AddrPort, failOpen bool) Plan {
	return Plan{
		Enabled: true,
		Routes:  []Route{{Suffix: "corp.example", Resolvers: []netip.AddrPort{zoneResolverX}, FailOpen: failOpen}},
		Exit:    &ExitDNS{Resolvers: []netip.AddrPort{via}},
	}
}

func hasOPT(message dnsmessage.Message) (*dnsmessage.OPTResource, bool) {
	for _, additional := range message.Additionals {
		if opt, ok := additional.Body.(*dnsmessage.OPTResource); ok {
			return opt, true
		}
	}
	return nil, false
}

// A zone's Internet resolver is asked through the exit node, its private
// answer kept; the answer carries no relay option, and no EDNS the
// application did not ask with; a relay option of the application's own is
// replaced.
func TestResolverEngineAsksAZonesResolverThroughTheExitNode(t *testing.T) {
	t.Parallel()
	x := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("10.20.0.5"), false)
	plan := exitZonePlan(startRelayingExit(t, x.address, netip.AddrPort{}, "9.9.9.9"), false)
	engine := zoneEngine(t)
	message := resolveName(t, engine, plan, "wiki.corp.example.", dnsmessage.TypeA)
	if got := firstA(t, message); got != netip.MustParseAddr("10.20.0.5") {
		t.Fatalf("answer %s", got)
	}
	if _, ok := hasOPT(message); ok {
		t.Fatal("an answer to a question without EDNS has EDNS")
	}
	message = resolveEDNS(t, engine, plan, "wiki.corp.example.")
	if opt, ok := hasOPT(message); !ok || len(opt.Options) != 0 {
		t.Fatalf("EDNS answer options %#v", message.Additionals)
	}
	ownOption := packRelayQuery(t, "wiki.corp.example.", dnsmessage.TypeA, netip.MustParseAddrPort("8.8.8.8:53"))
	response, err := engine.resolve(t.Context(), plan, ownOption, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if got := firstA(t, unpackMessage(t, response)); got != netip.MustParseAddr("10.20.0.5") {
		t.Fatalf("answer to a question with its own relay option %s", got)
	}
	if _, marked := relayStatusOf(response); marked {
		t.Fatal("the relay option reached the application")
	}
	if x.asked.Load() != 3 {
		t.Fatalf("X asked %d times", x.asked.Load())
	}
	health := engine.resolverHealth(plan, maximumReportedResolvers)
	if len(health) != 1 || health[0].LastOK.IsZero() {
		t.Fatalf("health through the exit node %+v", health)
	}
	plan.Exit = nil
	if health := engine.resolverHealth(plan, maximumReportedResolvers); !health[0].LastOK.IsZero() {
		t.Fatalf("health asked directly took the exit node's: %+v", health)
	}
}

// X's REFUSED (a filter blocking the name) is the zone's answer, never
// failing open; on Android an NXDOMAIN that is cached.
func TestResolverEngineKeepsTheRefusalOfAResolverBehindTheExitNode(t *testing.T) {
	t.Parallel()
	x := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	system := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("93.184.216.34"), false)
	plan := exitZonePlan(startRelayingExit(t, x.address, system.address, "9.9.9.9"), true)
	if message := resolveName(t, zoneEngine(t), plan, "blocked.corp.example.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeRefused {
		t.Fatalf("rcode %v", message.RCode)
	}
	android := zoneEngine(t)
	android.failuresAsNXDOMAIN = true
	message := resolveEDNS(t, android, plan, "blocked.corp.example.")
	if _, ttl, _ := soaOf(t, message); message.RCode != dnsmessage.RCodeNameError || ttl == 0 {
		t.Fatalf("Android: %v, TTL %d", message.RCode, ttl)
	}
	if code, _, _ := extendedErrorOf(t, message); code != edeProhibited {
		t.Fatalf("Android extended error %d", code)
	}
	if system.asked.Load() != 0 {
		t.Fatal("a refused name failed open")
	}
}

// X that does not answer counts against X asked through the exit node, not
// X asked directly; a zone that fails open then asks the exit node's
// forwarder, one that fails closed answers SERVFAIL.
func TestResolverEngineCountsASilentResolverBehindTheExitNode(t *testing.T) {
	t.Parallel()
	system := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("93.184.216.34"), false)
	via := startRelayingExit(t, startUnresponsiveUDPUpstream(t), system.address, "9.9.9.9")
	engine := zoneEngine(t)
	if got := firstA(t, resolveName(t, engine, exitZonePlan(via, true), "wiki.corp.example.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("open zone answer %s", got)
	}
	for range breakerFailures - 1 {
		if message := resolveName(t, engine, exitZonePlan(via, false), "wiki.corp.example.", dnsmessage.TypeA); message.RCode !=
			dnsmessage.RCodeServerFailure {
			t.Fatalf("closed zone %v", message.RCode)
		}
	}
	if !engine.relayBreaker.open(zoneResolverX) || engine.breaker.open(zoneResolverX) {
		t.Fatal("the breaker of X through the exit node did not open alone")
	}
}

// The forwarder that does not relay to X (not listed) says nothing of X.
func TestResolverEngineDoesNotCountAResolverTheExitNodeDidNotAsk(t *testing.T) {
	t.Parallel()
	system := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("93.184.216.34"), false)
	via := startRelayingExit(t, netip.AddrPort{}, system.address, "1.1.1.1")
	engine := zoneEngine(t)
	for range breakerFailures {
		if message := resolveName(t, engine, exitZonePlan(via, false), "wiki.corp.example.", dnsmessage.TypeA); message.RCode !=
			dnsmessage.RCodeServerFailure {
			t.Fatalf("closed zone %v", message.RCode)
		}
	}
	if engine.relayBreaker.open(zoneResolverX) {
		t.Fatal("X's breaker opened on questions the exit node did not ask")
	}
	if got := firstA(t, resolveName(t, engine, exitZonePlan(via, true), "wiki.corp.example.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("open zone answer %s", got)
	}
}

// An exit node that does not relay answers the question itself: a zone
// that fails open takes its answer, one that fails closed does not (D1c
// Q3), on Android as an NXDOMAIN not cached.
func TestResolverEngineTakesAnOldExitNodesAnswerOnlyForAnOpenZone(t *testing.T) {
	t.Parallel()
	old := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("93.184.216.34"), false)
	engine := zoneEngine(t)
	if got := firstA(t, resolveName(t, engine, exitZonePlan(old.address, true), "wiki.corp.example.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("open zone answer %s", got)
	}
	if old.asked.Load() != 1 {
		t.Fatalf("the old exit node was asked %d times", old.asked.Load())
	}
	if message := resolveName(t, engine, exitZonePlan(old.address, false), "wiki.corp.example.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeServerFailure {
		t.Fatalf("closed zone %v", message.RCode)
	}
	engine.failuresAsNXDOMAIN = true
	message := resolveEDNS(t, engine, exitZonePlan(old.address, false), "wiki.corp.example.")
	if _, ttl, _ := soaOf(t, message); message.RCode != dnsmessage.RCodeNameError || ttl != 0 {
		t.Fatalf("Android closed zone %v, TTL %d", message.RCode, ttl)
	}
	if engine.relayBreaker.open(zoneResolverX) {
		t.Fatal("an old exit node counted against X")
	}
}

func TestRelayedAnswerReadsTheStatus(t *testing.T) {
	t.Parallel()
	query := packRelayQuery(t, "a.example.", dnsmessage.TypeA, zoneResolverX)
	base := unpackMessage(t, packQuery(t, "a.example.", dnsmessage.TypeA))
	base.Response = true
	plain, err := base.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for status, want := range map[byte]error{
		relayNoAnswer: errRelayNoAnswer, relayNotAllowed: errRelaySkipped,
		relayBusy: errRelaySkipped, relayUplinkDown: errRelaySkipped,
	} {
		if _, err := relayedAnswer(withRelayStatus(query, plain, status), false); !errors.Is(err, want) {
			t.Fatalf("status %d: %v", status, err)
		}
	}
	answered, err := relayedAnswer(withRelayStatus(query, plain, relayAnswered), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hasOPT(unpackMessage(t, answered)); ok {
		t.Fatal("the EDNS the node added stayed")
	}
	if _, err := relayedAnswer(plain, false); err == nil {
		t.Fatal("an answer without a status was taken as X's")
	} else if _, old := oldExitAnswer(err); !old {
		t.Fatalf("no status: %v", err)
	}
}

// In a captive portal window a zone that fails open asks the network's
// resolvers directly, never through the exit node; only a zone's own
// resolvers are ever relayed.
func TestResolverEngineAsksTheNetworkDirectlyInACaptiveWindow(t *testing.T) {
	t.Parallel()
	exit := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("93.184.216.34"), false)
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.80"), false)
	engine := zoneEngine(t, network.address)
	engine.captive.Store(true)
	if got := firstA(t, resolveName(t, engine, exitZonePlan(exit.address, true), "portal.corp.example.",
		dnsmessage.TypeA)); got != netip.MustParseAddr("192.0.2.80") {
		t.Fatalf("answer %s", got)
	}
	if exit.asked.Load() != 0 {
		t.Fatal("the exit node was asked in a captive portal window")
	}
	gate := engine.zoneGate([]netip.AddrPort{zoneResolverX}, exit.address)
	if zoneResolver(gate, netip.MustParseAddrPort("8.8.8.8:53")) || !zoneResolver(gate, zoneResolverX) ||
		zoneResolver(nil, zoneResolverX) {
		t.Fatal("a resolver other than the zone's would be relayed")
	}
}

// A CNAME chase never fails open past a resolver's REFUSED, an old exit
// node's own answer included (D1b §5.3).
func TestChaseKeepsARefusalBeforeAnOldExitNodesAnswer(t *testing.T) {
	t.Parallel()
	refusing := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	old := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("93.184.216.34"), false)
	plan := exitZonePlan(old.address, true)
	plan.Routes[0].Resolvers = []netip.AddrPort{refusing.address, zoneResolverX}
	_, err := zoneEngine(t).askOutside(t.Context(), plan, "app.corp.example", dnsmessage.TypeA, "udp")
	if _, answered := upstreamAnswer(err); !answered {
		t.Fatalf("chase: %v", err)
	}
	if old.asked.Load() != 1 {
		t.Fatalf("the old exit node was asked %d times", old.asked.Load())
	}
}

// An application's own relay option goes nowhere: a name no zone holds is
// asked of the exit node's forwarder without it.
func TestResolverEngineDropsTheApplicationsRelayOption(t *testing.T) {
	t.Parallel()
	x := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("10.20.0.5"), false)
	system := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("93.184.216.34"), false)
	plan := Plan{Enabled: true, Exit: &ExitDNS{
		Resolvers: []netip.AddrPort{startRelayingExit(t, x.address, system.address, "9.9.9.9")},
	}}
	response, err := zoneEngine(t).resolve(t.Context(), plan,
		packRelayQuery(t, "public.example.", dnsmessage.TypeA, zoneResolverX), "udp")
	if err != nil {
		t.Fatal(err)
	}
	if got := firstA(t, unpackMessage(t, response)); got != netip.MustParseAddr("93.184.216.34") || x.asked.Load() != 0 {
		t.Fatalf("answer %s, X asked %d times", got, x.asked.Load())
	}
}

// An exit node's forwarder that does not answer at all says nothing of X.
func TestResolverEngineDoesNotCountAnUnreachableExitNodeAgainstX(t *testing.T) {
	t.Parallel()
	plan := exitZonePlan(startUnresponsiveUDPUpstream(t), false)
	engine := zoneEngine(t)
	for range breakerFailures {
		if message := resolveName(t, engine, plan, "wiki.corp.example.", dnsmessage.TypeA); message.RCode !=
			dnsmessage.RCodeServerFailure {
			t.Fatalf("closed zone %v", message.RCode)
		}
	}
	if engine.relayBreaker.open(zoneResolverX) {
		t.Fatal("an unreachable exit node opened X's breaker")
	}
}
