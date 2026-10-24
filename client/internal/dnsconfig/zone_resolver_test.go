package dnsconfig

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// deadResolver refuses at once: nothing listens on its port.
var deadResolver = netip.MustParseAddrPort("127.0.0.1:1")

func zoneEngine(t *testing.T, network ...netip.AddrPort) *resolverEngine {
	t.Helper()
	engine := newResolverEngine()
	engine.networkResolvers = func() []netip.AddrPort { return slices.Clone(network) }
	return engine
}

func resolveName(t *testing.T, engine *resolverEngine, plan Plan, name string,
	recordType dnsmessage.Type,
) dnsmessage.Message {
	t.Helper()
	response, _ := engine.resolve(t.Context(), plan, packQuery(t, name, recordType), "udp")
	return unpackMessage(t, response)
}

// A forward zone none of whose resolvers can be used fails as it says:
// closed answers SERVFAIL without asking anyone, open asks the host's
// network resolvers, or the exit node's forwarder while one is in use.
func TestResolverEngineUnavailableZoneFollowsItsFailureMode(t *testing.T) {
	t.Parallel()
	closed := Plan{Enabled: true, Routes: []Route{{Suffix: "corp", Unavailable: true}}}
	if message := resolveName(t, zoneEngine(t, deadResolver), closed, "wiki.corp.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeServerFailure {
		t.Fatalf("closed zone = %v", message.RCode)
	}

	network := startUDPUpstream(t, netip.MustParseAddr("192.0.2.10"))
	open := Plan{Enabled: true, Routes: []Route{{Suffix: "corp", Unavailable: true, FailOpen: true}}}
	if got := firstA(t, resolveName(t, zoneEngine(t, network), open, "wiki.corp.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("open zone asked the network for %s", got)
	}

	exit := startUDPUpstream(t, netip.MustParseAddr("192.0.2.20"))
	open.Exit = &ExitDNS{Resolvers: []netip.AddrPort{exit}}
	if got := firstA(t, resolveName(t, zoneEngine(t, deadResolver), open, "wiki.corp.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.20") {
		t.Fatalf("open zone while using an exit node got %s", got)
	}
	// Without IPv6 at the exit node, AAAA has no data at once.
	if message := resolveName(t, zoneEngine(t), open, "wiki.corp.", dnsmessage.TypeAAAA); message.RCode !=
		dnsmessage.RCodeSuccess || len(message.Answers) != 0 {
		t.Fatalf("AAAA = %v %#v", message.RCode, message.Answers)
	}
}

// When the zone's resolvers do not answer, an open zone still answers from
// the network within a stub resolver's 5 seconds; a closed one SERVFAILs.
func TestResolverEngineZoneResolversThatDoNotAnswer(t *testing.T) {
	t.Parallel()
	silent := startUnresponsiveUDPUpstream(t)
	network := startUDPUpstream(t, netip.MustParseAddr("192.0.2.30"))
	open := Plan{Enabled: true, Routes: []Route{{
		Suffix: "corp.internal", Resolvers: []netip.AddrPort{silent},
		FailOpen: true,
	}}}
	started := time.Now()
	if got := firstA(t, resolveName(t, zoneEngine(t, network), open, "a.corp.internal.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.30") {
		t.Fatalf("open zone fell back to %s", got)
	}
	if elapsed := time.Since(started); elapsed >= queryTimeout {
		t.Fatalf("fell back after %s", elapsed)
	}
	closed := open
	closed.Routes = []Route{{Suffix: "corp.internal", Resolvers: []netip.AddrPort{deadResolver}}}
	if message := resolveName(t, zoneEngine(t, network), closed, "a.corp.internal.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeServerFailure {
		t.Fatalf("closed zone = %v", message.RCode)
	}
}

// A zone resolver that fails three times in a row is skipped: questions go
// straight to the next resolver.
func TestResolverEngineSkipsAFailingZoneResolver(t *testing.T) {
	t.Parallel()
	engine := zoneEngine(t)
	plan := Plan{Enabled: true, Routes: []Route{{
		Suffix:    "corp.internal",
		Resolvers: []netip.AddrPort{deadResolver},
	}}}
	for range breakerFailures {
		resolveName(t, engine, plan, "a.corp.internal.", dnsmessage.TypeA)
	}
	if !engine.breaker.open(deadResolver) {
		t.Fatal("the failing resolver is still asked")
	}
	good := startUDPUpstream(t, netip.MustParseAddr("192.0.2.40"))
	plan.Routes[0].Resolvers = append(plan.Routes[0].Resolvers, good)
	if got := firstA(t, resolveName(t, engine, plan, "a.corp.internal.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.40") {
		t.Fatalf("answer %s", got)
	}
}

// While an exit node is in use a zone keeps its resolvers in their order:
// those in the mesh or a private network asked directly, Internet ones
// through the exit node's forwarder (DNS design D1c §5), an IPv6 one left
// out when the exit node carries no IPv6.
func TestZoneTargetsWhileUsingAnExitNode(t *testing.T) {
	t.Parallel()
	device := netip.MustParseAddrPort("100.64.0.7:5335")
	forwarder := netip.MustParseAddrPort("100.64.0.9:53")
	cloudflare := netip.MustParseAddrPort("1.1.1.1:53")
	cloudflare6 := netip.MustParseAddrPort("[2606:4700:4700::1111]:53")
	plan := Plan{Exit: &ExitDNS{Resolvers: []netip.AddrPort{forwarder}}}
	engine := zoneEngine(t)
	question := dnsmessage.Question{Type: dnsmessage.TypeA}
	route := Route{Suffix: "corp.internal", Resolvers: []netip.AddrPort{cloudflare6, device, cloudflare}}
	if targets, _, _ := engine.zoneTargets(plan, route, question); !slices.Equal(targets,
		[]netip.AddrPort{device, cloudflare}) {
		t.Fatalf("targets = %v", targets)
	}
	plan.Exit.IPv6 = true
	if targets, _, _ := engine.zoneTargets(plan, route, question); !slices.Equal(targets, route.Resolvers) {
		t.Fatalf("targets with IPv6 = %v", targets)
	}
	if via := engine.relayVia(plan); via != forwarder {
		t.Fatalf("relayed via %s", via)
	}
	route.Resolvers = []netip.AddrPort{cloudflare}
	if targets, _, _ := engine.zoneTargets(plan, route, question); !slices.Equal(targets, route.Resolvers) {
		t.Fatalf("Internet-only targets = %v", targets)
	}
	plan.Exit.Resolvers = nil // chosen, no exit node carrying the traffic
	if targets, _, _ := engine.zoneTargets(plan, route, question); len(targets) != 0 {
		t.Fatalf("targets without a forwarder = %v", targets)
	}
	if targets, _, _ := engine.zoneTargets(plan, Route{Suffix: "corp", Unavailable: true}, question); len(targets) != 0 {
		t.Fatalf("unavailable targets = %v", targets)
	}
}

func TestResolverBreaker(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 22, 12, 0, 0, 0, time.UTC)
	breaker := newResolverBreaker(func() time.Time { return now })
	resolver := netip.MustParseAddrPort("100.64.0.7:53")
	failure := errUpstreamServerFailure
	for range breakerFailures - 1 {
		if !breaker.allow(resolver) {
			t.Fatal("skipped before the third failure")
		}
		breaker.record(resolver, failure)
	}
	breaker.record(resolver, nil) // a success forgets the failures
	for range breakerFailures {
		breaker.record(resolver, failure)
	}
	if breaker.allow(resolver) || !breaker.open(resolver) {
		t.Fatal("not skipped after three failures")
	}
	now = now.Add(breakerCooldown)
	if !breaker.allow(resolver) || breaker.allow(resolver) {
		t.Fatal("after the cooldown exactly one question tries it")
	}
	breaker.release(resolver) // that question was given up
	if !breaker.allow(resolver) {
		t.Fatal("a given-up trial keeps it skipped")
	}
	now = now.Add(breakerProbeLimit)
	if !breaker.allow(resolver) {
		t.Fatal("a trial that never reported keeps it skipped")
	}
	breaker.record(resolver, failure)
	if breaker.allow(resolver) {
		t.Fatal("a failed trial does not skip it again")
	}
	now = now.Add(breakerCooldown)
	if !breaker.allow(resolver) {
		t.Fatal("not tried again")
	}
	breaker.record(resolver, nil)
	first, second := breaker.allow(resolver), breaker.allow(resolver)
	if !first || !second || breaker.open(resolver) {
		t.Fatal("a success does not close it")
	}
	for index := range maxBreakerEntries + 10 {
		breaker.record(netip.AddrPortFrom(netip.MustParseAddr("100.64.1.1"), uint16(1024+index)), failure)
	}
	if len(breaker.states) > maxBreakerEntries {
		t.Fatalf("breaker remembers %d resolvers", len(breaker.states))
	}
}

// countingUpstream answers every UDP question with rcode (an A record of
// answer when valid, TC set when truncated) until the test ends, and
// counts them. Nothing listens on its TCP port.
type countingUpstream struct {
	address netip.AddrPort
	asked   atomic.Int32
}

func startCountingUpstream(t *testing.T, rcode dnsmessage.RCode, answer netip.Addr, truncated bool) *countingUpstream {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	local, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listener address %T", listener.LocalAddr())
	}
	upstream := &countingUpstream{address: local.AddrPort()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxQueryBytes)
		for {
			count, remote, err := listener.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			upstream.asked.Add(1)
			var query dnsmessage.Message
			if query.Unpack(buffer[:count]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{
				ID: query.ID, Response: true, RCode: rcode,
				Truncated: truncated,
			}, Questions: query.Questions}
			if answer.IsValid() && !truncated {
				response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{
					Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30,
				}, Body: &dnsmessage.AResource{A: answer.As4()}}}
			}
			if payload, err := response.Pack(); err == nil {
				_, _ = listener.WriteToUDPAddrPort(payload, remote)
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return upstream
}

// SERVFAIL and REFUSED are about the name, not the resolver: they never
// skip it, and the next resolver is still asked.
func TestResolverEngineBreakerIgnoresAnswersAboutTheName(t *testing.T) {
	t.Parallel()
	for _, rcode := range []dnsmessage.RCode{
		dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused,
		dnsmessage.RCodeNameError,
	} {
		engine := zoneEngine(t)
		failing := startCountingUpstream(t, rcode, netip.Addr{}, false)
		plan := Plan{Enabled: true, Routes: []Route{{
			Suffix:    "corp.internal",
			Resolvers: []netip.AddrPort{failing.address},
		}}}
		for range breakerFailures + 1 {
			resolveName(t, engine, plan, "broken.corp.internal.", dnsmessage.TypeA)
		}
		if engine.breaker.open(failing.address) || failing.asked.Load() != breakerFailures+1 {
			t.Fatalf("%v: breaker open %t after %d questions", rcode, engine.breaker.open(failing.address),
				failing.asked.Load())
		}
	}
}

// A zone resolver that answers SERVFAIL or REFUSED (a filter blocking the
// name, DNSSEC) is the zone's answer once no other resolver of the zone
// answers better: the next resolver is still asked, but a zone that fails
// open never asks the network past it (DNS design D1b §5.3).
func TestResolverEngineZoneNeverFailsOpenPastAnAnswer(t *testing.T) {
	t.Parallel()
	for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused} {
		for name, test := range map[string]struct {
			resolvers func(answering, good netip.AddrPort) []netip.AddrPort
			want      dnsmessage.RCode
		}{
			"only resolver": {func(answering, _ netip.AddrPort) []netip.AddrPort {
				return []netip.AddrPort{answering}
			}, rcode},
			"after a dead one": {func(answering, _ netip.AddrPort) []netip.AddrPort {
				return []netip.AddrPort{deadResolver, answering}
			}, rcode},
			"before a dead one": {func(answering, _ netip.AddrPort) []netip.AddrPort {
				return []netip.AddrPort{answering, deadResolver}
			}, rcode},
			"before a good one": {func(answering, good netip.AddrPort) []netip.AddrPort {
				return []netip.AddrPort{answering, good}
			}, dnsmessage.RCodeSuccess},
		} {
			t.Run(fmt.Sprintf("%v %s", rcode, name), func(t *testing.T) {
				t.Parallel()
				answering := startCountingUpstream(t, rcode, netip.Addr{}, false)
				good := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.70"), false)
				network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.71"), false)
				plan := Plan{Enabled: true, Routes: []Route{{
					Suffix: "corp.internal", Resolvers: test.resolvers(answering.address, good.address), FailOpen: true,
				}}}
				message := resolveName(t, zoneEngine(t, network.address), plan, "blocked.corp.internal.", dnsmessage.TypeA)
				if message.RCode != test.want || network.asked.Load() != 0 || answering.asked.Load() != 1 {
					t.Fatalf("rcode %v (want %v), network asked %d, answering resolver asked %d",
						message.RCode, test.want, network.asked.Load(), answering.asked.Load())
				}
			})
		}
	}
}

// fakeLiveness reports the addresses in stopped and records those asked.
type fakeLiveness struct {
	mu      sync.Mutex
	stopped map[netip.Addr]bool
	asked   []netip.Addr
}

func (l *fakeLiveness) Stopped(address netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopped[address]
}

func (l *fakeLiveness) Asked(address netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked = append(l.asked, address)
}

// The zone's own resolvers the liveness reports stopped are asked last, in
// their order, never dropped; the exit node's forwarder keeps its place and
// is not noted as asked (DNS design D1b §5.6).
func TestByLivenessAsksStoppedResolversLast(t *testing.T) {
	t.Parallel()
	stoppedA := netip.MustParseAddrPort("100.64.0.1:53")
	alive := netip.MustParseAddrPort("100.64.0.2:53")
	stoppedB := netip.MustParseAddrPort("100.64.0.3:5335")
	forwarder := netip.MustParseAddrPort("100.64.0.9:53")
	engine := zoneEngine(t)
	own := []netip.AddrPort{stoppedA, alive, stoppedB}
	if got := engine.byLiveness([]netip.AddrPort{stoppedA, alive, stoppedB, forwarder}, own); !slices.Equal(got,
		[]netip.AddrPort{stoppedA, alive, stoppedB, forwarder}) {
		t.Fatalf("without liveness = %v", got)
	}
	liveness := &fakeLiveness{stopped: map[netip.Addr]bool{stoppedA.Addr(): true, stoppedB.Addr(): true, forwarder.Addr(): true}}
	engine.setLiveness(liveness)
	if got := engine.byLiveness([]netip.AddrPort{stoppedA, alive, stoppedB, forwarder}, own); !slices.Equal(got,
		[]netip.AddrPort{alive, forwarder, stoppedA, stoppedB}) {
		t.Fatalf("ordered = %v", got)
	}
	if !slices.Equal(liveness.asked, []netip.Addr{stoppedA.Addr(), alive.Addr(), stoppedB.Addr()}) {
		t.Fatalf("noted as asked = %v", liveness.asked)
	}
}

// A zone whose first resolver Device stopped answers from the next one at
// once; the stopped one is not asked.
func TestResolverEngineAsksAStoppedResolverDeviceLast(t *testing.T) {
	t.Parallel()
	// A mesh address nothing answers on: asking it would cost the attempt
	// timeout.
	stopped := netip.MustParseAddrPort("100.64.0.99:53")
	next := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.81"), false)
	engine := zoneEngine(t)
	engine.setLiveness(&fakeLiveness{stopped: map[netip.Addr]bool{stopped.Addr(): true}})
	plan := Plan{Enabled: true, Routes: []Route{{
		Suffix: "corp.internal", Resolvers: []netip.AddrPort{stopped, next.address},
	}}}
	started := time.Now()
	if got := firstA(t, resolveName(t, engine, plan, "a.corp.internal.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.81") {
		t.Fatalf("answer %s", got)
	}
	if elapsed := time.Since(started); elapsed >= resolverAttemptTimeout {
		t.Fatalf("the stopped resolver was asked first: %s", elapsed)
	}
}

// A truncated UDP answer from a resolver the node cannot reach over TCP is
// passed on truncated (the client asks again over TCP) and never skips
// the resolver.
func TestResolverEngineKeepsATruncatedAnswerWithoutTCP(t *testing.T) {
	t.Parallel()
	engine := zoneEngine(t)
	upstream := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.50"), true)
	plan := Plan{Enabled: true, Routes: []Route{{
		Suffix:    "corp.internal",
		Resolvers: []netip.AddrPort{upstream.address},
	}}}
	for range breakerFailures {
		message := resolveName(t, engine, plan, "big.corp.internal.", dnsmessage.TypeTXT)
		if message.RCode != dnsmessage.RCodeSuccess || !message.Truncated {
			t.Fatalf("answer = %v truncated %t", message.RCode, message.Truncated)
		}
	}
	if engine.breaker.open(upstream.address) {
		t.Fatal("a resolver without TCP is skipped")
	}
}

// A zone that fails closed never asks the host's network, whatever the
// exit node and captive portal window; it asks the exit node's forwarder
// only in place of its own Internet resolvers.
func TestResolverEngineClosedZonesNeverAskTheNetwork(t *testing.T) {
	t.Parallel()
	internetResolver := netip.MustParseAddrPort("192.0.2.1:53") // documentation range: never answers
	skipWhenTheNetworkAnswers(t, internetResolver)
	for _, withExit := range []bool{false, true} {
		for _, captive := range []bool{false, true} {
			for name, resolvers := range map[string][]netip.AddrPort{
				"unavailable": nil,
				"dead device": {deadResolver},
				"internet":    {internetResolver},
				"mixed":       {deadResolver, internetResolver},
			} {
				t.Run(fmt.Sprintf("exit %t captive %t %s", withExit, captive, name), func(t *testing.T) {
					t.Parallel()
					network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.60"), false)
					exit := startCountingUpstream(t, dnsmessage.RCodeServerFailure, netip.Addr{}, false)
					engine := zoneEngine(t, network.address)
					engine.captive.Store(captive)
					plan := Plan{Enabled: true, Routes: []Route{{
						Suffix: "corp.internal", Resolvers: resolvers,
						Unavailable: resolvers == nil,
					}}}
					if withExit {
						plan.Exit = &ExitDNS{Resolvers: []netip.AddrPort{exit.address}, IPv6: true}
					}
					message := resolveName(t, engine, plan, "secret.corp.internal.", dnsmessage.TypeA)
					exitAllowed := withExit && name != "unavailable" && name != "dead device" && (!captive || name != "internet")
					if message.RCode != dnsmessage.RCodeServerFailure || network.asked.Load() != 0 ||
						(!exitAllowed && exit.asked.Load() != 0) {
						t.Errorf("exit %t captive %t %s: %v, network asked %d, exit asked %d", withExit, captive, name,
							message.RCode, network.asked.Load(), exit.asked.Load())
					}
				})
			}
		}
	}
}

// Under concurrent questions the breaker never gets stuck: once the
// resolver answers again, it is asked.
func TestResolverBreakerUnderConcurrency(t *testing.T) {
	t.Parallel()
	var nowNanos atomic.Int64
	start := time.Date(2026, time.October, 22, 12, 0, 0, 0, time.UTC)
	breaker := newResolverBreaker(func() time.Time { return start.Add(time.Duration(nowNanos.Load())) })
	resolver := netip.MustParseAddrPort("100.64.0.7:53")
	var wait sync.WaitGroup
	for worker := range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for round := range 200 {
				if !breaker.allow(resolver) {
					continue
				}
				switch (worker + round) % 3 {
				case 0:
					breaker.record(resolver, errNoResolver)
				case 1:
					breaker.release(resolver)
				default:
					breaker.record(resolver, nil)
				}
			}
		}()
	}
	wait.Wait()
	nowNanos.Store(int64(breakerCooldown + breakerProbeLimit))
	if !breaker.allow(resolver) {
		t.Fatal("stuck skipped after the cooldown")
	}
	breaker.record(resolver, nil)
	if breaker.open(resolver) || !breaker.allow(resolver) {
		t.Fatal("a success does not close it")
	}
}

// skipWhenTheNetworkAnswers skips a test that needs resolver to stay silent
// on a network that answers every DNS question itself (a router that
// intercepts port 53).
func skipWhenTheNetworkAnswers(t *testing.T, resolver netip.AddrPort) {
	t.Helper()
	connection, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(resolver))
	if err != nil {
		return
	}
	defer connection.Close()
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 7}, Questions: []dnsmessage.Question{{
		Name: dnsmessage.MustNewName("probe.invalid."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}}}).Pack()
	if err != nil {
		return
	}
	_ = connection.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := connection.Write(query); err != nil {
		return
	}
	if _, err := connection.Read(make([]byte, 512)); err == nil {
		t.Skipf("this network answers DNS sent to %s: the test needs it silent", resolver)
	}
}
