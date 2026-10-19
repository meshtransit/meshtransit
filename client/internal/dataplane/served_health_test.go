package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/client/internal/routesettings"
)

var (
	prodSite = networkmap.ServedSite{
		Ref: "prod", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}, Masquerade: true,
		Probes: []networkmap.RouteProbe{{Address: netip.MustParseAddr("10.35.0.4")}},
	}
	uatSite = networkmap.ServedSite{
		Ref: "uat", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.128.0/17")}, Masquerade: true,
		Probes: []networkmap.RouteProbe{{Address: netip.MustParseAddr("10.35.128.4"), TCP: true, Port: 22}},
	}
)

func healthyHelper(packets uint64) netadmin.ServedHealth {
	return netadmin.ServedHealth{
		ServedResult:    netadmin.ServedResult{Installed: slices.Concat(prodSite.Prefixes, uatSite.Prefixes)},
		SelfTestPackets: packets, SelfTestKnown: true, ConntrackCount: 10, ConntrackMax: 100,
	}
}

func judged(t *testing.T, rounds []routerRound) []SiteHealth {
	t.Helper()
	sites := []networkmap.ServedSite{prodSite, uatSite}
	var health []SiteHealth
	prior := routerHealth{}.trackedOrEmpty()
	for _, round := range rounds {
		health, prior = judgeRouter(sites, round, prior)
	}
	return health
}

func codes(health []SiteHealth) map[string]string {
	result := map[string]string{}
	for _, site := range health {
		result[site.Ref] = site.State + "/" + site.Code
	}
	return result
}

func TestJudgeRouterTellsAnUnansweredProbeFromABlockedForwardPath(t *testing.T) {
	t.Parallel()
	answered := routerRound{
		before: healthyHelper(10), after: healthyHelper(12),
		outcomes: map[probeRef]probeOutcome{{"prod", 0}: probeAnswered, {"uat", 0}: probeAnswered},
	}
	// Both left the router (counter +2), prod got no answer.
	silent := routerRound{
		before: healthyHelper(12), after: healthyHelper(14),
		outcomes: map[probeRef]probeOutcome{{"prod", 0}: probeSilent, {"uat", 0}: probeAnswered},
	}
	// Neither crossed the forward path (counter unchanged).
	blocked := routerRound{
		before: healthyHelper(14), after: healthyHelper(14),
		outcomes: map[probeRef]probeOutcome{{"prod", 0}: probeSilent, {"uat", 0}: probeSilent},
	}
	if got := codes(judged(t, []routerRound{answered})); got["prod"] != "ok/ok" || got["uat"] != "ok/ok" {
		t.Fatalf("answered = %v", got)
	}
	// Two silent rounds are not yet a failure; the third is.
	if got := codes(judged(t, []routerRound{silent, silent})); got["prod"] != "ok/ok" {
		t.Fatalf("two silent rounds = %v", got)
	}
	if got := codes(judged(t, []routerRound{silent, silent, silent})); got["prod"] != "failed/probe_failed" || got["uat"] != "ok/ok" {
		t.Fatalf("three silent rounds = %v", got)
	}
	if got := codes(judged(t, []routerRound{blocked, blocked, blocked})); got["prod"] != "failed/forward_blocked" ||
		got["uat"] != "failed/forward_blocked" {
		t.Fatalf("three blocked rounds = %v", got)
	}
	// One answer resets the count.
	if got := codes(judged(t, []routerRound{blocked, blocked, answered, blocked})); got["prod"] != "ok/ok" {
		t.Fatalf("an answer between = %v", got)
	}
	// A reset TCP probe reached its host: the service is down.
	refused := routerRound{
		before: healthyHelper(1), after: healthyHelper(2),
		outcomes: map[probeRef]probeOutcome{{"uat", 0}: probeRefused},
	}
	if got := codes(judged(t, []routerRound{refused, refused, refused})); got["uat"] != "failed/probe_failed" {
		t.Fatalf("refused = %v", got)
	}
	// Without a counter (or a table installed again) a silent round proves
	// nothing either way.
	unknown := blocked
	unknown.after.SelfTestKnown = false
	if got := codes(judged(t, []routerRound{unknown, unknown, unknown})); got["prod"] != "ok/ok" {
		t.Fatalf("no counter = %v", got)
	}
	reset := blocked
	reset.after.SelfTestPackets = 0
	if got := codes(judged(t, []routerRound{reset, reset, reset})); got["prod"] != "ok/ok" {
		t.Fatalf("counter reset = %v", got)
	}
}

func TestJudgeRouterPutsHostProblemsFirst(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		mutate func(*routerRound)
		want   map[string]string
	}{
		"table gone": {
			func(round *routerRound) { round.before.Problems = []string{netadmin.ProblemRulesMissing} },
			map[string]string{"prod": "failed/nft_rules_missing", "uat": "failed/nft_rules_missing"},
		},
		"forwarding off": {
			func(round *routerRound) { round.before.Problems = []string{netadmin.ProblemForwardingOff} },
			map[string]string{"prod": "failed/forwarding_off", "uat": "failed/forwarding_off"},
		},
		"uat no longer offered": {func(round *routerRound) {
			round.before.Installed = prodSite.Prefixes
			round.before.Refused = []routesettings.Refusal{{Prefix: uatSite.Prefixes[0], Reason: routesettings.ReasonNotAdvertised}}
		}, map[string]string{"prod": "ok/ok", "uat": "failed/prefix_not_advertised"}},
		"uat has no route out": {func(round *routerRound) {
			round.before.Installed = prodSite.Prefixes
			round.before.Refused = []routesettings.Refusal{{Prefix: uatSite.Prefixes[0], Reason: "no_route"}}
		}, map[string]string{"prod": "ok/ok", "uat": "failed/no_route"}},
		"conntrack nearly full": {
			func(round *routerRound) { round.before.ConntrackCount = 81 },
			map[string]string{"prod": "degraded/conntrack_high", "uat": "degraded/conntrack_high"},
		},
	} {
		round := routerRound{before: healthyHelper(1), after: healthyHelper(1), outcomes: map[probeRef]probeOutcome{}}
		test.mutate(&round)
		if got := codes(judged(t, []routerRound{round})); !equalCodes(got, test.want) {
			t.Errorf("%s: %v, want %v", name, got, test.want)
		}
	}
}

func TestJudgeRouterWaitsForAHelperThatDoesNotAnswer(t *testing.T) {
	t.Parallel()
	healthy := routerRound{before: healthyHelper(1), after: healthyHelper(1), outcomes: map[probeRef]probeOutcome{}}
	missed := routerRound{beforeErr: errors.New("busy"), outcomes: map[probeRef]probeOutcome{}}
	forwardingOff := healthy
	forwardingOff.before.Problems = []string{netadmin.ProblemForwardingOff}
	// Missed checks keep the last judgement, ok or not, until three in a row.
	if got := codes(judged(t, []routerRound{healthy, missed, missed})); got["prod"] != "ok/ok" {
		t.Fatalf("two missed checks after ok = %v", got)
	}
	if got := codes(judged(t, []routerRound{forwardingOff, missed})); got["prod"] != "failed/forwarding_off" {
		t.Fatalf("a missed check after a failure = %v", got)
	}
	if got := codes(judged(t, []routerRound{healthy, missed, missed, missed})); got["prod"] != "failed/route_forwarding_failed" ||
		got["uat"] != "failed/route_forwarding_failed" {
		t.Fatalf("three missed checks = %v", got)
	}
	if got := codes(judged(t, []routerRound{missed, missed, healthy, missed, missed})); got["prod"] != "ok/ok" {
		t.Fatalf("an answer between = %v", got)
	}
}

func TestProbeCauseConcludesOnlyFromAClearCount(t *testing.T) {
	t.Parallel()
	outcomes := map[probeRef]probeOutcome{{"prod", 0}: probeSilent, {"uat", 0}: probeSilent, {"lab", 0}: probeAnswered}
	// Of 3 sent, 1 answered: a count of 1 means neither silent one left,
	// 3 that both did, 2 that one did, which cannot be told apart.
	for crossed, want := range map[uint64]string{1: SiteCodeForwardBlocked, 3: SiteCodeProbeFailed, 2: ""} {
		round := routerRound{before: healthyHelper(10), after: healthyHelper(10 + crossed), outcomes: outcomes}
		causes := probeCause(round)
		if causes["prod"] != want || causes["uat"] != want || causes["lab"] != "" {
			t.Errorf("%d crossed: %v, want %q", crossed, causes, want)
		}
	}
}

func equalCodes(first, second map[string]string) bool {
	if len(first) != len(second) {
		return false
	}
	for key, value := range first {
		if second[key] != value {
			return false
		}
	}
	return true
}

func TestProbesOfSkipsSitesASelfTestCannotCheck(t *testing.T) {
	t.Parallel()
	plain := uatSite
	plain.Ref, plain.Masquerade = "plain", false
	refs := probesOf([]networkmap.ServedSite{prodSite, plain, uatSite}, prodSite.Prefixes)
	if !slices.Equal(refs, []probeRef{{"prod", 0}}) {
		t.Fatalf("probesOf() = %v", refs)
	}
}

// echoKernel answers what the self-tester writes, as a Site behind a
// working forward path would.
type echoKernel struct {
	tester *selfTester
	answer func(packetmeta.Header) []byte
	sent   chan packetmeta.Header
}

func (k *echoKernel) write(packet []byte) error {
	header, err := packetmeta.Parse(packet)
	if err != nil {
		return err
	}
	k.sent <- header
	if reply := k.answer(header); reply != nil {
		go k.tester.take(reply)
	}
	return nil
}

func TestSelfTesterMatchesAnswersAndResetsTCP(t *testing.T) {
	t.Parallel()
	tester := newSelfTester()
	target := netip.MustParseAddr("10.35.0.4")
	kernel := &echoKernel{tester: tester, sent: make(chan packetmeta.Header, 8)}
	tester.attach(kernel.write)
	kernel.answer = func(header packetmeta.Header) []byte {
		switch header.Protocol {
		case packetmeta.ProtocolICMPv4:
			reply := packetmeta.EchoRequest(header.Destination, header.Source, header.ICMPIdentifier, 1)
			reply[20] = packetmeta.ICMPv4EchoReply
			return reply
		case packetmeta.ProtocolTCP:
			if header.TCPFlags != packetmeta.TCPFlagSYN {
				return nil
			}
			flags := packetmeta.TCPFlagSYN | packetmeta.TCPFlagACK
			if header.DestinationPort == 23 {
				flags = packetmeta.TCPFlagRST | packetmeta.TCPFlagACK
			}
			return packetmeta.TCPSegment(header.Destination, header.Source, header.DestinationPort, header.SourcePort, 7, 1, flags)
		}
		return nil
	}
	ctx := context.Background()
	if outcome := tester.probe(ctx, target, 0, time.Second); outcome != probeAnswered {
		t.Fatalf("echo = %v", outcome)
	}
	if sent := <-kernel.sent; sent.Source != overlayframe.SelfTestIPv4 || sent.Destination != target {
		t.Fatalf("echo sent %+v", sent)
	}
	if outcome := tester.probe(ctx, target, 22, time.Second); outcome != probeAnswered {
		t.Fatalf("tcp = %v", outcome)
	}
	<-kernel.sent // SYN
	if reset := <-kernel.sent; reset.TCPFlags != packetmeta.TCPFlagRST {
		t.Fatalf("an answered TCP self-test was not reset: %+v", reset)
	}
	if outcome := tester.probe(ctx, target, 23, time.Second); outcome != probeRefused {
		t.Fatalf("closed port = %v", outcome)
	}
	<-kernel.sent
	kernel.answer = func(packetmeta.Header) []byte { return nil }
	if outcome := tester.probe(ctx, target, 0, 50*time.Millisecond); outcome != probeSilent {
		t.Fatalf("no answer = %v", outcome)
	}
	// Anything to a self-test address is taken, answer or not; other
	// packets are not.
	stray := packetmeta.EchoRequest(target, overlayframe.SelfTestIPv4, 999, 1)
	if !tester.take(stray) {
		t.Fatal("a stray packet to the self-test address was let through")
	}
	if tester.take(packetmeta.EchoRequest(target, netip.MustParseAddr("100.64.1.2"), 1, 1)) {
		t.Fatal("a packet to a Device was taken")
	}
	// An ICMP error about a self-test answers it: the Site's network is
	// reached, the target is not.
	kernel.answer = func(header packetmeta.Header) []byte {
		request := packetmeta.EchoRequest(header.Source, header.Destination, header.ICMPIdentifier, 1)
		unreachable, err := packetmeta.Unreachable(request)
		if err != nil {
			t.Error(err)
			return nil
		}
		return unreachable
	}
	if outcome := tester.probe(ctx, target, 0, time.Second); outcome != probeRefused {
		t.Fatalf("host unreachable = %v", outcome)
	}
	<-kernel.sent
	tester.attach(nil)
	if outcome := tester.probe(ctx, target, 0, time.Second); outcome != probeUnsent {
		t.Fatalf("detached = %v", outcome)
	}
}
