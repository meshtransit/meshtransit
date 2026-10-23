package dnsconfig

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A zone that fails open shares its budget among its resolvers (TD-CLI-66
// L4).
func TestAttemptWithinSharesTheBudget(t *testing.T) {
	t.Parallel()
	for count, want := range map[int]time.Duration{
		0: resolverAttemptTimeout, 1: resolverAttemptTimeout, 2: resolverAttemptTimeout,
		4: 750 * time.Millisecond, 10: minAttemptTimeout,
	} {
		if got := attemptWithin(failOpenPrimaryBudget, count); got != want {
			t.Fatalf("%d resolvers: %s, want %s", count, got, want)
		}
	}
}

// What failed during a captive portal window is asked again once it closes
// (TD-CLI-66 L7).
func TestClosingACaptiveWindowForgetsFailures(t *testing.T) {
	t.Parallel()
	engine := zoneEngine(t)
	resolver := netip.MustParseAddrPort("100.64.0.7:53")
	engine.setCaptiveWindow(true)
	for range breakerFailures {
		engine.breaker.record(resolver, errUpstreamServerFailure)
		engine.relayBreaker.record(resolver, errUpstreamServerFailure)
	}
	engine.setCaptiveWindow(true)
	if !engine.breaker.open(resolver) {
		t.Fatal("staying open forgot the failures")
	}
	engine.setCaptiveWindow(false)
	if engine.breaker.open(resolver) || engine.relayBreaker.open(resolver) {
		t.Fatal("closing the window kept the failures")
	}
}

// After its cooldown a resolver that stopped answering is tried by the
// node's own question: an application's question goes on to the next
// resolver at once (TD-CLI-66 L6).
func TestTrippedResolverIsTriedInTheBackground(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	dead := startUnresponsiveUDPUpstream(t)
	good := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("10.35.0.7"), false)
	engine := zoneEngine(t)
	engine.breaker = newResolverBreaker(clock)
	plan := Plan{Enabled: true, Routes: []Route{{Suffix: "corp.example", Resolvers: []netip.AddrPort{dead, good.address}}}}
	for range breakerFailures {
		engine.breaker.record(dead, errUpstreamServerFailure)
	}
	mu.Lock()
	now = now.Add(breakerCooldown)
	mu.Unlock()
	started := time.Now()
	if got := firstA(t, resolveName(t, engine, plan, "wiki.corp.example.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("10.35.0.7") {
		t.Fatalf("answer %s", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the application's question waited %s on the tripped resolver", elapsed)
	}
	// The background trial fails: the resolver gets a new cooldown.
	deadline := time.Now().Add(3 * resolverAttemptTimeout)
	for !engine.breaker.open(dead) {
		if time.Now().After(deadline) {
			t.Fatal("the failed background trial did not open the breaker again")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A zone's only resolver carries the trial in the application's question.
	single := Plan{Enabled: true, Routes: []Route{{Suffix: "lab.example", Resolvers: []netip.AddrPort{good.address}}}}
	for range breakerFailures {
		engine.breaker.record(good.address, errUpstreamServerFailure)
	}
	mu.Lock()
	now = now.Add(2 * breakerCooldown)
	mu.Unlock()
	if got := firstA(t, resolveName(t, engine, single, "x.lab.example.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("10.35.0.7") {
		t.Fatalf("a recovered only resolver: %s", got)
	}
}

// A forwarded question asks for at most 1232 bytes over UDP (D5d).
func TestForwardedQuestionsAskForAtMost1232Bytes(t *testing.T) {
	t.Parallel()
	for size, want := range map[int]int{4096: forwardUDPSize, 1232: 1232, 512: 512} {
		clamped := unpackMessage(t, clampEDNSSize(packEDNS0Query(t, "a.example.", dnsmessage.TypeA, size)))
		if got := int(clamped.Additionals[0].Header.Class); got != want {
			t.Fatalf("asked %d: %d, want %d", size, got, want)
		}
		if opt, ok := clamped.Additionals[0].Body.(*dnsmessage.OPTResource); !ok || len(opt.Options) != 1 {
			t.Fatalf("asked %d: options lost: %#v", size, clamped.Additionals[0].Body)
		}
	}
	plain := packQuery(t, "a.example.", dnsmessage.TypeA)
	if string(clampEDNSSize(plain)) != string(plain) {
		t.Fatal("a question without EDNS was changed")
	}
}
