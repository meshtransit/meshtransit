package dnsconfig

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/networkmap"
)

// retireForwarder is a forwarder whose clock the test moves.
func retireForwarder(t *testing.T) (*ExitForwarder, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	forwarder := NewExitForwarder(nil, func() []netip.Prefix { return nil })
	forwarder.now = func() time.Time { return now }
	return forwarder, &now
}

func relayAllowedFor(forwarder *ExitForwarder, target, consumer string) bool {
	return forwarder.relayAllowed(netip.AddrPortFrom(netip.MustParseAddr(target), 53), netip.MustParseAddr(consumer),
		nil)
}

// A resolver Core stops listing is still relayed to for relayRetireGrace,
// for the consumers that had it: their maps may still carry its zone
// (TD-CORE-89).
func TestExitForwarderRelaysARetiredResolverWithinTheGrace(t *testing.T) {
	t.Parallel()
	forwarder, now := retireForwarder(t)
	open, scoped := netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("1.1.1.1")
	forwarder.SetRelay([]netip.Addr{open}, []networkmap.RelayScope{{
		Targets: []netip.Addr{scoped}, Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")},
	}}, nil)
	forwarder.SetRelay(nil, nil, nil)
	*now = now.Add(relayRetireGrace - time.Second)
	for _, check := range []struct {
		target, consumer string
		want             bool
	}{
		{"9.9.9.9", "100.64.0.5", true},
		{"1.1.1.1", "100.64.0.4", true},
		{"1.1.1.1", "100.64.0.5", false}, // never in its scope
		{"8.8.8.8", "100.64.0.4", false}, // never listed
	} {
		if got := relayAllowedFor(forwarder, check.target, check.consumer); got != check.want {
			t.Fatalf("%s for %s within the grace = %v, want %v", check.target, check.consumer, got, check.want)
		}
	}
	*now = now.Add(2 * time.Second)
	if relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.5") || relayAllowedFor(forwarder, "1.1.1.1", "100.64.0.4") {
		t.Fatal("a retired resolver is relayed to past the grace")
	}
	// The next list forgets what ran out.
	forwarder.SetRelay(nil, nil, nil)
	forwarder.mu.Lock()
	left := len(forwarder.relayRetired)
	forwarder.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d retired resolvers kept past the grace", left)
	}
}

// A resolver listed again is Core's again: removing it once more starts a
// new grace; one moved from every consumer to a scope keeps the others for
// the grace only.
func TestExitForwarderRetiresAResolverOnlyWhenCoreDropsIt(t *testing.T) {
	t.Parallel()
	forwarder, now := retireForwarder(t)
	target := netip.MustParseAddr("9.9.9.9")
	forwarder.SetRelay([]netip.Addr{target}, nil, nil)
	forwarder.SetRelay(nil, nil, nil)
	*now = now.Add(time.Minute)
	forwarder.SetRelay([]netip.Addr{target}, nil, nil)
	forwarder.mu.Lock()
	_, retired := forwarder.relayRetired[target]
	forwarder.mu.Unlock()
	if retired {
		t.Fatal("a resolver listed again is still retired")
	}
	forwarder.SetRelay(nil, nil, nil)
	*now = now.Add(relayRetireGrace - time.Second)
	if !relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.5") {
		t.Fatal("removing a resolver again started no new grace")
	}

	forwarder, now = retireForwarder(t)
	forwarder.SetRelay([]netip.Addr{target}, nil, nil)
	forwarder.SetRelay(nil, []networkmap.RelayScope{{
		Targets: []netip.Addr{target}, Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")},
	}}, nil)
	if !relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.4") || !relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.5") {
		t.Fatal("a resolver moved to a scope is refused within the grace")
	}
	*now = now.Add(relayRetireGrace)
	if !relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.4") || relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.5") {
		t.Fatal("past the grace, the scope alone does not decide")
	}
}

// A node that stops serving an Exit Pool relays to nothing, retired
// resolvers included.
func TestExitForwarderClearRelayForgetsRetiredResolvers(t *testing.T) {
	t.Parallel()
	forwarder, _ := retireForwarder(t)
	forwarder.SetRelay([]netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil, nil)
	forwarder.SetRelay(nil, nil, nil)
	forwarder.ClearRelay()
	if relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.5") {
		t.Fatal("a cleared forwarder relays to a retired resolver")
	}
}

// An answer that cannot carry the relay status becomes a SERVFAIL that
// does, so the consumer never takes the exit node for an old one
// (TD-CLI-72).
func TestMarkRelayedFallsBackToAMarkedFailure(t *testing.T) {
	t.Parallel()
	query := packRelayQuery(t, "wiki.corp.", dnsmessage.TypeA, zoneResolverX)
	large := unpackMessage(t, query)
	large.Response = true
	for index := range 4500 {
		large.Answers = append(large.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name: large.Questions[0].Name, Type: dnsmessage.TypeA,
				Class: dnsmessage.ClassINET, TTL: 30,
			},
			Body: &dnsmessage.AResource{A: [4]byte{93, 184, byte(index >> 8), byte(index)}},
		})
	}
	tooLarge, err := large.Pack()
	if err != nil || len(tooLarge) <= maxDNSMessageBytes {
		t.Fatalf("%d bytes, %v", len(tooLarge), err)
	}
	for name, response := range map[string][]byte{"unreadable": {1, 2, 3}, "too large": tooLarge} {
		marked := markRelayed(query, response, "tcp", relayAnswered)
		status, ok := relayStatusOf(marked)
		if !ok || status != relayAnswered {
			t.Fatalf("%s: status %d %v", name, status, ok)
		}
		if message := unpackMessage(t, marked); message.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("%s: rcode %v", name, message.RCode)
		}
	}
}

// A relayed answer never points the consumer into the mesh; other private
// addresses stay (DNS design D1c Q2).
func TestRelayedAnswersHideTheMeshRanges(t *testing.T) {
	t.Parallel()
	hides := relayedAnswerHides(nil, nil, []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0:ab12::7")})
	for address, want := range map[string]bool{
		"100.64.1.2": true, "100.127.255.1": true, "198.18.0.5": true, "198.19.1.1": true,
		"fd00::1": true, "fd7a:115c:a1e0:1::9": true,
		"10.20.0.5": false, "192.168.1.10": false, "93.184.216.34": false, "fd12:3456::1": false,
	} {
		if got := hides(netip.MustParseAddr(address)); got != want {
			t.Fatalf("%s hidden = %v, want %v", address, got, want)
		}
	}
}

// Maps that keep coming during the grace never extend it; a consumer that
// leaves a scope keeps the resolver for the grace, and a resolver moved to
// another scope keeps its old consumers for the grace too.
func TestExitForwarderRetiresPerConsumerWithoutExtending(t *testing.T) {
	t.Parallel()
	forwarder, now := retireForwarder(t)
	x := netip.MustParseAddr("9.9.9.9")
	scope := func(sources ...string) []networkmap.RelayScope {
		prefixes := make([]netip.Prefix, 0, len(sources))
		for _, source := range sources {
			prefixes = append(prefixes, netip.MustParsePrefix(source+"/32"))
		}
		return []networkmap.RelayScope{{Targets: []netip.Addr{x}, Sources: prefixes}}
	}
	forwarder.SetRelay(nil, scope("100.64.0.4", "100.64.0.5"), nil)
	forwarder.SetRelay(nil, scope("100.64.0.4"), nil) // 100.64.0.5 left the scope
	for range 5 {
		*now = now.Add(20 * time.Second)
		forwarder.SetRelay(nil, scope("100.64.0.4"), nil)
	}
	if !relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.5") {
		t.Fatal("a consumer that left the scope lost the resolver within the grace")
	}
	*now = now.Add(relayRetireGrace - 100*time.Second)
	forwarder.SetRelay(nil, scope("100.64.0.4"), nil)
	if relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.5") || !relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.4") {
		t.Fatal("later maps extended the grace, or the scope lost its consumer")
	}

	// Open, then scoped, then gone: each consumer keeps it until its own
	// deadline, the scoped one the later.
	forwarder, now = retireForwarder(t)
	forwarder.SetRelay([]netip.Addr{x}, nil, nil)
	*now = now.Add(time.Minute)
	forwarder.SetRelay(nil, scope("100.64.0.4"), nil)
	*now = now.Add(time.Minute - time.Second)
	forwarder.SetRelay(nil, nil, nil)
	*now = now.Add(time.Minute + 2*time.Second) // past the open deadline
	if relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.9") || !relayAllowedFor(forwarder, "9.9.9.9", "100.64.0.4") {
		t.Fatal("the open grace and the scoped one are not each kept")
	}
}

// Over UDP too, a failure that must carry the status does.
func TestMarkRelayedMarksAFailureOverUDP(t *testing.T) {
	t.Parallel()
	query := packRelayQuery(t, "wiki.corp.", dnsmessage.TypeA, zoneResolverX)
	marked := markRelayed(query, []byte{1, 2, 3}, "udp", relayNoAnswer)
	if status, ok := relayStatusOf(marked); !ok || status != relayNoAnswer {
		t.Fatalf("status %d %v", status, ok)
	}
}

// A signed question keeps its bytes: clamping its EDNS would break the TSIG.
func TestClampEDNSSizeLeavesSignedQuestions(t *testing.T) {
	t.Parallel()
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 9},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{
			{Header: opt, Body: &dnsmessage.OPTResource{}},
			{Header: dnsmessage.ResourceHeader{
				Name: dnsmessage.MustNewName("key.example."), Type: typeTSIG,
				Class: dnsmessage.ClassANY,
			}, Body: &dnsmessage.UnknownResource{Type: typeTSIG, Data: []byte{1, 2, 3}}},
		},
	}
	signedQuery, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if clamped := clampEDNSSize(signedQuery); string(clamped) != string(signedQuery) {
		t.Fatal("a signed question was written again")
	}
	message.Additionals = message.Additionals[:1]
	plain, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if clamped := clampEDNSSize(plain); string(clamped) == string(plain) {
		t.Fatal("an unsigned question kept its 4096-byte EDNS")
	}
}
