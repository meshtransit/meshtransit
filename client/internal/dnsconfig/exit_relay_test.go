package dnsconfig

import (
	"net/netip"
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// relayForwarder is a forwarder on an exit node whose own network is
// 45.76.10.8/29, relaying to listed and asking upstream in their place.
func relayForwarder(t *testing.T, upstream netip.AddrPort, listed ...string) *ExitForwarder {
	t.Helper()
	forwarder := NewExitForwarder(nil, func() []netip.Prefix {
		return []netip.Prefix{netip.MustParsePrefix("45.76.10.8/29")}
	})
	absent := filepath.Join(t.TempDir(), "absent")
	forwarder.resolvConf, forwarder.resolvedConf, forwarder.relayUpstream = absent, absent, upstream
	targets := make([]netip.Addr, 0, len(listed))
	for _, address := range listed {
		targets = append(targets, netip.MustParseAddr(address))
	}
	forwarder.SetRelay(targets, []netip.Prefix{netip.MustParsePrefix("52.10.0.0/24")})
	return forwarder
}

// packRelayQuery is a question with EDNS asking to relay to target, with
// any other options.
func packRelayQuery(t *testing.T, name string, recordType dnsmessage.Type, target netip.AddrPort,
	options ...dnsmessage.Option,
) []byte {
	t.Helper()
	query := unpackMessage(t, packQuery(t, name, recordType))
	header := dnsmessage.ResourceHeader{}
	if err := header.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	query.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.OPTResource{
		Options: append([]dnsmessage.Option{{Code: ednsOptionRelay, Data: encodeRelayTarget(target)}}, options...),
	}}}
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func relayAnswer(t *testing.T, forwarder *ExitForwarder, query []byte) (dnsmessage.Message, byte) {
	t.Helper()
	response := forwarder.answer(t.Context(), query, "udp", netip.MustParseAddr("100.64.0.4"))
	status, ok := relayStatusOf(response)
	if !ok {
		t.Fatalf("answer %x carries no relay status", response)
	}
	return unpackMessage(t, response), status
}

func TestRelayTargetRoundTrips(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"9.9.9.9:53", "[2606:4700:4700::1111]:53"} {
		want := netip.MustParseAddrPort(target)
		got, err := decodeRelayTarget(encodeRelayTarget(want))
		if err != nil || got != want {
			t.Fatalf("%s: got %s, %v", target, got, err)
		}
	}
	for name, data := range map[string][]byte{
		"empty":          nil,
		"other version":  {2, 1, 0, 53, 9, 9, 9, 9},
		"short v4":       {1, 1, 0, 53, 9, 9, 9},
		"v4 as v6 size":  {1, 2, 0, 53, 9, 9, 9, 9},
		"unknown family": {1, 3, 0, 53, 9, 9, 9, 9},
		"mapped v4": append([]byte{1, 2, 0, 53},
			netip.MustParseAddr("::ffff:9.9.9.9").AsSlice()...),
	} {
		if _, err := decodeRelayTarget(data); err == nil {
			t.Fatalf("%s: decoded", name)
		}
	}
}

func FuzzDecodeRelayTarget(f *testing.F) {
	f.Add(encodeRelayTarget(netip.MustParseAddrPort("9.9.9.9:53")))
	f.Add(encodeRelayTarget(netip.MustParseAddrPort("[2606:4700:4700::1111]:53")))
	f.Add([]byte{1, 2, 0, 53})
	f.Fuzz(func(t *testing.T, data []byte) {
		target, err := decodeRelayTarget(data)
		if err != nil {
			return
		}
		if again, err := decodeRelayTarget(encodeRelayTarget(target)); err != nil || again != target {
			t.Fatalf("%x: %s does not round-trip: %s, %v", data, target, again, err)
		}
	})
}

// A listed resolver is asked for any name, the exit network's own included,
// and its private answers stay: the admins chose it (DNS design D1c Q2).
func TestExitForwarderRelaysToAListedResolver(t *testing.T) {
	t.Parallel()
	forwarder := relayForwarder(t, startUDPUpstream(t, netip.MustParseAddr("10.20.0.5")), "9.9.9.9")
	message, status := relayAnswer(t, forwarder,
		packRelayQuery(t, "wiki.corp.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53")))
	if status != relayAnswered || message.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("status %d, %v", status, message.RCode)
	}
	if got := firstA(t, message); got != netip.MustParseAddr("10.20.0.5") {
		t.Fatalf("answer %s", got)
	}
}

func TestExitForwarderPassesOnTheResolversRefusal(t *testing.T) {
	t.Parallel()
	forwarder := relayForwarder(t, startUDPResponseUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}), "9.9.9.9")
	message, status := relayAnswer(t, forwarder,
		packRelayQuery(t, "blocked.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53")))
	if status != relayAnswered || message.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("status %d, %v", status, message.RCode)
	}
}

func TestExitForwarderRelayedAnswersHideTheExitsOwn(t *testing.T) {
	t.Parallel()
	for _, hidden := range []string{"169.254.169.254", "45.76.10.9", "52.10.0.7", "127.0.0.1", "0.0.0.0"} {
		forwarder := relayForwarder(t, startUDPUpstream(t, netip.MustParseAddr(hidden)), "9.9.9.9")
		message, status := relayAnswer(t, forwarder,
			packRelayQuery(t, "public.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53")))
		if status != relayAnswered || message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 0 {
			t.Fatalf("%s: status %d, %v %#v", hidden, status, message.RCode, message.Answers)
		}
	}
}

func TestExitForwarderRefusesWhatItDoesNotRelay(t *testing.T) {
	t.Parallel()
	listed := []string{"9.9.9.9", "45.76.10.10", "52.10.0.53", "2606:4700:4700::1111", "10.0.0.53"}
	duplicate := dnsmessage.Option{Code: ednsOptionRelay, Data: encodeRelayTarget(netip.MustParseAddrPort("9.9.9.9:53"))}
	malformed := unpackMessage(t, packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53")))
	malformed.Additionals[0].Body = &dnsmessage.OPTResource{
		Options: []dnsmessage.Option{{Code: ednsOptionRelay, Data: []byte{relayVersion, 9}}},
	}
	malformedQuery, err := malformed.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string][]byte{
		"not listed":         packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("8.8.8.8:53")),
		"not port 53":        packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:5353")),
		"the exit's network": packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("45.76.10.10:53")),
		"a served Site":      packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("52.10.0.53:53")),
		"IPv6 without IPv6":  packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("[2606:4700:4700::1111]:53")),
		"private":            packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("10.0.0.53:53")),
		"the option twice":   packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53"), duplicate),
		"a malformed option": malformedQuery,
	} {
		forwarder := relayForwarder(t, netip.AddrPort{}, listed...)
		message, status := relayAnswer(t, forwarder, query)
		if status != relayNotAllowed || message.RCode != dnsmessage.RCodeRefused {
			t.Fatalf("%s: status %d, %v", name, status, message.RCode)
		}
	}
}

func TestExitForwarderRelaysOverIPv6WhereTheHostHasIt(t *testing.T) {
	t.Parallel()
	forwarder := relayForwarder(t, netip.AddrPort{}, "2606:4700:4700::1111")
	target := netip.MustParseAddrPort("[2606:4700:4700::1111]:53")
	if forwarder.relayAllowed(target, []netip.Prefix{netip.MustParsePrefix("45.76.10.8/29")}) {
		t.Fatal("relayed over IPv6 from a host without it")
	}
	if !forwarder.relayAllowed(target, []netip.Prefix{netip.MustParsePrefix("2600:1f18::5/128")}) {
		t.Fatal("did not relay over IPv6 from a host with it")
	}
}

// A resolver that does not answer is the resolver's fault, until a second
// one does not either, or the exit node's probes find no way out.
func TestExitForwarderTellsWhoDidNotAnswer(t *testing.T) {
	t.Parallel()
	silent := startUnresponsiveUDPUpstream(t)
	forwarder := relayForwarder(t, silent, "9.9.9.9", "1.1.1.1")
	ask := func(target string) (dnsmessage.Message, byte) {
		return relayAnswer(t, forwarder,
			packRelayQuery(t, "public.example.", dnsmessage.TypeA, netip.MustParseAddrPort(target)))
	}
	if message, status := ask("9.9.9.9:53"); status != relayNoAnswer || message.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("one silent resolver: status %d, %v", status, message.RCode)
	}
	if _, status := ask("1.1.1.1:53"); status != relayUplinkDown {
		t.Fatalf("two silent resolvers: status %d", status)
	}

	down := relayForwarder(t, silent, "9.9.9.9")
	down.SetUplinkDown(true)
	message, status := relayAnswer(t, down,
		packRelayQuery(t, "public.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53")))
	if status != relayUplinkDown || message.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("probes down: status %d, %v", status, message.RCode)
	}
}

func TestExitForwarderHoldsBackAResolverThatKeepsNotAnswering(t *testing.T) {
	t.Parallel()
	forwarder := relayForwarder(t, netip.AddrPort{}, "9.9.9.9")
	target := netip.MustParseAddr("9.9.9.9")
	for range maxStalledRelayQuestions {
		if !forwarder.holdRelay(target) {
			t.Fatal("an answering resolver was held back")
		}
	}
	if !forwarder.holdRelay(target) {
		t.Fatal("an answering resolver was capped")
	}
	forwarder.releaseRelay(target)
	for range relayStalledAfter {
		forwarder.noteRelay(target, false)
	}
	if forwarder.holdRelay(target) {
		t.Fatal("a stalled resolver took more than its share")
	}
	if !forwarder.holdRelay(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("a stalled resolver held back another")
	}
	forwarder.noteRelay(target, true)
	if !forwarder.holdRelay(target) {
		t.Fatal("a resolver that answered again stayed held back")
	}

	message := unpackMessage(t, packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53")))
	busy := forwarder.relay(t.Context(), packRelayQuery(t, "a.example.", dnsmessage.TypeA,
		netip.MustParseAddrPort("9.9.9.9:53")), message, message.Questions[0], "udp",
		netip.MustParseAddrPort("9.9.9.9:53"), false, nil)
	if status, _ := relayStatusOf(busy); status != relayBusy || unpackMessage(t, busy).RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("not admitted: status %d", status)
	}
}

// Every answer to a relayed question carries its status; one to any other
// question carries none.
func TestExitForwarderMarksEveryRelayedAnswer(t *testing.T) {
	t.Parallel()
	forwarder := relayForwarder(t, netip.AddrPort{}, "9.9.9.9")
	query := unpackMessage(t, packRelayQuery(t, "a.example.", dnsmessage.TypeA, netip.MustParseAddrPort("9.9.9.9:53")))
	query.Additionals[0].Header.TTL |= 1 << 16 // EDNS version 1
	badVersion, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	message, status := relayAnswer(t, forwarder, badVersion)
	if rcode := message.Additionals[len(message.Additionals)-1].Header.ExtendedRCode(message.RCode); status != relayNotAllowed ||
		rcode != 16 { // BADVERS
		t.Fatalf("EDNS version 1: status %d, %v", status, rcode)
	}
	plain := forwarder.answer(t.Context(), packQuery(t, "wiki.", dnsmessage.TypeA), "udp", netip.MustParseAddr("100.64.0.4"))
	if _, ok := relayStatusOf(plain); ok {
		t.Fatal("an answer to a question not relayed carries a relay status")
	}
	if got := withRelayStatus(packQuery(t, "a.example.", dnsmessage.TypeA), plain, relayBusy); string(got) != string(plain) {
		t.Fatal("a status was added to an answer to a question not relayed")
	}
}

func TestWithoutRelayOptionKeepsTheOthers(t *testing.T) {
	t.Parallel()
	other := dnsmessage.Option{Code: 65001, Data: []byte{1}}
	stripped, err := withoutRelayOption(packRelayQuery(t, "a.example.", dnsmessage.TypeA,
		netip.MustParseAddrPort("9.9.9.9:53"), other))
	if err != nil {
		t.Fatal(err)
	}
	message := unpackMessage(t, stripped)
	if _, present, _ := relayOption(message); present {
		t.Fatal("the relay option stayed")
	}
	opt, ok := message.Additionals[0].Body.(*dnsmessage.OPTResource)
	if !ok || len(opt.Options) != 1 || opt.Options[0].Code != other.Code {
		t.Fatalf("options %#v", message.Additionals)
	}
}

// Resolvers that are down themselves are their own fault while others
// answer: the exit node's way out is down only when nothing answered since.
func TestExitForwarderTellsADeadResolverFromADeadUplink(t *testing.T) {
	t.Parallel()
	forwarder := relayForwarder(t, netip.AddrPort{}, "9.9.9.9", "1.1.1.1", "8.8.8.8")
	first, second := netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("1.1.1.1")
	if forwarder.noteRelay(first, false) {
		t.Fatal("one silent resolver took the uplink down")
	}
	if !forwarder.noteRelay(second, false) {
		t.Fatal("two silent resolvers and no answer left the uplink up")
	}
	forwarder.noteRelay(netip.MustParseAddr("8.8.8.8"), true)
	if forwarder.noteRelay(first, false) || forwarder.noteRelay(second, false) {
		t.Fatal("dead resolvers took the uplink down while another answered")
	}
	forwarder.SetRelay([]netip.Addr{second}, nil)
	forwarder.mu.Lock()
	_, kept := forwarder.relayStalled[first]
	forwarder.mu.Unlock()
	if kept {
		t.Fatal("a resolver no longer listed is still tracked")
	}
}

// The status counts within the asker's UDP size: an answer that fits only
// without it is truncated, still marked.
func TestRelayStatusFitsTheAskersUDPSize(t *testing.T) {
	t.Parallel()
	query := unpackMessage(t, packRelayQuery(t, "big.example.", dnsmessage.TypeA, zoneResolverX))
	query.Additionals[0].Header.Class = defaultUDPSize
	packedQuery, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	response := query
	response.Response = true
	header := dnsmessage.ResourceHeader{}
	if err := header.SetEDNS0(defaultUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	response.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.OPTResource{}}}
	for index := 0; ; index++ {
		response.Answers = append(response.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30,
			},
			Body: &dnsmessage.AResource{A: [4]byte{93, 184, 0, byte(index)}},
		})
		packed, err := response.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if len(packed) > defaultUDPSize-6 {
			marked := markRelayed(packedQuery, packed, "udp", relayAnswered)
			message := unpackMessage(t, marked)
			if status, ok := relayStatusOf(marked); len(marked) > defaultUDPSize || !ok || status != relayAnswered ||
				(len(packed) <= defaultUDPSize && !message.Truncated) {
				t.Fatalf("%d bytes from %d: truncated %v, status %d %v", len(marked), len(packed), message.Truncated, status, ok)
			}
			return
		}
	}
}
