package dnsconfig

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/networkmap"
)

func TestWithoutPrivateAnswersDropsWhatIsNoInternet(t *testing.T) {
	t.Parallel()
	name := dnsmessage.MustNewName("printer.corp.example.")
	header := func(kind dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: name, Type: kind, Class: dnsmessage.ClassINET, TTL: 30}
	}
	https := &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: name}}
	https.SetParam(dnsmessage.SVCParamIPv4Hint, []byte{10, 1, 2, 3})
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			{Header: header(dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{10, 1, 2, 3}}},
			{Header: header(dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}},
			{Header: header(dnsmessage.TypeAAAA), Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("fd12::1").As16()}},
			{Header: header(dnsmessage.TypeHTTPS), Body: https},
			{Header: header(dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{45, 76, 10, 10}}},
		},
	}
	packed, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	own := netip.MustParsePrefix("45.76.10.8/29")
	filtered, err := withoutPrivateAnswers(packed, func(address netip.Addr) bool {
		return address.IsPrivate() || own.Contains(address)
	})
	if err != nil {
		t.Fatal(err)
	}
	got := unpackMessage(t, filtered)
	if len(got.Answers) != 1 || got.ID != 7 {
		t.Fatalf("answers = %#v", got.Answers)
	}
	if answer, ok := got.Answers[0].Body.(*dnsmessage.AResource); !ok || answer.A != [4]byte{93, 184, 216, 34} {
		t.Fatalf("kept %#v", got.Answers[0].Body)
	}
	// Nothing to remove: the upstream's bytes go back unchanged.
	public := message
	public.Answers = message.Answers[1:2]
	packed, _ = public.Pack()
	if unchanged, err := withoutPrivateAnswers(packed, func(netip.Addr) bool { return false }); err != nil ||
		string(unchanged) != string(packed) {
		t.Fatalf("an unfiltered response changed: %v", err)
	}
}

func TestCompileSendsNamesToTheExitNode(t *testing.T) {
	t.Parallel()
	snapshot := networkmap.Snapshot{
		Revision: 3,
		Peers: []networkmap.Node{{StableID: "exit", Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.9/32"), netip.MustParsePrefix("fd7a::9/128"),
		}}},
		Exits: []networkmap.ExitPool{{Ref: "pool", Candidates: []networkmap.ExitCandidate{{
			DeviceID: "exit", DNS4: netip.MustParseAddr("100.64.0.9"), DNS6: netip.MustParseAddr("fd7a::9"),
		}}}},
		ExitRoute: &networkmap.ExitRoute{Pool: "pool", Node: "exit", IPv6: true},
	}
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("100.64.0.9:53"), netip.MustParseAddrPort("[fd7a::9]:53")}
	if !plan.Enabled || plan.Exit == nil || !plan.Exit.IPv6 || len(plan.Exit.Resolvers) != 2 ||
		plan.Exit.Resolvers[0] != want[0] || plan.Exit.Resolvers[1] != want[1] {
		t.Fatalf("plan = %+v", plan)
	}
	config, err := buildResolvedConfig(plan, testDNSEndpoint())
	if err != nil || !config.DefaultRoute {
		t.Fatalf("the resolver is not the host's default with an exit node: %+v, %v", config, err)
	}
	// An address that is not the exit node's own, such as one on the
	// Internet a compromised Core names, is never asked.
	snapshot.Exits[0].Candidates[0].DNS4 = netip.MustParseAddr("8.8.8.8")
	snapshot.Exits[0].Candidates[0].DNS6 = netip.MustParseAddr("fd7a::10")
	if plan, err := Compile(snapshot); err != nil || len(plan.Exit.Resolvers) != 0 {
		t.Fatalf("plan with foreign DNS addresses = %+v, %v", plan.Exit, err)
	}
	// No exit node yet: still the default, answering nothing.
	snapshot.ExitRoute.Node = ""
	if plan, err := Compile(snapshot); err != nil || plan.Exit == nil || len(plan.Exit.Resolvers) != 0 {
		t.Fatalf("plan without an exit node = %+v, %v", plan, err)
	}
}

func TestResolverEngineAsksTheExitNode(t *testing.T) {
	t.Parallel()
	exit := startUDPUpstream(t, netip.MustParseAddr("93.184.216.34"))
	site := startUDPUpstream(t, netip.MustParseAddr("10.35.0.7"))
	plan := Plan{
		Enabled: true,
		Routes:  []Route{{Suffix: "corp.example", Resolvers: []netip.AddrPort{site}}},
		Exit:    &ExitDNS{Resolvers: []netip.AddrPort{exit}},
	}
	for name, want := range map[string]netip.Addr{
		"public.example.":    netip.MustParseAddr("93.184.216.34"),
		"wiki.corp.example.": netip.MustParseAddr("10.35.0.7"), // a Site's resolver keeps its suffix
	} {
		response, err := newResolverEngine().resolve(t.Context(), plan, packQuery(t, name, dnsmessage.TypeA), "udp")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := firstA(t, unpackMessage(t, response)); got != want {
			t.Fatalf("%s: answer %s, want %s", name, got, want)
		}
	}
	// Without IPv6 at the exit node, AAAA has no data at once.
	response, err := newResolverEngine().resolve(t.Context(), plan, packQuery(t, "public.example.", dnsmessage.TypeAAAA), "udp")
	if err != nil {
		t.Fatal(err)
	}
	if message := unpackMessage(t, response); message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 0 {
		t.Fatalf("AAAA without IPv6 = %v %#v", message.RCode, message.Answers)
	}
	// No exit node: a failure, never the host's own resolvers.
	plan.Exit = &ExitDNS{}
	response, _ = newResolverEngine().resolve(t.Context(), plan, packQuery(t, "public.example.", dnsmessage.TypeA), "udp")
	if message := unpackMessage(t, response); message.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("without an exit node = %v", message.RCode)
	}
}

func TestExitForwarderAnswersFromTheHostResolver(t *testing.T) {
	t.Parallel()
	upstream := startUDPUpstream(t, netip.MustParseAddr("93.184.216.34"))
	resolvConf := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolvConf, []byte("# host\nnameserver 127.0.0.1\nnameserver fe80::1%eth0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	forwarder := NewExitForwarder(nil, func() []netip.Prefix { return nil })
	forwarder.port, forwarder.upstreamPort, forwarder.resolvConf = 0, upstream.Port(), resolvConf
	forwarder.Configure([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil)
	t.Cleanup(forwarder.Close)
	forwarder.lifecycle.Lock()
	listening := forwarder.udp[0].LocalAddr().String()
	forwarder.lifecycle.Unlock()
	connection, err := (&net.Dialer{}).DialContext(t.Context(), "udp", listening)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := connection.Write(packQuery(t, "public.example.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, maxDNSMessageBytes)
	count, err := connection.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := firstA(t, unpackMessage(t, buffer[:count])); got != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("answer %s", got)
	}
	if forwarder.Failing() {
		t.Fatal("an answering upstream was reported failing")
	}
}

func TestExitForwarderBoundsEachConsumer(t *testing.T) {
	t.Parallel()
	forwarder := NewExitForwarder(nil, func() []netip.Prefix { return nil })
	consumer, other := netip.MustParseAddr("100.64.0.4"), netip.MustParseAddr("100.64.0.5")
	now := time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)
	for range exitQuestionBurst {
		if !forwarder.chargeLocked(consumer, now) {
			t.Fatal("a question within the burst was refused")
		}
	}
	if forwarder.chargeLocked(consumer, now) {
		t.Fatal("a question beyond the burst was answered")
	}
	if !forwarder.chargeLocked(other, now) {
		t.Fatal("one consumer's questions refused another's")
	}
	if !forwarder.chargeLocked(consumer, now.Add(100*time.Millisecond)) {
		t.Fatal("the rate did not refill")
	}
}

// firstA returns the only answer of message, an A record.
func firstA(t *testing.T, message dnsmessage.Message) netip.Addr {
	t.Helper()
	if len(message.Answers) != 1 {
		t.Fatalf("answers %#v, want one", message.Answers)
	}
	answer, ok := message.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer %#v is no A record", message.Answers[0].Body)
	}
	return netip.AddrFrom4(answer.A)
}

func TestExitForwarderKeepsTheExitNetworksOwnNames(t *testing.T) {
	t.Parallel()
	forwarder := NewExitForwarder(nil, func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("45.76.10.8/29")} })
	for _, name := range []string{"5.0.35.10.in-addr.arpa.", "10.10.76.45.in-addr.arpa."} {
		response := forwarder.answer(t.Context(), packQuery(t, name, dnsmessage.TypePTR), "udp", netip.MustParseAddr("100.64.0.4"))
		if message := unpackMessage(t, response); message.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("%s: %v", name, message.RCode)
		}
	}
}

func TestExitForwarderBoundsWhatOneConsumerHolds(t *testing.T) {
	t.Parallel()
	forwarder := NewExitForwarder(nil, nil)
	consumer := netip.MustParseAddr("100.64.0.4")
	for range maxExitConsumerConnections {
		if !forwarder.hold(consumer, maxExitConsumerConnections) {
			t.Fatal("a connection within the limit was refused")
		}
	}
	if forwarder.hold(consumer, maxExitConsumerConnections) {
		t.Fatal("a connection beyond the limit was taken")
	}
	if !forwarder.hold(netip.MustParseAddr("100.64.0.5"), maxExitConsumerConnections) {
		t.Fatal("one consumer's connections refused another's")
	}
	forwarder.release(consumer)
	if !forwarder.hold(consumer, maxExitConsumerConnections) {
		t.Fatal("a released connection was not freed")
	}
}

func TestExitForwarderFailsOnlyAfterAQuietWindow(t *testing.T) {
	t.Parallel()
	forwarder := NewExitForwarder(nil, nil)
	forwarder.running, forwarder.answeredAt = true, time.Now()
	for range exitFailuresToFail {
		forwarder.noteUpstream(false)
	}
	if forwarder.Failing() {
		t.Fatal("failing while the upstreams answered recently")
	}
	forwarder.answeredAt = time.Now().Add(-exitFailingAfter)
	if !forwarder.Failing() {
		t.Fatal("not failing after a quiet window")
	}
	forwarder.noteUpstream(true)
	if forwarder.Failing() {
		t.Fatal("still failing after an answer")
	}
}
