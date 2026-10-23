package dnsconfig

import (
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/underlay"
)

var packetResolverAddress = netip.MustParseAddr("192.0.2.53")

func newTestPacketResolver(t *testing.T, exitRouted *atomic.Bool, network ...netip.AddrPort) *PacketResolver {
	t.Helper()
	options := PacketResolverOptions{
		Address:          packetResolverAddress,
		MaxUDPResponse:   1252,
		NetworkResolvers: func() []netip.AddrPort { return slices.Clone(network) },
	}
	if exitRouted != nil {
		options.ExitRouted = exitRouted.Load
	}
	return NewPacketResolver(options)
}

func answerPacket(t *testing.T, resolver *PacketResolver, plan Plan, name string) dnsmessage.Message {
	t.Helper()
	if err := resolver.Apply(t.Context(), plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	response := resolver.Answer(t.Context(), packQuery(t, name, dnsmessage.TypeA))
	if response == nil {
		t.Fatalf("no answer for %s", name)
	}
	return unpackMessage(t, response)
}

// Android has no split DNS: every name reaches the resolver, the mesh's
// answered locally and any other from the network's resolvers.
func TestPacketResolverAnswersEveryName(t *testing.T) {
	t.Parallel()
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.10"), false)
	resolver := newTestPacketResolver(t, nil, network.address)
	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatal(err)
	}

	local := answerPacket(t, resolver, plan, "node-a.example.mesh.")
	if local.RCode != dnsmessage.RCodeSuccess || len(local.Answers) != 1 || network.asked.Load() != 0 {
		t.Fatalf("mesh name = %v %v, network asked %d", local.RCode, local.Answers, network.asked.Load())
	}
	internet := answerPacket(t, resolver, plan, "www.example.org.")
	if internet.RCode != dnsmessage.RCodeSuccess || firstA(t, internet) != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("internet name = %v %v", internet.RCode, internet.Answers)
	}
	// A disabled plan (DNS off in the map) still answers from the network.
	disabled := answerPacket(t, resolver, Plan{}, "www.example.org.")
	if disabled.RCode != dnsmessage.RCodeSuccess || network.asked.Load() != 2 {
		t.Fatalf("disabled plan = %v, network asked %d", disabled.RCode, network.asked.Load())
	}
	if stats := resolver.Stats(); stats.Queries != 3 || stats.Failures != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

// While the Internet is routed into the mesh, no name leaves through the
// network until the plan has the exit node's resolvers, whatever else it
// names (DNS design D4 §3.3).
func TestPacketResolverNeverLeaksWhileExitRouted(t *testing.T) {
	t.Parallel()
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.10"), false)
	configured := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.11"), false)
	var exitRouted atomic.Bool
	exitRouted.Store(true)
	resolver := newTestPacketResolver(t, &exitRouted, network.address)

	plans := map[string]Plan{
		"disabled":          {},
		"default resolvers": {Enabled: true, DefaultResolvers: []netip.AddrPort{configured.address}},
		"fail open zone":    {Enabled: true, Routes: []Route{{Suffix: "corp", Unavailable: true, FailOpen: true}}},
		"exit without resolvers": {
			Enabled: true, Exit: &ExitDNS{},
		},
	}
	for name, plan := range plans {
		for _, query := range []string{"www.example.org.", "wiki.corp."} {
			if message := answerPacket(t, resolver, plan, query); message.RCode != dnsmessage.RCodeServerFailure {
				t.Fatalf("%s: %s = %v, want SERVFAIL", name, query, message.RCode)
			}
		}
	}
	if network.asked.Load() != 0 || configured.asked.Load() != 0 {
		t.Fatalf("asked network %d, configured %d", network.asked.Load(), configured.asked.Load())
	}

	// With the exit node's resolvers, names go to them.
	exit := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.12"), false)
	viaExit := answerPacket(t, resolver, Plan{Enabled: true, Exit: &ExitDNS{Resolvers: []netip.AddrPort{exit.address}}},
		"www.example.org.")
	if firstA(t, viaExit) != netip.MustParseAddr("192.0.2.12") || network.asked.Load() != 0 {
		t.Fatalf("via exit = %v, network asked %d", viaExit.Answers, network.asked.Load())
	}

	// Once the routes are gone, the network answers again.
	exitRouted.Store(false)
	if message := answerPacket(t, resolver, Plan{}, "www.example.org."); message.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("after exit = %v", message.RCode)
	}
}

// A zone's Internet resolvers are not asked while the exit node is pending;
// its resolvers in the mesh or a private network still are.
func TestZoneTargetsWhileExitPending(t *testing.T) {
	t.Parallel()
	engine := zoneEngine(t)
	engine.exitRouted = func() bool { return true }
	private := netip.MustParseAddrPort("10.0.0.53:53")
	route := Route{Suffix: "corp", Resolvers: []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:53"), private}}
	targets, _, _ := engine.zoneTargets(Plan{Enabled: true, Routes: []Route{route}}, route,
		dnsmessage.Question{Type: dnsmessage.TypeA})
	if !slices.Equal(targets, []netip.AddrPort{private}) {
		t.Fatalf("targets = %v", targets)
	}
}

// A zone that fails closed never reaches the network's resolvers, also in
// the full resolver mode.
func TestPacketResolverKeepsClosedZonesClosed(t *testing.T) {
	t.Parallel()
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.10"), false)
	resolver := newTestPacketResolver(t, nil, network.address)
	plan := Plan{Enabled: true, Routes: []Route{
		{Suffix: "corp", Unavailable: true},
		{Suffix: "lab", Resolvers: []netip.AddrPort{deadResolver}},
	}}
	for _, name := range []string{"wiki.corp.", "host.lab."} {
		if message := answerPacket(t, resolver, plan, name); message.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("%s = %v", name, message.RCode)
		}
	}
	if network.asked.Load() != 0 {
		t.Fatalf("network asked %d", network.asked.Load())
	}
}

// An answer larger than the interface allows goes back truncated, never in
// a packet larger than the MTU.
func TestPacketResolverCapsAnswersBelowTheMTU(t *testing.T) {
	t.Parallel()
	large := startScriptedUpstream(t, func(query dnsmessage.Message) dnsmessage.Message {
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true},
			Questions: query.Questions,
		}
		for index := range 120 {
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(index)}},
			})
		}
		return response
	})
	resolver := newTestPacketResolver(t, nil, large)
	if err := resolver.Apply(t.Context(), Plan{}); err != nil {
		t.Fatal(err)
	}
	response := resolver.Answer(t.Context(), packEDNS0Query(t, "big.example.org.", dnsmessage.TypeA, 4096))
	if len(response) == 0 || len(response) > 1252 || !isTruncated(response) {
		t.Fatalf("answer of %d bytes, truncated %v", len(response), isTruncated(response))
	}
	if stats := resolver.Stats(); stats.Truncated != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

// The network's resolvers are looked up again as soon as they change.
func TestPacketResolverFollowsNetworkChanges(t *testing.T) {
	t.Parallel()
	first := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.21"), false)
	second := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.22"), false)
	var generation atomic.Uint64
	resolver := NewPacketResolver(PacketResolverOptions{
		NetworkResolvers: func() []netip.AddrPort {
			if generation.Load() == 0 {
				return []netip.AddrPort{first.address}
			}
			return []netip.AddrPort{second.address}
		},
		NetworkGeneration: generation.Load,
	})
	if got := firstA(t, answerPacket(t, resolver, Plan{}, "a.example.org.")); got != netip.MustParseAddr("192.0.2.21") {
		t.Fatalf("first network = %s", got)
	}
	generation.Store(1)
	if got := firstA(t, answerPacket(t, resolver, Plan{}, "a.example.org.")); got != netip.MustParseAddr("192.0.2.22") {
		t.Fatalf("second network = %s", got)
	}
}

func TestPacketResolverRefusesLoopsAndAnswersNothingClosed(t *testing.T) {
	t.Parallel()
	resolver := newTestPacketResolver(t, nil)
	loop := Plan{Enabled: true, DefaultResolvers: []netip.AddrPort{netip.AddrPortFrom(packetResolverAddress, 53)}}
	if err := resolver.Apply(t.Context(), loop); err == nil {
		t.Fatal("a plan asking the resolver itself was applied")
	}
	if resolver.Answer(t.Context(), []byte{1, 2, 3}) != nil {
		t.Fatal("a short message was answered")
	}
	if err := resolver.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if resolver.Answer(t.Context(), packQuery(t, "a.example.org.", dnsmessage.TypeA)) != nil {
		t.Fatal("a closed resolver answered")
	}
	if err := resolver.Apply(t.Context(), Plan{}); err == nil {
		t.Fatal("a closed resolver took a plan")
	}
}

// A private resolver the platform cannot reach is never asked: on a phone,
// a zone's resolver on a LAN it is not on would be asked of the Wi-Fi it is
// on. Not parallel: the reach policy is process-wide.
func TestUnreachablePrivateResolversAreNotAsked(t *testing.T) {
	underlay.SetPrivateReach(func(netip.Addr) bool { return false })
	t.Cleanup(func() { underlay.SetPrivateReach(nil) })
	if !unreachableResolver(netip.MustParseAddr("192.168.7.53")) ||
		unreachableResolver(netip.MustParseAddr("8.8.8.8")) || unreachableResolver(netip.MustParseAddr("100.64.0.9")) {
		t.Fatal("unreachableResolver does not keep private resolvers only")
	}
	if _, err := exchangeDNS(t.Context(), packQuery(t, "a.corp.", dnsmessage.TypeA),
		netip.MustParseAddrPort("192.168.7.53:53"), "udp"); !errors.Is(err, errUnreachableResolver) {
		t.Fatalf("exchangeDNS() error = %v", err)
	}
}
