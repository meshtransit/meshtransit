package dnsconfig

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// extendedErrorOf returns the Extended DNS Error a response carries.
func extendedErrorOf(t *testing.T, message dnsmessage.Message) (uint16, string, bool) {
	t.Helper()
	for _, additional := range message.Additionals {
		opt, ok := additional.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, option := range opt.Options {
			if option.Code == ednsOptionExtendedError && len(option.Data) >= 2 {
				return binary.BigEndian.Uint16(option.Data), string(option.Data[2:]), true
			}
		}
	}
	return 0, "", false
}

func resolveEDNS(t *testing.T, engine *resolverEngine, plan Plan, name string) dnsmessage.Message {
	t.Helper()
	response, _ := engine.resolve(t.Context(), plan, packEDNS0Query(t, name, dnsmessage.TypeA, 1232), "udp")
	return unpackMessage(t, response)
}

// With failuresAsNXDOMAIN (Android) a zone's failure is NXDOMAIN with the
// reason as an Extended DNS Error: a resolver that refused, one that failed,
// none that answered; without EDNS the reason is left out. Without it the
// answers are as before (DNS design D1b §5.3, §20).
func TestResolverEngineAnswersFailuresAsNXDOMAIN(t *testing.T) {
	t.Parallel()
	refusing := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	failing := startCountingUpstream(t, dnsmessage.RCodeServerFailure, netip.Addr{}, false)
	network := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("192.0.2.70"), false)
	android := zoneEngine(t, network.address)
	android.failuresAsNXDOMAIN = true
	desktop := zoneEngine(t, network.address)
	for name, test := range map[string]struct {
		root    Route
		rcode   dnsmessage.RCode // without the option
		ede     uint16
		edeText string
	}{
		"refused": {
			Route{Suffix: ".", Resolvers: []netip.AddrPort{refusing.address}, FailOpen: true},
			dnsmessage.RCodeRefused, edeProhibited, "resolver refused",
		},
		"failed": {
			Route{Suffix: ".", Resolvers: []netip.AddrPort{failing.address}, FailOpen: true},
			dnsmessage.RCodeServerFailure, edeOther, "resolver failed",
		},
		"closed, unavailable": {
			Route{Suffix: ".", Unavailable: true},
			dnsmessage.RCodeServerFailure, edeNoReachableAuthority, "no resolver answered",
		},
	} {
		plan := rootPlan(test.root)
		message := resolveEDNS(t, android, plan, "blocked.example.")
		code, text, found := extendedErrorOf(t, message)
		if message.RCode != dnsmessage.RCodeNameError || len(message.Answers) != 0 || !found || code != test.ede ||
			text != test.edeText {
			t.Errorf("%s: %v, EDE %d %q %t", name, message.RCode, code, text, found)
		}
		plain := resolveName(t, android, plan, "blocked-plain.example.", dnsmessage.TypeA)
		if _, _, found := extendedErrorOf(t, plain); plain.RCode != dnsmessage.RCodeNameError || found {
			t.Errorf("%s without EDNS: %v, EDE %t", name, plain.RCode, found)
		}
		if got := resolveEDNS(t, desktop, plan, "blocked.example.").RCode; got != test.rcode {
			t.Errorf("%s on the desktop: %v, want %v", name, got, test.rcode)
		}
	}
	if network.asked.Load() != 0 {
		t.Fatalf("a failure fell open to the network %d times", network.asked.Load())
	}
	// Answers and fail open are unchanged.
	open := rootPlan(Route{Suffix: ".", Unavailable: true, FailOpen: true})
	if got := firstA(t, resolveName(t, android, open, "www.example.com.", dnsmessage.TypeA)); got !=
		netip.MustParseAddr("192.0.2.70") {
		t.Fatalf("fail open answered %s", got)
	}
	if message := resolveName(t, android, open, "use-application-dns.net.", dnsmessage.TypeA); message.RCode !=
		dnsmessage.RCodeNameError {
		t.Fatalf("canary = %v", message.RCode)
	}
}

// A zone that fails closed answers its names NXDOMAIN on Android, and a
// CNAME of the mesh into a refused name too.
func TestResolverEngineAnswersAZoneAndAChaseFailureAsNXDOMAIN(t *testing.T) {
	t.Parallel()
	refusing := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	plan, engine := namesPlan(t)
	engine.failuresAsNXDOMAIN = true
	plan.Routes = append(plan.Routes, Route{Suffix: "corp.example", Unavailable: true})
	if message := resolveEDNS(t, engine, plan, "app.corp.example."); message.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("a closed zone = %v", message.RCode)
	}
	plan.Root = &Route{Suffix: ".", Resolvers: []netip.AddrPort{refusing.address}}
	help := resolveName(t, engine, plan, "help.corp.lan.", dnsmessage.TypeA)
	if help.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("a chase into a refused name = %v", help.RCode)
	}
}

func TestPacketResolverTakesFailuresAsNXDOMAIN(t *testing.T) {
	t.Parallel()
	if !NewPacketResolver(PacketResolverOptions{FailuresAsNXDOMAIN: true}).engine.failuresAsNXDOMAIN ||
		NewPacketResolver(PacketResolverOptions{}).engine.failuresAsNXDOMAIN {
		t.Fatal("the option does not reach the engine")
	}
}

// soaOf returns the owner and TTL of a response's SOA.
func soaOf(t *testing.T, message dnsmessage.Message) (string, uint32, bool) {
	t.Helper()
	for _, authority := range message.Authorities {
		if soa, ok := authority.Body.(*dnsmessage.SOAResource); ok {
			return authority.Header.Name.String(), min(authority.Header.TTL, soa.MinTTL), true
		}
	}
	return "", 0, false
}

// A resolver's NOTIMP is a failure too; a resolver's failure is cached as
// long as other negative answers, one no resolver answered not at all, and
// the SOA speaks for the zone.
func TestResolverEngineNXDOMAINFailuresCarryTheZoneAndTheirCaching(t *testing.T) {
	t.Parallel()
	notImplemented := startCountingUpstream(t, dnsmessage.RCodeNotImplemented, netip.Addr{}, false)
	refusing := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	engine := zoneEngine(t)
	engine.failuresAsNXDOMAIN = true
	for name, test := range map[string]struct {
		route Route
		ttl   uint32
		ede   uint16
	}{
		"notimp":      {Route{Suffix: "corp.example", Resolvers: []netip.AddrPort{notImplemented.address}}, 10, edeOther},
		"refused":     {Route{Suffix: "corp.example", Resolvers: []netip.AddrPort{refusing.address}}, 10, edeProhibited},
		"unavailable": {Route{Suffix: "corp.example", Unavailable: true}, 0, edeNoReachableAuthority},
	} {
		plan := Plan{Enabled: true, Routes: []Route{test.route}}
		message := resolveEDNS(t, engine, plan, "app.corp.example.")
		owner, ttl, found := soaOf(t, message)
		code, _, edeFound := extendedErrorOf(t, message)
		if message.RCode != dnsmessage.RCodeNameError || !found || owner != "corp.example." || ttl != test.ttl ||
			!edeFound || code != test.ede {
			t.Errorf("%s: %v, SOA %q ttl %d %t, EDE %d %t", name, message.RCode, owner, ttl, found, code, edeFound)
		}
	}
}

// A CNAME of the mesh chased into a refused name keeps the reason.
func TestResolverEngineChaseFailureCarriesTheReason(t *testing.T) {
	t.Parallel()
	refusing := startCountingUpstream(t, dnsmessage.RCodeRefused, netip.Addr{}, false)
	plan, engine := namesPlan(t)
	engine.failuresAsNXDOMAIN = true
	plan.Root = &Route{Suffix: ".", Resolvers: []netip.AddrPort{refusing.address}}
	message := resolveEDNS(t, engine, plan, "help.corp.lan.")
	code, text, found := extendedErrorOf(t, message)
	owner, _, _ := soaOf(t, message)
	if message.RCode != dnsmessage.RCodeNameError || !found || code != edeProhibited || text != "resolver refused" ||
		owner != "corp.lan." {
		t.Fatalf("chase = %v, EDE %d %q %t, SOA %q", message.RCode, code, text, found, owner)
	}
}
