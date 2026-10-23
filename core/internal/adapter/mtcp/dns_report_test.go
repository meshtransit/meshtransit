package mtcp

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// The digest of an encoded DNS configuration is the vector of
// docs/protocol/dns-digest-v1.md §4.
func TestDigestDNSConfigMatchesTheSpecification(t *testing.T) {
	t.Parallel()
	config := &mtcpv1.DnsConfig{
		Routes: []*mtcpv1.DnsRoute{
			{Suffix: "073438549244.296056403058.mesh.internal"},
			{Suffix: "corp.internal", FailOpen: true, Resolvers: []*mtcpv1.Resolver{
				{Ip: netip.MustParseAddr("100.64.0.21").AsSlice(), Port: 5335},
				{Ip: netip.MustParseAddr("192.0.2.53").AsSlice()},
			}},
			{Suffix: ".", Unavailable: true},
		},
		SearchDomains: []string{"073438549244.296056403058.mesh.internal", "corp.internal"},
		Records:       []*mtcpv1.DnsRecord{{Name: "not.covered", Type: mtcpv1.DnsRecord_A, Value: []byte{1, 2, 3, 4}}},
	}
	digest, err := digestDNSConfig(config)
	if err != nil || digest.Routes() != 3 ||
		digest.Digest().String() != "sha256:e0ade8e76caf31f2f615616fa198aeb45a96511e0161cb2d055923f995c63504" {
		t.Fatalf("digest = %s over %d routes, %v", digest.Digest(), digest.Routes(), err)
	}
}

func dnsHealthReport(resolvers ...*mtcpv1.ResolverHealth) *mtcpv1.DnsHealthReport {
	return &mtcpv1.DnsHealthReport{Resolvers: resolvers}
}

func resolverHealth(address string, port uint32, state mtcpv1.ResolverHealth_State) *mtcpv1.ResolverHealth {
	return &mtcpv1.ResolverHealth{Ip: netip.MustParseAddr(address).AsSlice(), Port: port, State: state}
}

// A node reports resolver health only with dns.root1, and only on the
// resolvers its map sent: others are left out. Reports closer than the
// interval are dropped (mtcp-v1 §8.6).
func TestConversationDNSHealth(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	var violation protocolError
	ok := resolverHealth("100.64.0.21", 5335, mtcpv1.ResolverHealth_OK)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageDNSHealthReport, dnsHealthReport(ok)); !errors.As(err,
		&violation) {
		t.Fatalf("dns health without dns.root1: %v", err)
	}
	f.session.capabilities = append(f.session.capabilities, "dns.root1")
	for name, report := range map[string]*mtcpv1.DnsHealthReport{
		"unknown state": dnsHealthReport(resolverHealth("100.64.0.21", 5335, mtcpv1.ResolverHealth_STATE_UNSPECIFIED)),
		"twice":         dnsHealthReport(ok, resolverHealth("100.64.0.21", 5335, mtcpv1.ResolverHealth_BROKEN)),
		"short address": dnsHealthReport(&mtcpv1.ResolverHealth{Ip: []byte{1, 2}, State: mtcpv1.ResolverHealth_OK}),
		"port":          dnsHealthReport(resolverHealth("100.64.0.21", 70000, mtcpv1.ResolverHealth_OK)),
	} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageDNSHealthReport, report); !errors.As(err, &violation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Declared, but the session gets no root zone (no dns.forward1): dropped.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageDNSHealthReport, dnsHealthReport(ok)); err != nil {
		t.Fatal(err)
	}
	f.talk.dnsRoot.Store(true)
	// Before any map: dropped, not refused.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageDNSHealthReport, dnsHealthReport(ok)); err != nil {
		t.Fatal(err)
	}
	f.talk.sink.mu.Lock()
	f.talk.sink.hasCurrent = true
	f.talk.sink.dnsResolvers = map[netip.AddrPort]struct{}{
		netip.MustParseAddrPort("100.64.0.21:5335"): {}, netip.MustParseAddrPort("192.0.2.53:53"): {},
	}
	f.talk.sink.mu.Unlock()
	report := dnsHealthReport(ok, resolverHealth("192.0.2.53", 0, mtcpv1.ResolverHealth_REFUSING),
		resolverHealth("198.51.100.9", 53, mtcpv1.ResolverHealth_BROKEN))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageDNSHealthReport, report); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(dnsHealthInterval / 2)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageDNSHealthReport, report); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(dnsHealthInterval)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageDNSHealthReport, dnsHealthReport(ok)); err != nil {
		t.Fatal(err)
	}
	f.streams.mu.Lock()
	defer f.streams.mu.Unlock()
	want := [][]mapsession.ResolverHealth{
		{
			{Resolver: netip.MustParseAddrPort("100.64.0.21:5335"), State: mapsession.ResolverOK},
			{Resolver: netip.MustParseAddrPort("192.0.2.53:53"), State: mapsession.ResolverRefusing},
		},
		{{Resolver: netip.MustParseAddrPort("100.64.0.21:5335"), State: mapsession.ResolverOK}},
	}
	if !slices.EqualFunc(f.streams.dnsHealth, want, slices.Equal) {
		t.Fatalf("stored %v", f.streams.dnsHealth)
	}
}

// The DNS part of an EnforcementReport counts only where the session gets
// the root zone (dns.root1 with what it needs): a digest,
// or none with a known reason; anything else is left out while the policy
// evidence is stored.
func TestConversationEnforcementDNSEvidence(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.talk.nodeKey = node.Key(f.session.Hello().GetNodeKey())
	filter := make([]byte, 32)
	filter[0] = 1
	dns := make([]byte, 32)
	dns[0] = 2
	reports := []*mtcpv1.EnforcementReport{
		{DnsDigest: dns, DnsRoutes: 3},
		{DnsReason: mapsession.DNSUserOff},
		{DnsReason: "made_up"},
		{DnsDigest: dns[:5], DnsReason: mapsession.DNSApplyFailed},
	}
	send := func() {
		t.Helper()
		for _, report := range reports {
			report.Digest, report.Grants, report.AppliedMs = filter, 1, f.now().UnixMilli()
			f.clock = f.clock.Add(time.Minute) // past the enforcement pacing
			if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport, report); err != nil {
				t.Fatal(err)
			}
		}
	}
	send()
	// What the session gets decides, not what it declared (Request.DNSRoot).
	f.session.capabilities = append(f.session.capabilities, "dns.root1")
	f.talk.dnsRoot.Store(true)
	send()
	f.streams.mu.Lock()
	defer f.streams.mu.Unlock()
	if len(f.streams.reports) != 8 {
		t.Fatalf("%d reports stored", len(f.streams.reports))
	}
	for index, report := range f.streams.reports[:4] {
		if report.DNS.IsValid() || report.DNSReason != "" {
			t.Errorf("without dns.root1, report %d kept DNS evidence %+v", index, report)
		}
	}
	got := f.streams.reports[4:]
	if !got[0].DNS.IsValid() || got[0].DNS.Routes() != 3 || got[0].DNSReason != "" ||
		got[1].DNS.IsValid() || got[1].DNSReason != mapsession.DNSUserOff ||
		got[2].DNS.IsValid() || got[2].DNSReason != "" ||
		got[3].DNS.IsValid() || got[3].DNSReason != mapsession.DNSApplyFailed {
		t.Fatalf("with dns.root1: %+v", got)
	}
}
