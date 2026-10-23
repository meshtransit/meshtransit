package mtcpclient

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/dnsdigest"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/policydigest"
)

// With dns.root1 the node declares the root zone and reports the DNS it
// applied with its enforcement evidence (mtcp-v1 §8.4); without Core taking
// it, the DNS part stays out.
func TestStreamNetmapReportsDNSEvidenceWhereCoreTakesIt(t *testing.T) {
	t.Parallel()
	for _, takes := range []bool{true, false} {
		received := make(chan *mtcpv1.EnforcementReport, 1)
		core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
			core.keyUpdate(s)
			_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(1))
			if report, ok := core.expect(s, sharedmtcp.MessageEnforcementReport).(*mtcpv1.EnforcementReport); ok {
				received <- report
			}
			_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_REVOKED})
			answerPings(s)
		})
		if takes {
			core.extra = []string{"dns.split", "dns.forward1", "dns.root1"}
		}
		material, options := core.options(t)
		enforcement := make(chan controlplane.EnforcementReport, 1)
		options.EnableDNSForward, options.EnforcementReports = true, enforcement
		err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
			func(context.Context, networkmap.Snapshot) error {
				enforcement <- controlplane.EnforcementReport{
					Digest: policydigest.Digest{1}, AppliedAt: time.Now(),
					DNSKnown: true, DNSDigest: dnsdigest.Digest{3}, DNSRoutes: 4,
				}
				return nil
			})
		if !errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) {
			t.Fatalf("StreamNetmap = %v", err)
		}
		if !slices.ContainsFunc(core.hello, func(hello *mtcpv1.ClientHello) bool {
			return slices.Contains(hello.GetCapabilities(), "dns.root1")
		}) {
			t.Fatal("the map stream did not declare dns.root1")
		}
		report := <-received
		if takes != (len(report.GetDnsDigest()) == 32) || takes && (report.GetDnsDigest()[0] != 3 ||
			report.GetDnsRoutes() != 4 || report.GetDnsReason() != "") {
			t.Fatalf("takes %t: enforcement report %v", takes, report)
		}
	}
}

// Resolver health goes to Core where it takes it (dns.root1), with ports
// other than 53 and the last answer's time; a later report waits for a
// change of state past the spacing, or the heartbeat.
func TestStreamNetmapReportsResolverHealth(t *testing.T) {
	t.Parallel()
	reports := make(chan *mtcpv1.DnsHealthReport, 1)
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(1))
		if report, ok := core.expect(s, sharedmtcp.MessageDNSHealthReport).(*mtcpv1.DnsHealthReport); ok {
			reports <- report
		}
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_REVOKED})
		answerPings(s)
	})
	core.extra = []string{"dns.split", "dns.forward1", "dns.root1"}
	material, options := core.options(t)
	health := make(chan []controlplane.ResolverHealth, 1)
	lastOK := time.UnixMilli(1792740000000)
	health <- []controlplane.ResolverHealth{
		{Resolver: netip.MustParseAddrPort("100.64.0.21:5335"), State: controlplane.ResolverOK, LastOK: lastOK},
		{Resolver: netip.MustParseAddrPort("1.1.1.1:53"), State: controlplane.ResolverIdle},
	}
	options.EnableDNSForward, options.DNSHealth = true, health
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return nil })
	if !errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) {
		t.Fatalf("StreamNetmap = %v", err)
	}
	report := <-reports
	resolvers := report.GetResolvers()
	if len(resolvers) != 2 || resolvers[0].GetPort() != 5335 || resolvers[0].GetState() != mtcpv1.ResolverHealth_OK ||
		resolvers[0].GetLastOkMs() != lastOK.UnixMilli() || resolvers[1].GetPort() != 0 ||
		resolvers[1].GetState() != mtcpv1.ResolverHealth_IDLE || resolvers[1].GetLastOkMs() != 0 {
		t.Fatalf("resolver health report %v", report)
	}
}

func TestSendDNSHealthCadence(t *testing.T) {
	t.Parallel()
	ok := []controlplane.ResolverHealth{{
		Resolver: netip.MustParseAddrPort("1.1.1.1:53"), State: controlplane.ResolverOK,
		LastOK: time.Now(),
	}}
	moved := []controlplane.ResolverHealth{{
		Resolver: ok[0].Resolver, State: controlplane.ResolverOK,
		LastOK: time.Now().Add(time.Second),
	}}
	broken := []controlplane.ResolverHealth{{Resolver: ok[0].Resolver, State: controlplane.ResolverBroken}}
	for name, test := range map[string]struct {
		next  []controlplane.ResolverHealth
		since time.Duration
		send  bool
	}{
		"same state soon":         {moved, time.Minute, false},
		"same state at heartbeat": {moved, dnsHealthHeartbeat, true},
		"new state too soon":      {broken, dnsHealthSpacing / 2, false},
		"new state after spacing": {broken, dnsHealthSpacing, true},
	} {
		run := &sessionRun{dnsHealthSent: ok, dnsHealthSentAt: time.Now().Add(-test.since)}
		if got := run.dnsHealthDue(test.next); got != test.send {
			t.Errorf("%s: due %t, want %t", name, got, test.send)
		}
	}
	if !(&sessionRun{}).dnsHealthDue(ok) {
		t.Fatal("the first report is not due")
	}
	if (&sessionRun{}).dnsHealthDue(nil) ||
		(&sessionRun{dnsHealthSent: []controlplane.ResolverHealth{}}).dnsHealthDue(nil) {
		t.Fatal("an empty report is due with none sent before")
	}
	if !(&sessionRun{dnsHealthSent: ok, dnsHealthSentAt: time.Now().Add(-dnsHealthSpacing)}).dnsHealthDue(nil) {
		t.Fatal("resolvers gone are not reported")
	}
}
