package dnsconfig

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A diagnostic question says where the name went and what came back.
func TestQueryReportsThePathAndTheAnswer(t *testing.T) {
	t.Parallel()
	zone := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("10.35.0.7"), false)
	engine := zoneEngine(t)
	plan := Plan{Enabled: true, Routes: []Route{{Suffix: "corp.example", Resolvers: []netip.AddrPort{zone.address}}}}
	report, err := engine.query(t.Context(), plan, "Wiki.Corp.Example.", "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Name != "wiki.corp.example" || report.Type != "A" || report.Path != PathZone ||
		report.Zone != "corp.example" || report.FailOpen || len(report.Resolvers) != 1 ||
		report.Resolvers[0].Address != zone.address || report.RCode != "NOERROR" ||
		len(report.Answers) != 1 || report.Answers[0] != "10.35.0.7" {
		t.Fatalf("report %+v", report)
	}
	// Through the exit node: a zone's Internet resolver is marked so.
	plan = exitZonePlan(netip.MustParseAddrPort("100.64.0.9:53"), true)
	if described := engine.describe(plan, dnsmessage.Message{}, dnsmessage.Question{Type: dnsmessage.TypeA},
		"wiki.corp.example"); described.Path != PathZone || len(described.Resolvers) != 1 ||
		!described.Resolvers[0].ViaExit || !described.FailOpen {
		t.Fatalf("through the exit node %+v", described)
	}
	plan.Routes = nil
	if described := engine.describe(plan, dnsmessage.Message{}, dnsmessage.Question{Type: dnsmessage.TypeA},
		"public.example"); described.Path != PathExit {
		t.Fatalf("a name no zone holds, with an exit node: %+v", described)
	}
	if described := engine.describe(Plan{Enabled: true}, dnsmessage.Message{},
		dnsmessage.Question{Type: dnsmessage.TypeA}, "public.example"); described.Path != PathHost {
		t.Fatalf("a name no zone holds: %+v", described)
	}
	for _, bad := range [][2]string{{"", "A"}, {"x.example", "BOGUS"}, {"bad..name", "A"}} {
		if _, err := engine.query(t.Context(), plan, bad[0], bad[1]); !errors.Is(err, ErrQueryName) {
			t.Fatalf("%q %q: %v", bad[0], bad[1], err)
		}
	}
}

// A short name is tried under the search domains; a name the host keeps is
// not asked.
func TestQueryExpandsShortNamesAndLeavesTheHostsAlone(t *testing.T) {
	t.Parallel()
	zone := startCountingUpstream(t, dnsmessage.RCodeSuccess, netip.MustParseAddr("10.35.0.7"), false)
	engine := zoneEngine(t)
	plan := Plan{
		Enabled: true, SearchDomains: []string{"lab.example", "corp.example"},
		Routes: []Route{{Suffix: "corp.example", Resolvers: []netip.AddrPort{zone.address}}},
	}
	report, err := engine.query(t.Context(), plan, "wiki", "A")
	if err != nil || report.Name != "wiki.corp.example" || report.Path != PathZone || report.RCode != "NOERROR" {
		t.Fatalf("short name: %+v %v", report, err)
	}
	report, err = engine.query(t.Context(), plan, "www.example.org", "A")
	if err != nil || report.Path != PathHost || report.RCode != "" || zone.asked.Load() != 1 {
		t.Fatalf("host's name: %+v %v, zone asked %d", report, err, zone.asked.Load())
	}
}
