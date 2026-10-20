package mtcp

import (
	"errors"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func routeHealthReport(states ...mtcpv1.RouteHealthReport_SiteHealth_State) *mtcpv1.RouteHealthReport {
	report := &mtcpv1.RouteHealthReport{}
	for index, state := range states {
		report.Sites = append(report.Sites, &mtcpv1.RouteHealthReport_SiteHealth{
			SiteRef: string(rune('a' + index)), State: state, Code: "ok",
		})
	}
	return report
}

func TestConversationRefusesRouteHealthItDidNotNegotiate(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport,
		routeHealthReport(mtcpv1.RouteHealthReport_SiteHealth_OK))
	var violation protocolError
	if !errors.As(err, &violation) {
		t.Fatalf("route health without router.health1: %v", err)
	}
	f.session.capabilities = append(f.session.capabilities, "router.health1")
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport,
		routeHealthReport(mtcpv1.RouteHealthReport_SiteHealth_OK)); !errors.As(err, &violation) {
		t.Fatalf("route health from a node that cannot route: %v", err)
	}
	f.session.capabilities = append(f.session.capabilities, "router.subnet.v1")
	for name, report := range map[string]*mtcpv1.RouteHealthReport{
		"unknown state": routeHealthReport(mtcpv1.RouteHealthReport_SiteHealth_STATE_UNSPECIFIED),
		"unsorted": {Sites: []*mtcpv1.RouteHealthReport_SiteHealth{
			{SiteRef: "b", State: mtcpv1.RouteHealthReport_SiteHealth_OK, Code: "ok"},
			{SiteRef: "a", State: mtcpv1.RouteHealthReport_SiteHealth_OK, Code: "ok"},
		}},
		"code with spaces": {Sites: []*mtcpv1.RouteHealthReport_SiteHealth{
			{SiteRef: "a", State: mtcpv1.RouteHealthReport_SiteHealth_FAILED, Code: "not ok"},
		}},
	} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport, report); !errors.As(err, &violation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A valid report before any map is dropped, not refused.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport,
		routeHealthReport(mtcpv1.RouteHealthReport_SiteHealth_FAILED)); err != nil {
		t.Fatal(err)
	}
	f.streams.mu.Lock()
	defer f.streams.mu.Unlock()
	if len(f.streams.health) != 0 {
		t.Fatalf("stored %v without a map", f.streams.health)
	}
}

func TestServedOnlyKeepsTheSitesCoreSent(t *testing.T) {
	t.Parallel()
	sites := []mapsession.SiteHealth{
		{Ref: "a", State: mapsession.RouteHealthOK, Code: "ok"},
		{Ref: "b", State: mapsession.RouteHealthFailed, Code: "probe_failed"},
		{Ref: "c", State: mapsession.RouteHealthOK, Code: "ok"},
	}
	kept := servedOnly(sites, []mapsession.ServedSite{{Ref: "b"}, {Ref: "c"}, {Ref: "z"}})
	if !slices.Equal(kept, sites[1:]) {
		t.Fatalf("servedOnly() = %v", kept)
	}
}

func TestConversationPacesRouteHealth(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.talk.nodeKey = node.Key(f.session.Hello().GetNodeKey())
	stored := func() [][]mapsession.SiteHealth {
		f.streams.mu.Lock()
		defer f.streams.mu.Unlock()
		return slices.Clone(f.streams.health)
	}
	report := func(code string) []mapsession.SiteHealth {
		return []mapsession.SiteHealth{{Ref: "prod", State: mapsession.RouteHealthFailed, Code: code}}
	}
	for index := range routeHealthBurst + 2 {
		f.talk.reportRouteHealth(report("code_"+string(rune('a'+index))), nil)
	}
	if got := stored(); len(got) != routeHealthBurst {
		t.Fatalf("stored %d at once, want the burst of %d", len(got), routeHealthBurst)
	}
	delay, armed := f.routeHealthTimer.pending()
	if !armed || delay != 2*time.Second {
		t.Fatalf("timer %s armed %t, want 2 s", delay, armed)
	}
	f.advance(2 * time.Second)
	f.routeHealthTimer.trigger()
	got := stored()
	if len(got) != routeHealthBurst+1 || got[len(got)-1][0].Code != "code_d" {
		t.Fatalf("stored %v, want the latest report last", got)
	}
	// A report kept when the session ends, such as a router's going_away,
	// is stored once then, whatever the budget; nothing after.
	f.talk.reportRouteHealth(report("going_away"), nil)
	before := len(stored())
	f.talk.stopRouteHealthPacing()
	if got := stored(); len(got) != before+1 || got[len(got)-1][0].Code != "going_away" {
		t.Fatalf("the last report was not stored when the session ended: %v", got)
	}
	f.talk.reportRouteHealth(report("late"), nil)
	f.advance(time.Minute)
	f.routeHealthTimer.trigger()
	if got := stored(); got[len(got)-1][0].Code == "late" {
		t.Fatal("a report was stored after the session ended")
	}
}

// Exit health needs router.exit.v1 (Sites router.subnet.v1), and a pool's
// health must be well formed.
func TestConversationRefusesExitHealthItDidNotNegotiate(t *testing.T) {
	t.Parallel()
	exitReport := func(state mtcpv1.RouteHealthReport_SiteHealth_State,
		families mtcpv1.ExitCandidate_Families) *mtcpv1.RouteHealthReport {
		return &mtcpv1.RouteHealthReport{Exit: &mtcpv1.RouteHealthReport_ExitHealth{PoolRef: "p-main", State: state,
			Code: "egress_ok", Families: families}}
	}
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.session.capabilities = append(f.session.capabilities, "router.health1", "router.subnet.v1")
	var violation protocolError
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport,
		exitReport(mtcpv1.RouteHealthReport_SiteHealth_OK, mtcpv1.ExitCandidate_BOTH)); !errors.As(err, &violation) {
		t.Fatalf("exit health without router.exit.v1: %v", err)
	}
	exitOnly := newConversationFixture(t, sharedmtcp.MessagePing)
	exitOnly.session.capabilities = append(exitOnly.session.capabilities, "router.health1", "router.exit.v1")
	if err := exitOnly.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport,
		routeHealthReport(mtcpv1.RouteHealthReport_SiteHealth_OK)); !errors.As(err, &violation) {
		t.Fatalf("Site health without router.subnet.v1: %v", err)
	}
	for name, report := range map[string]*mtcpv1.RouteHealthReport{
		"unknown state":    exitReport(mtcpv1.RouteHealthReport_SiteHealth_STATE_UNSPECIFIED, mtcpv1.ExitCandidate_V4),
		"unknown families": exitReport(mtcpv1.RouteHealthReport_SiteHealth_OK, mtcpv1.ExitCandidate_Families(9)),
		"no pool": {Exit: &mtcpv1.RouteHealthReport_ExitHealth{
			State: mtcpv1.RouteHealthReport_SiteHealth_OK, Code: "ok"}},
	} {
		if err := exitOnly.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport, report); !errors.As(err, &violation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A valid exit-only report before any map is dropped, not refused.
	if err := exitOnly.talk.Receive(t.Context(), sharedmtcp.MessageRouteHealthReport,
		exitReport(mtcpv1.RouteHealthReport_SiteHealth_FAILED, mtcpv1.ExitCandidate_V4)); err != nil {
		t.Fatal(err)
	}
	exitOnly.streams.mu.Lock()
	defer exitOnly.streams.mu.Unlock()
	if len(exitOnly.streams.exits) != 0 {
		t.Fatalf("stored %v without a map", exitOnly.streams.exits)
	}
}
