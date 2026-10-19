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
		f.talk.reportRouteHealth(report("code_" + string(rune('a'+index))))
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
	f.talk.reportRouteHealth(report("late"))
	f.talk.stopRouteHealthPacing()
	f.advance(time.Minute)
	f.routeHealthTimer.trigger()
	if got := stored(); got[len(got)-1][0].Code == "late" {
		t.Fatal("a report was stored after the session ended")
	}
}
