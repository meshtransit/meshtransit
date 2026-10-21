package mtcp

import (
	"errors"
	"slices"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func TestConversationRefusesRouteSelectionItDidNotNegotiate(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	valid := &mtcpv1.RouteSelectionReport{Sites: []*mtcpv1.RouteSelectionReport_SiteSelection{
		{SiteRef: "a", Router: "01890f00-0000-7000-8000-000000000402",
			Reason: mtcpv1.RouteSelectionReport_SiteSelection_PRIMARY},
	}}
	var violation protocolError
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteSelectionReport, valid); !errors.As(err, &violation) {
		t.Fatalf("route selection without routes.selection1: %v", err)
	}
	f.session.capabilities = append(f.session.capabilities, "routes.selection1", "routes.subnet.v1")
	for name, report := range map[string]*mtcpv1.RouteSelectionReport{
		"unknown reason": {Sites: []*mtcpv1.RouteSelectionReport_SiteSelection{{SiteRef: "a"}}},
		"router not an id": {Sites: []*mtcpv1.RouteSelectionReport_SiteSelection{
			{SiteRef: "a", Router: "router-1", Reason: mtcpv1.RouteSelectionReport_SiteSelection_PRIMARY},
		}},
		"primary without a router": {Sites: []*mtcpv1.RouteSelectionReport_SiteSelection{
			{SiteRef: "a", Reason: mtcpv1.RouteSelectionReport_SiteSelection_PRIMARY},
		}},
		"none with a router": {Sites: []*mtcpv1.RouteSelectionReport_SiteSelection{
			{SiteRef: "a", Router: "01890f00-0000-7000-8000-000000000402",
				Reason: mtcpv1.RouteSelectionReport_SiteSelection_NONE},
		}},
		"unsorted": {Sites: []*mtcpv1.RouteSelectionReport_SiteSelection{
			{SiteRef: "b", Reason: mtcpv1.RouteSelectionReport_SiteSelection_NONE},
			{SiteRef: "a", Reason: mtcpv1.RouteSelectionReport_SiteSelection_NONE},
		}},
	} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteSelectionReport, report); !errors.As(err, &violation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A valid report before any map is dropped, not refused.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteSelectionReport, valid); err != nil {
		t.Fatal(err)
	}
	f.streams.mu.Lock()
	defer f.streams.mu.Unlock()
	if len(f.streams.selection) != 0 {
		t.Fatalf("stored %v without a map", f.streams.selection)
	}
}

func TestSelectedOnlyKeepsTheRoutersCoreSent(t *testing.T) {
	t.Parallel()
	first, _ := node.ParseID("01890f00-0000-7000-8000-000000000401")
	second, _ := node.ParseID("01890f00-0000-7000-8000-000000000402")
	stranger, _ := node.ParseID("01890f00-0000-7000-8000-000000000409")
	sites := []mapsession.SiteSelection{
		{Ref: "a", Router: second, Reason: mapsession.RouteSelectionLocalFailover},
		{Ref: "b", Router: stranger, Reason: mapsession.RouteSelectionPrimary},
		{Ref: "c", Reason: mapsession.RouteSelectionNone},
		{Ref: "z", Router: first, Reason: mapsession.RouteSelectionPrimary},
	}
	routes := []mapsession.SiteRoute{
		{Ref: "a", Candidates: []node.ID{first, second}},
		{Ref: "b", Candidates: []node.ID{first}},
		{Ref: "c", Candidates: []node.ID{first}},
	}
	if kept := mapsession.SelectedOnly(sites, routes); !slices.Equal(kept, []mapsession.SiteSelection{sites[0], sites[2]}) {
		t.Fatalf("SelectedOnly() = %v", kept)
	}
}

// An exit selection needs routes.exit.v1 and is validated; a node that
// takes only Exit Pools never overwrites Site selections.
func TestConversationValidatesExitSelection(t *testing.T) {
	t.Parallel()
	exitNode := "01890f00-0000-7000-8000-000000000701"
	report := func(reason mtcpv1.RouteSelectionReport_ExitSelection_Reason, used string) *mtcpv1.RouteSelectionReport {
		return &mtcpv1.RouteSelectionReport{Exit: &mtcpv1.RouteSelectionReport_ExitSelection{PoolRef: "p-main",
			ExitNode: used, Reason: reason}}
	}
	var violation protocolError
	subnetOnly := newConversationFixture(t, sharedmtcp.MessagePing)
	subnetOnly.session.capabilities = append(subnetOnly.session.capabilities, "routes.selection1", "routes.subnet.v1")
	if err := subnetOnly.talk.Receive(t.Context(), sharedmtcp.MessageRouteSelectionReport,
		report(mtcpv1.RouteSelectionReport_ExitSelection_PRIMARY, exitNode)); !errors.As(err, &violation) {
		t.Fatalf("exit selection without routes.exit.v1: %v", err)
	}
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.session.capabilities = append(f.session.capabilities, "routes.selection1", "routes.exit.v1")
	for name, invalid := range map[string]*mtcpv1.RouteSelectionReport{
		"unknown reason":       report(mtcpv1.RouteSelectionReport_ExitSelection_REASON_UNSPECIFIED, exitNode),
		"none with a node":     report(mtcpv1.RouteSelectionReport_ExitSelection_NONE, exitNode),
		"sticky without node":  report(mtcpv1.RouteSelectionReport_ExitSelection_STICKY, ""),
		"malformed exit node":  report(mtcpv1.RouteSelectionReport_ExitSelection_LOCAL_FAILOVER, "node-7"),
		"Sites without subnet": {Sites: []*mtcpv1.RouteSelectionReport_SiteSelection{{SiteRef: "a"}}},
	} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteSelectionReport, invalid); !errors.As(err, &violation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, valid := range []*mtcpv1.RouteSelectionReport{
		report(mtcpv1.RouteSelectionReport_ExitSelection_STICKY, exitNode),
		report(mtcpv1.RouteSelectionReport_ExitSelection_NONE, ""),
	} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRouteSelectionReport, valid); err != nil {
			t.Fatal(err)
		}
	}
	f.streams.mu.Lock()
	defer f.streams.mu.Unlock()
	if len(f.streams.selection) != 0 {
		t.Fatalf("an exit-only node stored Site selections %v", f.streams.selection)
	}
}

func TestReadExitSelection(t *testing.T) {
	t.Parallel()
	exitNode := "01890f00-0000-7000-8000-000000000701"
	read := func(reason mtcpv1.RouteSelectionReport_ExitSelection_Reason, used string) (*mapsession.ExitSelection, bool) {
		return readExitSelection(&mtcpv1.RouteSelectionReport_ExitSelection{PoolRef: "p-main", ExitNode: used,
			Reason: reason})
	}
	if exit, ok := readExitSelection(nil); !ok || exit != nil {
		t.Fatalf("absent = %+v, %v", exit, ok)
	}
	for reason, want := range map[mtcpv1.RouteSelectionReport_ExitSelection_Reason]mapsession.RouteSelectionReason{
		mtcpv1.RouteSelectionReport_ExitSelection_PRIMARY:        mapsession.RouteSelectionPrimary,
		mtcpv1.RouteSelectionReport_ExitSelection_LOCAL_FAILOVER: mapsession.RouteSelectionLocalFailover,
		mtcpv1.RouteSelectionReport_ExitSelection_STICKY:         mapsession.RouteSelectionSticky,
	} {
		exit, ok := read(reason, exitNode)
		if !ok || exit.Ref != "p-main" || exit.Node.String() != exitNode || exit.Reason != want {
			t.Errorf("%v = %+v, %v", reason, exit, ok)
		}
	}
	if exit, ok := read(mtcpv1.RouteSelectionReport_ExitSelection_NONE, ""); !ok || exit.Node != (node.ID{}) {
		t.Fatalf("none = %+v, %v", exit, ok)
	}
	// Not canonical: upper case.
	if _, ok := read(mtcpv1.RouteSelectionReport_ExitSelection_PRIMARY, "01890F00-0000-7000-8000-000000000701"); ok {
		t.Fatal("a non-canonical exit node was read")
	}
}

func TestSelectedReportKeepsTheSitesAndExitCoreSent(t *testing.T) {
	t.Parallel()
	router, _ := node.ParseID("01890f00-0000-7000-8000-000000000402")
	exitNode, _ := node.ParseID("01890f00-0000-7000-8000-000000000701")
	pools := []mapsession.ExitPoolRoute{{Ref: "p-main", Candidates: []node.ID{exitNode}}}
	exit := &mapsession.ExitSelection{Ref: "p-main", Node: exitNode, Reason: mapsession.RouteSelectionSticky}
	// An exit-only node: no Sites, its exit node.
	report := selectedReport(nil, exit, nil, pools)
	if len(report.sites) != 0 || report.exit == nil || *report.exit != *exit {
		t.Fatalf("exit-only report = %+v", report)
	}
	// Both: the Site router and the exit node, each checked against what was sent.
	sites := []mapsession.SiteSelection{{Ref: "a", Router: router, Reason: mapsession.RouteSelectionPrimary}}
	report = selectedReport(sites, exit, []mapsession.SiteRoute{{Ref: "a", Candidates: []node.ID{router}}}, pools)
	if len(report.sites) != 1 || report.exit == nil {
		t.Fatalf("both = %+v", report)
	}
	// A pool the session was not sent is dropped; its Sites stay.
	report = selectedReport(sites, &mapsession.ExitSelection{Ref: "p-other", Node: exitNode,
		Reason: mapsession.RouteSelectionPrimary}, []mapsession.SiteRoute{{Ref: "a", Candidates: []node.ID{router}}}, pools)
	if len(report.sites) != 1 || report.exit != nil {
		t.Fatalf("unsent pool = %+v", report)
	}
}
