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
