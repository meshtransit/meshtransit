package mapsession

import (
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

func TestExitSelectionIsCheckedAndKeptOnlyForPoolsSent(t *testing.T) {
	t.Parallel()
	exitNode, _ := node.ParseID("01a159eb-da65-77e1-a9aa-0696ec043e4f")
	other, _ := node.ParseID("01a144c1-5017-78d7-9ac9-244ebfb3c10e")
	pool := "01a159f2-8c40-718b-bea7-ea6c60ff7b0e"
	for _, test := range []struct {
		exit  ExitSelection
		valid bool
	}{
		{ExitSelection{Ref: pool, Node: exitNode, Reason: RouteSelectionPrimary}, true},
		{ExitSelection{Ref: pool, Node: exitNode, Reason: RouteSelectionLocalFailover}, true},
		{ExitSelection{Ref: pool, Node: exitNode, Reason: RouteSelectionSticky}, true},
		{ExitSelection{Ref: pool, Reason: RouteSelectionNone}, true},
		{ExitSelection{Ref: pool, Node: exitNode, Reason: RouteSelectionNone}, false},
		{ExitSelection{Ref: pool, Reason: RouteSelectionSticky}, false},
		{ExitSelection{Ref: "", Node: exitNode, Reason: RouteSelectionPrimary}, false},
		{ExitSelection{Ref: pool, Node: exitNode, Reason: RouteSelectionSticky + 1}, false},
	} {
		if got := ValidExitSelection(test.exit); got != test.valid {
			t.Errorf("ValidExitSelection(%+v) = %v, want %v", test.exit, got, test.valid)
		}
	}
	// A Site never takes the exit-only reason.
	if ValidSiteSelection([]SiteSelection{{Ref: pool, Router: exitNode, Reason: RouteSelectionSticky}}) {
		t.Fatal("a Site accepted the sticky reason")
	}
	pools := []ExitPoolRoute{{Ref: pool, Candidates: []node.ID{exitNode}}}
	if kept := SelectedExitOnly(&ExitSelection{Ref: pool, Node: exitNode, Reason: RouteSelectionSticky}, pools); kept == nil {
		t.Fatal("a candidate of a pool sent was dropped")
	}
	if kept := SelectedExitOnly(&ExitSelection{Ref: pool, Reason: RouteSelectionNone}, pools); kept == nil {
		t.Fatal("an unserved pool sent was dropped")
	}
	for _, exit := range []*ExitSelection{
		nil,
		{Ref: pool, Node: other, Reason: RouteSelectionPrimary},
		{Ref: "01a159f2-8c40-718b-bea7-ea6c60ff7b0f", Node: exitNode, Reason: RouteSelectionPrimary},
	} {
		if kept := SelectedExitOnly(exit, pools); kept != nil {
			t.Errorf("SelectedExitOnly(%+v) kept %+v", exit, kept)
		}
	}
}
