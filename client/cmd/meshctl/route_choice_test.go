package main

import "testing"

func TestRouteChoiceCommand(t *testing.T) {
	t.Parallel()
	if _, show, ok := routeChoiceCommand([]string{"show"}); !show || !ok {
		t.Fatal("show is not a route choice read")
	}
	if change, show, ok := routeChoiceCommand([]string{"exit-use", "auto"}); !ok || show || change.ExitUse == nil ||
		*change.ExitUse != "auto" || change.AcceptRoutes != nil || change.ExitAllowLAN != nil {
		t.Fatalf("exit-use auto = %+v %v %v", change, show, ok)
	}
	if change, _, ok := routeChoiceCommand([]string{"accept", "on"}); !ok || change.AcceptRoutes == nil ||
		!*change.AcceptRoutes || change.ExitUse != nil {
		t.Fatalf("accept on = %+v %v", change, ok)
	}
	if change, _, ok := routeChoiceCommand([]string{"exit-allow-lan", "off"}); !ok || change.ExitAllowLAN == nil ||
		*change.ExitAllowLAN {
		t.Fatalf("exit-allow-lan off = %+v %v", change, ok)
	}
	for _, args := range [][]string{
		{"exit-mode", "on"},
		{"operators", "on"},
		{"accept", "maybe"},
		{"exit-use", ""},
		{"exit-use"},
		{"show", "extra"},
		{"accept-public", "on"},
		{"advertise", "10.0.0.0/8"},
		{},
	} {
		if _, _, ok := routeChoiceCommand(args); ok {
			t.Errorf("%q went to meshd", args)
		}
	}
}
