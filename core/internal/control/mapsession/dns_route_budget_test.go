package mapsession

import "testing"

// The root zone is the client's own default route, not a domain of the
// budget: unavailable and open it is still no zone left to the host, and
// it stays when the domains are full (DNS design D1b §3.2).
func TestRouteBudgetLeavesTheRootZoneOut(t *testing.T) {
	t.Parallel()
	view := DNSView{zones: []DNSForwardZone{
		{Domain: ".", OtherNames: DNSOtherForward, FailOpen: true},
		{Domain: "corp.internal", OtherNames: DNSOtherForward},
	}}
	config, left := view.routeBudget()
	if len(config.host) != 0 || len(config.routes) != 1 || config.routes[0] != "corp.internal" || len(left) != 0 ||
		len(view.zones) != 2 || view.overBudget != 0 {
		t.Fatalf("config %+v, left %v, zones %+v, over budget %d", config, left, view.zones, view.overBudget)
	}
}
