package dnsconfig

import (
	"fmt"
	"net/netip"
	"testing"

	"meshtransit.net/client/internal/networkmap"
)

// Core keeps each map's DNS routes within what the helper takes (DNS design
// D3 §4.3) by following how Compile and buildResolvedConfig turn a
// configuration into domains (core mapsession clientDNSRoutes.cost). These
// cases are TestClientDNSRoutesCost's, with the same counts: a change here
// must change Core's copy too.
func TestRouteDomainsMatchCoreBudget(t *testing.T) {
	t.Parallel()
	many := func(count int, format string) []string {
		values := make([]string, count)
		for index := range values {
			values[index] = fmt.Sprintf(format, index)
		}
		return values
	}
	for name, test := range map[string]struct {
		routes, search, host, names []string
		want                        int
	}{
		"split": {
			routes: []string{"mesh.internal", "x.corp.com"}, host: []string{"corp.com"},
			names: []string{"a.corp.com", "b.corp.com", "y.x.corp.com", "free.example.org"}, want: 5,
		},
		"covered": {
			routes: []string{"mesh.internal", "corp.com"}, host: []string{"app.corp.com"},
			names: []string{"app.corp.com"}, want: 3,
		},
		"searched": {
			routes: []string{"mesh.internal"}, search: []string{"corp.com"}, host: []string{"corp.com"},
			names: []string{"a.corp.com", "b.corp.com"}, want: 2,
		},
		"past the client's budget": {
			routes: []string{"mesh.internal"}, host: []string{"corp.com"},
			names: many(300, "n%d.corp.com"), want: 2,
		},
		"no names, budget gone": {
			routes: append([]string{"mesh.internal"}, many(200, "z%d.lan")...),
			search: []string{"net.mesh.internal"}, host: many(55, "h%d.example.org"), want: 257,
		},
		"no names, budget left": {routes: []string{"mesh.internal"}, host: many(5, "h%d.example.org"), want: 1},
	} {
		config := &networkmap.DNSConfig{SearchDomains: test.search}
		for _, route := range test.routes {
			config.Routes = append(config.Routes, networkmap.DNSRoute{Suffix: route})
		}
		for _, zone := range test.host {
			config.Routes = append(config.Routes, networkmap.DNSRoute{Suffix: zone, Unavailable: true, FailOpen: true})
		}
		for index, record := range test.names {
			config.Records = append(config.Records, networkmap.DNSRecord{
				Name: record, Type: networkmap.DNSRecordA,
				Address: netip.AddrFrom4([4]byte{10, 0, byte(index >> 8), byte(index)}),
			})
		}
		plan, err := Compile(networkmap.Snapshot{Revision: 1, DNS: config})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resolved, err := buildResolvedConfig(plan, testDNSEndpoint())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := len(resolved.SearchDomains) + len(resolved.RouteDomains); got != test.want {
			t.Errorf("%s: %d domains, want %d", name, got, test.want)
		}
	}
}
