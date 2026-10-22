package mapsession

import (
	"slices"
	"testing"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

func TestWithoutProtectedZones(t *testing.T) {
	t.Parallel()
	zones := []appmapsession.DNSZone{{Zone: 1, Domain: "corp.internal"}, {Zone: 2, Domain: "lab.lan"},
		{Zone: 3, Domain: "."}, {Zone: 4, Domain: "relay.lab.lan"}}
	names := []appmapsession.DNSName{{Zone: 1, FQDN: "git.corp.internal"}, {Zone: 2, FQDN: "nas.lab.lan"},
		{Zone: 4, FQDN: "x.relay.lab.lan"}}
	keptZones, keptNames := withoutProtectedZones(zones, names, []string{"relay2.corp.internal", "relay.lab.lan"})
	var domains []string
	for _, zone := range keptZones {
		domains = append(domains, zone.Domain)
	}
	// corp.internal holds relay2, relay.lab.lan is a protected name and its
	// parent lab.lan holds it; the root waits for D1b.
	if !slices.Equal(domains, []string{"."}) || len(keptNames) != 0 {
		t.Fatalf("zones %v, names %v", domains, keptNames)
	}
	if kept, _ := withoutProtectedZones(zones, names, nil); len(kept) != 4 {
		t.Fatalf("without protected names: %d zones", len(kept))
	}
}
