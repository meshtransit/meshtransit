package mtcp

import (
	"fmt"
	"slices"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// A root zone carries the deployment's own host names, bounded; a map
// without one carries none (TD-CLI-70).
func TestWithInfrastructureOnlyWithARootZone(t *testing.T) {
	t.Parallel()
	names := []string{"console.example.net", "10.0.0.1", "trailing.example.net.", "-bad.example.net", "single",
		"console.example.net"}
	for index := range MaximumDNSInfrastructureNames + 5 {
		names = append(names, fmt.Sprintf("host%d.example.net", index))
	}
	root := withInfrastructure(&mtcpv1.DnsConfig{Routes: []*mtcpv1.DnsRoute{{Suffix: "."}}}, names)
	got := root.GetInfrastructureNames()
	if len(got) != MaximumDNSInfrastructureNames || got[0] != "console.example.net" ||
		slices.ContainsFunc(got, func(name string) bool {
			return name == "10.0.0.1" || name == "single" || name == "-bad.example.net" || name == "trailing.example.net."
		}) || slices.Index(got[1:], "console.example.net") >= 0 {
		t.Fatalf("root zone infrastructure = %v", root.GetInfrastructureNames())
	}
	zone := withInfrastructure(&mtcpv1.DnsConfig{Routes: []*mtcpv1.DnsRoute{{Suffix: "corp.example"}}}, names)
	if len(zone.GetInfrastructureNames()) != 0 {
		t.Fatalf("a map without a root zone carries %v", zone.GetInfrastructureNames())
	}
	if withInfrastructure(nil, names) != nil {
		t.Fatal("no DNS became some")
	}
}
