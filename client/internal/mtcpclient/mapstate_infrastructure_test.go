package mtcpclient

import (
	"fmt"
	"slices"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// Infrastructure names are canonical and bounded; one the node cannot read
// is left out alone (TD-CLI-70).
func TestConvertDNSCarriesInfrastructureNames(t *testing.T) {
	t.Parallel()
	raw := []string{"Console.Example.NET.", "bad name", "console.example.net"}
	for index := range maxInfrastructureNames + 5 {
		raw = append(raw, fmt.Sprintf("host%d.example.net", index))
	}
	config, err := convertDNS(&mtcpv1.DnsConfig{
		Routes:              []*mtcpv1.DnsRoute{{Suffix: ".", Resolvers: []*mtcpv1.Resolver{{Ip: []byte{1, 1, 1, 1}}}}},
		InfrastructureNames: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.InfrastructureNames) != maxInfrastructureNames || config.InfrastructureNames[0] != "console.example.net" ||
		slices.Contains(config.InfrastructureNames, "bad name") {
		t.Fatalf("infrastructure names = %v", config.InfrastructureNames)
	}
}
