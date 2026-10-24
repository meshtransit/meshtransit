package networkmap

import (
	"net/netip"
	"testing"
)

func TestDNSConfigEmpty(t *testing.T) {
	t.Parallel()
	var none *DNSConfig
	if !none.Empty() || !(&DNSConfig{}).Empty() {
		t.Fatal("no DNS is not empty")
	}
	for name, config := range map[string]*DNSConfig{
		"search":   {SearchDomains: []string{"corp.example"}},
		"record":   {Records: []DNSRecord{{Name: "a.mesh.internal"}}},
		"resolver": {Resolvers: []DNSResolver{{Address: netip.MustParseAddrPort("9.9.9.9:53")}}},
		"route":    {Routes: []DNSRoute{{Suffix: "corp.example"}}},
	} {
		if config.Empty() {
			t.Fatalf("%s: empty", name)
		}
	}
}
