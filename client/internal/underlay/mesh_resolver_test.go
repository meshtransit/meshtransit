package underlay

import (
	"net/netip"
	"testing"
)

func TestMeshResolverIsNeverTheNetworks(t *testing.T) {
	t.Parallel()
	for address, mesh := range map[string]bool{
		"127.53.53.53": true, "::1": true, "0.0.0.0": true, "192.0.2.53": true, "100.64.0.1": true,
		"fd7a:115c:a1e0::53": true, "::ffff:127.0.0.1": true,
		"192.168.1.1": false, "10.0.0.2": false, "8.8.8.8": false, "2001:4860:4860::8888": false,
	} {
		if got := meshResolver(netip.MustParseAddr(address)); got != mesh {
			t.Errorf("meshResolver(%s) = %v, want %v", address, got, mesh)
		}
	}
}
