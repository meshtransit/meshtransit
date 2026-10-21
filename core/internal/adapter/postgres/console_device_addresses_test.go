package postgres

import "testing"

func TestDecodeDeviceAddressesKeepsCanonicalAddressesIPv4First(t *testing.T) {
	t.Parallel()
	addresses, ok := decodeDeviceAddresses([]string{"100.64.0.7", "fd7a:115c:a1e0::7"})
	if !ok || len(addresses) != 2 || addresses[0].String() != "100.64.0.7" || !addresses[1].Is6() {
		t.Fatalf("decoded = %v, %v", addresses, ok)
	}
	if addresses, ok := decodeDeviceAddresses([]string{}); !ok || len(addresses) != 0 {
		t.Fatalf("no address = %v, %v", addresses, ok)
	}
	// PostgreSQL writes an IPv4-compatible address dotted; the API answers Go's form.
	if addresses, ok := decodeDeviceAddresses([]string{"::100.64.0.7", "::ffff:100.64.0.7"}); !ok ||
		addresses[0].String() != "::6440:7" || addresses[1].String() != "::ffff:100.64.0.7" {
		t.Fatalf("IPv6 forms = %v, %v", addresses, ok)
	}
	for _, encoded := range [][]string{
		{"fd7a:115c:a1e0::7", "100.64.0.7"},
		{"100.64.0.7/32"},
		{"fe80::1%en0"},
		{"100.64.0.1", "100.64.0.2", "100.64.0.3", "100.64.0.4", "100.64.0.5"},
	} {
		if _, ok := decodeDeviceAddresses(encoded); ok {
			t.Errorf("decodeDeviceAddresses(%q) accepted", encoded)
		}
	}
}
