package postgres

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeRelayRevocations(t *testing.T) {
	t.Parallel()

	node := strings.Repeat("ab", 32)
	contract := strings.Repeat("0c", 16)
	got, err := decodeRelayRevocations(`{"nodes":["` + node + `"],"trust_contracts":["` + contract + `"]}`)
	if err != nil || len(got.NodeKeys) != 1 || got.NodeKeys[0][0] != 0xab || len(got.TrustContracts) != 1 || got.TrustContracts[0][15] != 0x0c {
		t.Fatalf("decodeRelayRevocations() = %+v, %v", got, err)
	}
	empty, err := decodeRelayRevocations(`{"nodes":[],"trust_contracts":[]}`)
	if err != nil || len(empty.NodeKeys) != 0 || len(empty.TrustContracts) != 0 {
		t.Fatalf("empty = %+v, %v", empty, err)
	}
	for _, bad := range []string{
		`not json`,
		`{"nodes":["` + node[:62] + `"],"trust_contracts":[]}`,
		`{"nodes":[],"trust_contracts":["` + strings.Repeat("zz", 16) + `"]}`,
	} {
		if _, err := decodeRelayRevocations(bad); !errors.Is(err, ErrRelayRevocations) {
			t.Errorf("decodeRelayRevocations(%q) error = %v", bad, err)
		}
	}
	if _, err := NewRelayRevocationStore(nil); !errors.Is(err, ErrRelayRevocations) {
		t.Fatal("nil pool accepted")
	}
}
