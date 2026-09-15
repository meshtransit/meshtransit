package policy

import (
	"errors"
	"testing"
)

func TestPortRangeRejectsInvalidBounds(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		first uint16
		last  uint16
	}{
		{name: "zero first", first: 0, last: 53},
		{name: "descending", first: 443, last: 80},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPortRange(testCase.first, testCase.last); !errors.Is(err, ErrInvalidPortRange) {
				t.Fatalf("NewPortRange() error = %v, want ErrInvalidPortRange", err)
			}
		})
	}
}

func TestProtocolHasNoWildcardValue(t *testing.T) {
	t.Parallel()

	for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP, ProtocolICMP} {
		if !protocol.IsValid() || protocol.String() == "" || protocol.String() == "unknown" {
			t.Fatalf("protocol %d is not a stable supported value", protocol)
		}
	}
	if ProtocolUnknown.IsValid() || Protocol(255).IsValid() {
		t.Fatal("unknown protocol unexpectedly valid")
	}
}
