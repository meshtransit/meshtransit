package node

import (
	"strings"
	"testing"
)

// Every collision candidate of a requested hostname starts with its family
// prefix, so reading only the hostnames with that prefix is enough to pick
// the same lowest free candidate as reading the whole Network.
func TestHostnameFamilyPrefixCoversEveryCandidate(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 63)
	for _, value := range []string{"laptop", "laptop.corp.example", long, long + ".example", "x"} {
		requested, err := ParseHostname(value)
		if err != nil {
			t.Fatalf("ParseHostname(%q) error = %v", value, err)
		}
		prefix, err := HostnameFamilyPrefix(requested)
		if err != nil || prefix == "" {
			t.Fatalf("HostnameFamilyPrefix(%q) = %q, %v", value, prefix, err)
		}
		for _, ordinal := range []int{0, 1, 9, 10, 99, 100, 1000, 54321, MaximumHostnameFamily} {
			candidate, err := hostnameCandidate(requested, ordinal)
			if err != nil {
				t.Fatalf("hostnameCandidate(%q, %d) error = %v", value, ordinal, err)
			}
			if !strings.HasPrefix(candidate.String(), prefix) {
				t.Fatalf("candidate %q of %q lacks family prefix %q", candidate, value, prefix)
			}
		}
	}
}

func TestNextAvailableHostnameBeyondOneThousandDevices(t *testing.T) {
	t.Parallel()
	requested, err := ParseHostname("sensor")
	if err != nil {
		t.Fatal(err)
	}
	occupied := make([]Hostname, 0, 5000)
	for ordinal := range 5000 {
		candidate, err := hostnameCandidate(requested, ordinal)
		if err != nil {
			t.Fatal(err)
		}
		occupied = append(occupied, candidate)
	}
	got, err := NextAvailableHostname(requested, occupied)
	if err != nil || got.String() != "sensor-5000" {
		t.Fatalf("NextAvailableHostname() = %q, %v; want sensor-5000", got, err)
	}
}
