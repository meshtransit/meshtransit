package node

import (
	"errors"
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

// Looking candidates up in order, a batch at a time, chooses what
// NextAvailableHostname chooses from every occupied hostname.
func TestHostnameCandidatesChooseAsNextAvailableHostname(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		requested string
		taken     []int // ordinals held by other Devices
		other     []string
	}{
		{name: "requested free", requested: "sensor", other: []string{"sensor-x", "sensors"}},
		{name: "requested taken", requested: "sensor", taken: []int{0}},
		{name: "gap inside a batch", requested: "sensor.example", taken: []int{0, 1, 2, 4}},
		{name: "first batches full", requested: "sensor", taken: sequence(0, 1100)},
		{name: "gap after many", requested: "sensor", taken: append(sequence(0, 70), sequence(71, 200)...)},
		{name: "long label", requested: strings.Repeat("a", 63) + ".example", taken: sequence(0, 12)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			requested, err := ParseHostname(test.requested)
			if err != nil {
				t.Fatal(err)
			}
			occupied := make([]Hostname, 0, len(test.taken)+len(test.other))
			held := make(map[string]struct{}, len(test.taken))
			for _, ordinal := range test.taken {
				candidate, err := hostnameCandidate(requested, ordinal)
				if err != nil {
					t.Fatal(err)
				}
				occupied = append(occupied, candidate)
				held[candidate.String()] = struct{}{}
			}
			for _, value := range test.other {
				occupied = append(occupied, mustParseHostname(t, value))
				held[value] = struct{}{}
			}
			want, err := NextAvailableHostname(requested, occupied)
			if err != nil {
				t.Fatal(err)
			}
			got := Hostname{}
			for from, count := 0, 1; !got.IsValid(); from, count = from+count, count*16 {
				candidates, err := HostnameCandidates(requested, from, count)
				if err != nil {
					t.Fatalf("HostnameCandidates(%d, %d) error = %v", from, count, err)
				}
				for _, candidate := range candidates {
					if _, taken := held[candidate.String()]; !taken {
						got = candidate
						break
					}
				}
			}
			if got != want {
				t.Fatalf("lookup chose %q, NextAvailableHostname chose %q", got, want)
			}
		})
	}
}

func TestHostnameCandidatesRejectOutOfRangeOrdinals(t *testing.T) {
	t.Parallel()
	requested := mustParseHostname(t, "sensor")
	for _, test := range []struct {
		name        string
		from, count int
	}{
		{name: "negative start", from: -1, count: 1},
		{name: "empty", from: 0, count: 0},
		{name: "past the family", from: MaximumHostnameFamily, count: 2},
	} {
		if _, err := HostnameCandidates(requested, test.from, test.count); !errors.Is(err, ErrInvalidHostnameAllocation) {
			t.Errorf("%s: error = %v, want ErrInvalidHostnameAllocation", test.name, err)
		}
	}
	if candidates, err := HostnameCandidates(requested, MaximumHostnameFamily, 1); err != nil || len(candidates) != 1 {
		t.Fatalf("last ordinal = %v, %v", candidates, err)
	}
}

func sequence(from, to int) []int {
	values := make([]int, 0, to-from)
	for value := from; value < to; value++ {
		values = append(values, value)
	}
	return values
}

func mustParseHostname(t *testing.T, value string) Hostname {
	t.Helper()
	hostname, err := ParseHostname(value)
	if err != nil {
		t.Fatalf("ParseHostname(%q) error = %v", value, err)
	}
	return hostname
}
