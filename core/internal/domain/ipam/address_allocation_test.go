package ipam_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/ipam"
)

func TestNextAvailableAddressSelectsLowestUsableCandidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prefix   string
		occupied []string
		want     string
	}{
		{name: "empty ipv4 prefix", prefix: "100.64.1.0/24", want: "100.64.1.1"},
		{
			name:     "ipv4 gap",
			prefix:   "100.64.1.0/24",
			occupied: []string{"100.64.1.1", "100.64.1.3"},
			want:     "100.64.1.2",
		},
		{name: "empty ipv6 prefix", prefix: "fd7a:115c:a1e0::/64", want: "fd7a:115c:a1e0::1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			prefix := netip.MustParsePrefix(test.prefix)
			occupied := parseAddresses(test.occupied)
			before := slices.Clone(occupied)
			got, err := ipam.NextAvailableAddress(prefix, occupied, 16)
			if err != nil {
				t.Fatalf("NextAvailableAddress() error = %v", err)
			}
			if got.String() != test.want {
				t.Fatalf("NextAvailableAddress() = %s, want %s", got, test.want)
			}
			if !slices.Equal(occupied, before) {
				t.Fatal("NextAvailableAddress() mutated the occupied snapshot")
			}
		})
	}
}

func TestNextAvailableAddressHonorsSearchBound(t *testing.T) {
	t.Parallel()

	prefix := netip.MustParsePrefix("100.64.1.0/24")
	occupied := parseAddresses([]string{"100.64.1.1", "100.64.1.2", "100.64.1.3"})
	address, err := ipam.NextAvailableAddress(prefix, occupied, 3)
	if !errors.Is(err, ipam.ErrAddressExhausted) {
		t.Fatalf("NextAvailableAddress() error = %v, want ErrAddressExhausted", err)
	}
	if address.IsValid() {
		t.Fatalf("NextAvailableAddress() = %s after exhaustion", address)
	}
}

func TestNextAvailableAddressDoesNotAllocateIPv4NetworkOrBroadcast(t *testing.T) {
	t.Parallel()

	address, err := ipam.NextAvailableAddress(netip.MustParsePrefix("192.0.2.0/30"), nil, 4)
	if err != nil || address != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("first /30 allocation = (%s, %v)", address, err)
	}
	address, err = ipam.NextAvailableAddress(
		netip.MustParsePrefix("192.0.2.0/30"),
		[]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
		4,
	)
	if !errors.Is(err, ipam.ErrAddressExhausted) || address.IsValid() {
		t.Fatalf("exhausted /30 allocation = (%s, %v)", address, err)
	}
}

func TestNextAvailableAddressRejectsUnsafeInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		prefix         netip.Prefix
		occupied       []netip.Addr
		candidateLimit int
	}{
		{name: "missing prefix", candidateLimit: 1},
		{name: "unmasked prefix", prefix: netip.MustParsePrefix("100.64.1.3/24"), candidateLimit: 1},
		{name: "missing bound", prefix: netip.MustParsePrefix("100.64.1.0/24")},
		{name: "excessive bound", prefix: netip.MustParsePrefix("100.64.1.0/24"), candidateLimit: ipam.MaxCandidateLimit + 1},
		{
			name:           "address outside prefix",
			prefix:         netip.MustParsePrefix("100.64.1.0/24"),
			occupied:       []netip.Addr{netip.MustParseAddr("100.64.2.1")},
			candidateLimit: 1,
		},
		{
			name:           "mixed family",
			prefix:         netip.MustParsePrefix("100.64.1.0/24"),
			occupied:       []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::1")},
			candidateLimit: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, err := ipam.NextAvailableAddress(test.prefix, test.occupied, test.candidateLimit)
			if !errors.Is(err, ipam.ErrInvalidAllocation) {
				t.Fatalf("NextAvailableAddress() error = %v, want ErrInvalidAllocation", err)
			}
			if address.IsValid() {
				t.Fatalf("NextAvailableAddress() = %s after invalid input", address)
			}
		})
	}
}

func parseAddresses(values []string) []netip.Addr {
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParseAddr(value))
	}
	return result
}
