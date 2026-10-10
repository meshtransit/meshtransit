package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

// A prefix with more Devices than one allocation window: the search starts
// at the lowest free address the store found, not at the prefix start.
func TestNextAvailableAddressFromStartsPastADenseRun(t *testing.T) {
	t.Parallel()

	prefix := netip.MustParsePrefix("100.64.0.0/20")
	start := netip.MustParseAddr("100.64.1.45") // .1 … 1.44 are taken
	occupied := []netip.Addr{netip.MustParseAddr("100.64.1.46")}
	got, err := NextAvailableAddressFrom(prefix, start, occupied, 256)
	if err != nil || got != start {
		t.Fatalf("NextAvailableAddressFrom() = %v, %v; want %v", got, err, start)
	}
	taken := []netip.Addr{start, netip.MustParseAddr("100.64.1.46")}
	if got, err := NextAvailableAddressFrom(prefix, start, taken, 256); err != nil ||
		got != netip.MustParseAddr("100.64.1.47") {
		t.Fatalf("NextAvailableAddressFrom() past taken = %v, %v", got, err)
	}
	// No start (or one before the first host) searches from the first host.
	if got, err := NextAvailableAddressFrom(prefix, netip.Addr{}, nil, 256); err != nil ||
		got != netip.MustParseAddr("100.64.0.1") {
		t.Fatalf("NextAvailableAddressFrom(no start) = %v, %v", got, err)
	}
	if got, err := NextAvailableAddressFrom(prefix, prefix.Addr(), nil, 256); err != nil ||
		got != netip.MustParseAddr("100.64.0.1") {
		t.Fatalf("NextAvailableAddressFrom(network address) = %v, %v", got, err)
	}
	// A start at or past the broadcast address means the prefix is full.
	for _, full := range []string{"100.64.15.255", "100.64.16.0"} {
		if _, err := NextAvailableAddressFrom(prefix, netip.MustParseAddr(full), nil, 256); !errors.Is(err, ErrAddressExhausted) {
			t.Fatalf("NextAvailableAddressFrom(%s) error = %v, want exhausted", full, err)
		}
	}
	if _, err := NextAvailableAddressFrom(prefix, netip.MustParseAddr("fd00::1"), nil, 256); !errors.Is(err, ErrInvalidAllocation) {
		t.Fatalf("start of another family: %v", err)
	}
}
