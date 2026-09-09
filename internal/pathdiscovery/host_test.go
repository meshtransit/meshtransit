package pathdiscovery

import (
	"net/netip"
	"testing"
)

func TestHostCandidatesFiltersOverlayAndUnsafeAddresses(t *testing.T) {
	t.Parallel()

	set, err := HostCandidates(
		[]netip.Addr{
			netip.MustParseAddr("192.168.1.20"),
			netip.MustParseAddr("192.168.1.20"),
			netip.MustParseAddr("2001:db8::20"),
			netip.MustParseAddr("100.64.0.3"),
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("169.254.1.1"),
		},
		41641,
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
	)
	if err != nil {
		t.Fatalf("HostCandidates() error = %v", err)
	}
	got := set.Candidates()
	if len(got) != 2 ||
		got[0].Endpoint() != netip.MustParseAddrPort("192.168.1.20:41641") ||
		got[1].Endpoint() != netip.MustParseAddrPort("[2001:db8::20]:41641") {
		t.Fatalf("HostCandidates() = %#v", got)
	}
	for _, candidate := range got {
		if candidate.Source() != SourceHost {
			t.Fatalf("host candidate source = %v", candidate.Source())
		}
	}
}

func TestHostCandidatesBoundsOutput(t *testing.T) {
	t.Parallel()

	addresses := make([]netip.Addr, MaxCandidates+8)
	for index := range addresses {
		addresses[index] = netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)})
	}
	set, err := HostCandidates(addresses, 41641, nil)
	if err != nil {
		t.Fatalf("HostCandidates() error = %v", err)
	}
	if set.Len() != MaxCandidates {
		t.Fatalf("HostCandidates().Len() = %d, want %d", set.Len(), MaxCandidates)
	}
}

func TestHostCandidatesRejectsInvalidBoundary(t *testing.T) {
	t.Parallel()

	if _, err := HostCandidates(nil, 0, nil); err == nil {
		t.Fatal("HostCandidates(port 0) error = nil")
	}
	tooMany := make([]netip.Addr, maxHostAddressInputs+1)
	if _, err := HostCandidates(tooMany, 41641, nil); err == nil {
		t.Fatal("HostCandidates(too many) error = nil")
	}
	if _, err := HostCandidates(
		nil,
		41641,
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")},
	); err == nil {
		t.Fatal("HostCandidates(non-canonical exclusion) error = nil")
	}
}
