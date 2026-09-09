package pathdiscovery

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestSource_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		source   Source
		expected string
	}{
		{name: "unknown", source: SourceUnknown, expected: "unknown"},
		{name: "host", source: SourceHost, expected: "host"},
		{name: "server reflexive", source: SourceServerReflexive, expected: "server_reflexive"},
		{name: "port mapping", source: SourcePortMapping, expected: "port_mapping"},
		{name: "configured", source: SourceConfigured, expected: "configured"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.source.String(); got != test.expected {
				t.Fatalf("Source.String() = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestNewCandidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint netip.AddrPort
		source   Source
		wantErr  bool
	}{
		{
			name:     "public ipv4 host",
			endpoint: netip.MustParseAddrPort("203.0.113.1:41641"),
			source:   SourceHost,
		},
		{
			name:     "private ipv4 host",
			endpoint: netip.MustParseAddrPort("192.168.1.10:41641"),
			source:   SourceHost,
		},
		{
			name:     "unique local ipv6 host",
			endpoint: netip.MustParseAddrPort("[fd00::1]:41641"),
			source:   SourceHost,
		},
		{
			name:     "server reflexive",
			endpoint: netip.MustParseAddrPort("198.51.100.8:41641"),
			source:   SourceServerReflexive,
		},
		{
			name:     "port mapping",
			endpoint: netip.MustParseAddrPort("198.51.100.9:41641"),
			source:   SourcePortMapping,
		},
		{
			name:     "configured",
			endpoint: netip.MustParseAddrPort("198.51.100.10:41641"),
			source:   SourceConfigured,
		},
		{
			name:    "zero value",
			source:  SourceHost,
			wantErr: true,
		},
		{
			name:     "unknown source",
			endpoint: netip.MustParseAddrPort("203.0.113.1:41641"),
			source:   SourceUnknown,
			wantErr:  true,
		},
		{
			name:     "zero port",
			endpoint: netip.MustParseAddrPort("203.0.113.1:0"),
			source:   SourceHost,
			wantErr:  true,
		},
		{
			name:     "mapped ipv4",
			endpoint: netip.MustParseAddrPort("[::ffff:192.0.2.1]:41641"),
			source:   SourceHost,
			wantErr:  true,
		},
		{
			name:     "unspecified",
			endpoint: netip.MustParseAddrPort("0.0.0.0:41641"),
			source:   SourceHost,
			wantErr:  true,
		},
		{
			name:     "multicast",
			endpoint: netip.MustParseAddrPort("224.0.0.1:41641"),
			source:   SourceHost,
			wantErr:  true,
		},
		{
			name:     "loopback",
			endpoint: netip.MustParseAddrPort("127.0.0.1:41641"),
			source:   SourceHost,
			wantErr:  true,
		},
		{
			name:     "link local ipv4",
			endpoint: netip.MustParseAddrPort("169.254.1.1:41641"),
			source:   SourceHost,
			wantErr:  true,
		},
		{
			name:     "zoned link local ipv6",
			endpoint: netip.MustParseAddrPort("[fe80::1%eth0]:41641"),
			source:   SourceHost,
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			candidate, err := NewCandidate(test.endpoint, test.source)
			if test.wantErr {
				if err == nil {
					t.Fatal("NewCandidate() error = nil, want non-nil")
				}

				return
			}
			if err != nil {
				t.Fatalf("NewCandidate() error = %v", err)
			}
			if candidate.Endpoint() != test.endpoint || candidate.Source() != test.source {
				t.Fatalf("NewCandidate() = %#v", candidate)
			}
		})
	}
}

func TestNewSet_NormalizesCandidates(t *testing.T) {
	t.Parallel()

	hostEndpoint := netip.MustParseAddrPort("192.168.1.20:41641")
	configuredEndpoint := netip.MustParseAddrPort("198.51.100.20:41641")
	reflexiveEndpoint := netip.MustParseAddrPort("203.0.113.20:41641")
	mappedEndpoint := netip.MustParseAddrPort("192.0.2.20:41641")
	inputs := []Candidate{
		mustCandidate(t, hostEndpoint, SourceHost),
		mustCandidate(t, reflexiveEndpoint, SourceServerReflexive),
		mustCandidate(t, mappedEndpoint, SourceHost),
		mustCandidate(t, configuredEndpoint, SourceConfigured),
		mustCandidate(t, mappedEndpoint, SourcePortMapping),
	}

	set, err := NewSet(inputs)
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	expected := []Candidate{
		mustCandidate(t, mappedEndpoint, SourcePortMapping),
		mustCandidate(t, reflexiveEndpoint, SourceServerReflexive),
		mustCandidate(t, configuredEndpoint, SourceConfigured),
		mustCandidate(t, hostEndpoint, SourceHost),
	}
	if got := set.Candidates(); !slices.Equal(got, expected) {
		t.Fatalf("NewSet() candidates = %#v, want %#v", got, expected)
	}
	if got := set.Endpoints(); !slices.Equal(got, []netip.AddrPort{
		mappedEndpoint,
		reflexiveEndpoint,
		configuredEndpoint,
		hostEndpoint,
	}) {
		t.Fatalf("Set.Endpoints() = %#v", got)
	}
}

func TestNewSet_RejectsInvalidAndOversizedInput(t *testing.T) {
	t.Parallel()

	valid := mustCandidate(
		t,
		netip.MustParseAddrPort("203.0.113.30:41641"),
		SourceServerReflexive,
	)
	tests := []struct {
		name       string
		candidates []Candidate
	}{
		{
			name:       "invalid candidate",
			candidates: []Candidate{{}},
		},
		{
			name:       "too many raw inputs",
			candidates: slices.Repeat([]Candidate{valid}, maxCandidateInputs+1),
		},
		{
			name:       "too many unique endpoints",
			candidates: uniqueCandidates(t, MaxCandidates+1),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewSet(test.candidates); err == nil {
				t.Fatal("NewSet() error = nil, want non-nil")
			}
		})
	}
}

func TestNewSet_TooManyCandidatesSentinel(t *testing.T) {
	t.Parallel()

	_, err := NewSet(uniqueCandidates(t, MaxCandidates+1))
	if !errors.Is(err, ErrTooManyCandidates) {
		t.Fatalf("NewSet() error = %v, want ErrTooManyCandidates", err)
	}
}

func TestSet_DefensiveCopiesAndEquality(t *testing.T) {
	t.Parallel()

	candidate := mustCandidate(
		t,
		netip.MustParseAddrPort("203.0.113.40:41641"),
		SourceServerReflexive,
	)
	inputs := []Candidate{candidate}
	set, err := NewSet(inputs)
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	inputs[0] = Candidate{}
	returned := set.Candidates()
	returned[0] = Candidate{}

	equal, err := NewSet([]Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() comparison error = %v", err)
	}
	if set.Len() != 1 || !set.Equal(equal) || set.Equal(Set{}) {
		t.Fatalf("Set state = len %d, equal %t", set.Len(), set.Equal(equal))
	}
	if got := set.Candidates()[0]; got != candidate {
		t.Fatalf("Set.Candidates() mutated internal value = %#v", got)
	}
}

func FuzzNewCandidate(f *testing.F) {
	f.Add("203.0.113.50:41641", uint8(SourceServerReflexive))
	f.Add("[2001:db8::50]:41641", uint8(SourceHost))
	f.Add("invalid", uint8(SourceUnknown))

	f.Fuzz(func(t *testing.T, value string, rawSource uint8) {
		endpoint, err := netip.ParseAddrPort(value)
		if err != nil {
			return
		}
		candidate, err := NewCandidate(endpoint, Source(rawSource))
		if err != nil {
			return
		}
		address := candidate.Endpoint().Addr()
		if !candidate.Endpoint().IsValid() || candidate.Endpoint().Port() == 0 ||
			address.Is4In6() || address.Zone() != "" || address != address.Unmap() ||
			!address.IsGlobalUnicast() || address.IsUnspecified() || address.IsMulticast() ||
			address.IsLoopback() || address.IsLinkLocalUnicast() ||
			candidate.Source() == SourceUnknown {
			t.Fatalf("NewCandidate() accepted unsafe value %#v", candidate)
		}
	})
}

func mustCandidate(t *testing.T, endpoint netip.AddrPort, source Source) Candidate {
	t.Helper()

	candidate, err := NewCandidate(endpoint, source)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}

	return candidate
}

func uniqueCandidates(t *testing.T, count int) []Candidate {
	t.Helper()

	candidates := make([]Candidate, 0, count)
	for index := range count {
		address := netip.AddrFrom4([4]byte{10, 0, 0, byte(index + 1)})
		candidates = append(
			candidates,
			mustCandidate(t, netip.AddrPortFrom(address, 41641), SourceHost),
		)
	}

	return candidates
}
