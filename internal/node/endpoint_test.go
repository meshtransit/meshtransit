package node

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestEndpointValidatesAddressAndSource(t *testing.T) {
	t.Parallel()

	validAddress := netip.MustParseAddrPort("192.0.2.10:41641")
	endpoint, err := NewEndpoint(validAddress, EndpointSourceSTUN)
	if err != nil {
		t.Fatalf("NewEndpoint() error = %v", err)
	}
	if !endpoint.IsValid() || endpoint.Address() != validAddress || endpoint.Source() != EndpointSourceSTUN {
		t.Fatalf("Endpoint = %+v, want validated endpoint", endpoint)
	}

	for _, test := range []struct {
		name    string
		address netip.AddrPort
		source  EndpointSource
	}{
		{name: "zero address", source: EndpointSourceSTUN},
		{name: "zero port", address: netip.MustParseAddrPort("192.0.2.10:0"), source: EndpointSourceSTUN},
		{name: "unspecified address", address: netip.MustParseAddrPort("0.0.0.0:41641"), source: EndpointSourceSTUN},
		{name: "multicast address", address: netip.MustParseAddrPort("224.0.0.1:41641"), source: EndpointSourceSTUN},
		{name: "IPv4 loopback", address: netip.MustParseAddrPort("127.0.0.1:41641"), source: EndpointSourceLocal},
		{name: "IPv6 loopback", address: netip.MustParseAddrPort("[::1]:41641"), source: EndpointSourceLocal},
		{name: "link-local address", address: netip.MustParseAddrPort("[fe80::1]:41641"), source: EndpointSourceLocal},
		{name: "IPv4-mapped address", address: netip.MustParseAddrPort("[::ffff:192.0.2.10]:41641"), source: EndpointSourceSTUN},
		{name: "zoned address", address: netip.MustParseAddrPort("[fe80::1%en0]:41641"), source: EndpointSourceLocal},
		{name: "unknown source", address: validAddress, source: EndpointSourceUnknown},
		{name: "future source", address: validAddress, source: EndpointSourceConfigured + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewEndpoint(test.address, test.source); !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("NewEndpoint() error = %v, want ErrInvalidEndpoint", err)
			}
		})
	}
}

func TestEndpointSetCanonicalizesAndCopies(t *testing.T) {
	t.Parallel()

	discoveryKey, err := NewDiscoveryKey([32]byte{1})
	if err != nil {
		t.Fatalf("NewDiscoveryKey() error = %v", err)
	}
	first, _ := NewEndpoint(netip.MustParseAddrPort("192.0.2.10:41641"), EndpointSourceSTUN)
	second, _ := NewEndpoint(netip.MustParseAddrPort("10.0.0.2:41641"), EndpointSourceLocal)
	input := []Endpoint{first, second}
	set, err := NewEndpointSet(discoveryKey, input)
	if err != nil {
		t.Fatalf("NewEndpointSet() error = %v", err)
	}
	input[0] = Endpoint{}
	want := []Endpoint{second, first}
	if !set.IsValid() || !slices.Equal(set.Endpoints(), want) {
		t.Fatalf("EndpointSet.Endpoints() = %+v, want %+v", set.Endpoints(), want)
	}
	got := set.Endpoints()
	got[0] = Endpoint{}
	if !slices.Equal(set.Endpoints(), want) {
		t.Fatal("EndpointSet exposed mutable endpoint storage")
	}
}

func TestEndpointSetRejectsUnsafeCollections(t *testing.T) {
	t.Parallel()

	discoveryKey, _ := NewDiscoveryKey([32]byte{1})
	endpoint, _ := NewEndpoint(netip.MustParseAddrPort("192.0.2.10:41641"), EndpointSourceSTUN)
	tooMany := make([]Endpoint, maximumEndpointCount+1)
	for index := range tooMany {
		tooMany[index], _ = NewEndpoint(
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 41641),
			EndpointSourceSTUN,
		)
	}
	for _, test := range []struct {
		name      string
		key       DiscoveryKey
		endpoints []Endpoint
	}{
		{name: "missing discovery key", endpoints: []Endpoint{endpoint}},
		{name: "invalid endpoint", key: discoveryKey, endpoints: []Endpoint{{}}},
		{name: "duplicate address", key: discoveryKey, endpoints: []Endpoint{endpoint, endpoint}},
		{name: "too many endpoints", key: discoveryKey, endpoints: tooMany},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewEndpointSet(test.key, test.endpoints); !errors.Is(err, ErrInvalidEndpointSet) {
				t.Fatalf("NewEndpointSet() error = %v, want ErrInvalidEndpointSet", err)
			}
		})
	}
}

func endpointSetFixture(t testing.TB) EndpointSet {
	t.Helper()
	discoveryKey, err := NewDiscoveryKey([32]byte{1})
	if err != nil {
		t.Fatalf("NewDiscoveryKey() error = %v", err)
	}
	endpoint, err := NewEndpoint(
		netip.MustParseAddrPort("192.0.2.10:41641"),
		EndpointSourceSTUN,
	)
	if err != nil {
		t.Fatalf("NewEndpoint() error = %v", err)
	}
	set, err := NewEndpointSet(discoveryKey, []Endpoint{endpoint})
	if err != nil {
		t.Fatalf("NewEndpointSet() error = %v", err)
	}
	return set
}
