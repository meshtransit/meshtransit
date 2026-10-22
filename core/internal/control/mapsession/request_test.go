package mapsession

import (
	"errors"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

func TestRequestValidatesNodeKey(t *testing.T) {
	nodeKey, err := node.NewKey([32]byte{2})
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	request, err := NewRequest(nodeKey)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if !request.IsValid() || request.NodeKey() != nodeKey {
		t.Fatalf("request = %+v, want valid immutable request", request)
	}
	if request.DNSForward() || request.WithDNSForward().DNSForward() ||
		!request.WithDNSForward().WithLargeMap().DNSForward() {
		t.Fatal("dns.forward1 is not recorded only when declared with large maps")
	}
	if request.WithDNSRecords().WithLargeMap().DNSRecords() ||
		!request.WithDNSRecords().WithDNSForward().WithLargeMap().DNSRecords() {
		t.Fatal("dns.records1 is not recorded only with dns.forward1 on large maps")
	}
	if _, err := NewRequest(node.Key{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NewRequest() without a Node key error = %v, want ErrInvalidRequest", err)
	}
}

func TestRequestCarriesImmutableEndpointSet(t *testing.T) {
	t.Parallel()

	nodeKey, err := node.NewKey([32]byte{2})
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	request, err := NewRequest(nodeKey)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if _, present := request.EndpointSet(); present {
		t.Fatal("new request unexpectedly contains endpoint set")
	}
	if _, present := request.PreferredRelay(); present {
		t.Fatal("new request unexpectedly contains preferred relay")
	}
	endpoint, err := node.NewEndpoint(
		netip.MustParseAddrPort("192.0.2.10:41641"),
		node.EndpointSourceSTUN,
	)
	if err != nil {
		t.Fatalf("node.NewEndpoint() error = %v", err)
	}
	discoveryKey, err := node.NewDiscoveryKey([32]byte{3})
	if err != nil {
		t.Fatalf("node.NewDiscoveryKey() error = %v", err)
	}
	set, err := node.NewEndpointSet(discoveryKey, []node.Endpoint{endpoint})
	if err != nil {
		t.Fatalf("node.NewEndpointSet() error = %v", err)
	}
	withEndpoints, err := request.WithEndpointSet(set)
	if err != nil {
		t.Fatalf("Request.WithEndpointSet() error = %v", err)
	}
	got, present := withEndpoints.EndpointSet()
	if !present || !withEndpoints.IsValid() || got.DiscoveryKey() != discoveryKey ||
		len(got.Endpoints()) != 1 || got.Endpoints()[0] != endpoint {
		t.Fatalf("Request.EndpointSet() = (%+v, %t), want endpoint fixture", got, present)
	}
	if _, present := request.EndpointSet(); present {
		t.Fatal("Request.WithEndpointSet() mutated original request")
	}
	if _, err := request.WithEndpointSet(node.EndpointSet{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Request.WithEndpointSet(zero) error = %v, want ErrInvalidRequest", err)
	}
	withPreference, err := withEndpoints.WithPreferredRelay(3)
	if err != nil {
		t.Fatalf("Request.WithPreferredRelay() error = %v", err)
	}
	if preferredRelay, present := withPreference.PreferredRelay(); !present || preferredRelay != 3 || !withPreference.IsValid() {
		t.Fatalf("Request.PreferredRelay() = (%d, %t), want (3, true)", preferredRelay, present)
	}
	if _, err := request.WithPreferredRelay(3); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Request.WithPreferredRelay() without endpoints error = %v, want invalid request", err)
	}
}
