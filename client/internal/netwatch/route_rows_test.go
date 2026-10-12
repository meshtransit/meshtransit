package netwatch

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDefaultRouteTokensFromRowsKeepDefaultsOfHostInterfaces(t *testing.T) {
	t.Parallel()
	rows := []routeRow{
		{bits: 0, index: 4, nextHop: netip.MustParseAddr("172.31.32.1")},
		// Windows can list one default route twice with different metrics.
		{bits: 0, index: 4, nextHop: netip.MustParseAddr("172.31.32.1")},
		{bits: 20, index: 4, nextHop: netip.IPv4Unspecified()},
		{bits: 0, index: 9, nextHop: netip.MustParseAddr("100.64.0.1")},
		{ipv6: true, bits: 0, index: 4, nextHop: netip.MustParseAddr("fe80::1")},
		{ipv6: true, bits: 0, index: 7, nextHop: netip.IPv6Unspecified()},
	}

	tokens, indexes := defaultRouteTokensFromRows(rows, map[int]struct{}{9: {}})

	want := []string{
		"default|family=4|link=4|gateway=172.31.32.1",
		"default|family=6|link=4|gateway=fe80::1",
		"default|family=6|link=7|gateway=",
	}
	if !slices.Equal(tokens, want) {
		t.Fatalf("tokens = %v, want %v", tokens, want)
	}
	if _, ok := indexes[9]; ok {
		t.Fatal("excluded interface 9 carries a default route")
	}
	if len(indexes) != 2 {
		t.Fatalf("indexes = %v, want 4 and 7", indexes)
	}
}

func TestDefaultRouteTokensFromRowsSeeGatewayChange(t *testing.T) {
	t.Parallel()
	before, _ := defaultRouteTokensFromRows([]routeRow{
		{bits: 0, index: 4, nextHop: netip.MustParseAddr("192.168.1.1")},
	}, nil)
	after, _ := defaultRouteTokensFromRows([]routeRow{
		{bits: 0, index: 4, nextHop: netip.MustParseAddr("192.168.8.1")},
	}, nil)
	if slices.Equal(before, after) {
		t.Fatalf("tokens did not change with the gateway: %v", before)
	}
}
