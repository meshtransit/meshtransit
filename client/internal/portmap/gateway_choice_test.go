package portmap

import (
	"net/netip"
	"testing"
)

func TestPreferredGatewayTakesLowestMetric(t *testing.T) {
	t.Parallel()
	got, ok := preferredGateway([]gatewayCandidate{
		{nextHop: netip.MustParseAddr("192.168.8.1"), index: 12, metric: 50},
		{nextHop: netip.MustParseAddr("172.31.32.1"), index: 4, metric: 25},
		{nextHop: netip.MustParseAddr("10.0.0.1"), index: 3, metric: 25},
	})
	if !ok || got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("preferredGateway() = %v, %v; want 10.0.0.1 (lowest metric, then index)", got, ok)
	}
}

func TestPreferredGatewayUnmapsNextHop(t *testing.T) {
	t.Parallel()
	got, ok := preferredGateway([]gatewayCandidate{
		{nextHop: netip.MustParseAddr("::ffff:192.168.1.1"), index: 5, metric: 10},
	})
	if !ok || got != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("preferredGateway() = %v, %v; want 192.168.1.1", got, ok)
	}
}

func TestPreferredGatewayRejectsOnLinkBestRoute(t *testing.T) {
	t.Parallel()
	// Mobile broadband's on-link default route wins; the Wi-Fi router behind
	// the worse route is not the one traffic leaves through.
	_, ok := preferredGateway([]gatewayCandidate{
		{nextHop: netip.IPv4Unspecified(), index: 2, metric: 10},
		{nextHop: netip.MustParseAddr("192.168.1.1"), index: 5, metric: 50},
	})
	if ok {
		t.Fatal("preferredGateway() returned a gateway behind a worse route")
	}
	if _, ok := preferredGateway(nil); ok {
		t.Fatal("preferredGateway(nil) found a gateway")
	}
}
