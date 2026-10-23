package underlay

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
)

func reportResolvers(t *testing.T, resolvers ...NetworkResolver) {
	t.Helper()
	SetReportedResolvers(resolvers)
	t.Cleanup(func() { SetReportedResolvers(nil) })
}

// A socket to a network's resolver is protected, then bound to that
// network; other sockets are not bound.
func TestASocketToANetworksResolverIsBoundToIt(t *testing.T) {
	installRecorder(t, false)
	var bound []int64
	refuse := false
	SetNetworkBinder(func(_ uintptr, network int64) error {
		bound = append(bound, network)
		if refuse {
			return errors.New("background network")
		}
		return nil
	})
	t.Cleanup(func() { SetNetworkBinder(nil) })
	listener, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	resolver := netip.MustParseAddrPort(listener.LocalAddr().String())
	reportResolvers(t, NetworkResolver{Address: resolver, Network: 7})
	before := ReportedGeneration()
	reportResolvers(t, NetworkResolver{Address: resolver, Network: 7})
	if ReportedGeneration() == before {
		t.Fatal("the generation did not change")
	}

	conn, err := Dialer(0).DialContext(t.Context(), "udp4", resolver.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	other, err := Dialer(0).DialContext(t.Context(), "udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	_ = other.Close()
	if !slices.Equal(bound, []int64{7}) {
		t.Fatalf("bound to %v", bound)
	}
	// A network the platform cannot bind to fails that dial only.
	refuse = true
	if _, err := Dialer(0).DialContext(t.Context(), "udp4", resolver.String()); err == nil {
		t.Fatal("a refused bind was used")
	}
}

func TestThroughMeshAndPrivateReach(t *testing.T) {
	SetMeshRoutes([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	t.Cleanup(func() { SetMeshRoutes(nil); SetPrivateReach(nil) })
	site, lan, carrier := netip.MustParseAddr("10.20.0.53"), netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("10.20.0.1")
	if !ThroughMesh(site) || ThroughMesh(lan) {
		t.Fatal("ThroughMesh does not follow the routes")
	}
	// A network's own resolver inside a Site's route stays on its network.
	reportResolvers(t, NetworkResolver{Address: netip.AddrPortFrom(carrier, 53), Network: 3})
	if ThroughMesh(carrier) {
		t.Fatal("a network's resolver went through the mesh")
	}
	if !PrivateReachable(lan) {
		t.Fatal("without a policy every resolver is reachable")
	}
	SetPrivateReach(func(netip.Addr) bool { return false })
	if !PrivateReachable(site) || !PrivateReachable(carrier) || PrivateReachable(lan) {
		t.Fatal("private reach does not keep a Site's and the network's resolvers only")
	}
}
