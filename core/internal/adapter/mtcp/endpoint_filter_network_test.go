package mtcp

import (
	"net/netip"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

// TD-SEC-76: a peer of another Network (reached through a share) is sent
// only the addresses the Internet sees, never its LAN or interface ones.
func TestPeerOfAnotherNetworkGetsNoHostCandidates(t *testing.T) {
	t.Parallel()
	var stored []node.Endpoint
	for _, value := range []struct {
		text   string
		source node.EndpointSource
	}{
		{"192.168.1.5:41641", node.EndpointSourceLocal},
		{"[2001:db8::5]:41641", node.EndpointSourceLocal},
		{"203.0.113.9:41641", node.EndpointSourceSTUN},
		{"198.51.100.7:41641", node.EndpointSourcePortMapped},
	} {
		stored = append(stored, must(node.NewEndpoint(netip.MustParseAddrPort(value.text), value.source)))
	}
	nodeID := must(node.NewID([16]byte{0x01, 0x89, 0x0f, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x42}))
	connectivity := must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
		Key:         must(mapsession.NewConnectivityKey(nodeID, 1)),
		EndpointSet: must(node.NewEndpointSet(must(node.NewDiscoveryKey([32]byte{7})), stored)), EndpointSetPresent: true,
		Online: true,
	}))
	kinds := func(filter endpointFilter) []mtcpv1.Endpoint_Kind {
		t.Helper()
		device := &mtcpv1.Device{}
		if err := encodeConnectivity(device, connectivity, false, filter, nil); err != nil {
			t.Fatal(err)
		}
		var got []mtcpv1.Endpoint_Kind
		for _, endpoint := range device.Endpoints {
			got = append(got, endpoint.Kind)
		}
		return got
	}
	if same := kinds(endpointFilter{}); len(same) != 4 {
		t.Fatalf("a peer of this Network lost endpoints: %v", same)
	}
	// The LAN HOST goes; the public HOST, reflexive and mapped stay.
	got := kinds(endpointFilter{}.publicCandidatesOnly())
	hosts := 0
	for _, kind := range got {
		if kind == mtcpv1.Endpoint_HOST {
			hosts++
		}
	}
	if len(got) != 3 || hosts != 1 {
		t.Fatalf("a peer of another Network = %v, want the public HOST, reflexive and mapped", got)
	}
}
