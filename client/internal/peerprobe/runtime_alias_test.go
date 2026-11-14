package peerprobe

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/shared/disco"
)

// TD-SEC-76: a peer of another Network (a share) is told only addresses the
// Internet already sees, whatever way they were learned; other peers still
// get the LAN ones.
func TestCallMeMaybeSendsOnlyPublicAddressesToAPeerOfAnotherNetwork(t *testing.T) {
	t.Parallel()
	r := &Runtime{
		localEndpoints: []disco.Endpoint{
			{Kind: disco.EndpointHost, Addr: netip.MustParseAddrPort("192.168.1.20:41641")},
			{Kind: disco.EndpointHost, Addr: netip.MustParseAddrPort("[2001:db8::10]:41641")},
			{Kind: disco.EndpointServerReflex, Addr: netip.MustParseAddrPort("203.0.113.9:41641")},
		},
		// A same-LAN peer reflected this Device's LAN address back.
		reflexive: map[netip.AddrPort]time.Time{netip.MustParseAddrPort("192.168.1.20:41642"): time.Unix(1, 0)},
	}
	addresses := func(publicOnly bool) []string {
		t.Helper()
		message, ok := r.callMeMaybe(time.Unix(1, 0), publicOnly)
		if !ok {
			t.Fatal("no CALL_ME_MAYBE")
		}
		var got []string
		for _, endpoint := range message.Endpoints {
			got = append(got, endpoint.Addr.String())
		}
		slices.Sort(got)
		return got
	}
	if same := addresses(false); len(same) != 4 {
		t.Fatalf("a peer of this Network = %v", same)
	}
	want := []string{"203.0.113.9:41641", "[2001:db8::10]:41641"}
	if shared := addresses(true); !slices.Equal(shared, want) {
		t.Fatalf("a peer of another Network = %v, want %v", shared, want)
	}
	// Only LAN addresses: nothing is sent to a peer of another Network.
	r.localEndpoints = r.localEndpoints[:1]
	if _, ok := r.callMeMaybe(time.Unix(2, 0), true); ok {
		t.Fatal("a CALL_ME_MAYBE with no endpoint was built")
	}
}
