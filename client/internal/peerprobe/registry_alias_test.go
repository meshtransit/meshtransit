package peerprobe

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/shared/disco"
)

// TD-SEC-76: a peer of another Network cannot point this Device's probes
// into its LAN: only public addresses of its CALL_ME_MAYBE are kept.
func TestCallMeMaybeFromAPeerOfAnotherNetworkKeepsOnlyPublicAddresses(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(testIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)
	message := func(seq uint64) disco.CallMeMaybe {
		return disco.CallMeMaybe{Seq: seq, SentAt: time.Now().UnixMilli(), Endpoints: []disco.Endpoint{
			{Kind: disco.EndpointHost, Addr: netip.MustParseAddrPort("192.168.1.30:41641")},
			{Kind: disco.EndpointServerReflex, Addr: netip.MustParseAddrPort("203.0.113.9:41641")},
		}}
	}
	accepted := func(alias bool, seq uint64) []netip.AddrPort {
		t.Helper()
		peer := &peerChannel{peerID: 2, discoveryKey: testIdentity(t).Public(), alias: alias}
		incoming, err := registry.acceptCallMeMaybe(peer, message(seq), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		call, ok := incoming.(IncomingCallMeMaybe)
		if !ok {
			t.Fatalf("incoming = %T", incoming)
		}
		got := slices.Clone(call.endpoints)
		slices.SortFunc(got, func(a, b netip.AddrPort) int { return a.Compare(b) })
		return got
	}
	if same := accepted(false, 1); len(same) != 2 {
		t.Fatalf("a peer of this Network = %v", same)
	}
	if shared := accepted(true, 1); !slices.Equal(shared, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")}) {
		t.Fatalf("a peer of another Network = %v", shared)
	}
}
