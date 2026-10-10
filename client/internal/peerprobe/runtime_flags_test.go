package peerprobe

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
)

func TestCallMeMaybeFlags(t *testing.T) {
	t.Parallel()
	endpoint := func(kind disco.EndpointKind, addr string) disco.Endpoint {
		return disco.Endpoint{Kind: kind, Addr: netip.MustParseAddrPort(addr)}
	}
	for _, tt := range []struct {
		name      string
		endpoints []disco.Endpoint
		want      disco.Flags
	}{
		{"ipv4 only", []disco.Endpoint{endpoint(disco.EndpointServerReflex, "198.51.100.7:41641")}, 0},
		{"global ipv6 host", []disco.Endpoint{endpoint(disco.EndpointHost, "[2001:db8::10]:41641")}, disco.FlagIPv6},
		{"unique-local only", []disco.Endpoint{endpoint(disco.EndpointHost, "[fd00::10]:41641")}, 0},
		{"peer-reflexive ipv6 is not ours", []disco.Endpoint{endpoint(disco.EndpointPeerReflexive, "[2001:db8::10]:41641")}, 0},
		{
			"port mapped and ipv6",
			[]disco.Endpoint{endpoint(disco.EndpointPortMapped, "203.0.113.7:50000"), endpoint(disco.EndpointServerReflex, "[2001:db8::10]:41641")},
			disco.FlagPortMapped | disco.FlagIPv6,
		},
	} {
		if got := callMeMaybeFlags(tt.endpoints); got != tt.want {
			t.Errorf("%s: flags %08b, want %08b", tt.name, got, tt.want)
		}
	}
}

// TestRuntimeProbesAPingingPeerOnce: a known address that pings while no
// path is proven gets one immediate probe, not one per ping.
func TestRuntimeProbesAPingingPeerOnce(t *testing.T) {
	t.Parallel()
	clock := &runtimeClock{now: time.Unix(2_000, 0)}
	local, remote := testIdentity(t), testIdentity(t)
	transport := newRuntimeTransport()
	runtime, err := newRuntime(t.Context(), local, transport, nil, pathdiscovery.NewProbeTelemetry(),
		clock.Now, time.Millisecond, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	snapshot.Peers[0].Endpoints = nil
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	remoteChannel := testPeerChannel(t, remote, local)
	source := netip.MustParseAddrPort("[2001:db8::30]:41641")
	runtime.registry.LearnPeerReflexive(snapshot.Peers[0].ID, source, clock.Now())
	for index := range 3 {
		packet, err := remoteChannel.Seal(disco.Ping{
			TxID: disco.TxID{byte(index + 1)}, Node: testNodeKey(t, snapshot.Peers[0].PublicKey),
		})
		if err != nil {
			t.Fatal(err)
		}
		runtime.processDatagram(receivedDatagram{packet: packet, source: source, socket: generation.Socket})
	}
	// Three pongs and one probe, all to the pinging address.
	deadline := time.Now().Add(2 * time.Second)
	for len(transport.sentSnapshot()) < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("sent %d datagrams, want 3 pongs and 1 probe", len(transport.sentSnapshot()))
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	sends := transport.sentSnapshot()
	if len(sends) != 4 {
		t.Fatalf("sent %d datagrams, want 4", len(sends))
	}
	for _, send := range sends {
		if send.destination != source {
			t.Fatalf("sent to %s", send.destination)
		}
	}
}
