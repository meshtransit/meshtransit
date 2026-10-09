package peerprobe

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/key"
)

// relayTransport adds a relay path to the fake socket transport.
type relayTransport struct {
	*runtimeTransport
	relayed chan relaySend
}

type relaySend struct {
	packet []byte
	node   [32]byte
}

func (t *relayTransport) SendRelayDatagram(packet []byte, peerNode [32]byte) error {
	t.relayed <- relaySend{packet: append([]byte(nil), packet...), node: peerNode}
	return nil
}

func newRelayRuntime(t *testing.T) (*Runtime, *relayTransport, key.DiscoPrivate, key.DiscoPrivate) {
	t.Helper()
	local, remote := testIdentity(t), testIdentity(t)
	transport := &relayTransport{runtimeTransport: newRuntimeTransport(), relayed: make(chan relaySend, 16)}
	runtime, err := newRuntime(t.Context(), local, transport, nil, pathdiscovery.NewProbeTelemetry(),
		time.Now, time.Millisecond, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	return runtime, transport, local, remote
}

func TestRuntimeSendsCallMeMaybeThroughRelay(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	own := netip.MustParseAddrPort("198.51.100.5:41641")
	runtime.SetLocalEndpoints([]disco.Endpoint{{Kind: disco.EndpointServerReflex, Addr: own}},
		disco.NATInfo{Mapping: disco.MappingEndpointIndependent})

	var sent relaySend
	select {
	case sent = <-transport.relayed:
	case <-time.After(3 * time.Second):
		t.Fatal("no CALL_ME_MAYBE sent through the relay")
	}
	if sent.node != testNodeKey(t, snapshot.Peers[0].PublicKey) {
		t.Fatal("CALL_ME_MAYBE routed to the wrong node")
	}
	message, err := testPeerChannel(t, remote, local).Open(sent.packet)
	if err != nil {
		t.Fatal(err)
	}
	call, ok := message.(disco.CallMeMaybe)
	if !ok || call.Seq == 0 || len(call.Endpoints) != 1 || call.Endpoints[0].Addr != own ||
		call.NAT.Mapping != disco.MappingEndpointIndependent {
		t.Fatalf("CALL_ME_MAYBE = %#v", message)
	}

	// Within the fast interval nothing more is sent; a trusted direct path
	// stops them altogether.
	runtime.registry.MarkPong(snapshot.Peers[0].ID, time.Now())
	select {
	case extra := <-transport.relayed:
		t.Fatalf("unexpected CALL_ME_MAYBE %x", extra.packet[:8])
	case <-time.After(1500 * time.Millisecond):
	}
	if runtime.telemetry.Snapshot().CallMeMaybeSent != 1 {
		t.Fatalf("sent counter = %d", runtime.telemetry.Snapshot().CallMeMaybeSent)
	}
}

func TestRuntimeAnswersRelayedCallMeMaybe(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	snapshot.Peers[0].Endpoints = nil // only the CALL_ME_MAYBE tells where the peer is
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	advertised := netip.MustParseAddrPort("203.0.113.40:41641")
	wire := testPeerChannel(t, remote, local)
	seal := func(seq uint64) []byte {
		packet, err := wire.Seal(disco.CallMeMaybe{
			Seq: seq, SentAt: time.Now().UnixMilli(),
			Endpoints: []disco.Endpoint{{Kind: disco.EndpointServerReflex, Addr: advertised}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}
	peerNode := testNodeKey(t, snapshot.Peers[0].PublicKey)

	// A relay-attested node that is not the sender's: ignored.
	runtime.HandleRelayDatagram(seal(1), [32]byte{0x99})
	select {
	case <-transport.attempts:
		t.Fatal("probed after a CALL_ME_MAYBE from a mismatched relay source")
	case <-time.After(200 * time.Millisecond):
	}

	runtime.HandleRelayDatagram(seal(2), peerNode)
	sent := waitForRuntimeSend(t, transport.runtimeTransport)
	if sent.destination != advertised {
		t.Fatalf("probed %v, want the advertised endpoint", sent.destination)
	}
	if message, err := wire.Open(sent.packet); err != nil {
		t.Fatal(err)
	} else if _, ok := message.(disco.Ping); !ok {
		t.Fatalf("sent %#v, want a ping", message)
	}
	if runtime.telemetry.Snapshot().CallMeMaybeAccepted != 1 {
		t.Fatal("accepted counter not incremented")
	}

	// A replay of an older sequence is refused.
	if _, err := runtime.registry.OpenRelayed(seal(2), peerNode, generation, time.Now()); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("replayed CALL_ME_MAYBE: %v", err)
	}
	if candidates := runtime.registry.PeerCandidates(snapshot.Peers[0].ID, time.Now()); !slices.Contains(candidates, advertised) {
		t.Fatalf("candidates %v lack the advertised endpoint", candidates)
	}
}

func TestLearnedCandidatesAreBoundedAndSurviveReplace(t *testing.T) {
	t.Parallel()

	_, _, registry, snapshot, generation := testRegistry(t)
	now := time.Unix(1_000, 0)
	peerID := snapshot.Peers[0].ID
	for index := range maxLearnedCandidates + 5 {
		endpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(index)}), 4000)
		registry.LearnPeerReflexive(peerID, endpoint, now.Add(time.Duration(index)*time.Millisecond))
	}
	if learned := len(registry.byID[peerID].learned); learned != maxLearnedCandidates {
		t.Fatalf("learned candidates = %d", learned)
	}
	next := cloneTestSnapshot(snapshot)
	next.Revision++
	nextGeneration := generation
	nextGeneration.MapRevision = next.Revision
	if _, err := registry.Replace(next, nextGeneration, now); err != nil {
		t.Fatal(err)
	}
	if learned := len(registry.byID[peerID].learned); learned != maxLearnedCandidates {
		t.Fatalf("learned candidates after Replace = %d", learned)
	}
	if candidates := registry.PeerCandidates(peerID, now.Add(learnedCandidateLifetime+time.Second)); len(candidates) != 1 {
		t.Fatalf("expired learned candidates still offered: %d", len(candidates))
	}
}
