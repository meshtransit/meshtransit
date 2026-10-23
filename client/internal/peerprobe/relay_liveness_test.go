package peerprobe

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
)

type relayPongRecorder struct {
	mu    sync.Mutex
	pongs map[uint64]int
}

func (*relayPongRecorder) ObservePath(pathdiscovery.PathObservation) {}

func (r *relayPongRecorder) ObserveRelayPong(peerID uint64, _ time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pongs[peerID]++
}

func (r *relayPongRecorder) count(peerID uint64) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pongs[peerID]
}

// nextRelayed returns the next message sent through the relay of type T,
// skipping others (CALL_ME_MAYBE runs on its own schedule).
func nextRelayed[T disco.Message](t *testing.T, transport *relayTransport, wire interface {
	Open([]byte) (disco.Message, error)
}, within time.Duration,
) (T, relaySend, bool) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case sent := <-transport.relayed:
			message, err := wire.Open(sent.packet)
			if err != nil {
				t.Fatal(err)
			}
			if typed, ok := message.(T); ok {
				return typed, sent, true
			}
		case <-deadline:
			var zero T
			return zero, relaySend{}, false
		}
	}
}

func TestRuntimeAnswersRelayedPingWithRelayedPong(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	wire := testPeerChannel(t, remote, local)
	peerNode := testNodeKey(t, snapshot.Peers[0].PublicKey)
	ping := func(id byte) []byte {
		packet, err := wire.Seal(disco.Ping{TxID: disco.TxID{id}, Node: peerNode, SentAt: time.Now().UnixMilli()})
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}

	runtime.HandleRelayDatagram(ping(1), [32]byte{0x99})
	if _, _, ok := nextRelayed[disco.Pong](t, transport, wire, 300*time.Millisecond); ok {
		t.Fatal("answered a relayed PING from a mismatched relay source")
	}
	runtime.HandleRelayDatagram(ping(2), peerNode)
	pong, sent, ok := nextRelayed[disco.Pong](t, transport, wire, 2*time.Second)
	if !ok || pong.TxID != (disco.TxID{2}) || pong.Observed.IsValid() || sent.node != peerNode {
		t.Fatalf("relayed PONG = %#v (sent %v)", pong, ok)
	}
	// A second PING within a second gets no PONG.
	runtime.HandleRelayDatagram(ping(3), peerNode)
	if _, _, ok := nextRelayed[disco.Pong](t, transport, wire, 300*time.Millisecond); ok {
		t.Fatal("relayed PONGs are not paced")
	}
}

func TestRuntimePingsRouterThroughRelayAndReportsPong(t *testing.T) {
	t.Parallel()

	local, remote := testIdentity(t), testIdentity(t)
	transport := &relayTransport{runtimeTransport: newRuntimeTransport(), relayed: make(chan relaySend, 64)}
	recorder := &relayPongRecorder{pongs: map[uint64]int{}}
	runtime, err := newRuntime(t.Context(), local, transport, recorder, pathdiscovery.NewProbeTelemetry(),
		time.Now, time.Millisecond, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	peerID := snapshot.Peers[0].ID
	wire := testPeerChannel(t, remote, local)
	runtime.SetRelayLiveness([]uint64{peerID, 0, peerID})

	ping, sent, ok := nextRelayed[disco.Ping](t, transport, wire, 3*time.Second)
	if !ok || ping.Padding != 0 || sent.node != testNodeKey(t, snapshot.Peers[0].PublicKey) {
		t.Fatalf("relay PING = %#v (sent %v)", ping, ok)
	}
	answer := func(id disco.TxID, observed netip.AddrPort) []byte {
		packet, err := wire.Seal(disco.Pong{TxID: id, Observed: observed, Echo: ping.SentAt})
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}
	// Unknown transactions and PONGs naming a source are not proof.
	runtime.HandleRelayDatagram(answer(disco.TxID{0x42}, netip.AddrPort{}), sent.node)
	if _, err := runtime.registry.OpenRelayed(answer(ping.TxID, netip.MustParseAddrPort("192.0.2.1:41641")),
		sent.node, generation, time.Now()); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("relayed PONG with a source: %v", err)
	}
	runtime.HandleRelayDatagram(answer(ping.TxID, netip.AddrPort{}), sent.node)
	deadline := time.Now().Add(2 * time.Second)
	for recorder.count(peerID) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if recorder.count(peerID) != 1 {
		t.Fatalf("relay PONGs reported = %d, want 1", recorder.count(peerID))
	}
	// The same PONG again proves nothing more.
	runtime.HandleRelayDatagram(answer(ping.TxID, netip.AddrPort{}), sent.node)

	// A proven direct path ends the relay pings.
	runtime.registry.MarkPong(peerID, time.Now())
	for {
		select {
		case <-transport.relayed:
			continue
		default:
		}
		break
	}
	if _, _, ok := nextRelayed[disco.Ping](t, transport, wire, 1500*time.Millisecond); ok {
		t.Fatal("pinged through the relay a peer with a proven direct path")
	}
	if recorder.count(peerID) != 1 {
		t.Fatalf("a repeated PONG was reported: %d", recorder.count(peerID))
	}
}

func TestRegistryRefusesDirectPongWithoutSource(t *testing.T) {
	t.Parallel()

	runtime, _, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	packet, err := testPeerChannel(t, remote, local).Seal(disco.Pong{TxID: disco.TxID{1}, Echo: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.registry.Open(packet, netip.MustParseAddrPort("198.51.100.9:41641"), generation,
		time.Now()); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("direct PONG without a source: %v", err)
	}
}

// Past the bound the first peers of the list, the most needed (routers
// before resolver Devices), are kept, not the lowest IDs.
func TestSetRelayLivenessKeepsTheFirstPeers(t *testing.T) {
	t.Parallel()
	runtime := &Runtime{}
	var ids []uint64
	for id := uint64(MaxRelayLivenessPeers + 10); id > 0; id-- {
		ids = append(ids, id)
	}
	runtime.SetRelayLiveness(append([]uint64{0, ids[0]}, ids...))
	runtime.relayMu.Lock()
	targets := slices.Clone(runtime.relay.targets)
	runtime.relayMu.Unlock()
	want := slices.Clone(ids[:MaxRelayLivenessPeers])
	slices.Sort(want)
	if !slices.Equal(targets, want) {
		t.Fatalf("targets = %v, want %v", targets, want)
	}
}
