package peerprobe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
)

// measureResult is what MeasureRoundTrip returned.
type measureResult struct {
	roundTrip RoundTrip
	err       error
}

// measureAsync runs MeasureRoundTrip in the background.
func measureAsync(ctx context.Context, runtime *Runtime, peerID uint64) <-chan measureResult {
	done := make(chan measureResult, 1)
	go func() {
		roundTrip, err := runtime.MeasureRoundTrip(ctx, peerID)
		done <- measureResult{roundTrip: roundTrip, err: err}
	}()
	return done
}

func awaitMeasurement(t *testing.T, done <-chan measureResult) measureResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the measurement")
		return measureResult{}
	}
}

// pongTo answers a sealed PING with a PONG from the given wire.
func pongTo(t *testing.T, wire interface {
	Open([]byte) (disco.Message, error)
	Seal(disco.Message) ([]byte, error)
}, packet []byte, observed netip.AddrPort,
) []byte {
	t.Helper()
	message, err := wire.Open(packet)
	if err != nil {
		t.Fatal(err)
	}
	ping, ok := message.(disco.Ping)
	if !ok {
		t.Fatalf("expected a PING, got %#v", message)
	}
	pong, err := wire.Seal(disco.Pong{TxID: ping.TxID, Observed: observed, Echo: ping.SentAt})
	if err != nil {
		t.Fatal(err)
	}
	return pong
}

func TestMeasureRoundTripPingsTheConfirmedDirectEndpoint(t *testing.T) {
	t.Parallel()

	runtime, transport, _, local, remote, snapshot, generation := testRuntime(t)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	wire := testPeerChannel(t, remote, local)
	endpoint := snapshot.Peers[0].Endpoints[0]
	observed := netip.MustParseAddrPort("198.51.100.10:41641")
	// The scheduled probe's PONG confirms the endpoint.
	scheduled := waitForRuntimeSend(t, transport)
	runtime.HandleDatagram(pongTo(t, wire, scheduled.packet, observed), endpoint, generation.Socket)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, confirmed := runtime.registry.ConfirmedEndpoint(snapshot.Peers[0].ID, time.Now(), directTrust); confirmed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scheduled PONG did not confirm the endpoint")
		}
		time.Sleep(time.Millisecond)
	}

	done := measureAsync(t.Context(), runtime, snapshot.Peers[0].ID)
	measured := waitForRuntimeSend(t, transport)
	if measured.destination != endpoint {
		t.Fatalf("measurement PING went to %v, want %v", measured.destination, endpoint)
	}
	runtime.HandleDatagram(pongTo(t, wire, measured.packet, observed), endpoint, generation.Socket)
	result := awaitMeasurement(t, done)
	if result.err != nil || result.roundTrip.Relayed || result.roundTrip.Duration < 0 {
		t.Fatalf("MeasureRoundTrip() = %#v, %v", result.roundTrip, result.err)
	}
	// A confirmed endpoint costs the probe budget nothing.
	runtime.registry.mu.RLock()
	tokens := runtime.registry.byID[snapshot.Peers[0].ID].allowance.budget.tokens
	runtime.registry.mu.RUnlock()
	if tokens < unconfirmedProbeBurst-1 {
		t.Fatalf("probe tokens = %v after the measurement", tokens)
	}
}

func TestMeasureRoundTripGoesThroughTheRelayWithoutADirectPath(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	wire := testPeerChannel(t, remote, local)
	peerNode := testNodeKey(t, snapshot.Peers[0].PublicKey)

	done := measureAsync(t.Context(), runtime, snapshot.Peers[0].ID)
	ping, sent, ok := nextRelayed[disco.Ping](t, transport, wire, 2*time.Second)
	if !ok || sent.node != peerNode {
		t.Fatalf("relay PING = %#v (sent %v)", ping, ok)
	}
	pong, err := wire.Seal(disco.Pong{TxID: ping.TxID, Echo: ping.SentAt})
	if err != nil {
		t.Fatal(err)
	}
	runtime.HandleRelayDatagram(pong, peerNode)
	result := awaitMeasurement(t, done)
	if result.err != nil || !result.roundTrip.Relayed || result.roundTrip.Duration < 0 {
		t.Fatalf("MeasureRoundTrip() = %#v, %v", result.roundTrip, result.err)
	}
	runtime.relayMu.Lock()
	pending := len(runtime.relay.pending)
	runtime.relayMu.Unlock()
	if pending != 0 {
		t.Fatalf("%d relay PINGs left pending", pending)
	}
}

func TestMeasureRoundTripReportsNoAnswer(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	runtime.measure.timeout = 100 * time.Millisecond
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	wire := testPeerChannel(t, remote, local)
	done := measureAsync(t.Context(), runtime, snapshot.Peers[0].ID)
	if _, _, ok := nextRelayed[disco.Ping](t, transport, wire, 2*time.Second); !ok {
		t.Fatal("no relay PING was sent")
	}
	if result := awaitMeasurement(t, done); !errors.Is(result.err, ErrNoAnswer) {
		t.Fatalf("MeasureRoundTrip() error = %v, want ErrNoAnswer", result.err)
	}
}

func TestMeasureRoundTripRunsOneMeasurementOfAPeerAtATime(t *testing.T) {
	t.Parallel()

	runtime, _, local, remote := newRelayRuntime(t)
	runtime.measure.timeout = 300 * time.Millisecond
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	peerID := snapshot.Peers[0].ID
	first := measureAsync(t.Context(), runtime, peerID)
	deadline := time.Now().Add(time.Second)
	for {
		runtime.measure.mu.Lock()
		_, running := runtime.measure.running[peerID]
		runtime.measure.mu.Unlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first measurement did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := runtime.MeasureRoundTrip(t.Context(), peerID); !errors.Is(err, ErrMeasurementBusy) {
		t.Fatalf("second MeasureRoundTrip() error = %v, want ErrMeasurementBusy", err)
	}
	awaitMeasurement(t, first)
}

func TestMeasureRoundTripSpacesMeasurementsOfAPeer(t *testing.T) {
	t.Parallel()

	runtime, _, local, remote := newRelayRuntime(t)
	const spacing = 300 * time.Millisecond
	runtime.measure.spacing = spacing
	runtime.measure.timeout = 50 * time.Millisecond
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	peerID := snapshot.Peers[0].ID
	awaitMeasurement(t, measureAsync(t.Context(), runtime, peerID))
	started := time.Now()
	awaitMeasurement(t, measureAsync(t.Context(), runtime, peerID))
	if elapsed := time.Since(started); elapsed < spacing-20*time.Millisecond {
		t.Fatalf("the second measurement started after %v, want at least %v", elapsed, spacing)
	}
}

func TestMeasureRoundTripStopsWithItsContext(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	wire := testPeerChannel(t, remote, local)
	ctx, cancel := context.WithCancel(t.Context())
	done := measureAsync(ctx, runtime, snapshot.Peers[0].ID)
	if _, _, ok := nextRelayed[disco.Ping](t, transport, wire, 2*time.Second); !ok {
		t.Fatal("no relay PING was sent")
	}
	cancel()
	if result := awaitMeasurement(t, done); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("MeasureRoundTrip() error = %v, want context.Canceled", result.err)
	}
}

func TestMeasureRoundTripRefusesUnknownPeersAndInvalidCalls(t *testing.T) {
	t.Parallel()

	runtime, _, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, err := runtime.MeasureRoundTrip(t.Context(), snapshot.Peers[0].ID); !errors.Is(err, ErrInactive) {
		t.Fatalf("before a map: error = %v, want ErrInactive", err)
	}
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.MeasureRoundTrip(t.Context(), 0); !errors.Is(err, ErrInvalidProbe) {
		t.Fatalf("peer 0: error = %v, want ErrInvalidProbe", err)
	}
	if _, err := runtime.MeasureRoundTrip(t.Context(), 99); !errors.Is(err, ErrUnknownPeer) || Unanswered(err) {
		t.Fatalf("unknown peer: error = %v, want ErrUnknownPeer (not a lost sample)", err)
	}
	var none *Runtime
	if _, err := none.MeasureRoundTrip(t.Context(), 2); !errors.Is(err, ErrInactive) {
		t.Fatalf("nil runtime: error = %v, want ErrInactive", err)
	}
}

func TestMeasureRoundTripWaitsOutTheRelayPacingWithAMargin(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	peerID := snapshot.Peers[0].ID
	wire := testPeerChannel(t, remote, local)
	// A relay PING left just now and its PONG already came: nothing to attach to.
	sentAt := time.Now()
	runtime.relayMu.Lock()
	runtime.relay.sent[peerID] = sentAt
	runtime.relayMu.Unlock()

	done := measureAsync(t.Context(), runtime, peerID)
	if _, _, ok := nextRelayed[disco.Ping](t, transport, wire, 3*time.Second); !ok {
		t.Fatal("no relay PING was sent")
	}
	if elapsed := time.Since(sentAt); elapsed < relayLivenessSpacing+relaySpacingMargin-20*time.Millisecond {
		t.Fatalf("the measurement PING left %v after the last one, want at least %v",
			elapsed, relayLivenessSpacing+relaySpacingMargin)
	}
	awaitMeasurement(t, done)
}

func TestMeasureRoundTripRelaysWhenTheDirectPathIsNotCurrent(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	peerID := snapshot.Peers[0].ID
	endpoint := snapshot.Peers[0].Endpoints[0]
	// The endpoint answered, but longer ago than directTrust: the data plane
	// relays by now.
	runtime.registry.ConfirmProbe(peerID, endpoint, time.Now().Add(-directTrust-time.Second))
	if _, confirmed := runtime.registry.ConfirmedEndpoint(peerID, time.Now(), directTrust); confirmed {
		t.Fatal("a confirmation older than directTrust still counts")
	}
	runtime.registry.ConfirmProbe(peerID, endpoint, time.Now())
	if got, confirmed := runtime.registry.ConfirmedEndpoint(peerID, time.Now(), directTrust); !confirmed || got != endpoint {
		t.Fatalf("ConfirmedEndpoint() = %v, %v", got, confirmed)
	}

	runtime.registry.ConfirmProbe(peerID, endpoint, time.Now().Add(-directTrust-time.Second))
	runtime.measure.timeout = 200 * time.Millisecond
	wire := testPeerChannel(t, remote, local)
	done := measureAsync(t.Context(), runtime, peerID)
	if _, _, ok := nextRelayed[disco.Ping](t, transport, wire, 2*time.Second); !ok {
		t.Fatal("the measurement did not go through the relay")
	}
	awaitMeasurement(t, done)
}

func TestMeasureRoundTripIgnoresARelayPongFromAnotherPeer(t *testing.T) {
	t.Parallel()

	runtime, transport, local, remote := newRelayRuntime(t)
	runtime.measure.timeout = 300 * time.Millisecond
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	wire := testPeerChannel(t, remote, local)
	done := measureAsync(t.Context(), runtime, snapshot.Peers[0].ID)
	ping, _, ok := nextRelayed[disco.Ping](t, transport, wire, 2*time.Second)
	if !ok {
		t.Fatal("no relay PING was sent")
	}
	// The right transaction, delivered as coming from another node: the
	// registry refuses to open it for this peer.
	pong, err := wire.Seal(disco.Pong{TxID: ping.TxID, Echo: ping.SentAt})
	if err != nil {
		t.Fatal(err)
	}
	runtime.HandleRelayDatagram(pong, [32]byte{0x99})
	if result := awaitMeasurement(t, done); !errors.Is(result.err, ErrNoAnswer) {
		t.Fatalf("MeasureRoundTrip() error = %v, want ErrNoAnswer", result.err)
	}
}

func TestMeasurementsRefusedBeforeSendingDoNotDelayTheNext(t *testing.T) {
	t.Parallel()

	measurements := newMeasurements()
	now := time.Now()
	if _, err := measurements.begin(2, now); err != nil {
		t.Fatal(err)
	}
	measurements.end(2, now, false)
	if wait, err := measurements.begin(2, now); err != nil || wait != 0 {
		t.Fatalf("after a refused measurement: wait %v, error %v", wait, err)
	}
	measurements.end(2, now, true)
	if wait, err := measurements.begin(2, now.Add(300*time.Millisecond)); err != nil ||
		wait != measurements.spacing-300*time.Millisecond {
		t.Fatalf("after a sent measurement: wait %v, error %v", wait, err)
	}
}

func TestUnansweredTellsLostSamplesFromFailures(t *testing.T) {
	t.Parallel()

	for _, lost := range []error{ErrNoAnswer, ErrInactive, ErrNoPath, ErrSendFailed, pathdiscovery.ErrSocketChanged} {
		if !Unanswered(fmt.Errorf("wrapped: %w", lost)) {
			t.Fatalf("Unanswered(%v) = false", lost)
		}
	}
	for _, failure := range []error{
		nil, ErrMeasurementBusy, ErrInvalidProbe, ErrUnknownPeer, ErrNoRelay, context.Canceled, errors.New("other"),
	} {
		if Unanswered(failure) {
			t.Fatalf("Unanswered(%v) = true", failure)
		}
	}
}

// pacedRelayPeer answers relay PINGs like a real peer: after a short delay,
// and at most one a second (relayPingAnswerSpacing). It drops PINGs whose
// TxID is in lose.
type pacedRelayPeer struct {
	mu       sync.Mutex
	answered time.Time
	pings    int
	refused  int
	lose     map[disco.TxID]bool
}

func (p *pacedRelayPeer) run(
	t *testing.T,
	runtime *Runtime,
	transport *relayTransport,
	wire interface {
		Open([]byte) (disco.Message, error)
		Seal(disco.Message) ([]byte, error)
	},
	peerNode [32]byte,
) {
	t.Helper()
	go func() {
		for {
			select {
			case <-t.Context().Done():
				return
			case sent := <-transport.relayed:
				message, err := wire.Open(sent.packet)
				if err != nil {
					continue
				}
				ping, ok := message.(disco.Ping)
				if !ok {
					continue
				}
				p.mu.Lock()
				p.pings++
				lost := p.lose[ping.TxID]
				refused := !p.answered.IsZero() && time.Since(p.answered) < relayPingAnswerSpacing
				if refused {
					p.refused++
				} else if !lost {
					p.answered = time.Now()
				}
				p.mu.Unlock()
				if lost || refused {
					continue
				}
				time.AfterFunc(20*time.Millisecond, func() {
					if pong, err := wire.Seal(disco.Pong{TxID: ping.TxID, Echo: ping.SentAt}); err == nil {
						runtime.HandleRelayDatagram(pong, peerNode)
					}
				})
			}
		}
	}()
}

func relayLivenessRuntime(t *testing.T) (*Runtime, *relayTransport, uint64, [32]byte, interface {
	Open([]byte) (disco.Message, error)
	Seal(disco.Message) ([]byte, error)
},
) {
	t.Helper()
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
	return runtime, transport, snapshot.Peers[0].ID, testNodeKey(t, snapshot.Peers[0].PublicKey),
		testPeerChannel(t, remote, local)
}

func TestMeasurementsOfALivenessTargetAreAllAnswered(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("takes about ten seconds")
	}

	runtime, transport, peerID, peerNode, wire := relayLivenessRuntime(t)
	peer := &pacedRelayPeer{lose: map[disco.TxID]bool{}}
	peer.run(t, runtime, transport, wire, peerNode)
	// A Site router reached through the relay: liveness pings it every second.
	runtime.SetRelayLiveness([]uint64{peerID})
	time.Sleep(1300 * time.Millisecond)

	for sample := range 6 {
		roundTrip, err := runtime.MeasureRoundTrip(t.Context(), peerID)
		if err != nil || !roundTrip.Relayed {
			t.Fatalf("sample %d: %#v, %v; every PING the peer got was answerable", sample, roundTrip, err)
		}
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.refused != 0 {
		t.Fatalf("the peer refused %d of %d PINGs: they broke its pacing", peer.refused, peer.pings)
	}
}

func TestAMeasurementPingStaysPendingForLiveness(t *testing.T) {
	t.Parallel()

	runtime, transport, peerID, peerNode, wire := relayLivenessRuntime(t)
	runtime.measure.timeout = 50 * time.Millisecond
	done := measureAsync(t.Context(), runtime, peerID)
	ping, _, ok := nextRelayed[disco.Ping](t, transport, wire, 2*time.Second)
	if !ok {
		t.Fatal("no relay PING was sent")
	}
	if result := awaitMeasurement(t, done); !errors.Is(result.err, ErrNoAnswer) {
		t.Fatalf("MeasureRoundTrip() error = %v, want ErrNoAnswer", result.err)
	}
	// The PONG comes after the measurement gave up: still news for liveness.
	runtime.relayMu.Lock()
	entry, pending := runtime.relay.pending[ping.TxID]
	runtime.relayMu.Unlock()
	if !pending || entry.reply != nil {
		t.Fatalf("the measurement's PING after it ended = %#v (pending %v)", entry, pending)
	}
	pong, err := wire.Seal(disco.Pong{TxID: ping.TxID, Echo: ping.SentAt})
	if err != nil {
		t.Fatal(err)
	}
	runtime.HandleRelayDatagram(pong, peerNode)
	deadline := time.Now().Add(time.Second)
	for {
		runtime.relayMu.Lock()
		_, still := runtime.relay.pending[ping.TxID]
		runtime.relayMu.Unlock()
		if !still {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late PONG was not taken")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMeasureRoundTripFailsWithoutARelay(t *testing.T) {
	t.Parallel()

	runtime, _, _, _, _, snapshot, generation := testRuntime(t)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.MeasureRoundTrip(t.Context(), snapshot.Peers[0].ID); !errors.Is(err, ErrNoRelay) ||
		Unanswered(err) {
		t.Fatalf("without a relay or a direct path: error = %v, want ErrNoRelay (not a lost sample)", err)
	}
}

func TestAMeasurementHoldsLivenessOffItsPeer(t *testing.T) {
	t.Parallel()

	runtime, transport, peerID, peerNode, wire := relayLivenessRuntime(t)
	recorder, ok := runtime.observer.(*relayPongRecorder)
	if !ok {
		t.Fatal("the runtime does not report to the recorder")
	}
	runtime.SetRelayLiveness([]uint64{peerID})
	liveness, _, sent := nextRelayed[disco.Ping](t, transport, wire, 3*time.Second)
	if !sent {
		t.Fatal("no liveness PING was sent")
	}
	livenessAt := time.Now()

	done := measureAsync(t.Context(), runtime, peerID)
	// The next relay PING is the measurement's, a margin past the peer's pacing.
	measured, _, ok := nextRelayed[disco.Ping](t, transport, wire, 3*time.Second)
	if !ok {
		t.Fatal("the measurement sent no relay PING")
	}
	if elapsed := time.Since(livenessAt); elapsed < relayMeasurementWait-20*time.Millisecond {
		t.Fatalf("the measurement PING left %v after liveness, want at least %v", elapsed, relayMeasurementWait)
	}
	if measured.TxID == liveness.TxID {
		t.Fatal("the measurement reused the liveness PING")
	}
	pong, err := wire.Seal(disco.Pong{TxID: measured.TxID, Echo: measured.SentAt})
	if err != nil {
		t.Fatal(err)
	}
	runtime.HandleRelayDatagram(pong, peerNode)
	if result := awaitMeasurement(t, done); result.err != nil || !result.roundTrip.Relayed {
		t.Fatalf("MeasureRoundTrip() = %#v, %v", result.roundTrip, result.err)
	}
	// The measurement's PONG proved the peer up for liveness too.
	deadline := time.Now().Add(time.Second)
	for recorder.count(peerID) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if recorder.count(peerID) != 1 {
		t.Fatalf("liveness PONGs reported = %d, want 1", recorder.count(peerID))
	}
}

func TestALostLivenessPingDoesNotCostAMeasurement(t *testing.T) {
	t.Parallel()

	runtime, transport, peerID, peerNode, wire := relayLivenessRuntime(t)
	peer := &pacedRelayPeer{lose: map[disco.TxID]bool{}}
	peer.run(t, runtime, transport, wire, peerNode)
	// A liveness PING just left and will never be answered.
	lost := disco.TxID{0x51}
	peer.lose[lost] = true
	now := time.Now()
	runtime.relayMu.Lock()
	runtime.relay.sent[peerID] = now
	runtime.relay.pending[lost] = relayPing{peerID: peerID, sentAt: now, deadline: now.Add(relayPongWithin)}
	runtime.relayMu.Unlock()

	for sample := range 2 {
		if roundTrip, err := runtime.MeasureRoundTrip(t.Context(), peerID); err != nil || !roundTrip.Relayed {
			t.Fatalf("sample %d = %#v, %v; want an answer", sample, roundTrip, err)
		}
	}
}

func TestAMeasurementGivesThePeerBackToLivenessOnceItsPingLeft(t *testing.T) {
	t.Parallel()

	runtime, transport, peerID, _, wire := relayLivenessRuntime(t)
	done := measureAsync(t.Context(), runtime, peerID)
	if _, _, ok := nextRelayed[disco.Ping](t, transport, wire, 2*time.Second); !ok {
		t.Fatal("the measurement sent no relay PING")
	}
	// The measurement now waits for its PONG; liveness must not wait with it.
	runtime.relayMu.Lock()
	_, held := runtime.relay.waiting[peerID]
	runtime.relayMu.Unlock()
	if held {
		t.Fatal("the measurement still holds liveness off the peer after its PING left")
	}
	if result := awaitMeasurement(t, done); !errors.Is(result.err, ErrNoAnswer) {
		t.Fatalf("MeasureRoundTrip() error = %v, want ErrNoAnswer", result.err)
	}
}

func TestAMeasurementWaitsAgainWhenARelayPingLeftDuringItsWait(t *testing.T) {
	t.Parallel()

	runtime, transport, peerID, _, wire := relayLivenessRuntime(t)
	runtime.measure.timeout = 50 * time.Millisecond
	runtime.relayMu.Lock()
	runtime.relay.sent[peerID] = time.Now()
	runtime.relayMu.Unlock()
	done := measureAsync(t.Context(), runtime, peerID)
	time.Sleep(300 * time.Millisecond)
	// A map change keeps the measurement's hold, and a PING that left
	// anyway pushes the measurement's turn back.
	runtime.forgetRelayPings()
	runtime.relayMu.Lock()
	_, held := runtime.relay.waiting[peerID]
	stamped := time.Now()
	runtime.relay.sent[peerID] = stamped
	runtime.relayMu.Unlock()
	if !held {
		t.Fatal("a map change released the measurement's hold on the peer")
	}
	if _, _, ok := nextRelayed[disco.Ping](t, transport, wire, 3*time.Second); !ok {
		t.Fatal("the measurement sent no relay PING")
	}
	if elapsed := time.Since(stamped); elapsed < relayMeasurementWait-20*time.Millisecond {
		t.Fatalf("the measurement PING left %v after the other PING, want at least %v", elapsed, relayMeasurementWait)
	}
	awaitMeasurement(t, done)
}

func TestLivenessDoesNotPingWhenItCannotRecordThePing(t *testing.T) {
	t.Parallel()

	runtime, transport, peerID, _, _ := relayLivenessRuntime(t)
	relayed, ok := runtime.transport.(pathdiscovery.RelayDatagramTransport)
	if !ok {
		t.Fatal("the test transport cannot relay")
	}
	runtime.SetRelayLiveness([]uint64{peerID})
	deadline := time.Now().Add(time.Hour)
	runtime.relayMu.Lock()
	for i := range maxRelayLivenessPending {
		runtime.relay.pending[disco.TxID{byte(i), byte(i >> 8), 0xee}] = relayPing{peerID: 1 << 40, deadline: deadline}
	}
	delete(runtime.relay.sent, peerID)
	// Forget what the liveness loop sent before the pending PINGs filled up.
	for len(transport.relayed) > 0 {
		<-transport.relayed
	}
	runtime.relayMu.Unlock()
	runtime.sendRelayPings(relayed)
	runtime.relayMu.Lock()
	_, sent := runtime.relay.sent[peerID]
	runtime.relayMu.Unlock()
	if sent || len(transport.relayed) != 0 {
		t.Fatalf("liveness pinged with its pending PINGs full (sent %v, %d queued)", sent, len(transport.relayed))
	}
}
