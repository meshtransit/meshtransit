package peerprobe

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
)

// On-demand round trips to one peer, for the app's connection test. One
// measurement is one disco PING and its PONG: to the peer's confirmed
// direct endpoint when it has one, which the probe budget does not charge,
// otherwise through the relay (disco-v2 §3.2.1). The peer already bounds the
// answers it sends (maxIncomingPingsPerPeer, relayPingAnswerSpacing); the
// limits here keep this node within them and bound its own work.
const (
	// maxConcurrentMeasurements bounds measurements in flight on the node.
	maxConcurrentMeasurements = 4
	// defaultMeasurementSpacing is the least time between two measurements
	// of one peer, the relay's PONG pacing.
	defaultMeasurementSpacing = time.Second
	// defaultMeasurementTimeout is how long a measurement waits for its
	// PONG once its PING left or it took the PONG of one in flight.
	defaultMeasurementTimeout = 2 * time.Second
	// relaySpacingMargin is added to the peer's relay PONG pacing before a
	// measurement sends its own relay PING: the previous PING may have
	// reached the peer later than it left here, and an early one goes
	// unanswered.
	relaySpacingMargin = 250 * time.Millisecond
	// relayMeasurementWait is how long after the last relay PING to a peer a
	// measurement sends its own, and so the longest it waits to send.
	relayMeasurementWait = relayLivenessSpacing + relaySpacingMargin
	// maxRelayTurns bounds how often a measurement waits again for its turn
	// when another relay PING to the peer left while it waited.
	maxRelayTurns = 3
)

// errRelayTurnTaken reports a relay PING to the peer sent while the
// measurement waited for its turn: it must wait again.
var errRelayTurnTaken = errors.New("peerprobe: the relay turn was taken")

var (
	// ErrMeasurementBusy reports a measurement of the peer already running,
	// or the node's measurement slots all in use.
	ErrMeasurementBusy = errors.New("peerprobe: another measurement is running")
	// ErrNoAnswer reports a PING the peer did not answer in time.
	ErrNoAnswer = errors.New("peerprobe: the peer did not answer")
	// ErrNoPath reports a relay PING that could not leave, or the relay PINGs
	// waiting for answers at their limit.
	ErrNoPath = errors.New("peerprobe: no path to the peer")
	// ErrNoRelay reports a peer with no confirmed direct path while this
	// node's transport cannot ping through the relay.
	ErrNoRelay = errors.New("peerprobe: no relay to ping the peer through")
)

// Unanswered reports whether err means only that this measurement got no
// answer: the peer did not answer, or the node was between maps, sockets or
// paths when it tried, or could not send just then. The next one may
// succeed, so the apps count it as a lost sample, not a failure. A peer this
// node cannot measure at all (ErrUnknownPeer, ErrNoRelay) is a failure.
func Unanswered(err error) bool {
	for _, lost := range []error{
		ErrNoAnswer, ErrNoPath, ErrSendFailed, ErrInactive, ErrInvalidGeneration,
		ErrProbeThrottled, pathdiscovery.ErrSocketChanged, pathdiscovery.ErrPeerProbeCapacity,
		pathdiscovery.ErrPeerProbeInactive,
	} {
		if errors.Is(err, lost) {
			return true
		}
	}
	return false
}

// RoundTrip is one measured round trip to a peer.
type RoundTrip struct {
	Duration time.Duration
	// Relayed reports a PING that went through the relay.
	Relayed bool
}

// measurements is the state of the measurements in flight. Its waiters
// receive the round trip of the PONG that answers their PING; they are
// registered before the PING leaves, so a fast PONG is never missed.
type measurements struct {
	mu      sync.Mutex
	running map[uint64]struct{}
	last    map[uint64]time.Time
	direct  map[pathdiscovery.ProbeID]chan<- time.Duration
	slots   chan struct{}
	spacing time.Duration
	timeout time.Duration
}

func newMeasurements() *measurements {
	return &measurements{
		running: map[uint64]struct{}{},
		last:    map[uint64]time.Time{},
		direct:  map[pathdiscovery.ProbeID]chan<- time.Duration{},
		slots:   make(chan struct{}, maxConcurrentMeasurements),
		spacing: defaultMeasurementSpacing,
		timeout: defaultMeasurementTimeout,
	}
}

// begin claims the peer's measurement and returns how long to wait for the
// spacing since its last one.
func (m *measurements) begin(peerID uint64, now time.Time) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, running := m.running[peerID]; running {
		return 0, ErrMeasurementBusy
	}
	// Entries past the spacing no longer constrain anything.
	for id, at := range m.last {
		if now.Sub(at) >= m.spacing {
			delete(m.last, id)
		}
	}
	m.running[peerID] = struct{}{}
	wait := time.Duration(0)
	if at, measured := m.last[peerID]; measured {
		wait = m.spacing - now.Sub(at)
	}
	// Bounded by the spacing whatever the clock did.
	return min(max(wait, 0), m.spacing), nil
}

// end releases the peer's measurement. A measurement that sent a PING
// counts from now for spacing; one refused before it sent does not.
func (m *measurements) end(peerID uint64, now time.Time, sent bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.running, peerID)
	if sent {
		m.last[peerID] = now
	}
}

func (m *measurements) watchDirect(id pathdiscovery.ProbeID, reply chan<- time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.direct[id] = reply
}

func (m *measurements) forgetDirect(id pathdiscovery.ProbeID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.direct, id)
}

// completeDirect hands an authenticated direct round trip to the
// measurement waiting for it, if any.
func (m *measurements) completeDirect(id pathdiscovery.ProbeID, roundTrip time.Duration) {
	m.mu.Lock()
	reply, waiting := m.direct[id]
	delete(m.direct, id)
	m.mu.Unlock()
	if waiting {
		deliverRoundTrip(reply, roundTrip)
	}
}

// deliverRoundTrip sends without blocking: each waiter has room for one
// answer, and a second answer to the same PING is not news.
func deliverRoundTrip(reply chan<- time.Duration, roundTrip time.Duration) {
	select {
	case reply <- roundTrip:
	default:
	}
}

// MeasureRoundTrip measures one round trip to the peer. It waits for the
// spacing since the peer's last measurement, through the relay up to
// another 1.25 s for the peer's pacing, then up to two seconds for the PONG.
// It fails with ErrMeasurementBusy while another measurement of the peer
// runs, and with ErrNoAnswer when the PONG does not come.
func (r *Runtime) MeasureRoundTrip(ctx context.Context, peerID uint64) (RoundTrip, error) {
	if r == nil {
		return RoundTrip{}, ErrInactive
	}
	if ctx == nil || peerID == 0 {
		return RoundTrip{}, ErrInvalidProbe
	}
	wait, err := r.measure.begin(peerID, r.clock())
	if err != nil {
		return RoundTrip{}, err
	}
	sent := false
	defer func() { r.measure.end(peerID, r.clock(), sent) }()
	select {
	case r.measure.slots <- struct{}{}:
	default:
		return RoundTrip{}, ErrMeasurementBusy
	}
	defer func() { <-r.measure.slots }()
	if err := r.sleep(ctx, wait); err != nil {
		return RoundTrip{}, err
	}
	sent = true
	// Only a path the peer answered on within directTrust is the direct
	// path in use: an older confirmation may be a path that died, while
	// the data plane already relays.
	if endpoint, confirmed := r.registry.ConfirmedEndpoint(peerID, r.clock(), directTrust); confirmed {
		measureCtx, cancel := context.WithTimeout(ctx, r.measure.timeout)
		defer cancel()
		return r.measureDirect(measureCtx, ctx, peerID, endpoint)
	}
	return r.measureRelayed(ctx, peerID)
}

func (r *Runtime) measureDirect(
	measureCtx context.Context,
	parent context.Context,
	peerID uint64,
	endpoint netip.AddrPort,
) (RoundTrip, error) {
	reply := make(chan time.Duration, 1)
	transaction, err := r.probeWatched(measureCtx, r.activeGeneration(), peerID, endpoint, false, reply)
	if err != nil {
		return RoundTrip{}, err
	}
	defer r.measure.forgetDirect(transaction.ID)
	return r.awaitRoundTrip(measureCtx, parent, reply, false)
}

// measureRelayed measures through the relay. The peer answers one relay
// PING from this node a second (relayPingAnswerSpacing), which relay
// liveness also uses for Site routers and exit nodes. So the measurement
// sends its own PING only relayMeasurementWait after the last relay PING to
// the peer, a margin past the peer's pacing, and while it waits liveness
// leaves the peer to it. Once the PING has left liveness may ping again:
// its next PING is a second later, past the peer's pacing, and the
// measurement's PONG proves the peer up for liveness just the same.
func (r *Runtime) measureRelayed(ctx context.Context, peerID uint64) (RoundTrip, error) {
	relayed, supported := r.transport.(pathdiscovery.RelayDatagramTransport)
	if !supported {
		return RoundTrip{}, ErrNoRelay
	}
	reply := make(chan time.Duration, 1)
	defer r.releaseRelayMeasurement(peerID, reply)
	for turn := 0; ; turn++ {
		if turn == maxRelayTurns {
			return RoundTrip{}, ErrNoPath
		}
		if wait := r.awaitRelayTurn(peerID, reply); wait > 0 {
			if err := r.sleep(ctx, wait); err != nil {
				return RoundTrip{}, err
			}
		}
		err := r.sendRelayMeasurement(peerID, reply, relayed)
		if err == nil {
			break
		}
		if !errors.Is(err, errRelayTurnTaken) {
			return RoundTrip{}, err
		}
	}
	// The answer is awaited from when the PING left.
	measureCtx, cancel := context.WithTimeout(ctx, r.measure.timeout)
	defer cancel()
	return r.awaitRoundTrip(measureCtx, ctx, reply, true)
}

// awaitRelayTurn returns how long the measurement waits before its PING, and
// meanwhile holds liveness off the peer.
func (r *Runtime) awaitRelayTurn(peerID uint64, reply chan<- time.Duration) time.Duration {
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	r.relay.waiting[peerID] = reply
	last, sent := r.relay.sent[peerID]
	if !sent {
		return 0
	}
	return min(max(relayMeasurementWait-r.clock().Sub(last), 0), relayMeasurementWait)
}

// sendRelayMeasurement seals the measurement's relay PING, records it as
// pending and sends it, in the active generation under the lifecycle read
// lock, as liveness does.
func (r *Runtime) sendRelayMeasurement(
	peerID uint64,
	reply chan<- time.Duration,
	relayed pathdiscovery.RelayDatagramTransport,
) error {
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	select {
	case <-r.done:
		return ErrInactive
	default:
	}
	if !r.activeGeneration().IsValid() {
		return ErrInactive
	}
	var id disco.TxID
	if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
		return ErrInvalidProbe
	}
	now := r.clock()
	packet, node, err := r.registry.SealRelayPing(peerID, id, now)
	if err != nil {
		return err
	}
	r.relayMu.Lock()
	r.pruneRelayPings(now)
	if len(r.relay.pending) >= maxRelayPending {
		r.relayMu.Unlock()
		return ErrNoPath
	}
	previous, hadPrevious := r.relay.sent[peerID]
	if hadPrevious && now.Sub(previous) < relayMeasurementWait {
		// Another relay PING left while this measurement slept.
		r.relayMu.Unlock()
		return errRelayTurnTaken
	}
	r.relay.sent[peerID] = now
	r.relay.pending[id] = relayPing{peerID: peerID, sentAt: now, deadline: now.Add(relayPongWithin), reply: reply}
	if r.relay.waiting[peerID] == reply {
		delete(r.relay.waiting, peerID)
	}
	r.relayMu.Unlock()
	if err := relayed.SendRelayDatagram(packet, node); err != nil {
		// Nothing left: liveness need not keep this PING's pacing.
		r.relayMu.Lock()
		delete(r.relay.pending, id)
		if r.relay.sent[peerID].Equal(now) {
			if hadPrevious {
				r.relay.sent[peerID] = previous
			} else {
				delete(r.relay.sent, peerID)
			}
		}
		r.relayMu.Unlock()
		return ErrNoPath
	}
	return nil
}

// pruneRelayPings forgets relay PINGs past their deadline. relayMu is held.
func (r *Runtime) pruneRelayPings(now time.Time) {
	for id, ping := range r.relay.pending {
		if !now.Before(ping.deadline) {
			delete(r.relay.pending, id)
		}
	}
}

// releaseRelayMeasurement gives the peer back to liveness. The
// measurement's PING stays pending until its deadline with no reply, so
// liveness still learns from a late PONG.
func (r *Runtime) releaseRelayMeasurement(peerID uint64, reply chan<- time.Duration) {
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	if r.relay.waiting[peerID] == reply {
		delete(r.relay.waiting, peerID)
	}
	for id, ping := range r.relay.pending {
		if ping.reply == reply {
			ping.reply = nil
			r.relay.pending[id] = ping
		}
	}
}

func (r *Runtime) awaitRoundTrip(
	measureCtx context.Context,
	parent context.Context,
	reply <-chan time.Duration,
	relayed bool,
) (RoundTrip, error) {
	select {
	case roundTrip := <-reply:
		return RoundTrip{Duration: max(roundTrip, 0), Relayed: relayed}, nil
	case <-measureCtx.Done():
		return RoundTrip{}, timedOut(parent, measureCtx.Err())
	case <-r.done:
		return RoundTrip{}, ErrInactive
	}
}

// timedOut turns the measurement's own deadline into ErrNoAnswer and keeps
// the caller's cancellation as it is.
func timedOut(parent context.Context, err error) error {
	if parentErr := parent.Err(); parentErr != nil {
		return parentErr
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrNoAnswer
	}
	return err
}

// sleep waits for delay, the context or the runtime closing.
func (r *Runtime) sleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return ErrInactive
	}
}
