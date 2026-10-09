package peerprobe

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/key"
)

const (
	maxQueuedDatagrams      = 128
	maxProbeDatagramSize    = 2048
	maxScheduledProbes      = 512
	maxScheduledPerPeer     = 8
	defaultProbePace        = 10 * time.Millisecond
	minProbeRefresh         = 2800 * time.Millisecond
	maxProbeRefresh         = 3200 * time.Millisecond
	incomingPingWindow      = time.Second
	maxIncomingPings        = 128
	maxIncomingPingsPerPeer = 16

	// CALL_ME_MAYBE schedule (disco-v2 §4.2, §4.3): every 5 s during a
	// peer's first minute without a trusted direct path, then every 15 s.
	callMeMaybeTick       = time.Second
	callMeMaybeFast       = 5 * time.Second
	callMeMaybeSlow       = 15 * time.Second
	callMeMaybeFastPeriod = time.Minute
	directTrust           = 6500 * time.Millisecond
	maxBurstQueue         = 16
	maxLocalReflexive     = 8
)

// PathObserver receives authenticated direct-path observations. It must return
// immediately and must not retain references to mutable runtime state.
type PathObserver interface {
	ObservePath(pathdiscovery.PathObservation)
}

type receivedDatagram struct {
	packet  []byte
	source  netip.AddrPort
	socket  pathdiscovery.Socket
	relayed bool
	peer    key.NodePublic // relay-attested sender, when relayed
}

type probeTarget struct {
	peerID   uint64
	endpoint netip.AddrPort
}

type probeBatch struct {
	generation pathdiscovery.ProbeGeneration
	targets    []probeTarget
}

type pingWindow struct {
	generation pathdiscovery.ProbeGeneration
	startedAt  time.Time
	total      int
	perPeer    map[uint64]int
}

// Runtime moves authenticated path-probe work off the encrypted-packet receive
// loop, schedules bounded outgoing probes, and completes matching replies.
type Runtime struct {
	transport pathdiscovery.DatagramTransport
	registry  *Registry
	manager   *pathdiscovery.ProbeManager
	observer  PathObserver
	telemetry *pathdiscovery.ProbeTelemetry
	clock     func() time.Time
	pace      time.Duration
	refresh   time.Duration

	lifecycleMu sync.RWMutex
	enqueueMu   sync.RWMutex
	stateMu     sync.RWMutex
	active      pathdiscovery.ProbeGeneration
	windowMu    sync.Mutex
	window      pingWindow

	localMu        sync.Mutex
	localEndpoints []disco.Endpoint
	localNAT       disco.NATInfo
	reflexive      map[netip.AddrPort]time.Time // own addresses peers observed
	callSeq        uint64
	callSent       map[uint64]time.Time

	datagrams chan receivedDatagram
	slots     chan struct{}
	schedules chan probeBatch
	bursts    chan probeBatch
	done      <-chan struct{}
	cancel    context.CancelFunc
	workers   sync.WaitGroup
	closeOnce sync.Once
}

var (
	_ pathdiscovery.DatagramHandler      = (*Runtime)(nil)
	_ pathdiscovery.RelayDatagramHandler = (*Runtime)(nil)
)

// NewRuntime creates a session-scoped peer-probe runtime. Close must be called
// before the session identity is destroyed.
func NewRuntime(
	ctx context.Context,
	identity key.DiscoPrivate,
	transport pathdiscovery.DatagramTransport,
	observer PathObserver,
	telemetry *pathdiscovery.ProbeTelemetry,
) (*Runtime, error) {
	return newRuntime(
		ctx,
		identity,
		transport,
		observer,
		telemetry,
		time.Now,
		defaultProbePace,
		randomProbeRefresh(),
	)
}

func newRuntime(
	ctx context.Context,
	identity key.DiscoPrivate,
	transport pathdiscovery.DatagramTransport,
	observer PathObserver,
	telemetry *pathdiscovery.ProbeTelemetry,
	clock func() time.Time,
	pace time.Duration,
	refresh time.Duration,
) (*Runtime, error) {
	if ctx == nil || transport == nil || telemetry == nil || clock == nil ||
		pace <= 0 || refresh <= 0 {
		return nil, errors.New("peerprobe: runtime dependencies are invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	registry, err := NewRegistry(identity)
	if err != nil {
		return nil, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	runtime := &Runtime{
		transport: transport,
		registry:  registry,
		manager:   pathdiscovery.NewProbeManager(),
		observer:  observer,
		telemetry: telemetry,
		clock:     clock,
		pace:      pace,
		refresh:   refresh,
		datagrams: make(chan receivedDatagram, maxQueuedDatagrams),
		slots:     make(chan struct{}, maxQueuedDatagrams),
		schedules: make(chan probeBatch, 1),
		bursts:    make(chan probeBatch, maxBurstQueue),
		reflexive: make(map[netip.AddrPort]time.Time),
		callSent:  make(map[uint64]time.Time),
		done:      workerCtx.Done(),
		cancel:    cancel,
	}
	runtime.workers.Go(func() { runtime.runDatagrams(workerCtx) })
	runtime.workers.Go(func() { runtime.runScheduler(workerCtx) })
	runtime.workers.Go(func() { runtime.runBursts(workerCtx) })
	runtime.workers.Go(func() { runtime.runCallMeMaybe(workerCtx) })

	return runtime, nil
}

// Activate replaces peer channels, resets outstanding transactions, and
// schedules a bounded deterministic probe round for the new generation.
func (r *Runtime) Activate(
	snapshot networkmap.Snapshot,
	generation pathdiscovery.ProbeGeneration,
) (int, int, error) {
	if r == nil {
		return 0, 0, ErrInactive
	}
	select {
	case <-r.done:
		return 0, 0, ErrInactive
	default:
	}

	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	select {
	case <-r.done:
		return 0, 0, ErrInactive
	default:
	}
	r.deactivateLocked()
	channelCount, err := r.registry.Replace(snapshot, generation, r.clock())
	if err != nil {
		return 0, 0, err
	}
	if _, err := r.manager.Activate(generation); err != nil {
		return 0, 0, err
	}
	r.stateMu.Lock()
	r.active = generation
	r.stateMu.Unlock()
	r.resetPingWindow(generation)
	targets := r.roundTargets()
	r.offerSchedule(probeBatch{
		generation: generation,
		targets:    targets,
	})
	r.telemetry.RecordMapActivation()

	return channelCount, len(targets), nil
}

// Deactivate rejects packet work immediately and removes pending probes while
// keeping the registry reusable for a later map in the same session.
func (r *Runtime) Deactivate() int {
	if r == nil {
		return 0
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()

	return r.deactivateLocked()
}

func (r *Runtime) deactivateLocked() int {
	r.stateMu.Lock()
	r.active = pathdiscovery.ProbeGeneration{}
	r.stateMu.Unlock()
	r.resetPingWindow(pathdiscovery.ProbeGeneration{})
	r.registry.Deactivate()

	removed := r.manager.Deactivate()
	if removed > 0 {
		r.telemetry.RecordPendingInvalidated(uint64(removed))
	}

	return removed
}

// Probe starts and sends one transaction through the current shared socket.
func (r *Runtime) Probe(
	ctx context.Context,
	peerID uint64,
	endpoint netip.AddrPort,
) (pathdiscovery.ProbeTransaction, error) {
	if r == nil {
		return pathdiscovery.ProbeTransaction{}, ErrInactive
	}
	generation := r.activeGeneration()

	return r.probe(ctx, generation, peerID, endpoint)
}

func (r *Runtime) probe(
	ctx context.Context,
	generation pathdiscovery.ProbeGeneration,
	peerID uint64,
	endpoint netip.AddrPort,
) (pathdiscovery.ProbeTransaction, error) {
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	if ctx == nil {
		return pathdiscovery.ProbeTransaction{}, ErrInvalidProbe
	}
	if err := ctx.Err(); err != nil {
		return pathdiscovery.ProbeTransaction{}, err
	}
	select {
	case <-r.done:
		return pathdiscovery.ProbeTransaction{}, ErrInactive
	default:
	}
	if !generation.IsValid() || generation != r.activeGeneration() {
		return pathdiscovery.ProbeTransaction{}, ErrInactive
	}
	r.telemetry.RecordProbeAttempt()
	transaction, err := r.manager.Start(r.clock(), peerID, endpoint)
	if err != nil {
		r.telemetry.RecordProbeStartFailure()
		return pathdiscovery.ProbeTransaction{}, err
	}
	r.telemetry.RecordProbeStarted()
	if transaction.Generation != generation {
		r.manager.Cancel(transaction)
		r.telemetry.RecordProbeSendFailure()

		return pathdiscovery.ProbeTransaction{}, ErrInvalidGeneration
	}
	packet, err := r.registry.SealPing(transaction, 0)
	if err != nil {
		r.manager.Cancel(transaction)
		r.telemetry.RecordProbeSendFailure()

		return pathdiscovery.ProbeTransaction{}, err
	}
	usedSocket, err := r.transport.SendDatagram(packet, endpoint)
	if err != nil {
		r.manager.Cancel(transaction)
		r.telemetry.RecordProbeSendFailure()

		return pathdiscovery.ProbeTransaction{}, fmt.Errorf(
			"peerprobe: sending ping: %w",
			err,
		)
	}
	if usedSocket != generation.Socket {
		r.manager.Cancel(transaction)
		r.telemetry.RecordProbeSendFailure()

		return pathdiscovery.ProbeTransaction{}, pathdiscovery.ErrSocketChanged
	}

	r.telemetry.RecordProbeSent()

	return transaction, nil
}

// MatchesDatagram identifies encrypted peer-probe packets for shared-socket
// demultiplexing. It remains true after Close so these packets never reach the
// encrypted tunnel parser.
func (*Runtime) MatchesDatagram(packet []byte) bool {
	return disco.LooksLikeDisco(packet)
}

// HandleDatagram copies a bounded packet into a non-blocking queue. Expensive
// authentication and any response send happen on the owned worker.
func (r *Runtime) HandleDatagram(
	packet []byte,
	source netip.AddrPort,
	socket pathdiscovery.Socket,
) {
	if r == nil || len(packet) > maxProbeDatagramSize ||
		!disco.LooksLikeDisco(packet) {
		return
	}
	r.enqueue(receivedDatagram{packet: packet, source: source, socket: socket})
}

// HandleRelayDatagram queues a disco packet that a relay delivered from
// peerNode. Only CALL_ME_MAYBE is acted on this way.
func (r *Runtime) HandleRelayDatagram(packet []byte, peerNode [32]byte) {
	if r == nil || len(packet) > maxProbeDatagramSize || !disco.LooksLikeDisco(packet) {
		return
	}
	r.enqueue(receivedDatagram{packet: packet, relayed: true, peer: key.NodePublic(peerNode)})
}

func (r *Runtime) enqueue(datagram receivedDatagram) {
	r.enqueueMu.RLock()
	defer r.enqueueMu.RUnlock()
	select {
	case <-r.done:
		return
	default:
	}
	select {
	case r.slots <- struct{}{}:
	default:
		r.telemetry.RecordDatagramDrop()
		return
	}
	datagram.packet = bytes.Clone(datagram.packet)
	select {
	case r.datagrams <- datagram:
	case <-r.done:
		<-r.slots
		r.telemetry.RecordDatagramDrop()
	default:
		<-r.slots
		r.telemetry.RecordDatagramDrop()
	}
}

// Close stops owned workers, clears pending state, and destroys derived shared
// secrets. The caller remains responsible for the session identity.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.cancel()
		r.enqueueMu.Lock()
		defer r.enqueueMu.Unlock()
		r.workers.Wait()
		r.lifecycleMu.Lock()
		r.deactivateLocked()
		r.registry.Close()
		r.lifecycleMu.Unlock()
		drainDatagrams(r.datagrams, r.slots)
		drainSchedules(r.schedules)
	})
}

func (r *Runtime) runDatagrams(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case datagram := <-r.datagrams:
			r.processDatagram(datagram)
			<-r.slots
		}
	}
}

func (r *Runtime) processDatagram(datagram receivedDatagram) {
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	select {
	case <-r.done:
		return
	default:
	}
	generation := r.activeGeneration()
	if !generation.IsValid() {
		return
	}
	now := r.clock()
	if datagram.relayed {
		message, err := r.registry.OpenRelayed(datagram.packet, datagram.peer, generation, now)
		if call, ok := message.(IncomingCallMeMaybe); ok && err == nil {
			r.answerCallMeMaybe(generation, call)
		}
		return
	}
	if datagram.socket != generation.Socket {
		return
	}
	message, err := r.registry.Open(
		datagram.packet,
		datagram.source,
		generation,
		now,
	)
	if err != nil {
		return
	}
	switch message := message.(type) {
	case IncomingCallMeMaybe:
		r.answerCallMeMaybe(generation, message)
	case IncomingPing:
		r.telemetry.RecordAuthenticatedPing()
		if r.registry.LearnPeerReflexive(message.PeerID(), message.Source(), now) {
			// A ping from an address we did not know is the hole its NAT
			// just opened towards us: answer and probe it straight away.
			r.telemetry.RecordPeerReflexiveLearned()
			r.offerBurst(probeBatch{generation: generation, targets: []probeTarget{{
				peerID: message.PeerID(), endpoint: message.Source(),
			}}})
		}
		if !r.allowIncomingPing(now, message) {
			r.telemetry.RecordPingRateLimited()
			return
		}
		packet, err := r.registry.SealPong(message)
		if err != nil {
			r.telemetry.RecordPongSendFailure()
			return
		}
		usedSocket, err := r.transport.SendDatagram(packet, message.Source())
		if err != nil || usedSocket != generation.Socket {
			r.telemetry.RecordPongSendFailure()
			return
		}
		r.telemetry.RecordPongSent()
	case IncomingPong:
		r.telemetry.RecordAuthenticatedPong()
		reply := message.AuthenticatedReply()
		observation, err := r.manager.Complete(now, reply)
		if err != nil {
			r.telemetry.RecordCompletionRejection()
			return
		}
		r.registry.MarkPong(reply.PeerID, now)
		r.noteReflexive(reply.ObservedLocalEndpoint, now)
		r.telemetry.RecordProbeCompletion()
		if r.observer == nil {
			return
		}
		r.observer.ObservePath(observation)
	}
}

func (r *Runtime) runScheduler(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timerChannel <-chan time.Time
	current := probeBatch{}
	index := 0
	roundStarted := time.Time{}
	waitingForRound := false
	for {
		select {
		case <-ctx.Done():
			return
		case current = <-r.schedules:
			index = 0
			roundStarted = time.Time{}
			waitingForRound = true
			if len(current.targets) == 0 {
				timerChannel = nil

				continue
			}
			resetRuntimeTimer(timer, 0)
			timerChannel = timer.C
		case <-timerChannel:
			timerChannel = nil
			if current.generation != r.activeGeneration() {
				continue
			}
			if waitingForRound {
				roundStarted = r.clock()
				waitingForRound = false
				r.telemetry.RecordRoundStarted()
			}
			if index < len(current.targets) {
				target := current.targets[index]
				// Probe cancels its transaction on every send failure. A later
				// target must still get its independently paced attempt.
				_, _ = r.probe(
					ctx,
					current.generation,
					target.peerID,
					target.endpoint,
				)
				index++
			}
			if index < len(current.targets) {
				resetRuntimeTimer(timer, r.pace)
				timerChannel = timer.C

				continue
			}
			r.telemetry.RecordRoundCompleted()
			index = 0
			waitingForRound = true
			// Candidates learned since the last round are probed in the next.
			current.targets = r.roundTargets()
			resetRuntimeTimer(
				timer,
				nextProbeRoundDelay(roundStarted, r.clock(), r.refresh),
			)
			timerChannel = timer.C
		}
	}
}

func nextProbeRoundDelay(startedAt, now time.Time, interval time.Duration) time.Duration {
	if startedAt.IsZero() || now.IsZero() || now.Before(startedAt) {
		return interval
	}
	elapsed := now.Sub(startedAt)
	if elapsed >= interval {
		return 0
	}

	return interval - elapsed
}

func randomProbeRefresh() time.Duration {
	span := maxProbeRefresh - minProbeRefresh
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return minProbeRefresh + span/2
	}

	return minProbeRefresh + time.Duration(random.Int64())
}

func (r *Runtime) activeGeneration() pathdiscovery.ProbeGeneration {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()

	return r.active
}

func (r *Runtime) offerSchedule(batch probeBatch) {
	select {
	case r.schedules <- batch:
		return
	default:
	}
	select {
	case <-r.schedules:
	default:
	}
	select {
	case r.schedules <- batch:
	default:
	}
}

func (r *Runtime) resetPingWindow(generation pathdiscovery.ProbeGeneration) {
	r.windowMu.Lock()
	r.window = pingWindow{generation: generation}
	r.windowMu.Unlock()
}

func (r *Runtime) allowIncomingPing(now time.Time, ping IncomingPing) bool {
	if now.IsZero() {
		return false
	}
	r.windowMu.Lock()
	defer r.windowMu.Unlock()
	if r.window.generation != ping.Generation() || r.window.startedAt.IsZero() ||
		now.Before(r.window.startedAt) ||
		!now.Before(r.window.startedAt.Add(incomingPingWindow)) {
		r.window = pingWindow{
			generation: ping.Generation(),
			startedAt:  now,
			perPeer:    make(map[uint64]int),
		}
	}
	if r.window.total >= maxIncomingPings ||
		r.window.perPeer[ping.PeerID()] >= maxIncomingPingsPerPeer {
		return false
	}
	r.window.total++
	r.window.perPeer[ping.PeerID()]++

	return true
}

// roundTargets interleaves every probe-eligible peer's candidates (map
// endpoints first, then learned ones), so one peer's long list cannot starve
// the others.
func (r *Runtime) roundTargets() []probeTarget {
	peers := r.registry.peers(r.clock())
	targets := make([]probeTarget, 0, min(len(peers), maxScheduledProbes))
	for endpointIndex := 0; endpointIndex < maxScheduledPerPeer; endpointIndex++ {
		for _, peer := range peers {
			if len(targets) == maxScheduledProbes {
				return targets
			}
			if !peer.probe || endpointIndex >= len(peer.candidates) {
				continue
			}
			targets = append(targets, probeTarget{
				peerID:   peer.peerID,
				endpoint: peer.candidates[endpointIndex],
			})
		}
	}

	return targets
}

func resetRuntimeTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

func drainDatagrams(
	datagrams <-chan receivedDatagram,
	slots chan struct{},
) {
	for {
		select {
		case <-datagrams:
			<-slots
		default:
			return
		}
	}
}

func drainSchedules(schedules <-chan probeBatch) {
	for {
		select {
		case <-schedules:
		default:
			return
		}
	}
}

// SetLocalEndpoints records this node's current candidates and NAT
// classification, advertised to peers in CALL_ME_MAYBE.
func (r *Runtime) SetLocalEndpoints(endpoints []disco.Endpoint, nat disco.NATInfo) {
	if r == nil {
		return
	}
	r.localMu.Lock()
	r.localEndpoints = append([]disco.Endpoint(nil), endpoints...)
	r.localNAT = nat
	r.localMu.Unlock()
}

// noteReflexive keeps the addresses peers saw this node at (from PONG), to
// advertise as peer-reflexive candidates.
func (r *Runtime) noteReflexive(observed netip.AddrPort, now time.Time) {
	if !validEndpoint(observed) {
		return
	}
	r.localMu.Lock()
	defer r.localMu.Unlock()
	for endpoint, seen := range r.reflexive {
		if now.Sub(seen) > learnedCandidateLifetime {
			delete(r.reflexive, endpoint)
		}
	}
	if _, known := r.reflexive[observed]; !known && len(r.reflexive) >= maxLocalReflexive {
		return
	}
	r.reflexive[observed] = now
}

// callMeMaybe builds the next CALL_ME_MAYBE from the current candidates.
func (r *Runtime) callMeMaybe(now time.Time) (disco.CallMeMaybe, bool) {
	r.localMu.Lock()
	defer r.localMu.Unlock()
	endpoints := make([]disco.Endpoint, 0, len(r.localEndpoints)+len(r.reflexive))
	seen := make(map[netip.AddrPort]struct{}, cap(endpoints))
	add := func(endpoint disco.Endpoint) {
		if _, dup := seen[endpoint.Addr]; dup || len(endpoints) >= disco.MaxEndpoints || !validEndpoint(endpoint.Addr) {
			return
		}
		seen[endpoint.Addr] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	for _, endpoint := range r.localEndpoints {
		add(endpoint)
	}
	for endpoint := range r.reflexive {
		add(disco.Endpoint{Kind: disco.EndpointPeerReflexive, Addr: endpoint})
	}
	if len(endpoints) == 0 {
		return disco.CallMeMaybe{}, false
	}
	r.callSeq++
	return disco.CallMeMaybe{Seq: r.callSeq, SentAt: now.UnixMilli(), NAT: r.localNAT, Endpoints: endpoints}, true
}

// answerCallMeMaybe pings every candidate of the peer at once, so both NATs
// open towards each other at the same time.
func (r *Runtime) answerCallMeMaybe(generation pathdiscovery.ProbeGeneration, call IncomingCallMeMaybe) {
	r.telemetry.RecordCallMeMaybeAccepted()
	candidates := r.registry.PeerCandidates(call.PeerID(), r.clock())
	targets := make([]probeTarget, 0, len(candidates))
	for _, endpoint := range candidates {
		targets = append(targets, probeTarget{peerID: call.PeerID(), endpoint: endpoint})
	}
	r.offerBurst(probeBatch{generation: generation, targets: targets})
}

func (r *Runtime) offerBurst(batch probeBatch) {
	if len(batch.targets) == 0 {
		return
	}
	select {
	case r.bursts <- batch:
	default:
		r.telemetry.RecordDatagramDrop()
	}
}

// runBursts sends urgent probes, paced like scheduled ones.
func (r *Runtime) runBursts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-r.bursts:
			for _, target := range batch.targets {
				if batch.generation != r.activeGeneration() {
					break
				}
				_, _ = r.probe(ctx, batch.generation, target.peerID, target.endpoint)
				select {
				case <-ctx.Done():
					return
				case <-time.After(r.pace):
				}
			}
		}
	}
}

// runCallMeMaybe sends CALL_ME_MAYBE through the relay to every peer that
// has no trusted direct path.
func (r *Runtime) runCallMeMaybe(ctx context.Context) {
	relayed, ok := r.transport.(pathdiscovery.RelayDatagramTransport)
	if !ok {
		return
	}
	ticker := time.NewTicker(callMeMaybeTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sendCallMeMaybes(relayed)
		}
	}
}

func (r *Runtime) sendCallMeMaybes(relayed pathdiscovery.RelayDatagramTransport) {
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	if !r.activeGeneration().IsValid() {
		return
	}
	now := r.clock()
	peers := r.registry.peers(now)
	live := make(map[uint64]struct{}, len(peers))
	for _, peer := range peers {
		live[peer.peerID] = struct{}{}
		if !peer.probe || (!peer.lastPong.IsZero() && now.Sub(peer.lastPong) < directTrust) {
			continue
		}
		interval := callMeMaybeSlow
		if now.Sub(peer.firstSeen) < callMeMaybeFastPeriod {
			interval = callMeMaybeFast
		}
		r.localMu.Lock()
		last := r.callSent[peer.peerID]
		r.localMu.Unlock()
		if !last.IsZero() && now.Sub(last) < interval {
			continue
		}
		message, ok := r.callMeMaybe(now)
		if !ok {
			return
		}
		packet, node, err := r.registry.SealCallMeMaybe(peer.peerID, message)
		if err != nil {
			continue
		}
		if err := relayed.SendRelayDatagram(packet, node); err != nil {
			continue
		}
		r.localMu.Lock()
		r.callSent[peer.peerID] = now
		r.localMu.Unlock()
		r.telemetry.RecordCallMeMaybeSent()
	}
	r.localMu.Lock()
	for peerID := range r.callSent {
		if _, ok := live[peerID]; !ok {
			delete(r.callSent, peerID)
		}
	}
	r.localMu.Unlock()
}
