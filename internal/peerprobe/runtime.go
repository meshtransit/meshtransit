package peerprobe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/meshtransit/meshd/internal/compat/disco"
	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
)

const (
	maxQueuedDatagrams      = 128
	maxProbeDatagramSize    = 2048
	maxScheduledProbes      = 512
	maxScheduledPerPeer     = 8
	defaultProbePace        = 10 * time.Millisecond
	incomingPingWindow      = time.Second
	maxIncomingPings        = 128
	maxIncomingPingsPerPeer = 16
)

// PathObserver receives authenticated direct-path observations. It must return
// immediately and must not retain references to mutable runtime state.
type PathObserver interface {
	ObservePath(pathdiscovery.PathObservation)
}

type receivedDatagram struct {
	packet []byte
	source netip.AddrPort
	socket pathdiscovery.Socket
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
	clock     func() time.Time
	pace      time.Duration

	lifecycleMu sync.RWMutex
	enqueueMu   sync.RWMutex
	stateMu     sync.RWMutex
	active      pathdiscovery.ProbeGeneration
	windowMu    sync.Mutex
	window      pingWindow

	datagrams chan receivedDatagram
	slots     chan struct{}
	schedules chan probeBatch
	done      <-chan struct{}
	cancel    context.CancelFunc
	workers   sync.WaitGroup
	closeOnce sync.Once
}

var _ pathdiscovery.DatagramHandler = (*Runtime)(nil)

// NewRuntime creates a session-scoped peer-probe runtime. Close must be called
// before the session identity is destroyed.
func NewRuntime(
	ctx context.Context,
	identity *disco.Identity,
	transport pathdiscovery.DatagramTransport,
	observer PathObserver,
) (*Runtime, error) {
	return newRuntime(
		ctx,
		identity,
		transport,
		observer,
		time.Now,
		defaultProbePace,
	)
}

func newRuntime(
	ctx context.Context,
	identity *disco.Identity,
	transport pathdiscovery.DatagramTransport,
	observer PathObserver,
	clock func() time.Time,
	pace time.Duration,
) (*Runtime, error) {
	if ctx == nil || transport == nil || clock == nil || pace <= 0 {
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
		clock:     clock,
		pace:      pace,
		datagrams: make(chan receivedDatagram, maxQueuedDatagrams),
		slots:     make(chan struct{}, maxQueuedDatagrams),
		schedules: make(chan probeBatch, 1),
		done:      workerCtx.Done(),
		cancel:    cancel,
	}
	runtime.workers.Go(func() { runtime.runDatagrams(workerCtx) })
	runtime.workers.Go(func() { runtime.runScheduler(workerCtx) })

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
	channelCount, err := r.registry.Replace(snapshot, generation)
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
	targets := buildProbeTargets(snapshot)
	r.offerSchedule(probeBatch{
		generation: generation,
		targets:    targets,
	})

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

	return r.manager.Deactivate()
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
	transaction, err := r.manager.Start(r.clock(), peerID, endpoint)
	if err != nil {
		return pathdiscovery.ProbeTransaction{}, err
	}
	if transaction.Generation != generation {
		r.manager.Cancel(transaction)

		return pathdiscovery.ProbeTransaction{}, ErrInvalidGeneration
	}
	packet, err := r.registry.SealPing(transaction, 0)
	if err != nil {
		r.manager.Cancel(transaction)

		return pathdiscovery.ProbeTransaction{}, err
	}
	usedSocket, err := r.transport.SendDatagram(packet, endpoint)
	if err != nil {
		r.manager.Cancel(transaction)

		return pathdiscovery.ProbeTransaction{}, fmt.Errorf(
			"peerprobe: sending ping: %w",
			err,
		)
	}
	if usedSocket != generation.Socket {
		r.manager.Cancel(transaction)

		return pathdiscovery.ProbeTransaction{}, pathdiscovery.ErrSocketChanged
	}

	return transaction, nil
}

// MatchesDatagram identifies encrypted peer-probe packets for shared-socket
// demultiplexing. It remains true after Close so these packets never reach the
// encrypted tunnel parser.
func (*Runtime) MatchesDatagram(packet []byte) bool {
	return disco.LooksLikePacket(packet)
}

// HandleDatagram copies a bounded packet into a non-blocking queue. Expensive
// authentication and any response send happen on the owned worker.
func (r *Runtime) HandleDatagram(
	packet []byte,
	source netip.AddrPort,
	socket pathdiscovery.Socket,
) {
	if r == nil || len(packet) > maxProbeDatagramSize ||
		!disco.LooksLikePacket(packet) {
		return
	}
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
		return
	}
	datagram := receivedDatagram{
		packet: bytes.Clone(packet),
		source: source,
		socket: socket,
	}
	select {
	case r.datagrams <- datagram:
	case <-r.done:
		<-r.slots
	default:
		<-r.slots
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
	if !generation.IsValid() || datagram.socket != generation.Socket {
		return
	}
	message, err := r.registry.Open(
		datagram.packet,
		datagram.source,
		generation,
	)
	if err != nil {
		return
	}
	now := r.clock()
	switch message := message.(type) {
	case IncomingPing:
		if !r.allowIncomingPing(now, message) {
			return
		}
		packet, err := r.registry.SealPong(message)
		if err != nil {
			return
		}
		usedSocket, err := r.transport.SendDatagram(packet, message.Source())
		if err != nil || usedSocket != generation.Socket {
			return
		}
	case IncomingPong:
		observation, err := r.manager.Complete(now, message.AuthenticatedReply())
		if err != nil || r.observer == nil {
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
	for {
		select {
		case <-ctx.Done():
			return
		case current = <-r.schedules:
			index = 0
			if len(current.targets) == 0 {
				timerChannel = nil

				continue
			}
			resetRuntimeTimer(timer, 0)
			timerChannel = timer.C
		case <-timerChannel:
			timerChannel = nil
			if current.generation != r.activeGeneration() {
				index = len(current.targets)
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
			}
		}
	}
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

func buildProbeTargets(snapshot networkmap.Snapshot) []probeTarget {
	targets := make([]probeTarget, 0, min(len(snapshot.Peers), maxScheduledProbes))
	for endpointIndex := 0; endpointIndex < maxScheduledPerPeer; endpointIndex++ {
		for _, peer := range snapshot.Peers {
			if len(targets) == maxScheduledProbes {
				return targets
			}
			if peer.DiscoveryKey == "" || peer.Expired || !peer.MachineAuthorized ||
				(peer.OnlineKnown && !peer.Online) || endpointIndex >= len(peer.Endpoints) {
				continue
			}
			targets = append(targets, probeTarget{
				peerID:   peer.ID,
				endpoint: peer.Endpoints[endpointIndex],
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
