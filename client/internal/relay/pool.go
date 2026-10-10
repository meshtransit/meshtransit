package relay

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"slices"
	"sync"
	"time"
)

const (
	maxActiveRegions    = 16
	sendQueueDepth      = 32
	receiveQueueDepth   = 128
	maxRegionQueuedByte = 1 << 20
	maxTotalQueuedByte  = 4 << 20
	minRetryDelay       = 250 * time.Millisecond
	maxRetryDelay       = 5 * time.Second
	connectTimeout      = 10 * time.Second
	receiveSilenceLimit = 2*time.Minute + 10*time.Second
	stableConnectionAge = 30 * time.Second
)

var (
	// ErrClosed means the relay pool no longer accepts traffic.
	ErrClosed = errors.New("relay: pool is closed")
	// ErrUnauthorized means a peer or region is outside the active map authority.
	ErrUnauthorized = errors.New("relay: destination is unauthorized")
	// ErrQueueFull means bounded relay memory is saturated and the packet was dropped.
	ErrQueueFull = errors.New("relay: send queue is full")
	// ErrRegionLimit means the bounded active-region limit has been reached.
	ErrRegionLimit = errors.New("relay: active region limit reached")
)

type sendRequest struct {
	destination Key
	packets     [][]byte
	bytes       int
}

type regionWorker struct {
	region      Region
	generation  uint64
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	send        chan sendRequest
	queuedBytes int
	busy        bool
	lastUsed    time.Time
	health      RegionHealth
}

type reverseRoute struct {
	regionID   int
	generation uint64
}

// Pool owns bounded relay connections and their goroutine lifecycle.
type Pool struct {
	config         Config
	dialer         Dialer
	parent         context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	retryDelay     func(int) time.Duration
	clock          func() time.Time
	receiveSilence time.Duration
	receive        chan Packet
	done           chan struct{}
	onFailure      func() // called, without blocking, when a region connection fails

	lifecycle        sync.Mutex
	mu               sync.Mutex
	workers          map[int]*regionWorker
	peerByKey        map[Key]Peer
	reverseByKey     map[Key]reverseRoute
	queuedBytes      int
	workerGeneration uint64
	isOpen           bool
	isClosed         bool
	wait             sync.WaitGroup
}

// New constructs a stopped relay pool from one validated map authority.
func New(parent context.Context, config Config, dialer Dialer) (*Pool, error) {
	if parent == nil {
		return nil, errors.New("relay: parent context is required")
	}
	if dialer == nil {
		return nil, errors.New("relay: dialer is required")
	}
	validated, err := Validate(config)
	if err != nil {
		return nil, err
	}
	peers := make(map[Key]Peer, len(validated.Peers))
	for _, peer := range validated.Peers {
		peers[peer.Key] = peer
	}

	return &Pool{
		config:         validated,
		dialer:         dialer,
		parent:         parent,
		retryDelay:     randomizedRetryDelay,
		clock:          time.Now,
		receiveSilence: receiveSilenceLimit,
		peerByKey:      peers,
	}, nil
}

// Open starts the required home-region connection. It never blocks on network I/O.
func (p *Pool) Open() error {
	if p == nil {
		return ErrClosed
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	if err := p.parent.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed {
		return ErrClosed
	}
	if p.isOpen {
		return nil
	}
	p.ctx, p.cancel = context.WithCancel(p.parent)
	p.receive = make(chan Packet, receiveQueueDepth)
	p.done = make(chan struct{})
	p.workers = make(map[int]*regionWorker)
	p.reverseByKey = make(map[Key]reverseRoute)
	p.queuedBytes = 0
	p.isOpen = true
	if _, err := p.startWorkerLocked(p.config.HomeRegion); err != nil {
		p.isOpen = false
		p.cancel()
		close(p.done)
		p.ctx = nil
		p.cancel = nil
		p.receive = nil
		p.done = nil
		p.workers = nil
		p.reverseByKey = nil

		return err
	}

	return nil
}

// Send queues one bounded packet batch for a control-authorized peer.
func (p *Pool) Send(regionID int, destination Key, packets [][]byte) error {
	if p == nil {
		return ErrClosed
	}
	if len(packets) == 0 {
		return errors.New("relay: packet batch is empty")
	}
	total := 0
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > MaxPacketSize {
			return errors.New("relay: packet size is invalid")
		}
		total += len(packet)
		if total > maxRegionQueuedByte {
			return ErrQueueFull
		}
	}
	request := sendRequest{
		destination: destination,
		packets:     clonePackets(packets),
		bytes:       total,
	}

	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	p.mu.Lock()
	if p.isClosed || !p.isOpen {
		p.mu.Unlock()

		return ErrClosed
	}
	peer, peerExists := p.peerByKey[destination]
	_, regionExists := p.config.Regions[regionID]
	reverse := p.reverseByKey[destination]
	if !peerExists || !regionExists || regionID <= 0 ||
		(peer.HomeRegion != regionID && reverse.regionID != regionID) {
		p.mu.Unlock()

		return ErrUnauthorized
	}
	p.mu.Unlock()
	worker, err := p.ensureWorker(regionID)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed || !p.isOpen {
		return ErrClosed
	}
	peer, peerExists = p.peerByKey[destination]
	_, regionExists = p.config.Regions[regionID]
	reverse = p.reverseByKey[destination]
	if !peerExists || !regionExists || regionID <= 0 ||
		peer.HomeRegion != regionID &&
			(reverse.regionID != regionID || reverse.generation != worker.generation) {
		return ErrUnauthorized
	}
	if worker.queuedBytes+total > maxRegionQueuedByte ||
		p.queuedBytes+total > maxTotalQueuedByte {
		return ErrQueueFull
	}
	worker.queuedBytes += total
	worker.lastUsed = p.clock()
	p.queuedBytes += total
	select {
	case worker.send <- request:
		return nil
	default:
		worker.queuedBytes -= total
		p.queuedBytes -= total

		return ErrQueueFull
	}
}

// ReplacePeers atomically replaces the bounded peer authorization set while
// retaining relay connections. Packets already in flight may complete; queued
// and newly received packets are checked again against the new authority.
func (p *Pool) ReplacePeers(peers []Peer) error {
	if p == nil {
		return ErrClosed
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	validated, err := Validate(Config{
		PrivateKey: p.config.PrivateKey,
		PublicKey:  p.config.PublicKey,
		HomeRegion: p.config.HomeRegion,
		Regions:    p.config.Regions,
		Peers:      peers,
	})
	if err != nil {
		return err
	}
	peerByKey := make(map[Key]Peer, len(validated.Peers))
	for _, peer := range validated.Peers {
		peerByKey[peer.Key] = peer
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed {
		return ErrClosed
	}
	p.config.Peers = validated.Peers
	p.peerByKey = peerByKey
	for peer := range p.reverseByKey {
		if _, authorized := peerByKey[peer]; !authorized {
			delete(p.reverseByKey, peer)
		}
	}

	return nil
}

// PrepareRegion starts an authenticated connection to a control-authorized
// region without routing packets through it. Callers can inspect Health before
// publishing a home-region change.
func (p *Pool) PrepareRegion(regionID int) error {
	if p == nil {
		return ErrClosed
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	_, err := p.ensureWorker(regionID)

	return err
}

// Health returns a defensive, non-secret snapshot of active region workers.
func (p *Pool) Health() HealthSnapshot {
	if p == nil {
		return HealthSnapshot{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isOpen {
		return HealthSnapshot{}
	}
	regionIDs := make([]int, 0, len(p.workers))
	for regionID := range p.workers {
		regionIDs = append(regionIDs, regionID)
	}
	slices.Sort(regionIDs)
	regions := make([]RegionHealth, 0, len(regionIDs))
	for _, regionID := range regionIDs {
		regions = append(regions, p.workers[regionID].health)
	}

	return HealthSnapshot{
		Available:  true,
		HomeRegion: p.config.HomeRegion,
		Regions:    regions,
	}
}

// Receive waits for one authenticated-source encrypted packet.
func (p *Pool) Receive() (Packet, error) {
	if p == nil {
		return Packet{}, ErrClosed
	}
	p.mu.Lock()
	if !p.isOpen {
		p.mu.Unlock()

		return Packet{}, net.ErrClosed
	}
	receive := p.receive
	done := p.done
	p.mu.Unlock()
	select {
	case <-done:
		return Packet{}, net.ErrClosed
	default:
	}
	for {
		select {
		case packet := <-receive:
			p.mu.Lock()
			_, authorized := p.peerByKey[packet.Source]
			p.mu.Unlock()
			if authorized {
				return packet, nil
			}
		case <-done:
			return Packet{}, net.ErrClosed
		}
	}
}

// Peer returns the signed rate-limit identity for one active peer.
func (p *Pool) Peer(key Key) (Peer, bool) {
	if p == nil {
		return Peer{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	peer, exists := p.peerByKey[key]

	return peer, exists
}

// Region returns a defensive copy of one active relay region.
func (p *Pool) Region(id int) (Region, bool) {
	if p == nil {
		return Region{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	region, exists := p.config.Regions[id]
	region.Nodes = append([]Node{}, region.Nodes...)

	return region, exists
}

// Stop ends the current connection generation while keeping the pool reusable.
func (p *Pool) Stop() error {
	if p == nil {
		return nil
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	p.stopLocked()

	return nil
}

// Close permanently stops the pool and clears its private relay authority.
func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	p.stopLocked()
	p.mu.Lock()
	p.isClosed = true
	clear(p.config.PrivateKey[:])
	p.mu.Unlock()

	return nil
}

func (p *Pool) stopLocked() {
	p.mu.Lock()
	if !p.isOpen {
		p.mu.Unlock()

		return
	}
	p.isOpen = false
	cancel := p.cancel
	done := p.done
	p.mu.Unlock()
	cancel()
	close(done)
	p.wait.Wait()
	p.mu.Lock()
	p.ctx = nil
	p.cancel = nil
	p.receive = nil
	p.done = nil
	p.workers = nil
	p.reverseByKey = nil
	p.queuedBytes = 0
	p.mu.Unlock()
}

// ensureWorker requires lifecycle to be held so eviction, replacement, and
// shutdown cannot overlap.
func (p *Pool) ensureWorker(regionID int) (*regionWorker, error) {
	for {
		p.mu.Lock()
		if p.isClosed || !p.isOpen {
			p.mu.Unlock()

			return nil, ErrClosed
		}
		if _, exists := p.config.Regions[regionID]; !exists || regionID <= 0 {
			p.mu.Unlock()

			return nil, ErrUnauthorized
		}
		if worker := p.workers[regionID]; worker != nil {
			worker.lastUsed = p.clock()
			p.mu.Unlock()

			return worker, nil
		}
		if len(p.workers) < maxActiveRegions {
			worker, err := p.startWorkerLocked(regionID)
			p.mu.Unlock()

			return worker, err
		}
		victim := p.evictionCandidateLocked()
		if victim == nil {
			p.mu.Unlock()

			return nil, ErrRegionLimit
		}
		delete(p.workers, victim.region.ID)
		victim.cancel()
		p.mu.Unlock()
		<-victim.done
	}
}

func (p *Pool) startWorkerLocked(regionID int) (*regionWorker, error) {
	region, exists := p.config.Regions[regionID]
	if !exists {
		return nil, ErrUnauthorized
	}
	if worker := p.workers[regionID]; worker != nil {
		return worker, nil
	}
	if len(p.workers) >= maxActiveRegions || p.workerGeneration == math.MaxUint64 {
		return nil, ErrRegionLimit
	}
	p.workerGeneration++
	workerCtx, cancel := context.WithCancel(p.ctx)
	worker := &regionWorker{
		region:     region,
		generation: p.workerGeneration,
		ctx:        workerCtx,
		cancel:     cancel,
		done:       make(chan struct{}),
		send:       make(chan sendRequest, sendQueueDepth),
		lastUsed:   p.clock(),
		health:     RegionHealth{RegionID: regionID},
	}
	p.workers[regionID] = worker
	p.wait.Add(1)
	go p.runWorker(worker)

	return worker, nil
}

func (p *Pool) evictionCandidateLocked() *regionWorker {
	var selected *regionWorker
	for regionID, worker := range p.workers {
		if regionID == p.config.HomeRegion || worker.busy || worker.queuedBytes != 0 ||
			p.hasReverseRegionLocked(regionID, worker.generation) {
			continue
		}
		if selected == nil || worker.lastUsed.Before(selected.lastUsed) ||
			(worker.lastUsed.Equal(selected.lastUsed) && regionID < selected.region.ID) {
			selected = worker
		}
	}

	return selected
}

func (p *Pool) hasReverseRegionLocked(regionID int, generation uint64) bool {
	for _, route := range p.reverseByKey {
		if route.regionID == regionID && route.generation == generation {
			return true
		}
	}

	return false
}

func (p *Pool) runWorker(worker *regionWorker) {
	defer func() {
		close(worker.done)
		p.wait.Done()
	}()
	attempt := 0
	for {
		if err := worker.ctx.Err(); err != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(worker.ctx, connectTimeout)
		client, err := p.dialer.Dial(
			dialCtx,
			p.config.PrivateKey,
			worker.region,
		)
		cancel()
		if err == nil && client == nil {
			err = errors.New("relay: dialer returned a nil client")
		}
		if err == nil && worker.ctx.Err() != nil {
			_ = client.Close()

			return
		}
		connectedAt := p.clock()
		if err == nil {
			p.markConnected(worker)
			err = p.runConnection(worker, client)
		}
		if worker.ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		p.markFailure(worker)
		attempt = nextRetryAttempt(attempt, p.clock().Sub(connectedAt))
		if !waitContext(worker.ctx, p.retryDelay(attempt)) {
			return
		}
	}
}

func nextRetryAttempt(previous int, connectedFor time.Duration) int {
	if connectedFor >= stableConnectionAge {
		return 1
	}
	if previous >= math.MaxInt {
		return math.MaxInt
	}

	return previous + 1
}

func (p *Pool) runConnection(worker *regionWorker, client Client) error {
	if client == nil {
		return errors.New("relay: dialer returned a nil client")
	}
	defer p.clearReverseRegion(worker.region.ID, worker.generation)
	receiveErr := make(chan error, 1)
	activity := make(chan struct{}, 1)
	go func() {
		receiveErr <- p.runReceiver(worker, client, activity)
	}()
	activityTimer := time.NewTimer(p.receiveSilence)
	defer activityTimer.Stop()

	for {
		select {
		case <-worker.ctx.Done():
			_ = client.Close()
			<-receiveErr

			return worker.ctx.Err()
		case err := <-receiveErr:
			_ = client.Close()

			return err
		case <-activity:
			resetTimer(activityTimer, p.receiveSilence)
		case <-activityTimer.C:
			_ = client.Close()
			<-receiveErr

			return errors.New("relay: authenticated connection became unresponsive")
		case request := <-worker.send:
			p.beginSend(worker, request.bytes)
			if !p.authorizes(worker, request.destination) {
				p.finishSend(worker, false)

				continue
			}
			for _, packet := range request.packets {
				if err := client.Send(request.destination, packet); err != nil {
					p.finishSend(worker, false)
					_ = client.Close()
					<-receiveErr

					return fmt.Errorf("relay: sending encrypted packet: %w", err)
				}
			}
			p.finishSend(worker, true)
		}
	}
}

func (p *Pool) authorizes(worker *regionWorker, destination Key) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	peer, peerExists := p.peerByKey[destination]
	if !peerExists || p.workers[worker.region.ID] != worker {
		return false
	}
	reverse := p.reverseByKey[destination]

	return peer.HomeRegion == worker.region.ID ||
		reverse.regionID == worker.region.ID && reverse.generation == worker.generation
}

func (p *Pool) runReceiver(
	worker *regionWorker,
	client Client,
	activity chan<- struct{},
) error {
	for {
		event, err := client.Receive()
		if err != nil {
			return err
		}
		switch event.Kind {
		case ReceiveActivity:
			if event.Source != (Key{}) || len(event.Data) != 0 {
				return errors.New("relay: liveness event contains packet data")
			}
		case ReceivePacket:
		case 0:
			return errors.New("relay: receive event kind is missing")
		default:
			return errors.New("relay: receive event kind is unsupported")
		}
		p.markActivity(worker, false)
		select {
		case activity <- struct{}{}:
		default:
		}
		if event.Kind == ReceiveActivity {
			continue
		}
		if event.Source == (Key{}) || len(event.Data) == 0 ||
			len(event.Data) > MaxPacketSize {
			continue
		}
		p.mu.Lock()
		_, authorized := p.peerByKey[event.Source]
		p.mu.Unlock()
		if !authorized {
			continue
		}
		p.markActivity(worker, true)
		p.setReverseRegion(event.Source, worker.region.ID, worker.generation)
		received := Packet{
			RegionID: worker.region.ID,
			Source:   event.Source,
			Data:     slices.Clone(event.Data),
		}
		select {
		case p.receive <- received:
		case <-worker.ctx.Done():
			return worker.ctx.Err()
		default:
		}
	}
}

func (p *Pool) setReverseRegion(peer Key, regionID int, generation uint64) {
	p.mu.Lock()
	worker := p.workers[regionID]
	_, authorized := p.peerByKey[peer]
	if authorized && worker != nil && worker.generation == generation {
		p.reverseByKey[peer] = reverseRoute{regionID: regionID, generation: generation}
	}
	p.mu.Unlock()
}

func (p *Pool) clearReverseRegion(regionID int, generation uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for peer, route := range p.reverseByKey {
		if route.regionID == regionID && route.generation == generation {
			delete(p.reverseByKey, peer)
		}
	}
}

func (p *Pool) beginSend(worker *regionWorker, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	worker.queuedBytes -= count
	p.queuedBytes -= count
	worker.busy = true
}

func (p *Pool) finishSend(worker *regionWorker, sent bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	worker.busy = false
	if sent {
		now := p.clock()
		worker.lastUsed = now
		worker.health.LastSend = now
	}
}

func (p *Pool) markConnected(worker *regionWorker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.workers[worker.region.ID] != worker {
		return
	}
	now := p.clock()
	worker.health.Connected = true
	worker.health.LastConnected = now
	worker.health.LastActivity = now
	worker.health.ConsecutiveFailures = 0
}

func (p *Pool) markActivity(worker *regionWorker, peerPacket bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.workers[worker.region.ID] != worker {
		return
	}
	now := p.clock()
	worker.health.LastActivity = now
	if peerPacket {
		worker.lastUsed = now
	}
}

func (p *Pool) markFailure(worker *regionWorker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.workers[worker.region.ID] != worker {
		return
	}
	worker.health.Connected = false
	worker.health.LastFailure = p.clock()
	if worker.health.ConsecutiveFailures < math.MaxInt {
		worker.health.ConsecutiveFailures++
	}
	if p.onFailure != nil {
		p.onFailure()
	}
}

// SetFailureHook installs a function called after a region connection
// fails, so the home relay can be re-chosen at once instead of at the next
// periodic refresh. hook must not block; it runs with the pool locked.
func (p *Pool) SetFailureHook(hook func()) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.onFailure = hook
	p.mu.Unlock()
}

func clonePackets(packets [][]byte) [][]byte {
	cloned := make([][]byte, len(packets))
	for index, packet := range packets {
		cloned[index] = slices.Clone(packet)
	}

	return cloned
}

func randomizedRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := minRetryDelay
	for range min(attempt-1, 5) {
		base *= 2
	}
	base = min(base, maxRetryDelay)
	span := int64(base / 2)
	if span == 0 {
		return base
	}
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(span))
	if err != nil {
		return base
	}

	return base/2 + time.Duration(random.Int64())
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}
