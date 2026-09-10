package relay

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"sync"
	"time"
)

const (
	maxPacketSize       = 2048
	maxActiveRegions    = 16
	sendQueueDepth      = 32
	receiveQueueDepth   = 128
	maxRegionQueuedByte = 1 << 20
	maxTotalQueuedByte  = 4 << 20
	minRetryDelay       = 250 * time.Millisecond
	maxRetryDelay       = 5 * time.Second
	connectTimeout      = 10 * time.Second
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
	send        chan sendRequest
	queuedBytes int
}

// Pool owns bounded relay connections and their goroutine lifecycle.
type Pool struct {
	config     Config
	dialer     Dialer
	ctx        context.Context
	cancel     context.CancelFunc
	retryDelay func(int) time.Duration
	receive    chan Packet
	done       chan struct{}

	mu           sync.Mutex
	workers      map[int]*regionWorker
	peerByKey    map[Key]Peer
	reverseByKey map[Key]int
	queuedBytes  int
	isOpen       bool
	isClosed     bool
	wait         sync.WaitGroup
	closeOnce    sync.Once
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
	ctx, cancel := context.WithCancel(parent)
	peers := make(map[Key]Peer, len(validated.Peers))
	for _, peer := range validated.Peers {
		peers[peer.Key] = peer
	}

	return &Pool{
		config:       validated,
		dialer:       dialer,
		ctx:          ctx,
		cancel:       cancel,
		retryDelay:   randomizedRetryDelay,
		receive:      make(chan Packet, receiveQueueDepth),
		done:         make(chan struct{}),
		workers:      make(map[int]*regionWorker),
		peerByKey:    peers,
		reverseByKey: make(map[Key]int),
	}, nil
}

// Open starts the required home-region connection. It never blocks on network I/O.
func (p *Pool) Open() error {
	if p == nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed {
		return ErrClosed
	}
	if p.isOpen {
		return nil
	}
	p.isOpen = true
	if _, err := p.ensureWorkerLocked(p.config.HomeRegion); err != nil {
		p.isOpen = false

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
		if len(packet) == 0 || len(packet) > maxPacketSize {
			return errors.New("relay: packet size is invalid")
		}
		total += len(packet)
		if total > maxRegionQueuedByte {
			return ErrQueueFull
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed || !p.isOpen {
		return ErrClosed
	}
	peer, peerExists := p.peerByKey[destination]
	_, regionExists := p.config.Regions[regionID]
	reverseRegion := p.reverseByKey[destination]
	if !peerExists || !regionExists || regionID <= 0 ||
		(peer.HomeRegion != regionID && reverseRegion != regionID) {
		return ErrUnauthorized
	}
	worker, err := p.ensureWorkerLocked(regionID)
	if err != nil {
		return err
	}
	if worker.queuedBytes+total > maxRegionQueuedByte ||
		p.queuedBytes+total > maxTotalQueuedByte {
		return ErrQueueFull
	}
	request := sendRequest{
		destination: destination,
		packets:     clonePackets(packets),
		bytes:       total,
	}
	worker.queuedBytes += total
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

// Receive waits for one authenticated-source encrypted packet.
func (p *Pool) Receive() (Packet, error) {
	if p == nil {
		return Packet{}, ErrClosed
	}
	select {
	case <-p.done:
		return Packet{}, net.ErrClosed
	default:
	}
	select {
	case packet := <-p.receive:
		return packet, nil
	case <-p.done:
		return Packet{}, net.ErrClosed
	}
}

// Peer returns the signed rate-limit identity for one active peer.
func (p *Pool) Peer(key Key) (Peer, bool) {
	if p == nil {
		return Peer{}, false
	}
	peer, exists := p.peerByKey[key]

	return peer, exists
}

// Region returns a defensive copy of one active relay region.
func (p *Pool) Region(id int) (Region, bool) {
	if p == nil {
		return Region{}, false
	}
	region, exists := p.config.Regions[id]
	region.Nodes = append([]Node{}, region.Nodes...)

	return region, exists
}

// Close cancels all connection workers and waits for every goroutine to exit.
func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.isClosed = true
		p.isOpen = false
		p.mu.Unlock()
		p.cancel()
		p.wait.Wait()
		clear(p.config.PrivateKey[:])
		close(p.done)
	})

	return nil
}

func (p *Pool) ensureWorkerLocked(regionID int) (*regionWorker, error) {
	region, exists := p.config.Regions[regionID]
	if !exists {
		return nil, ErrUnauthorized
	}
	if worker := p.workers[regionID]; worker != nil {
		return worker, nil
	}
	if len(p.workers) >= maxActiveRegions {
		return nil, ErrRegionLimit
	}
	worker := &regionWorker{
		region: region,
		send:   make(chan sendRequest, sendQueueDepth),
	}
	p.workers[regionID] = worker
	p.wait.Add(1)
	go p.runWorker(worker)

	return worker, nil
}

func (p *Pool) runWorker(worker *regionWorker) {
	defer p.wait.Done()
	attempt := 0
	for {
		if err := p.ctx.Err(); err != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(p.ctx, connectTimeout)
		client, err := p.dialer.Dial(
			dialCtx,
			p.config.PrivateKey,
			worker.region,
		)
		cancel()
		if err == nil {
			attempt = 0
			err = p.runConnection(worker, client)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) && p.ctx.Err() != nil {
			return
		}
		attempt++
		if !waitContext(p.ctx, p.retryDelay(attempt)) {
			return
		}
	}
}

func (p *Pool) runConnection(worker *regionWorker, client Client) error {
	if client == nil {
		return errors.New("relay: dialer returned a nil client")
	}
	defer p.clearReverseRegion(worker.region.ID)
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- p.runReceiver(worker.region.ID, client)
	}()

	for {
		select {
		case <-p.ctx.Done():
			_ = client.Close()
			<-receiveErr

			return p.ctx.Err()
		case err := <-receiveErr:
			_ = client.Close()

			return err
		case request := <-worker.send:
			p.releaseQueued(worker, request.bytes)
			for _, packet := range request.packets {
				if err := client.Send(request.destination, packet); err != nil {
					_ = client.Close()
					<-receiveErr

					return fmt.Errorf("relay: sending encrypted packet: %w", err)
				}
			}
		}
	}
}

func (p *Pool) runReceiver(regionID int, client Client) error {
	for {
		packet, err := client.Receive()
		if err != nil {
			return err
		}
		if packet.Source == (Key{}) || len(packet.Data) == 0 ||
			len(packet.Data) > maxPacketSize {
			continue
		}
		if _, exists := p.peerByKey[packet.Source]; !exists {
			continue
		}
		p.setReverseRegion(packet.Source, regionID)
		received := Packet{
			RegionID: regionID,
			Source:   packet.Source,
			Data:     slices.Clone(packet.Data),
		}
		select {
		case p.receive <- received:
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}
	}
}

func (p *Pool) setReverseRegion(peer Key, regionID int) {
	p.mu.Lock()
	p.reverseByKey[peer] = regionID
	p.mu.Unlock()
}

func (p *Pool) clearReverseRegion(regionID int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for peer, currentRegion := range p.reverseByKey {
		if currentRegion == regionID {
			delete(p.reverseByKey, peer)
		}
	}
}

func (p *Pool) releaseQueued(worker *regionWorker, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	worker.queuedBytes -= count
	p.queuedBytes -= count
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
