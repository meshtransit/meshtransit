package relay

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestPoolSendsAndReceivesAuthorizedPackets(t *testing.T) {
	t.Parallel()

	client := newFakeClient()
	dialer := &fakeDialer{client: client, calls: make(chan int, 1)}
	pool, err := New(t.Context(), testConfig(), dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	pool.retryDelay = func(int) time.Duration { return time.Millisecond }
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	select {
	case regionID := <-dialer.calls:
		if regionID != 1 {
			t.Fatalf("Dial() region = %d, want 1", regionID)
		}
	case <-time.After(time.Second):
		t.Fatal("Dial() was not called")
	}

	outbound := []byte{1, 2, 3}
	if err := pool.Send(1, Key{2}, [][]byte{outbound}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	outbound[0] = 9
	select {
	case sent := <-client.sent:
		if sent.destination != (Key{2}) || !slices.Equal(sent.packet, []byte{1, 2, 3}) {
			t.Fatalf("Send() delivered %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("Send() did not reach client")
	}

	client.received <- receiveResult{event: ReceiveEvent{
		Kind:   ReceivePacket,
		Source: Key{99},
		Data:   []byte{4},
	}}
	client.received <- receiveResult{event: ReceiveEvent{
		Kind:   ReceivePacket,
		Source: Key{2},
		Data:   []byte{5, 6},
	}}
	packet, err := receivePoolWithTimeout(pool, time.Second)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if packet.RegionID != 1 || packet.Source != (Key{2}) ||
		!slices.Equal(packet.Data, []byte{5, 6}) {
		t.Fatalf("Receive() = %#v", packet)
	}
}

func TestPoolBoundsDisconnectedSendQueue(t *testing.T) {
	t.Parallel()

	dialer := blockingDialer{}
	pool, err := New(t.Context(), testConfig(), dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for index := range sendQueueDepth {
		if err := pool.Send(1, Key{2}, [][]byte{{byte(index)}}); err != nil {
			t.Fatalf("Send(%d) error = %v", index, err)
		}
	}
	if err := pool.Send(1, Key{2}, [][]byte{{99}}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("saturated Send() error = %v, want ErrQueueFull", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := pool.Receive(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed Receive() error = %v", err)
	}
	if pool.config.PrivateKey != (Key{}) {
		t.Fatal("Close() retained private relay authority")
	}
}

func TestPoolRestartsConnectionGeneration(t *testing.T) {
	t.Parallel()

	dialer := blockingDialer{}
	pool, err := New(t.Context(), testConfig(), dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := pool.Stop(); err != nil {
		t.Fatalf("Stop() before Open() error = %v", err)
	}
	if err := pool.Open(); err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if err := pool.Stop(); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if pool.config.PrivateKey == (Key{}) {
		t.Fatal("Stop() cleared reusable private relay authority")
	}
	if err := pool.Open(); err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := pool.Open(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Open() after Close() error = %v, want ErrClosed", err)
	}
}

func TestPoolRejectsPeerOnWrongRegion(t *testing.T) {
	t.Parallel()

	config := testConfig()
	config.Regions[2] = Region{
		ID: 2,
		Nodes: []Node{{
			Name:     "relay-2",
			HostName: "relay-2.example.com",
			Port:     443,
		}},
	}
	pool, err := New(t.Context(), config, blockingDialer{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := pool.Send(2, Key{2}, [][]byte{{1}}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Send() error = %v, want ErrUnauthorized", err)
	}
}

func TestPoolLearnsAuthenticatedReverseRegion(t *testing.T) {
	t.Parallel()

	config := testConfig()
	config.HomeRegion = 2
	config.Regions[2] = Region{
		ID: 2,
		Nodes: []Node{{
			Name:     "relay-2",
			HostName: "relay-2.example.com",
			Port:     443,
		}},
	}
	client := newFakeClient()
	dialer := &fakeDialer{client: client, calls: make(chan int, 1)}
	pool, err := New(t.Context(), config, dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	select {
	case <-dialer.calls:
	case <-time.After(time.Second):
		t.Fatal("Dial() was not called")
	}
	if err := pool.Send(2, Key{2}, [][]byte{{1}}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Send() before observation error = %v, want ErrUnauthorized", err)
	}
	client.received <- receiveResult{event: ReceiveEvent{
		Kind:   ReceivePacket,
		Source: Key{2},
		Data:   []byte{2},
	}}
	if _, err := receivePoolWithTimeout(pool, time.Second); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := pool.Send(2, Key{2}, [][]byte{{3}}); err != nil {
		t.Fatalf("Send() after authenticated observation error = %v", err)
	}
}

func TestPoolBoundsActiveRegions(t *testing.T) {
	t.Parallel()

	config := testConfig()
	for regionID := 2; regionID <= maxActiveRegions+1; regionID++ {
		config.Regions[regionID] = Region{
			ID: regionID,
			Nodes: []Node{{
				Name:     "relay",
				HostName: "relay.example.com",
				Port:     443,
			}},
		}
		config.Peers = append(config.Peers, Peer{
			Key:        Key{byte(regionID + 1)},
			HomeRegion: regionID,
			Address:    config.Peers[0].Address.Next().Next(),
		})
	}
	pool, err := New(t.Context(), config, blockingDialer{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for regionID := 2; regionID <= maxActiveRegions; regionID++ {
		if err := pool.Send(
			regionID,
			Key{byte(regionID + 1)},
			[][]byte{{1}},
		); err != nil {
			t.Fatalf("Send(region %d) error = %v", regionID, err)
		}
	}
	lastRegion := maxActiveRegions + 1
	if err := pool.Send(
		lastRegion,
		Key{byte(lastRegion + 1)},
		[][]byte{{1}},
	); !errors.Is(err, ErrRegionLimit) {
		t.Fatalf("overflow region Send() error = %v, want ErrRegionLimit", err)
	}
}

func TestPoolReportsAuthenticatedRegionHealth(t *testing.T) {
	t.Parallel()

	client := newFakeClient()
	dialer := &fakeDialer{client: client, calls: make(chan int, 1)}
	pool, err := New(t.Context(), testConfig(), dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	select {
	case <-dialer.calls:
	case <-time.After(time.Second):
		t.Fatal("Dial() was not called")
	}
	waitForRegionHealth(t, pool, 1, func(health RegionHealth) bool {
		return health.Connected && !health.LastConnected.IsZero() &&
			!health.LastActivity.IsZero()
	})
	client.received <- receiveResult{event: ReceiveEvent{Kind: ReceiveActivity}}
	if err := pool.Send(1, Key{2}, [][]byte{{1}}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	select {
	case <-client.sent:
	case <-time.After(time.Second):
		t.Fatal("Send() did not reach client")
	}
	waitForRegionHealth(t, pool, 1, func(health RegionHealth) bool {
		return health.Connected && !health.LastSend.IsZero()
	})
	health := pool.Health()
	health.Regions[0].Connected = false
	if !pool.Health().Regions[0].Connected {
		t.Fatal("Health() returned mutable worker state")
	}
}

func TestPoolReconnectsSilentAuthenticatedConnection(t *testing.T) {
	t.Parallel()

	client := newFakeClient()
	dialer := &fakeDialer{client: client, calls: make(chan int, 1)}
	pool, err := New(t.Context(), testConfig(), dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	pool.receiveSilence = 100 * time.Millisecond
	pool.retryDelay = func(int) time.Duration { return time.Hour }
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	select {
	case <-dialer.calls:
	case <-time.After(time.Second):
		t.Fatal("Dial() was not called")
	}
	waitForRegionHealth(t, pool, 1, func(health RegionHealth) bool {
		return health.Connected
	})
	waitForRegionHealth(t, pool, 1, func(health RegionHealth) bool {
		return !health.Connected && health.ConsecutiveFailures == 1 &&
			!health.LastFailure.IsZero()
	})
}

func TestPoolDoesNotClearNewReverseGeneration(t *testing.T) {
	t.Parallel()

	peer := Key{2}
	worker := &regionWorker{region: Region{ID: 1}, generation: 2}
	pool := &Pool{
		workers: map[int]*regionWorker{1: worker},
		reverseByKey: map[Key]reverseRoute{
			peer: {regionID: 1, generation: 2},
		},
	}
	pool.clearReverseRegion(1, 1)
	if route, exists := pool.reverseByKey[peer]; !exists || route.generation != 2 {
		t.Fatalf("new reverse route was cleared: %#v", pool.reverseByKey)
	}
}

func TestPoolEvictsOnlyIdleNonHomeWorkers(t *testing.T) {
	t.Parallel()

	config := testConfig()
	for regionID := 2; regionID <= maxActiveRegions+1; regionID++ {
		config.Regions[regionID] = Region{
			ID: regionID,
			Nodes: []Node{{
				Name:     "relay",
				HostName: "relay.example.com",
				Port:     443,
			}},
		}
	}
	dialer := &countingBlockingDialer{}
	pool, err := New(t.Context(), config, dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for regionID := 2; regionID <= maxActiveRegions+1; regionID++ {
		if err := pool.PrepareRegion(regionID); err != nil {
			t.Fatalf("PrepareRegion(%d) error = %v", regionID, err)
		}
	}
	health := pool.Health()
	if !health.Available || health.HomeRegion != 1 || len(health.Regions) != maxActiveRegions {
		t.Fatalf("Health() = %#v", health)
	}
	seen := make(map[int]struct{}, len(health.Regions))
	for _, region := range health.Regions {
		seen[region.RegionID] = struct{}{}
	}
	if _, exists := seen[1]; !exists {
		t.Fatal("home worker was evicted")
	}
	if _, exists := seen[2]; exists {
		t.Fatal("oldest idle non-home worker was retained")
	}
	if _, exists := seen[maxActiveRegions+1]; !exists {
		t.Fatal("prepared replacement worker is missing")
	}
	if maximum := dialer.maximumActive(); maximum > maxActiveRegions {
		t.Fatalf("active dial workers = %d, want at most %d", maximum, maxActiveRegions)
	}
}

type sentPacket struct {
	destination Key
	packet      []byte
}

type receiveResult struct {
	event ReceiveEvent
	err   error
}

type fakeClient struct {
	sent      chan sentPacket
	received  chan receiveResult
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		sent:     make(chan sentPacket, 8),
		received: make(chan receiveResult, 8),
		closed:   make(chan struct{}),
	}
}

func (c *fakeClient) Send(destination Key, packet []byte) error {
	select {
	case c.sent <- sentPacket{destination: destination, packet: slices.Clone(packet)}:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *fakeClient) Receive() (ReceiveEvent, error) {
	select {
	case result := <-c.received:
		return result.event, result.err
	case <-c.closed:
		return ReceiveEvent{}, net.ErrClosed
	}
}

func (c *fakeClient) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })

	return nil
}

type fakeDialer struct {
	client Client
	calls  chan int
}

func (d *fakeDialer) Dial(
	ctx context.Context,
	_ Key,
	region Region,
) (Client, error) {
	select {
	case d.calls <- region.ID:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return d.client, nil
}

type blockingDialer struct{}

func (blockingDialer) Dial(
	ctx context.Context,
	_ Key,
	_ Region,
) (Client, error) {
	<-ctx.Done()

	return nil, ctx.Err()
}

type countingBlockingDialer struct {
	mu      sync.Mutex
	active  int
	maximum int
}

func (d *countingBlockingDialer) Dial(
	ctx context.Context,
	_ Key,
	_ Region,
) (Client, error) {
	d.mu.Lock()
	d.active++
	d.maximum = max(d.maximum, d.active)
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.active--
		d.mu.Unlock()
	}()
	<-ctx.Done()

	return nil, ctx.Err()
}

func (d *countingBlockingDialer) maximumActive() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.maximum
}

func waitForRegionHealth(
	t *testing.T,
	pool *Pool,
	regionID int,
	ready func(RegionHealth) bool,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, health := range pool.Health().Regions {
			if health.RegionID == regionID && ready(health) {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("region %d health did not become ready: %#v", regionID, pool.Health())
}

func receivePoolWithTimeout(pool *Pool, timeout time.Duration) (Packet, error) {
	type result struct {
		packet Packet
		err    error
	}
	completed := make(chan result, 1)
	go func() {
		packet, err := pool.Receive()
		completed <- result{packet: packet, err: err}
	}()
	select {
	case value := <-completed:
		return value.packet, value.err
	case <-time.After(timeout):
		return Packet{}, errors.New("receive timed out")
	}
}
