package relay

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
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

func TestPoolReplacesPeerAuthorityInPlace(t *testing.T) {
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
	if err := pool.ReplacePeers(nil); err != nil {
		t.Fatalf("ReplacePeers(nil) error = %v", err)
	}
	if _, exists := pool.Peer(Key{2}); exists {
		t.Fatal("removed peer remains authorized")
	}
	if err := pool.Send(1, Key{2}, [][]byte{{1}}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Send() error = %v, want ErrUnauthorized", err)
	}
	client.received <- receiveResult{event: ReceiveEvent{
		Kind:   ReceivePacket,
		Source: Key{2},
		Data:   []byte{2},
	}}
	replacement := Peer{
		Key:        Key{3},
		HomeRegion: 1,
		Address:    testConfig().Peers[0].Address.Next(),
	}
	if err := pool.ReplacePeers([]Peer{replacement}); err != nil {
		t.Fatalf("ReplacePeers(replacement) error = %v", err)
	}
	if peer, exists := pool.Peer(replacement.Key); !exists || peer != replacement {
		t.Fatalf("replacement peer = %#v, exists=%t", peer, exists)
	}
	client.received <- receiveResult{event: ReceiveEvent{
		Kind:   ReceivePacket,
		Source: replacement.Key,
		Data:   []byte{3},
	}}
	packet, err := receivePoolWithTimeout(pool, time.Second)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if packet.Source != replacement.Key || !slices.Equal(packet.Data, []byte{3}) {
		t.Fatalf("Receive() = %#v", packet)
	}
	select {
	case <-dialer.calls:
		t.Fatal("peer replacement restarted relay transport")
	default:
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

func TestPoolBoundsDisconnectedSendBytes(t *testing.T) {
	t.Parallel()

	pool, err := New(t.Context(), testConfig(), blockingDialer{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	packetCount := maxRegionQueuedByte / MaxPacketSize
	batch := make([][]byte, packetCount)
	for index := range batch {
		batch[index] = make([]byte, MaxPacketSize)
	}
	if err := pool.Send(1, Key{2}, batch); err != nil {
		t.Fatalf("full-budget Send() error = %v", err)
	}
	if err := pool.Send(1, Key{2}, [][]byte{{1}}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("over-budget Send() error = %v, want ErrQueueFull", err)
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

func TestPoolBacksOffAcrossAuthenticatedConnectionChurn(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	pool, err := New(parent, testConfig(), churnDialer{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	attempts := make(chan int, 3)
	callCount := 0
	pool.retryDelay = func(attempt int) time.Duration {
		attempts <- attempt
		callCount++
		if callCount == cap(attempts) {
			cancel()
		}

		return 0
	}
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	got := make([]int, 0, cap(attempts))
	for range cap(attempts) {
		select {
		case attempt := <-attempts:
			got = append(got, attempt)
		case <-time.After(time.Second):
			t.Fatalf("retry attempts = %v", got)
		}
	}
	if want := []int{1, 2, 3}; !slices.Equal(got, want) {
		t.Fatalf("retry attempts = %v, want %v", got, want)
	}
}

func TestNextRetryAttempt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		previous     int
		connectedFor time.Duration
		want         int
	}{
		{
			name: "first failure",
			want: 1,
		},
		{
			name:         "rapid churn",
			previous:     2,
			connectedFor: stableConnectionAge - time.Nanosecond,
			want:         3,
		},
		{
			name:         "stable connection",
			previous:     5,
			connectedFor: stableConnectionAge,
			want:         1,
		},
		{
			name:     "saturated counter",
			previous: int(^uint(0) >> 1),
			want:     int(^uint(0) >> 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := nextRetryAttempt(test.previous, test.connectedFor); got != test.want {
				t.Fatalf("nextRetryAttempt() = %d, want %d", got, test.want)
			}
		})
	}
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

type churnDialer struct{}

func (churnDialer) Dial(
	context.Context,
	Key,
	Region,
) (Client, error) {
	return churnClient{}, nil
}

type churnClient struct{}

func (churnClient) Send(Key, []byte) error {
	return nil
}

func (churnClient) Receive() (ReceiveEvent, error) {
	return ReceiveEvent{}, errors.New("connection dropped")
}

func (churnClient) Close() error {
	return nil
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

// freshDialer hands out a new client per dial and counts the dials.
type freshDialer struct{ calls chan int }

func (d *freshDialer) Dial(ctx context.Context, _ Key, region Region) (Client, error) {
	select {
	case d.calls <- region.ID:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return newFakeClient(), nil
}

func TestPoolReconnectDialsAgainAtOnce(t *testing.T) {
	t.Parallel()
	dialer := &freshDialer{calls: make(chan int, 4)}
	pool, err := New(t.Context(), testConfig(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	// A failed connection waits an hour: only Reconnect dials again soon.
	pool.retryDelay = func(int) time.Duration { return time.Hour }
	if err := pool.Open(); err != nil {
		t.Fatal(err)
	}
	wait := func(what string) {
		t.Helper()
		select {
		case <-dialer.calls:
		case <-time.After(time.Second):
			t.Fatalf("no dial %s", what)
		}
	}
	wait("at first")
	pool.Reconnect()
	wait("after Reconnect")
}

func TestPoolReconnectsAreSpacedWhenNetworksChurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := &freshDialer{calls: make(chan int, 16)}
		pool, err := New(t.Context(), testConfig(), dialer)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pool.Close() }()
		pool.retryDelay = func(int) time.Duration { return time.Hour }
		if err := pool.Open(); err != nil {
			t.Fatal(err)
		}
		dials := func() int {
			synctest.Wait()
			return len(dialer.calls)
		}
		if got := dials(); got != 1 {
			t.Fatalf("%d dials at first, want 1", got)
		}
		pool.Reconnect()
		if got := dials(); got != 2 {
			t.Fatalf("%d dials after one Reconnect, want 2: the first is at once", got)
		}
		// The networks churn: ten changes in 200 ms make one more dial,
		// a reconnectSpacing after the last one.
		for range 10 {
			pool.Reconnect()
			time.Sleep(20 * time.Millisecond)
		}
		if got := dials(); got != 2 {
			t.Fatalf("%d dials during the churn, want 2", got)
		}
		if health := pool.Health(); len(health.Regions) != 1 || health.Regions[0].Connected {
			t.Fatalf("Health() while the redial waits = %+v, want the region down", health)
		}
		time.Sleep(reconnectSpacing)
		if got := dials(); got != 3 {
			t.Fatalf("%d dials after the churn, want 3", got)
		}
		time.Sleep(10 * reconnectSpacing)
		if got := dials(); got != 3 {
			t.Fatalf("%d dials once the networks settled, want 3", got)
		}
	})
}

type refusingDialer struct{ calls chan int }

func (d *refusingDialer) Dial(_ context.Context, _ Key, region Region) (Client, error) {
	d.calls <- region.ID
	return nil, errors.New("refused")
}

func TestPoolSpacesReconnectsDuringTheFailureBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := &refusingDialer{calls: make(chan int, 16)}
		pool, err := New(t.Context(), testConfig(), dialer)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pool.Close() }()
		pool.retryDelay = func(int) time.Duration { return time.Hour }
		if err := pool.Open(); err != nil {
			t.Fatal(err)
		}
		dials := func() int {
			synctest.Wait()
			return len(dialer.calls)
		}
		dials()
		pool.Reconnect()
		if got := dials(); got != 2 {
			t.Fatalf("%d dials after one Reconnect in the backoff, want 2", got)
		}
		pool.Reconnect()
		if got := dials(); got != 2 {
			t.Fatalf("%d dials right after a second Reconnect, want 2 until the spacing ends", got)
		}
		time.Sleep(reconnectSpacing)
		if got := dials(); got != 3 {
			t.Fatalf("%d dials after the spacing, want 3", got)
		}
	})
}

func TestPoolClosesWhileARedialWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := &freshDialer{calls: make(chan int, 16)}
		pool, err := New(t.Context(), testConfig(), dialer)
		if err != nil {
			t.Fatal(err)
		}
		pool.retryDelay = func(int) time.Duration { return time.Hour }
		if err := pool.Open(); err != nil {
			t.Fatal(err)
		}
		pool.Reconnect()
		synctest.Wait()
		pool.Reconnect() // waits for the spacing
		synctest.Wait()
		start := time.Now()
		if err := pool.Close(); err != nil {
			t.Fatal(err)
		}
		if waited := time.Since(start); waited != 0 {
			t.Fatalf("Close() waited %v for the spacing", waited)
		}
	})
}
