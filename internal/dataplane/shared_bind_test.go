package dataplane

import (
	"context"
	"crypto/ecdh"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	compatstun "github.com/meshtransit/meshd/internal/compat/stun"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"github.com/meshtransit/meshd/internal/relay"
	"golang.zx2c4.com/wireguard/conn"
)

func TestNewSharedBind(t *testing.T) {
	t.Parallel()

	if _, err := newSharedBind(nil); err == nil {
		t.Fatal("newSharedBind() error = nil, want non-nil")
	}
	if shared, err := newSharedBind(newFakeInnerBind()); err != nil || shared == nil {
		t.Fatalf("newSharedBind() = %#v, %v", shared, err)
	}
	if _, err := newSharedBindWithGenerationSource(
		newFakeInnerBind(),
		nil,
	); err == nil {
		t.Fatal("newSharedBindWithGenerationSource(nil) error = nil, want non-nil")
	}
}

func TestSharedBindDemultiplexesControlDatagrams(t *testing.T) {
	t.Parallel()

	inner := newFakeInnerBind()
	shared, err := newSharedBind(inner)
	if err != nil {
		t.Fatalf("newSharedBind() error = %v", err)
	}
	handler := &recordingDatagramHandler{}
	if err := shared.setDatagramHandler(handler); err != nil {
		t.Fatalf("setDatagramHandler() error = %v", err)
	}
	receivers, port, err := shared.Open(41641)
	if err != nil || port != 41641 || len(receivers) != 1 {
		t.Fatalf("Open() = %d receivers, port %d, error %v", len(receivers), port, err)
	}

	stunPacket := compatstun.BindingRequest(compatstun.TransactionID{1, 2, 3})
	stunSource := netip.MustParseAddrPort("203.0.113.1:3478")
	inner.queue(stunPacket, stunSource)
	packets, sizes, endpoints := receiveBuffers()
	count, err := receivers[0](packets, sizes, endpoints)
	if err != nil || count != 1 || sizes[0] != 0 || endpoints[0] != nil {
		t.Fatalf("control receive = count %d size %d endpoint %#v error %v", count, sizes[0], endpoints[0], err)
	}
	recordedPackets, recordedSources, recordedSockets := handler.snapshot()
	if len(recordedPackets) != 1 || !slices.Equal(recordedPackets[0], stunPacket) ||
		recordedSources[0] != stunSource ||
		recordedSockets[0] != (pathdiscovery.Socket{Port: 41641, Generation: 1}) {
		t.Fatalf(
			"handler records = packets %x sources %v sockets %#v",
			recordedPackets,
			recordedSources,
			recordedSockets,
		)
	}

	wireGuardPacket := []byte{1, 2, 3, 4}
	wireGuardSource := netip.MustParseAddrPort("198.51.100.1:41641")
	inner.queue(wireGuardPacket, wireGuardSource)
	packets, sizes, endpoints = receiveBuffers()
	count, err = receivers[0](packets, sizes, endpoints)
	if err != nil || count != 1 || sizes[0] != len(wireGuardPacket) || endpoints[0] == nil ||
		!slices.Equal(packets[0][:sizes[0]], wireGuardPacket) {
		t.Fatalf("wireguard receive = count %d size %d endpoint %#v error %v", count, sizes[0], endpoints[0], err)
	}
	if recorded, _, _ := handler.snapshot(); len(recorded) != 1 {
		t.Fatalf("handler received %d packets, want 1", len(recorded))
	}
}

func TestSharedBindDropsMatchedDatagramWithInvalidSource(t *testing.T) {
	t.Parallel()

	inner := newFakeInnerBind()
	shared, err := newSharedBind(inner)
	if err != nil {
		t.Fatalf("newSharedBind() error = %v", err)
	}
	handler := &recordingDatagramHandler{}
	if err := shared.setDatagramHandler(handler); err != nil {
		t.Fatalf("setDatagramHandler() error = %v", err)
	}
	receivers, _, err := shared.Open(41641)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	inner.queueEndpoint(
		compatstun.BindingRequest(compatstun.TransactionID{4, 5, 6}),
		&fakeBindEndpoint{destination: "invalid"},
	)
	packets, sizes, endpoints := receiveBuffers()
	count, err := receivers[0](packets, sizes, endpoints)
	if err != nil || count != 1 || sizes[0] != 0 || endpoints[0] != nil {
		t.Fatalf("receive = count %d size %d endpoint %#v error %v", count, sizes[0], endpoints[0], err)
	}
	if recorded, _, _ := handler.snapshot(); len(recorded) != 0 {
		t.Fatalf("handler received %d packets, want 0", len(recorded))
	}
}

func TestSharedBindSendDatagramAndSocketGeneration(t *testing.T) {
	t.Parallel()

	inner := newFakeInnerBind()
	shared, err := newSharedBind(inner)
	if err != nil {
		t.Fatalf("newSharedBind() error = %v", err)
	}
	destination := netip.MustParseAddrPort("203.0.113.2:3478")
	packet := compatstun.BindingRequest(compatstun.TransactionID{7, 8, 9})
	if _, err := shared.SendDatagram(packet, destination); !errors.Is(err, pathdiscovery.ErrTransportClosed) {
		t.Fatalf("SendDatagram() closed error = %v", err)
	}
	if _, _, err := shared.Open(41641); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	socket, err := shared.SendDatagram(packet, destination)
	if err != nil {
		t.Fatalf("SendDatagram() error = %v", err)
	}
	if socket != (pathdiscovery.Socket{Port: 41641, Generation: 1}) || shared.Socket() != socket {
		t.Fatalf("SendDatagram() socket = %#v, current %#v", socket, shared.Socket())
	}
	sentPackets, sentDestination := inner.sentSnapshot()
	if len(sentPackets) != 1 || !slices.Equal(sentPackets[0], packet) || sentDestination != destination {
		t.Fatalf("SendDatagram() sent %x to %v", sentPackets, sentDestination)
	}
	if err := shared.Close(); err != nil || shared.Socket().IsOpen() {
		t.Fatalf("Close() error = %v, socket %#v", err, shared.Socket())
	}
	if _, _, err := shared.Open(41641); err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	if got := shared.Socket(); got.Generation != 2 || got.Port != 41641 {
		t.Fatalf("second Open() socket = %#v", got)
	}
}

func TestSharedBindSocketGenerationContinuesAcrossInstances(t *testing.T) {
	t.Parallel()

	generations := &socketGenerationSource{}
	first, err := newSharedBindWithGenerationSource(newFakeInnerBind(), generations)
	if err != nil {
		t.Fatalf("newSharedBindWithGenerationSource(first) error = %v", err)
	}
	if _, _, err := first.Open(41641); err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if got := first.Socket().Generation; got != 1 {
		t.Fatalf("first socket generation = %d, want 1", got)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	second, err := newSharedBindWithGenerationSource(newFakeInnerBind(), generations)
	if err != nil {
		t.Fatalf("newSharedBindWithGenerationSource(second) error = %v", err)
	}
	if _, _, err := second.Open(41641); err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	if got := second.Socket().Generation; got != 2 {
		t.Fatalf("second socket generation = %d, want 2", got)
	}
}

func TestSharedBindSocketGenerationExhaustionFailsClosed(t *testing.T) {
	t.Parallel()

	inner := newFakeInnerBind()
	shared, err := newSharedBindWithGenerationSource(inner, &socketGenerationSource{
		latest: math.MaxUint64,
	})
	if err != nil {
		t.Fatalf("newSharedBindWithGenerationSource() error = %v", err)
	}
	if _, _, err := shared.Open(41641); err == nil {
		t.Fatal("Open() at generation exhaustion error = nil")
	}
	if shared.Socket().IsOpen() || inner.isOpen {
		t.Fatalf("exhausted bind remained open: shared=%#v inner=%v", shared.Socket(), inner.isOpen)
	}
}

func TestSharedBindValidatesControlBoundary(t *testing.T) {
	t.Parallel()

	inner := newFakeInnerBind()
	shared, err := newSharedBind(inner)
	if err != nil {
		t.Fatalf("newSharedBind() error = %v", err)
	}
	handler := &recordingDatagramHandler{}
	if err := shared.setDatagramHandler(handler); err != nil {
		t.Fatalf("setDatagramHandler() error = %v", err)
	}
	if _, _, err := shared.Open(41641); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := shared.setDatagramHandler(&recordingDatagramHandler{}); err == nil {
		t.Fatal("setDatagramHandler() on open bind error = nil, want non-nil")
	}

	tests := []struct {
		name        string
		packet      []byte
		destination netip.AddrPort
	}{
		{name: "empty packet", destination: netip.MustParseAddrPort("203.0.113.3:3478")},
		{name: "oversized packet", packet: make([]byte, maxControlDatagramSize+1), destination: netip.MustParseAddrPort("203.0.113.3:3478")},
		{name: "zero destination", packet: []byte{1}},
		{name: "loopback destination", packet: []byte{1}, destination: netip.MustParseAddrPort("127.0.0.1:3478")},
		{name: "link local destination", packet: []byte{1}, destination: netip.MustParseAddrPort("169.254.1.1:3478")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := shared.SendDatagram(test.packet, test.destination); err == nil {
				t.Fatal("SendDatagram() error = nil, want non-nil")
			}
		})
	}
}

func TestSharedBindDelegatesWireGuardOperations(t *testing.T) {
	t.Parallel()

	inner := newFakeInnerBind()
	shared, err := newSharedBind(inner)
	if err != nil {
		t.Fatalf("newSharedBind() error = %v", err)
	}
	if err := shared.SetMark(42); err != nil || inner.mark != 42 {
		t.Fatalf("SetMark() error = %v, mark %d", err, inner.mark)
	}
	if shared.BatchSize() != 1 {
		t.Fatalf("BatchSize() = %d, want 1", shared.BatchSize())
	}
	endpoint, err := shared.ParseEndpoint("203.0.113.4:41641")
	if err != nil || endpoint.DstToString() != "203.0.113.4:41641" {
		t.Fatalf("ParseEndpoint() = %#v, %v", endpoint, err)
	}
}

func TestSharedBindRoutesEncryptedPacketsThroughRelay(t *testing.T) {
	t.Parallel()

	client := newRelayTestClient()
	pool, peerKey := newTestRelayPool(t, client)
	inner := newFakeInnerBind()
	shared, err := newSharedBindWithRelay(inner, &socketGenerationSource{}, pool)
	if err != nil {
		t.Fatalf("newSharedBindWithRelay() error = %v", err)
	}
	receivers, _, err := shared.Open(41641)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = shared.Close()
		_ = shared.closeRelayPermanently()
	})
	if len(receivers) != 2 {
		t.Fatalf("Open() receivers = %d, want 2", len(receivers))
	}

	encodedEndpoint := formatRelayEndpoint(1, peerKey)
	endpoint, err := shared.ParseEndpoint(encodedEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpoint() error = %v", err)
	}
	outbound := []byte{1, 2, 3}
	if err := shared.Send([][]byte{outbound}, endpoint); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	select {
	case sent := <-client.sent:
		if sent.destination != peerKey || !slices.Equal(sent.packet, outbound) {
			t.Fatalf("relay Send() = %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("relay Send() timed out")
	}

	packets := [][]byte{make([]byte, maxControlDatagramSize)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	type receiveResult struct {
		count int
		err   error
	}
	received := make(chan receiveResult, 1)
	go func() {
		count, err := receivers[1](packets, sizes, endpoints)
		received <- receiveResult{count: count, err: err}
	}()
	client.receive <- relay.ReceivedPacket{Source: peerKey, Data: []byte{4, 5, 6}}
	select {
	case result := <-received:
		if result.err != nil || result.count != 1 || sizes[0] != 3 ||
			!slices.Equal(packets[0][:sizes[0]], []byte{4, 5, 6}) {
			t.Fatalf("relay receive count=%d size=%d err=%v", result.count, sizes[0], result.err)
		}
		if endpoints[0].DstToString() != encodedEndpoint ||
			endpoints[0].DstIP() != netip.MustParseAddr("100.64.0.4") {
			t.Fatalf("relay source endpoint = %#v", endpoints[0])
		}
	case <-time.After(time.Second):
		t.Fatal("relay receive timed out")
	}
}

func TestSharedBindRestartsRelayAcrossBindCycles(t *testing.T) {
	t.Parallel()

	pool, _ := newTestRelayPool(t, newRelayTestClient())
	shared, err := newSharedBindWithRelay(
		newFakeInnerBind(),
		&socketGenerationSource{},
		pool,
	)
	if err != nil {
		t.Fatalf("newSharedBindWithRelay() error = %v", err)
	}
	if err := shared.Close(); err != nil {
		t.Fatalf("Close() before Open() error = %v", err)
	}
	for cycle := 1; cycle <= 2; cycle++ {
		receivers, _, err := shared.Open(41641)
		if err != nil || len(receivers) != 2 {
			t.Fatalf("Open(cycle %d) = %d receivers, %v", cycle, len(receivers), err)
		}
		if err := shared.Close(); err != nil {
			t.Fatalf("Close(cycle %d) error = %v", cycle, err)
		}
	}
	if err := shared.closeRelayPermanently(); err != nil {
		t.Fatalf("closeRelayPermanently() error = %v", err)
	}
	if _, _, err := shared.Open(41641); !errors.Is(err, relay.ErrClosed) {
		t.Fatalf("Open() after permanent close error = %v, want relay.ErrClosed", err)
	}
}

func newTestRelayPool(t *testing.T, client relay.Client) (*relay.Pool, relay.Key) {
	t.Helper()

	privateKey := relay.Key{1}
	private, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}
	peerKey := relay.Key{2}
	pool, err := relay.New(t.Context(), relay.Config{
		PrivateKey: privateKey,
		PublicKey:  relay.Key(private.PublicKey().Bytes()),
		HomeRegion: 1,
		Regions: map[int]relay.Region{
			1: {
				ID: 1,
				Nodes: []relay.Node{{
					Name:     "relay",
					HostName: "relay.example.com",
					Port:     443,
				}},
			},
		},
		Peers: []relay.Peer{{
			Key:        peerKey,
			HomeRegion: 1,
			Address:    netip.MustParseAddr("100.64.0.4"),
		}},
	}, relayTestDialer{client: client})
	if err != nil {
		t.Fatalf("relay.New() error = %v", err)
	}

	return pool, peerKey
}

type queuedDatagram struct {
	packet   []byte
	endpoint conn.Endpoint
}

type fakeInnerBind struct {
	mu          sync.Mutex
	isOpen      bool
	queueValues []queuedDatagram
	sentPackets [][]byte
	sentTo      netip.AddrPort
	mark        uint32
}

var _ conn.Bind = (*fakeInnerBind)(nil)

func newFakeInnerBind() *fakeInnerBind { return &fakeInnerBind{} }

func (b *fakeInnerBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.isOpen {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if port == 0 {
		port = 41641
	}
	b.isOpen = true

	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *fakeInnerBind) Close() error {
	b.mu.Lock()
	b.isOpen = false
	b.mu.Unlock()

	return nil
}

func (b *fakeInnerBind) SetMark(mark uint32) error {
	b.mu.Lock()
	b.mark = mark
	b.mu.Unlock()

	return nil
}

func (b *fakeInnerBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.isOpen {
		return pathdiscovery.ErrTransportClosed
	}
	b.sentPackets = make([][]byte, len(buffers))
	for index, buffer := range buffers {
		b.sentPackets[index] = slices.Clone(buffer)
	}
	destination, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil {
		return err
	}
	b.sentTo = destination

	return nil
}

func (b *fakeInnerBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	if _, err := netip.ParseAddrPort(value); err != nil {
		return nil, err
	}

	return &fakeBindEndpoint{destination: value}, nil
}

func (*fakeInnerBind) BatchSize() int { return 1 }

func (b *fakeInnerBind) receive(
	packets [][]byte,
	sizes []int,
	endpoints []conn.Endpoint,
) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.queueValues) == 0 {
		return 0, nil
	}
	value := b.queueValues[0]
	b.queueValues = b.queueValues[1:]
	copy(packets[0], value.packet)
	sizes[0] = len(value.packet)
	endpoints[0] = value.endpoint

	return 1, nil
}

func (b *fakeInnerBind) queue(packet []byte, source netip.AddrPort) {
	b.queueEndpoint(packet, &fakeBindEndpoint{destination: source.String()})
}

func (b *fakeInnerBind) queueEndpoint(packet []byte, endpoint conn.Endpoint) {
	b.mu.Lock()
	b.queueValues = append(b.queueValues, queuedDatagram{
		packet:   slices.Clone(packet),
		endpoint: endpoint,
	})
	b.mu.Unlock()
}

func (b *fakeInnerBind) sentSnapshot() ([][]byte, netip.AddrPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	packets := make([][]byte, len(b.sentPackets))
	for index, packet := range b.sentPackets {
		packets[index] = slices.Clone(packet)
	}

	return packets, b.sentTo
}

type fakeBindEndpoint struct {
	destination string
}

type relayTestSentPacket struct {
	destination relay.Key
	packet      []byte
}

type relayTestClient struct {
	sent      chan relayTestSentPacket
	receive   chan relay.ReceivedPacket
	closed    chan struct{}
	closeOnce sync.Once
}

func newRelayTestClient() *relayTestClient {
	return &relayTestClient{
		sent:    make(chan relayTestSentPacket, 1),
		receive: make(chan relay.ReceivedPacket, 1),
		closed:  make(chan struct{}),
	}
}

func (c *relayTestClient) Send(destination relay.Key, packet []byte) error {
	select {
	case c.sent <- relayTestSentPacket{
		destination: destination,
		packet:      slices.Clone(packet),
	}:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *relayTestClient) Receive() (relay.ReceivedPacket, error) {
	select {
	case packet := <-c.receive:
		return packet, nil
	case <-c.closed:
		return relay.ReceivedPacket{}, net.ErrClosed
	}
}

func (c *relayTestClient) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })

	return nil
}

type relayTestDialer struct {
	client relay.Client
}

func (d relayTestDialer) Dial(
	ctx context.Context,
	_ relay.Key,
	_ relay.Region,
) (relay.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return d.client, nil
}

func (*fakeBindEndpoint) ClearSrc()           {}
func (*fakeBindEndpoint) SrcToString() string { return "" }
func (e *fakeBindEndpoint) DstToString() string {
	return e.destination
}
func (e *fakeBindEndpoint) DstToBytes() []byte { return []byte(e.destination) }
func (e *fakeBindEndpoint) DstIP() netip.Addr {
	endpoint, _ := netip.ParseAddrPort(e.destination)

	return endpoint.Addr()
}
func (*fakeBindEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

type recordingDatagramHandler struct {
	mu      sync.Mutex
	packets [][]byte
	sources []netip.AddrPort
	sockets []pathdiscovery.Socket
}

var _ pathdiscovery.DatagramHandler = (*recordingDatagramHandler)(nil)

func (*recordingDatagramHandler) MatchesDatagram(packet []byte) bool {
	return compatstun.LooksLikeMessage(packet)
}

func (h *recordingDatagramHandler) HandleDatagram(
	packet []byte,
	source netip.AddrPort,
	socket pathdiscovery.Socket,
) {
	h.mu.Lock()
	h.packets = append(h.packets, slices.Clone(packet))
	h.sources = append(h.sources, source)
	h.sockets = append(h.sockets, socket)
	h.mu.Unlock()
}

func (h *recordingDatagramHandler) snapshot() (
	[][]byte,
	[]netip.AddrPort,
	[]pathdiscovery.Socket,
) {
	h.mu.Lock()
	defer h.mu.Unlock()
	packets := make([][]byte, len(h.packets))
	for index, packet := range h.packets {
		packets[index] = slices.Clone(packet)
	}

	return packets, slices.Clone(h.sources), slices.Clone(h.sockets)
}

func receiveBuffers() ([][]byte, []int, []conn.Endpoint) {
	return [][]byte{make([]byte, maxControlDatagramSize)}, make([]int, 1), make([]conn.Endpoint, 1)
}
