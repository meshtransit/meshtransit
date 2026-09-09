package dataplane

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	compatstun "github.com/meshtransit/meshd/internal/compat/stun"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
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
