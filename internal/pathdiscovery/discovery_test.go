package pathdiscovery

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	compatstun "github.com/meshtransit/meshd/internal/compat/stun"
)

func TestNewDiscovery(t *testing.T) {
	t.Parallel()

	transport := newFakeDiscoveryTransport()
	tests := []struct {
		name        string
		transport   DatagramTransport
		probeWindow time.Duration
		retryDelay  time.Duration
		wantErr     bool
	}{
		{
			name:        "valid",
			transport:   transport,
			probeWindow: time.Second,
			retryDelay:  100 * time.Millisecond,
		},
		{
			name:        "missing transport",
			probeWindow: time.Second,
			retryDelay:  100 * time.Millisecond,
			wantErr:     true,
		},
		{
			name:        "zero probe window",
			transport:   transport,
			probeWindow: 0,
			retryDelay:  100 * time.Millisecond,
			wantErr:     true,
		},
		{
			name:        "zero retry delay",
			transport:   transport,
			probeWindow: time.Second,
			retryDelay:  0,
			wantErr:     true,
		},
		{
			name:        "retry after window",
			transport:   transport,
			probeWindow: 100 * time.Millisecond,
			retryDelay:  100 * time.Millisecond,
			wantErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			discovery, err := newDiscovery(
				test.transport,
				test.probeWindow,
				test.retryDelay,
			)
			if test.wantErr {
				if err == nil {
					t.Fatal("newDiscovery() error = nil, want non-nil")
				}

				return
			}
			if err != nil || discovery == nil {
				t.Fatalf("newDiscovery() = %#v, %v", discovery, err)
			}
		})
	}
}

func TestDiscoveryDiscover(t *testing.T) {
	t.Parallel()

	firstServer := netip.MustParseAddrPort("203.0.113.1:3478")
	secondServer := netip.MustParseAddrPort("203.0.113.2:3478")
	firstAddress := netip.MustParseAddrPort("198.51.100.1:41641")
	secondAddress := netip.MustParseAddrPort("[2001:db8::1]:41641")
	transport := newFakeDiscoveryTransport()
	transport.mapped[firstServer] = firstAddress
	transport.mapped[secondServer] = secondAddress
	discovery, err := newDiscovery(transport, 50*time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("newDiscovery() error = %v", err)
	}
	transport.handler = discovery

	result, err := discovery.Discover(t.Context(), 7, []netip.AddrPort{
		secondServer,
		firstServer,
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.Scope != 7 || result.Socket != transport.Socket() ||
		result.ReachableServers != 2 || result.FailedServers != 0 {
		t.Fatalf("Discover() result = %#v", result)
	}
	if got := result.Candidates.Endpoints(); !slices.Equal(got, []netip.AddrPort{
		firstAddress,
		secondAddress,
	}) {
		t.Fatalf("Discover() endpoints = %v", got)
	}
	if transport.sendCount() != 2 {
		t.Fatalf("Discover() sends = %d, want 2", transport.sendCount())
	}
}

func TestDiscoveryDiscoverReturnsPartialResult(t *testing.T) {
	t.Parallel()

	responsiveServer := netip.MustParseAddrPort("203.0.113.3:3478")
	silentServer := netip.MustParseAddrPort("203.0.113.4:3478")
	expected := netip.MustParseAddrPort("198.51.100.3:41641")
	transport := newFakeDiscoveryTransport()
	transport.mapped[responsiveServer] = expected
	discovery, err := newDiscovery(transport, 30*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("newDiscovery() error = %v", err)
	}
	transport.handler = discovery

	result, err := discovery.Discover(
		t.Context(),
		8,
		[]netip.AddrPort{responsiveServer, silentServer},
	)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.ReachableServers != 1 || result.FailedServers != 1 ||
		!slices.Equal(result.Candidates.Endpoints(), []netip.AddrPort{expected}) {
		t.Fatalf("Discover() partial result = %#v", result)
	}
	if transport.sendCount() != 3 {
		t.Fatalf("Discover() sends = %d, want initial responses plus one retry", transport.sendCount())
	}
}

func TestDiscoveryDiscoverRejectsUnexpectedResponses(t *testing.T) {
	t.Parallel()

	server := netip.MustParseAddrPort("203.0.113.5:3478")
	transport := newFakeDiscoveryTransport()
	transport.mapped[server] = netip.MustParseAddrPort("198.51.100.5:41641")
	transport.responseSource = netip.MustParseAddrPort("203.0.113.99:3478")
	discovery, err := newDiscovery(transport, 25*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("newDiscovery() error = %v", err)
	}
	transport.handler = discovery

	_, err = discovery.Discover(t.Context(), 9, []netip.AddrPort{server})
	if !errors.Is(err, ErrNoSTUNResponse) || !errors.Is(err, ErrProbeTimeout) {
		t.Fatalf("Discover() error = %v, want no response and timeout", err)
	}
	discovery.mu.Lock()
	pendingCount := len(discovery.pending)
	discovery.mu.Unlock()
	if pendingCount != 0 {
		t.Fatalf("Discover() retained %d pending probes", pendingCount)
	}
}

func TestDiscoveryDiscoverRejectsSocketChange(t *testing.T) {
	t.Parallel()

	server := netip.MustParseAddrPort("203.0.113.6:3478")
	transport := newFakeDiscoveryTransport()
	transport.rebindOnSend = true
	discovery, err := newDiscovery(transport, 25*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("newDiscovery() error = %v", err)
	}
	transport.handler = discovery

	_, err = discovery.Discover(t.Context(), 10, []netip.AddrPort{server})
	if !errors.Is(err, ErrSocketChanged) {
		t.Fatalf("Discover() error = %v, want ErrSocketChanged", err)
	}
}

func TestDiscoveryDiscoverValidatesBoundary(t *testing.T) {
	t.Parallel()

	server := netip.MustParseAddrPort("203.0.113.7:3478")
	transport := newFakeDiscoveryTransport()
	discovery, err := newDiscovery(transport, 25*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("newDiscovery() error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name     string
		ctx      context.Context
		scope    uint64
		servers  []netip.AddrPort
		expected error
	}{
		{name: "cancelled", ctx: cancelled, scope: 1, servers: []netip.AddrPort{server}, expected: context.Canceled},
		{name: "zero scope", ctx: t.Context(), servers: []netip.AddrPort{server}, expected: ErrInvalidScope},
		{name: "no servers", ctx: t.Context(), scope: 1, expected: ErrInvalidSTUNServers},
		{name: "duplicate server", ctx: t.Context(), scope: 1, servers: []netip.AddrPort{server, server}, expected: ErrInvalidSTUNServers},
		{name: "unsafe server", ctx: t.Context(), scope: 1, servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")}, expected: ErrInvalidSTUNServers},
		{name: "too many servers", ctx: t.Context(), scope: 1, servers: testSTUNServers(maxSTUNServers + 1), expected: ErrInvalidSTUNServers},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := discovery.Discover(test.ctx, test.scope, test.servers)
			if !errors.Is(err, test.expected) {
				t.Fatalf("Discover() error = %v, want %v", err, test.expected)
			}
		})
	}
}

func TestDiscoveryDiscoverRequiresOpenSocket(t *testing.T) {
	t.Parallel()

	transport := newFakeDiscoveryTransport()
	transport.socket = Socket{}
	discovery, err := newDiscovery(transport, 25*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("newDiscovery() error = %v", err)
	}
	server := netip.MustParseAddrPort("203.0.113.8:3478")

	_, err = discovery.Discover(t.Context(), 11, []netip.AddrPort{server})
	if !errors.Is(err, ErrTransportClosed) {
		t.Fatalf("Discover() error = %v, want ErrTransportClosed", err)
	}
}

type fakeDiscoveryTransport struct {
	mu             sync.Mutex
	socket         Socket
	handler        DatagramHandler
	mapped         map[netip.AddrPort]netip.AddrPort
	responseSource netip.AddrPort
	rebindOnSend   bool
	sends          int
}

var _ DatagramTransport = (*fakeDiscoveryTransport)(nil)

func newFakeDiscoveryTransport() *fakeDiscoveryTransport {
	return &fakeDiscoveryTransport{
		socket: Socket{
			Port:       41641,
			Generation: 1,
		},
		mapped: make(map[netip.AddrPort]netip.AddrPort),
	}
}

func (t *fakeDiscoveryTransport) Socket() Socket {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.socket
}

func (t *fakeDiscoveryTransport) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (Socket, error) {
	t.mu.Lock()
	t.sends++
	if t.rebindOnSend {
		t.socket.Generation++
		t.rebindOnSend = false
	}
	socket := t.socket
	mapped := t.mapped[destination]
	source := t.responseSource
	if !source.IsValid() {
		source = destination
	}
	handler := t.handler
	t.mu.Unlock()

	if mapped.IsValid() && handler != nil && len(packet) >= 20 {
		var transactionID compatstun.TransactionID
		copy(transactionID[:], packet[8:20])
		handler.HandleDatagram(testBindingResponse(transactionID, mapped), source, socket)
	}

	return socket, nil
}

func (t *fakeDiscoveryTransport) sendCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.sends
}

func testBindingResponse(
	transactionID compatstun.TransactionID,
	address netip.AddrPort,
) []byte {
	const cookie = 0x2112a442

	addressBytes := address.Addr().AsSlice()
	family := byte(1)
	if address.Addr().Is6() {
		family = 2
	}
	value := make([]byte, 4+len(addressBytes))
	value[1] = family
	binary.BigEndian.PutUint16(value[2:4], address.Port()^uint16(cookie>>16))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], cookie)
	copy(mask[4:], transactionID[:])
	for index := range addressBytes {
		value[4+index] = addressBytes[index] ^ mask[index]
	}

	packet := make([]byte, 20, 24+len(value))
	binary.BigEndian.PutUint16(packet[0:2], 0x0101)
	binary.BigEndian.PutUint16(packet[2:4], uint16(4+len(value)))
	binary.BigEndian.PutUint32(packet[4:8], cookie)
	copy(packet[8:20], transactionID[:])
	packet = binary.BigEndian.AppendUint16(packet, 0x0020)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(value)))
	packet = append(packet, value...)

	return packet
}

func testSTUNServers(count int) []netip.AddrPort {
	servers := make([]netip.AddrPort, 0, count)
	for index := range count {
		address := netip.AddrFrom4([4]byte{203, 0, 113, byte(index + 1)})
		servers = append(servers, netip.AddrPortFrom(address, 3478))
	}

	return servers
}
