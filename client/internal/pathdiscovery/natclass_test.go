package pathdiscovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/netcheck"
	"meshtransit.net/test/natlab"
)

var labProber = netcheck.Config{ProbeTimeout: 100 * time.Millisecond, Retransmit: 20 * time.Millisecond, Budget: 2 * time.Second}

// labTransport runs the shared-socket contract over a natlab socket: one read
// loop hands every datagram to the joined handlers, as the packet engine does.
type labTransport struct {
	conn       *natlab.Conn
	mu         sync.Mutex
	generation uint64
	handler    DatagramHandler
	done       chan struct{}
}

func newLabTransport(t *testing.T, conn *natlab.Conn) *labTransport {
	t.Helper()
	tr := &labTransport{conn: conn, generation: 1, done: make(chan struct{})}
	go tr.read()
	t.Cleanup(func() {
		_ = conn.Close()
		<-tr.done
	})

	return tr
}

func (t *labTransport) setHandler(h DatagramHandler) {
	t.mu.Lock()
	t.handler = h
	t.mu.Unlock()
}

func (t *labTransport) Socket() Socket {
	t.mu.Lock()
	defer t.mu.Unlock()

	return Socket{Port: t.conn.LocalAddrPort().Port(), Generation: t.generation}
}

func (t *labTransport) SendDatagram(packet []byte, destination netip.AddrPort) (Socket, error) {
	if _, err := t.conn.WriteToUDPAddrPort(packet, destination); err != nil {
		return Socket{}, err
	}

	return t.Socket(), nil
}

func (t *labTransport) read() {
	defer close(t.done)
	buf := make([]byte, 2048)
	for {
		n, source, err := t.conn.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		t.mu.Lock()
		handler := t.handler
		t.mu.Unlock()
		if handler != nil && handler.MatchesDatagram(buf[:n]) {
			handler.HandleDatagram(buf[:n], source, t.Socket())
		}
	}
}

func TestNATClassifierSharesSocketWithDiscovery(t *testing.T) {
	t.Parallel()
	lab, err := natlab.NewLab(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	host, err := lab.AddNode("node", natlab.PortRestrictedCone)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := host.Listen(41641)
	if err != nil {
		t.Fatal(err)
	}
	transport := newLabTransport(t, conn)
	discovery, err := NewDiscovery(transport)
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := NewNATClassifier(transport, labProber)
	if err != nil {
		t.Fatal(err)
	}
	transport.setHandler(JoinHandlers(discovery, classifier, nil))

	var wg sync.WaitGroup
	var discovered DiscoveryResult
	var discoverErr error
	wg.Go(func() { discovered, discoverErr = discovery.Discover(context.Background(), 1, lab.STUN()) })
	report, err := classifier.Classify(context.Background(), lab.STUN(), conn.LocalAddrPorts())
	wg.Wait()
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if discoverErr != nil || discovered.ReachableServers != len(lab.STUN()) {
		t.Fatalf("discovery alongside classification: %+v, %v", discovered, discoverErr)
	}
	want := disco.NATInfo{
		Mapping:    disco.MappingEndpointIndependent,
		Filtering:  disco.FilteringAddressAndPortDependent,
		Allocation: disco.AllocationPreserving,
	}
	if report.Report.NAT != want || report.Socket != transport.Socket() {
		t.Fatalf("report = %+v, want %+v", report, want)
	}
}

// rebindingTransport replaces its socket generation after the first send.
type rebindingTransport struct {
	mu     sync.Mutex
	socket Socket
}

func (t *rebindingTransport) Socket() Socket {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.socket
}

func (t *rebindingTransport) SendDatagram([]byte, netip.AddrPort) (Socket, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.socket.Generation++

	return t.socket, nil
}

func TestNATClassifierRejectsSocketChange(t *testing.T) {
	t.Parallel()
	transport := &rebindingTransport{socket: Socket{Port: 41641, Generation: 1}}
	classifier, err := NewNATClassifier(transport, labProber)
	if err != nil {
		t.Fatal(err)
	}
	_, err = classifier.Classify(context.Background(), []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:3478")}, nil)
	if !errors.Is(err, netcheck.ErrNoResponse) && !errors.Is(err, ErrSocketChanged) {
		t.Fatalf("Classify error = %v", err)
	}
	closed := &rebindingTransport{}
	classifier, _ = NewNATClassifier(closed, labProber)
	if _, err := classifier.Classify(context.Background(), nil, nil); !errors.Is(err, ErrTransportClosed) {
		t.Fatalf("closed socket: %v", err)
	}
	if _, err := NewNATClassifier(nil, labProber); err == nil {
		t.Fatal("nil transport accepted")
	}
}

func TestNATServers(t *testing.T) {
	t.Parallel()
	servers := []RelayServer{
		{RegionID: 1, Endpoint: netip.MustParseAddrPort("[2001:db8::1]:3478")},
		{RegionID: 1, Endpoint: netip.MustParseAddrPort("192.0.2.1:3478")},
		{RegionID: 2, Endpoint: netip.MustParseAddrPort("192.0.2.1:3479")}, // same address
		{RegionID: 2, Endpoint: netip.MustParseAddrPort("192.0.2.2:3478")},
		{RegionID: 3, Endpoint: netip.MustParseAddrPort("192.0.2.3:3478")},
		{RegionID: 4, Endpoint: netip.MustParseAddrPort("192.0.2.4:3478")},
		{RegionID: 5, Endpoint: netip.MustParseAddrPort("192.0.2.5:3478")},
	}
	got := NATServers(servers)
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:3478"),
		netip.MustParseAddrPort("192.0.2.2:3478"),
		netip.MustParseAddrPort("192.0.2.3:3478"),
		netip.MustParseAddrPort("192.0.2.4:3478"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("NATServers = %v, want %v", got, want)
	}
	v6only := NATServers(servers[:1])
	if len(v6only) != 1 || !v6only[0].Addr().Is6() {
		t.Fatalf("IPv6-only = %v", v6only)
	}
	if NATServers(nil) == nil || len(NATServers(nil)) != 0 {
		t.Fatal("empty input")
	}
}

type recordingHandler struct {
	prefix byte
	seen   int
}

func (h *recordingHandler) MatchesDatagram(p []byte) bool { return len(p) > 0 && p[0] == h.prefix }

func (h *recordingHandler) HandleDatagram([]byte, netip.AddrPort, Socket) { h.seen++ }

func TestJoinHandlers(t *testing.T) {
	t.Parallel()
	a, b, c := &recordingHandler{prefix: 1}, &recordingHandler{prefix: 1}, &recordingHandler{prefix: 2}
	joined := JoinHandlers(a, nil, b, c)
	if !joined.MatchesDatagram([]byte{2}) || joined.MatchesDatagram([]byte{3}) {
		t.Fatal("MatchesDatagram")
	}
	joined.HandleDatagram([]byte{1}, netip.AddrPort{}, Socket{})
	joined.HandleDatagram([]byte{3}, netip.AddrPort{}, Socket{})
	if a.seen != 1 || b.seen != 1 || c.seen != 0 {
		t.Fatalf("deliveries a=%d b=%d c=%d", a.seen, b.seen, c.seen)
	}
}
