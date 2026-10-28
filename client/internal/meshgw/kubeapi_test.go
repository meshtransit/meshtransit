package meshgw

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/networkmap"
)

// recordingHandler keeps the forwarder's log records, with the attributes
// loggers derived from it add, for the tests.
type recordingHandler struct {
	log   *recordedLog
	attrs []slog.Attr
}

type recordedLog struct {
	mu      sync.Mutex
	records []slog.Record
}

func newRecordingHandler() *recordingHandler { return &recordingHandler{log: &recordedLog{}} }

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	record = record.Clone()
	record.AddAttrs(h.attrs...)
	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	h.log.records = append(h.log.records, record)
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &recordingHandler{log: h.log, attrs: append(append([]slog.Attr(nil), h.attrs...), attrs...)}
}

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// find returns the attributes of the first record with message.
func (h *recordingHandler) find(message string) (map[string]string, bool) {
	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	for _, record := range h.log.records {
		if record.Message != message {
			continue
		}
		attrs := map[string]string{}
		record.Attrs(func(attr slog.Attr) bool {
			attrs[attr.Key] = attr.Value.String()
			return true
		})
		return attrs, true
	}
	return nil, false
}

func (h *recordingHandler) waitFor(t *testing.T, message string) map[string]string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if attrs, ok := h.find(message); ok {
			return attrs
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q log record", message)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// echoBackend stands in for the API server: it echoes each connection to
// its end, then closes its side.
func echoBackend(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				request, _ := io.ReadAll(conn)
				_, _ = conn.Write(request)
			}()
		}
	}()
	return listener.Addr().String()
}

type forwarderTest struct {
	stacks    *Stacks
	wire      *wire
	clientNet *netstack.Net
	logs      *recordingHandler
	forwarder *KubeAPIForwarder
	stop      context.CancelFunc
	done      chan error
}

func startForwarder(t *testing.T, backend string, maxConnections int) *forwarderTest {
	t.Helper()
	stacks := newTestStacks(t)
	clientDevice, clientNet := newClient(t)
	w := newWire(t, clientDevice)
	w.attach(openTUN(t, stacks, gatewayConfig(gatewayAddr)))
	logs := newRecordingHandler()
	forwarder := &KubeAPIForwarder{
		Stacks:         stacks,
		Port:           443,
		Backend:        backend,
		MaxConnections: maxConnections,
		PeerAt: func(address netip.Addr) (daemon.PeerView, bool) {
			if address != clientAddr {
				return daemon.PeerView{}, false
			}
			return daemon.PeerView{
				DeviceID: "dev-laptop", Name: "laptop",
				Kubernetes: &networkmap.KubernetesAccess{OwnerRef: "01890f00-0000-7000-8000-000000000011", Grants: []networkmap.KubernetesGrant{
					{Group: "edit", ValidUntil: time.Now().Add(-time.Minute)},
					{Group: "view", ValidUntil: time.Now().Add(time.Hour)},
				}},
			}, true
		},
		Logger: slog.New(logs),
	}
	ctx, stop := context.WithCancel(t.Context())
	test := &forwarderTest{
		stacks: stacks, wire: w, clientNet: clientNet, logs: logs, forwarder: forwarder, stop: stop,
		done: make(chan error, 1),
	}
	go func() { test.done <- forwarder.Run(ctx) }()
	t.Cleanup(func() {
		stop()
		<-test.done
	})
	return test
}

func (f *forwarderTest) dial(t *testing.T, addr netip.Addr) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		conn, err := f.clientNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(addr, 443))
		cancel()
		if err == nil {
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatalf("SetDeadline() error = %v", err)
			}
			return conn
		}
		// The forwarder binds a moment after the stack starts.
		if time.Now().After(deadline) {
			t.Fatalf("Dial(%s) error = %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// kubectl's bytes reach the API server and back unchanged, through a
// half-close, and the log names the Device that connected.
func TestKubeAPIForwarderCarriesAConnection(t *testing.T) {
	t.Parallel()
	test := startForwarder(t, echoBackend(t), 16)
	conn := test.dial(t, gatewayAddr)
	defer func() { _ = conn.Close() }()

	sent := make([]byte, 128<<10)
	if _, err := rand.Read(sent); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	if _, err := conn.Write(sent); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := closeWrite(conn); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	received, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(received, sent) {
		t.Fatalf("got %d bytes back, want the %d sent", len(received), len(sent))
	}

	opened := test.logs.waitFor(t, "kube API connection opened")
	if opened["device_id"] != "dev-laptop" || opened["device_name"] != "laptop" || opened["source"] == "" ||
		opened["kubernetes_groups"] != "[view]" || opened["kubernetes_owner"] != "01890f00-0000-7000-8000-000000000011" {
		t.Fatalf("opened log = %v, want the laptop with its live group", opened)
	}
	closed := test.logs.waitFor(t, "kube API connection closed")
	if closed["device_id"] != "dev-laptop" || closed["bytes_to_api"] != "131072" || closed["bytes_from_api"] != "131072" {
		t.Fatalf("closed log = %v", closed)
	}
}

// When the map moves the gateway to new addresses, the forwarder listens
// on the new stack.
func TestKubeAPIForwarderFollowsTheStack(t *testing.T) {
	t.Parallel()
	test := startForwarder(t, echoBackend(t), 16)
	first := test.dial(t, gatewayAddr)
	_ = first.Close()

	moved := netip.MustParseAddr("100.64.0.11")
	test.wire.attach(openTUN(t, test.stacks, gatewayConfig(moved)))
	conn := test.dial(t, moved)
	defer func() { _ = conn.Close() }()
	roundTripHalfClosed(t, conn, "after the move")
}

// An API server that cannot be reached ends kubectl's connection at once.
func TestKubeAPIForwarderClosesWhenTheBackendFails(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	backend := listener.Addr().String()
	_ = listener.Close()
	test := startForwarder(t, backend, 16)
	conn := test.dial(t, gatewayAddr)
	defer func() { _ = conn.Close() }()
	if _, err := io.ReadAll(conn); err != nil && !errors.Is(err, io.EOF) && !isReset(err) {
		t.Fatalf("ReadAll() error = %v, want the connection closed", err)
	}
	attrs := test.logs.waitFor(t, "kube API server unreachable")
	if attrs["device_id"] != "dev-laptop" {
		t.Fatalf("unreachable log = %v", attrs)
	}
}

// Connections past the limit are refused, so a client cannot exhaust the
// pod.
func TestKubeAPIForwarderLimitsConnections(t *testing.T) {
	t.Parallel()
	test := startForwarder(t, echoBackend(t), 1)
	held := test.dial(t, gatewayAddr)
	defer func() { _ = held.Close() }()
	if _, err := held.Write([]byte("hold")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	test.logs.waitFor(t, "kube API connection opened")

	extra := test.dial(t, gatewayAddr)
	defer func() { _ = extra.Close() }()
	if _, err := io.ReadAll(extra); err != nil && !isReset(err) {
		t.Fatalf("ReadAll() past the limit error = %v, want it closed", err)
	}
	test.logs.waitFor(t, "kube API connection refused: too many open")
}

// Stopping the forwarder closes the connections it carries, so the gateway
// stops even under a long kubectl watch.
func TestKubeAPIForwarderStopsWithItsConnections(t *testing.T) {
	t.Parallel()
	test := startForwarder(t, echoBackend(t), 16)
	conn := test.dial(t, gatewayAddr)
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("watch")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	test.logs.waitFor(t, "kube API connection opened")
	test.stop()
	select {
	case err := <-test.done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		test.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return with a connection open")
	}
	if _, err := io.ReadAll(conn); err != nil && !isReset(err) {
		t.Fatalf("ReadAll() after the stop error = %v, want the connection closed", err)
	}
}

func roundTripHalfClosed(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := closeWrite(conn); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != message {
		t.Fatalf("ReadAll() = %q, %v; want %q", got, err, message)
	}
}

// isReset reports the text gonet gives a connection the other side reset.
func isReset(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Err != nil &&
		(opErr.Err.Error() == "connection reset by peer" || opErr.Err.Error() == "connection was reset")
}

func closeWrite(conn net.Conn) error {
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("the connection cannot half-close")
	}
	return half.CloseWrite()
}

// The forwarder reports listening once it takes connections on the stack's
// addresses, and stops reporting it when it stops.
func TestKubeAPIForwarderReportsListening(t *testing.T) {
	t.Parallel()
	test := startForwarder(t, echoBackend(t), 16)
	deadline := time.Now().Add(5 * time.Second)
	for !test.forwarder.Listening() {
		if time.Now().After(deadline) {
			t.Fatal("Listening() never became true")
		}
		time.Sleep(5 * time.Millisecond)
	}
	test.stop()
	if err := <-test.done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	test.done <- nil
	if test.forwarder.Listening() {
		t.Fatal("Listening() still true after Run returned")
	}
}

// A port another listener holds fails the bind: the forwarder is not
// listening, and binds once the port is free again.
func TestKubeAPIForwarderRetriesAFailedBind(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	_ = openTUN(t, stacks, gatewayConfig(gatewayAddr))
	current, _ := stacks.Current()
	squatter, err := current.Net.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort() error = %v", err)
	}
	logs := newRecordingHandler()
	forwarder := &KubeAPIForwarder{
		Stacks: stacks, Port: 443, Backend: echoBackend(t), MaxConnections: 4, Logger: slog.New(logs),
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- forwarder.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	logs.waitFor(t, "kube API listener failed")
	if forwarder.Listening() {
		t.Fatal("Listening() with the port taken")
	}
	_ = squatter.Close()
	deadline := time.Now().Add(10 * time.Second)
	for !forwarder.Listening() {
		if time.Now().After(deadline) {
			t.Fatal("the forwarder never bound after the port was freed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// addresslessConn is a connection whose peer reset it before the forwarder
// asked who it was: gonet then reports no remote address.
type addresslessConn struct{ net.Conn }

func (addresslessConn) RemoteAddr() net.Addr { return nil }

// A connection without a remote address is carried or refused like any
// other, never a panic that takes the gateway down.
func TestKubeAPIForwarderSurvivesAConnectionWithoutAnAddress(t *testing.T) {
	t.Parallel()
	logs := newRecordingHandler()
	forwarder := &KubeAPIForwarder{Backend: "127.0.0.1:1", MaxConnections: 4, Logger: slog.New(logs)}
	near, far := net.Pipe()
	defer func() { _ = far.Close() }()
	conn := addresslessConn{near}
	forwarder.forward(t.Context(), conn, conn.RemoteAddr())
	attrs := logs.waitFor(t, "kube API server unreachable")
	if attrs["source"] != "" || attrs["device_id"] != "" {
		t.Fatalf("unreachable log = %v, want no source", attrs)
	}
	if got := addressText(nil); got != "" {
		t.Fatalf("addressText(nil) = %q", got)
	}
}
