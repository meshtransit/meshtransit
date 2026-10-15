package mtcp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// recordingHandler records what established sessions receive and lets a
// test push messages to them.
type recordingHandler struct {
	mu       sync.Mutex
	sessions []*Session
	received []sharedmtcp.MessageType
	opened   atomic.Int32
}

type recordingConversation struct {
	handler *recordingHandler
	session *Session
}

func (handler *recordingHandler) Open(session *Session) Conversation {
	handler.mu.Lock()
	handler.sessions = append(handler.sessions, session)
	handler.mu.Unlock()
	handler.opened.Add(1)
	return recordingConversation{handler: handler, session: session}
}

func (conversation recordingConversation) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (conversation recordingConversation) Receive(_ context.Context, t sharedmtcp.MessageType, _ proto.Message) error {
	conversation.handler.mu.Lock()
	defer conversation.handler.mu.Unlock()
	conversation.handler.received = append(conversation.handler.received, t)
	if t == sharedmtcp.MessageLogout {
		return Violation(mtcpv1.Error_NOT_PERMITTED, "logout refused")
	}
	return nil
}

func (handler *recordingHandler) last() *Session {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.sessions[len(handler.sessions)-1]
}

type fixture struct {
	t       *testing.T
	server  *Server
	http    *httptest.Server
	control key.ControlPrivate
	handler *recordingHandler
}

func newFixture(t *testing.T, mutate func(*Options)) *fixture {
	t.Helper()
	control, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := clientip.NewResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := &recordingHandler{}
	options := Options{
		Keys:      []ControlKey{{Private: control, NotAfter: time.Now().Add(365 * 24 * time.Hour)}},
		ClientIPs: resolver, Handler: handler, Logger: slog.New(slog.DiscardHandler), Metrics: NewMetrics(),
		Capabilities: []string{"map.zstd", "disco.v2"},
	}
	if mutate != nil {
		mutate(&options)
	}
	server, err := NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error("shutdown:", err)
		}
		httpServer.Close()
	})
	return &fixture{t: t, server: server, http: httpServer, control: control, handler: handler}
}

// client is a minimal node speaking MTCP over the HTTP upgrade.
type client struct {
	t       *testing.T
	conn    net.Conn
	reader  *sharedmtcp.RecordReader
	session *sharedmtcp.Session
	hello   *mtcpv1.ServerHello
	asm     *sharedmtcp.Assembler
}

type dialOptions struct {
	machine   key.MachinePrivate
	timestamp int64
	version   uint32
	keyID     string
}

// refusal is the status line and headers of a refused upgrade.
type refusal struct {
	StatusCode int
	Header     http.Header
}

func (f *fixture) dial(options dialOptions) (*client, *refusal, error) {
	f.t.Helper()
	if options.machine.IsZero() {
		options.machine, _ = key.NewMachinePrivate(nil)
	}
	if options.timestamp == 0 {
		options.timestamp = time.Now().UnixMilli()
	}
	if options.version == 0 {
		options.version = 1
	}
	if options.keyID == "" {
		options.keyID = f.control.Public().ID().String()
	}
	handshake, init, err := sharedmtcp.StartClient(sharedmtcp.ClientConfig{
		Machine: options.machine, Control: f.control.Public(),
		Hello: &mtcpv1.ClientHello{ProtocolVersion: options.version, TimestampMs: options.timestamp,
			Capabilities: []string{"map.zstd", "stats.path1"}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	conn, err := (&net.Dialer{}).DialContext(f.t.Context(), "tcp", strings.TrimPrefix(f.http.URL, "http://"))
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	request := "POST /mtcp/v1 HTTP/1.1\r\nHost: control.test\r\nUpgrade: mtcp/1\r\nConnection: Upgrade\r\n" +
		"MTCP-Key: " + options.keyID + "\r\nMTCP-Handshake: " + base64.RawURLEncoding.EncodeToString(init) +
		"\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		f.t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffered := bufio.NewReader(conn)
	response, err := http.ReadResponse(buffered, nil)
	if err != nil {
		return nil, nil, err
	}
	_ = response.Body.Close() // an upgrade or a refusal carries no body the test reads
	if response.StatusCode != http.StatusSwitchingProtocols {
		return nil, &refusal{StatusCode: response.StatusCode, Header: response.Header}, nil
	}
	body, err := base64.RawURLEncoding.DecodeString(response.Header.Get(sharedmtcp.HeaderHandshake))
	if err != nil {
		f.t.Fatal(err)
	}
	session, hello, err := handshake.Finish(body)
	if err != nil {
		f.t.Fatal(err)
	}
	return &client{t: f.t, conn: conn, reader: sharedmtcp.NewRecordReader(buffered), session: session, hello: hello,
		asm: sharedmtcp.NewAssembler(sharedmtcp.CoreToNode)}, nil, nil
}

func (c *client) send(t sharedmtcp.MessageType, message proto.Message) {
	c.t.Helper()
	fragments, err := sharedmtcp.EncodeMessage(t, message, sharedmtcp.NodeToCore, sharedmtcp.EncodeOptions{})
	if err != nil {
		c.t.Fatal(err)
	}
	for _, fragment := range fragments {
		sealed, _ := c.session.Seal(nil, fragment)
		record, _ := sharedmtcp.AppendRecord(nil, sharedmtcp.RecordTransport, sealed)
		if _, err := c.conn.Write(record); err != nil {
			c.t.Fatal(err)
		}
	}
}

func (c *client) receive() (sharedmtcp.MessageType, proto.Message, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		recordType, body, err := c.reader.Next()
		if err != nil {
			return 0, nil, err
		}
		if recordType != sharedmtcp.RecordTransport {
			return 0, nil, errors.New("unexpected record")
		}
		fragment, err := c.session.Open(nil, body)
		if err != nil {
			return 0, nil, err
		}
		t, payload, complete, err := c.asm.Add(fragment)
		if err != nil {
			return 0, nil, err
		}
		if complete {
			message, err := sharedmtcp.DecodeMessage(t, payload)
			return t, message, err
		}
	}
}

func (c *client) expect(want sharedmtcp.MessageType) proto.Message {
	c.t.Helper()
	for {
		t, message, err := c.receive()
		if err != nil {
			c.t.Fatalf("waiting for %#x: %v", uint8(want), err)
		}
		if t == want {
			return message
		}
		if t != sharedmtcp.MessagePing {
			c.t.Fatalf("got %#x, want %#x", uint8(t), uint8(want))
		}
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestKeyDocument(t *testing.T) {
	f := newFixture(t, nil)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.http.URL+sharedmtcp.KeyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var document struct {
		Version int `json:"version"`
		Keys    []struct {
			Key         key.ControlPublic `json:"key"`
			NotAfter    time.Time         `json:"not_after"`
			Fingerprint string            `json:"fingerprint"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document.Version != 1 || len(document.Keys) != 1 || document.Keys[0].Key != f.control.Public() ||
		document.Keys[0].Fingerprint != sharedmtcp.ControlFingerprint(f.control.Public()) ||
		response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("key document = %+v", document)
	}
}

func TestSessionEstablishesOnFirstRecordAndAnswersPing(t *testing.T) {
	f := newFixture(t, nil)
	c, response, err := f.dial(dialOptions{})
	if err != nil || c == nil {
		t.Fatalf("dial: %v %v", response, err)
	}
	if got := c.hello.GetCapabilities(); len(got) != 1 || got[0] != "map.zstd" {
		t.Fatalf("negotiated capabilities %v", got)
	}
	if f.handler.opened.Load() != 0 {
		t.Fatal("a session was opened before its first TRANSPORT record")
	}
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{Nonce: []byte("n1")})
	if pong := c.expect(sharedmtcp.MessagePong).(*mtcpv1.Pong); string(pong.GetNonce()) != "n1" {
		t.Fatalf("pong nonce %q", pong.GetNonce())
	}
	waitFor(t, func() bool { return f.handler.opened.Load() == 1 })
	if err := f.handler.last().Send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_ACTIVE}); err != nil {
		t.Fatal(err)
	}
	c.expect(sharedmtcp.MessageLifecycle)
	c.send(sharedmtcp.MessageHealthReport, &mtcpv1.HealthReport{})
	waitFor(t, func() bool {
		f.handler.mu.Lock()
		defer f.handler.mu.Unlock()
		return len(f.handler.received) == 1 && f.handler.received[0] == sharedmtcp.MessageHealthReport
	})
	// A conversation's protocol error ends the session with that Error.
	c.send(sharedmtcp.MessageLogout, &mtcpv1.Logout{})
	if failure := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error); failure.GetCode() != mtcpv1.Error_NOT_PERMITTED ||
		!failure.GetFatal() {
		t.Fatalf("error = %+v", failure)
	}
}

func TestNewerSessionReplacesOlder(t *testing.T) {
	f := newFixture(t, nil)
	machine, _ := key.NewMachinePrivate(nil)
	// Distinct timestamps: two hellos in one millisecond are a replay.
	now := time.Now().UnixMilli()
	first, _, err := f.dial(dialOptions{machine: machine, timestamp: now})
	if first == nil {
		t.Fatalf("first dial failed: %v", err)
	}
	first.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	first.expect(sharedmtcp.MessagePong)
	second, _, err := f.dial(dialOptions{machine: machine, timestamp: now + 1})
	if second == nil {
		t.Fatalf("second dial failed: %v", err)
	}
	second.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	second.expect(sharedmtcp.MessagePong)
	if failure := first.expect(sharedmtcp.MessageError).(*mtcpv1.Error); failure.GetCode() != mtcpv1.Error_SESSION_REPLACED {
		t.Fatalf("old session got %+v", failure)
	}
	if _, _, err := first.receive(); err == nil {
		t.Fatal("replaced session stayed open")
	}
}

func TestHandshakePolicy(t *testing.T) {
	f := newFixture(t, nil)
	machine, _ := key.NewMachinePrivate(nil)
	now := time.Now().UnixMilli()
	if c, _, _ := f.dial(dialOptions{machine: machine, timestamp: now}); c == nil {
		t.Fatal("first handshake refused")
	}
	if c, response, err := f.dial(dialOptions{machine: machine, timestamp: now}); c != nil || (err == nil && response != nil) {
		t.Fatal("replayed ClientHello timestamp got an answer")
	}
	if c, _, _ := f.dial(dialOptions{timestamp: time.Now().Add(-11 * time.Minute).UnixMilli()}); c != nil {
		t.Fatal("stale timestamp accepted")
	}
	if _, response, _ := f.dial(dialOptions{keyID: "0011223344556677"}); response == nil ||
		response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("unknown key ID answered %v", response)
	}
	c, _, _ := f.dial(dialOptions{version: 2})
	if c == nil || c.hello.GetReject() != mtcpv1.ServerHello_VERSION_UNSUPPORTED {
		t.Fatal("unsupported version was not rejected in ServerHello")
	}
	for name, header := range map[string]string{
		"no upgrade": "POST /mtcp/v1 HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
		"bad base64": "POST /mtcp/v1 HTTP/1.1\r\nHost: x\r\nUpgrade: mtcp/1\r\nConnection: Upgrade\r\nMTCP-Key: " +
			f.control.Public().ID().String() + "\r\nMTCP-Handshake: ***\r\nContent-Length: 0\r\n\r\n",
	} {
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(f.http.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(conn, header)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err == nil {
			_ = response.Body.Close()
		}
		if err != nil || response.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %v %v", name, response, err)
		}
		_ = conn.Close()
	}
}

func TestSessionMustStartWithPingOrRegister(t *testing.T) {
	f := newFixture(t, nil)
	c, _, _ := f.dial(dialOptions{})
	c.send(sharedmtcp.MessageMapAck, &mtcpv1.MapAck{})
	if _, _, err := c.receive(); err == nil {
		t.Fatal("session survived a first message other than Ping or RegisterRequest")
	}
	if f.handler.opened.Load() != 0 {
		t.Fatal("unestablished session reached the application")
	}
}

func TestAdmissionShedsBeforeCryptography(t *testing.T) {
	f := newFixture(t, nil)
	f.server.admission = newAdmission(1, 2, 32, time.Now)
	var shed bool
	for range 4 {
		if _, response, _ := f.dial(dialOptions{}); response != nil && response.StatusCode == http.StatusServiceUnavailable {
			shed = response.Header.Get("Retry-After") != ""
		}
	}
	if !shed {
		t.Fatal("a burst over the source rate was not shed with Retry-After")
	}
}

func TestUnprovenSessionsCountAgainstTheirSource(t *testing.T) {
	f := newFixture(t, nil)
	// A generous rate, so only the unauthenticated count can refuse.
	f.server.admission = newAdmission(1000, 1000, 2, time.Now)
	for range 2 {
		c, response, err := f.dial(dialOptions{})
		if err != nil || c == nil {
			t.Fatalf("dial: %v %v", response, err)
		}
		c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
		c.expect(sharedmtcp.MessagePong)
	}
	// Both sessions are established but serve no Device: the source is full.
	if _, response, _ := f.dial(dialOptions{}); response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a third unproven connection from one source was admitted: %+v", response)
	}
	// Once a session proves a Device it no longer counts.
	waitFor(t, func() bool { return f.handler.opened.Load() == 2 })
	f.handler.last().proveDevice()
	if c, response, err := f.dial(dialOptions{}); err != nil || c == nil {
		t.Fatalf("dial after a session proved a Device: %v %v", response, err)
	}
}

func TestUnprovenSessionClosesAtItsLimit(t *testing.T) {
	f := newFixture(t, func(options *Options) { options.UnprovenLimit = 200 * time.Millisecond })
	unproven, _, _ := f.dial(dialOptions{})
	unproven.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	unproven.expect(sharedmtcp.MessagePong)
	proven, _, _ := f.dial(dialOptions{})
	proven.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	proven.expect(sharedmtcp.MessagePong)
	waitFor(t, func() bool { return f.handler.opened.Load() == 2 })
	f.handler.last().proveDevice()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, _, err := unproven.receive(); err != nil {
			break // Core closed the session that proved no Device
		}
		if time.Now().After(deadline) {
			t.Fatal("an unproven session stayed open past its limit")
		}
	}
	// The limit firing for the proven session closes nothing.
	f.handler.last().closeUnproven()
	proven.send(sharedmtcp.MessagePing, &mtcpv1.Ping{Nonce: []byte("still")})
	if pong := proven.expect(sharedmtcp.MessagePong).(*mtcpv1.Pong); string(pong.GetNonce()) != "still" {
		t.Fatalf("pong nonce %q", pong.GetNonce())
	}
}

// pendingFrom reads the unauthenticated count of address's source.
func (a *admission) pendingFrom(address netip.Addr) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if state, found := a.sources[sourceKey(address)]; found {
		return state.pending
	}
	return 0
}

func TestUnprovenSessionsReturnTheirSourceCountOnEveryEnd(t *testing.T) {
	f := newFixture(t, nil)
	f.server.admission = newAdmission(1000, 1000, 8, time.Now)
	loopback := netip.MustParseAddr("127.0.0.1")
	pending := func(want int) {
		t.Helper()
		waitFor(t, func() bool { return f.server.admission.pendingFrom(loopback) == want })
	}
	// A node that hangs up before proving a Device.
	closed, _, _ := f.dial(dialOptions{})
	closed.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	closed.expect(sharedmtcp.MessagePong)
	pending(1)
	_ = closed.conn.Close()
	pending(0)
	// A session replaced by a newer one of the same machine.
	machine, err := key.NewMachinePrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		c, response, err := f.dial(dialOptions{machine: machine})
		if err != nil || c == nil {
			t.Fatalf("dial: %v %v", response, err)
		}
		c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
		c.expect(sharedmtcp.MessagePong)
	}
	pending(1)
	// The remaining session proves a Device.
	waitFor(t, func() bool { return f.handler.opened.Load() == 3 })
	f.handler.last().proveDevice()
	pending(0)
}

func TestIdleSessionCloses(t *testing.T) {
	f := newFixture(t, func(options *Options) {
		options.Keepalive, options.IdleTimeout = 50*time.Millisecond, 200*time.Millisecond
	})
	c, _, _ := f.dial(dialOptions{})
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expect(sharedmtcp.MessagePong)
	waitFor(t, func() bool { return f.handler.opened.Load() == 1 })
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, _, err := c.receive(); err != nil {
			break // Core closed the silent session
		}
		if time.Now().After(deadline) {
			t.Fatal("idle session stayed open")
		}
	}
}

func TestWebSocketFallback(t *testing.T) {
	f := newFixture(t, nil)
	machine, _ := key.NewMachinePrivate(nil)
	handshake, init, _ := sharedmtcp.StartClient(sharedmtcp.ClientConfig{Machine: machine, Control: f.control.Public(),
		Hello: &mtcpv1.ClientHello{ProtocolVersion: 1, TimestampMs: time.Now().UnixMilli()}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	header := http.Header{}
	header.Set(sharedmtcp.HeaderKey, f.control.Public().ID().String())
	conn, response, err := websocket.Dial(ctx, strings.Replace(f.http.URL, "http", "ws", 1)+sharedmtcp.WebSocketPath,
		&websocket.DialOptions{Subprotocols: []string{sharedmtcp.WebSocketProtocol}, HTTPHeader: header})
	if response != nil && response.Body != nil {
		_ = response.Body.Close() // the library drains a refusal; an upgrade has no body
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	message, _ := sharedmtcp.AppendMessageRecord(nil, sharedmtcp.RecordInit, init)
	if err := conn.Write(ctx, websocket.MessageBinary, message); err != nil {
		t.Fatal(err)
	}
	_, reply, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recordType, body, err := sharedmtcp.ParseMessageRecord(reply)
	if err != nil || recordType != sharedmtcp.RecordResponse {
		t.Fatalf("RESPONSE: %v %v", recordType, err)
	}
	session, _, err := handshake.Finish(body)
	if err != nil {
		t.Fatal(err)
	}
	fragments, _ := sharedmtcp.EncodeMessage(sharedmtcp.MessagePing, &mtcpv1.Ping{Nonce: []byte("ws")},
		sharedmtcp.NodeToCore, sharedmtcp.EncodeOptions{})
	sealed, _ := session.Seal(nil, fragments[0])
	message, _ = sharedmtcp.AppendMessageRecord(nil, sharedmtcp.RecordTransport, sealed)
	if err := conn.Write(ctx, websocket.MessageBinary, message); err != nil {
		t.Fatal(err)
	}
	_, reply, err = conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ = sharedmtcp.ParseMessageRecord(reply)
	fragment, err := session.Open(nil, body)
	if err != nil || sharedmtcp.MessageType(fragment[0]) != sharedmtcp.MessagePong {
		t.Fatalf("pong over WebSocket: %v", err)
	}
}

// replayGuard refuses timestamps it has seen, as the durable store would for
// an INIT replayed to another replica.
type replayGuard struct {
	mu   sync.Mutex
	seen map[[32]byte]int64
}

func (guard *replayGuard) AcceptTimestamp(_ context.Context, machine [32]byte, _ []byte, timestamp int64) (bool, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if last, found := guard.seen[machine]; found && timestamp <= last {
		return false, nil
	}
	guard.seen[machine] = timestamp
	return true, nil
}

func TestDurableGuardRefusesReplayOnAnotherReplica(t *testing.T) {
	guard := &replayGuard{seen: map[[32]byte]int64{}}
	first := newFixture(t, func(options *Options) { options.Guard = guard })
	machine, _ := key.NewMachinePrivate(nil)
	timestamp := time.Now().UnixMilli()
	if c, _, _ := first.dial(dialOptions{machine: machine, timestamp: timestamp}); c == nil {
		t.Fatal("first handshake refused")
	}
	// A second replica shares the guard but not the first one's cache.
	second := newFixture(t, func(options *Options) {
		options.Guard = guard
		options.Keys = []ControlKey{{Private: first.control, NotAfter: time.Now().Add(time.Hour)}}
	})
	second.control = first.control
	if c, _, _ := second.dial(dialOptions{machine: machine, timestamp: timestamp}); c != nil {
		t.Fatal("replayed timestamp accepted by another replica")
	}
}

func TestKeyDocumentListsTheNextKeyDuringRotation(t *testing.T) {
	next, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(options *Options) {
		options.Keys = append(options.Keys, ControlKey{Private: next, NotAfter: time.Now().Add(2 * 365 * 24 * time.Hour)})
	})
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.http.URL+sharedmtcp.KeyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var document struct {
		Keys []struct {
			Key key.ControlPublic `json:"key"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if len(document.Keys) != 2 || document.Keys[0].Key != f.control.Public() || document.Keys[1].Key != next.Public() {
		t.Fatalf("key document = %+v, want current then next", document)
	}
}
