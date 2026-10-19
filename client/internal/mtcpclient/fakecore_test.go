package mtcpclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// fakeCore is a minimal MTCP server for client tests: it serves the key
// document, the upgrade and the WebSocket fallback, and hands every
// session to serve.
type fakeCore struct {
	t      *testing.T
	server *httptest.Server

	mu         sync.Mutex
	control    key.ControlPrivate
	refuseUp   bool // answer the upgrade with 404, as a proxy that drops Upgrade
	documented []key.ControlPublic
	serve      func(*coreSession)
	hello      []*mtcpv1.ClientHello
	modes      []string
	// extra are capabilities offered beyond the default ones.
	extra []string
}

// set changes the fake Core under its lock.
func (core *fakeCore) set(change func(core *fakeCore)) {
	core.mu.Lock()
	defer core.mu.Unlock()
	change(core)
}

func (core *fakeCore) controlKey() key.ControlPrivate {
	core.mu.Lock()
	defer core.mu.Unlock()
	return core.control
}

// coreSession is Core's side of one session in a test.
type coreSession struct {
	t         *testing.T
	conn      recordConn
	noise     *sharedmtcp.Session
	hello     *mtcpv1.ClientHello
	machine   key.MachinePublic
	assembler *sharedmtcp.Assembler
	hash      [32]byte
	control   key.ControlPrivate
}

func newFakeCore(t *testing.T) *fakeCore {
	t.Helper()
	control, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	core := &fakeCore{
		t: t, control: control, documented: []key.ControlPublic{control.Public()},
		serve: answerPings,
	}
	core.server = httptest.NewTLSServer(http.HandlerFunc(core.handle))
	t.Cleanup(core.server.Close)
	return core
}

// client returns an MTCP client that trusts the fake Core's certificate
// and accepts its port.
func (core *fakeCore) client() *Client {
	client := New()
	pool := x509.NewCertPool()
	pool.AddCert(core.server.Certificate())
	client.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	transport, _ := core.server.Client().Transport.(*http.Transport)
	transport = transport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	listener := core.server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener)
	}
	client.dialTLS = func(ctx context.Context, _ string, config *tls.Config) (net.Conn, error) {
		return (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", listener)
	}
	client.httpClient = &http.Client{
		Transport: transport, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	parsed, _ := url.Parse(core.server.URL)
	client.port = parsed.Port()
	return client
}

// origin is the control URL with the host name the certificate names.
func (core *fakeCore) origin() string {
	parsed, _ := url.Parse(core.server.URL)
	return "https://example.com:" + parsed.Port()
}

func (core *fakeCore) handle(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case sharedmtcp.KeyPath:
		type entry struct {
			Key      key.ControlPublic `json:"key"`
			NotAfter time.Time         `json:"not_after"`
		}
		document := struct {
			Version int     `json:"version"`
			Keys    []entry `json:"keys"`
		}{Version: 1}
		core.mu.Lock()
		documentedKeys := append([]key.ControlPublic(nil), core.documented...)
		core.mu.Unlock()
		for _, documented := range documentedKeys {
			document.Keys = append(document.Keys, entry{Key: documented, NotAfter: time.Now().Add(time.Hour)})
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(document)
	case sharedmtcp.UpgradePath:
		core.mu.Lock()
		refuse := core.refuseUp
		core.mu.Unlock()
		if refuse {
			http.NotFound(response, request)
			return
		}
		core.upgrade(response, request)
	case sharedmtcp.WebSocketPath:
		core.webSocket(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (core *fakeCore) knows(keyID string) bool {
	id := core.controlKey().Public().ID()
	return keyID == hex.EncodeToString(id[:])
}

func (core *fakeCore) upgrade(response http.ResponseWriter, request *http.Request) {
	if !core.knows(request.Header.Get(sharedmtcp.HeaderKey)) {
		http.Error(response, "unknown key", http.StatusMisdirectedRequest)
		return
	}
	init, err := base64.RawURLEncoding.DecodeString(request.Header.Get(sharedmtcp.HeaderHandshake))
	if err != nil {
		http.Error(response, "bad handshake", http.StatusBadRequest)
		return
	}
	server, err := sharedmtcp.ReadInit(core.controlKey(), init, nil)
	if err != nil {
		http.Error(response, "bad handshake", http.StatusBadRequest)
		return
	}
	noise, body, err := server.Respond(core.reply())
	if err != nil {
		http.Error(response, "respond", http.StatusInternalServerError)
		return
	}
	hijacker, _ := response.(http.Hijacker)
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + sharedmtcp.UpgradeToken +
		"\r\nConnection: Upgrade\r\n" + sharedmtcp.HeaderHandshake + ": " +
		base64.RawURLEncoding.EncodeToString(body) + "\r\n\r\n")
	_ = buffered.Flush()
	core.run("upgrade", &streamConn{conn: conn, reader: sharedmtcp.NewRecordReader(bufio.NewReader(conn))},
		noise, server)
}

func (core *fakeCore) webSocket(response http.ResponseWriter, request *http.Request) {
	if !core.knows(request.Header.Get(sharedmtcp.HeaderKey)) {
		http.Error(response, "unknown key", http.StatusMisdirectedRequest)
		return
	}
	conn, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols: []string{sharedmtcp.WebSocketProtocol},
	})
	if err != nil {
		return
	}
	transport := &webSocketConn{conn: conn}
	recordType, init, err := transport.read(time.Now().Add(5 * time.Second))
	if err != nil || recordType != sharedmtcp.RecordInit {
		_ = transport.close()
		return
	}
	server, err := sharedmtcp.ReadInit(core.controlKey(), init, nil)
	if err != nil {
		_ = transport.close()
		return
	}
	noise, body, err := server.Respond(core.reply())
	if err != nil || transport.write(sharedmtcp.RecordResponse, body) != nil {
		_ = transport.close()
		return
	}
	core.run("websocket", transport, noise, server)
}

func (core *fakeCore) reply() *mtcpv1.ServerHello {
	core.mu.Lock()
	capabilities := append([]string{"map.zstd", "stats.path1"}, core.extra...)
	core.mu.Unlock()
	return &mtcpv1.ServerHello{
		ProtocolVersion: 1, SessionId: make([]byte, 16), ServerTimeMs: time.Now().UnixMilli(),
		Capabilities: capabilities, Limits: &mtcpv1.Limits{KeepaliveS: 25, IdleTimeoutS: 75, MaxUnackedMap: 8},
	}
}

func (core *fakeCore) run(mode string, conn recordConn, noise *sharedmtcp.Session, server *sharedmtcp.ServerHandshake) {
	core.mu.Lock()
	core.hello = append(core.hello, server.Hello())
	core.modes = append(core.modes, mode)
	serve := core.serve
	core.mu.Unlock()
	session := &coreSession{
		t: core.t, conn: conn, noise: noise, hello: server.Hello(), machine: server.Machine(),
		assembler: sharedmtcp.NewAssembler(sharedmtcp.NodeToCore), hash: noise.HandshakeHash(), control: core.control,
	}
	defer func() { _ = conn.close() }()
	serve(session)
}

func (core *fakeCore) sessions() ([]*mtcpv1.ClientHello, []string) {
	core.mu.Lock()
	defer core.mu.Unlock()
	return append([]*mtcpv1.ClientHello(nil), core.hello...), append([]string(nil), core.modes...)
}

func (s *coreSession) send(t sharedmtcp.MessageType, message proto.Message) error {
	fragments, err := sharedmtcp.EncodeMessage(t, message, sharedmtcp.CoreToNode, sharedmtcp.EncodeOptions{})
	if err != nil {
		return err
	}
	for _, fragment := range fragments {
		sealed, err := s.noise.Seal(nil, fragment)
		if err != nil {
			return err
		}
		if err := s.conn.write(sharedmtcp.RecordTransport, sealed); err != nil {
			return err
		}
	}
	return nil
}

func (s *coreSession) receive(timeout time.Duration) (sharedmtcp.MessageType, proto.Message, error) {
	for {
		recordType, body, err := s.conn.read(time.Now().Add(timeout))
		if err != nil {
			return 0, nil, err
		}
		if recordType != sharedmtcp.RecordTransport {
			return 0, nil, sharedmtcp.ErrMalformed
		}
		fragment, err := s.noise.Open(nil, body)
		if err != nil {
			return 0, nil, err
		}
		t, payload, complete, err := s.assembler.Add(fragment)
		if err != nil {
			return 0, nil, err
		}
		if complete {
			message, err := sharedmtcp.DecodeMessage(t, payload)
			return t, message, err
		}
	}
}

// answerPings answers Pings until the node goes away.
func answerPings(s *coreSession) {
	for {
		_, message, err := s.receive(5 * time.Second)
		if err != nil {
			return
		}
		if ping, ok := message.(*mtcpv1.Ping); ok {
			if s.send(sharedmtcp.MessagePong, &mtcpv1.Pong{Nonce: ping.GetNonce()}) != nil {
				return
			}
		}
	}
}
