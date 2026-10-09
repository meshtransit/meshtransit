package stream_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/goleak"

	"meshtransit.net/relay/internal/server"
	"meshtransit.net/relay/internal/stream"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"relay.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type fixture struct {
	relay  *server.Server
	ln     *stream.Listener
	signer key.SigningPrivate
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, tune func(*stream.Config)) *fixture {
	t.Helper()
	relayKey, _ := key.NewRelayPrivate()
	signer, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{5}, 32))
	relay, err := server.New(server.Config{Key: relayKey, Keys: mtrp.NewStaticKeys(signer.Public())})
	if err != nil {
		t.Fatal(err)
	}
	cfg := stream.Config{
		Addr: "127.0.0.1:0", TLS: &tls.Config{Certificates: []tls.Certificate{testCert(t)}, MinVersion: tls.VersionTLS13},
		Handler: relay,
	}
	if tune != nil {
		tune(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := stream.Listen(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{relay: relay, ln: ln, signer: signer, cancel: cancel, done: make(chan error, 1)}
	go func() { f.done <- ln.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-f.done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after shutdown")
		}
	})
	return f
}

// transport sends and receives whole MTRP frames.
type transport interface {
	send(t *testing.T, frame []byte)
	recv(t *testing.T) []byte
	close()
}

type rawClient struct{ c *tls.Conn }

func dialRaw(t *testing.T, f *fixture) *rawClient {
	t.Helper()
	d := tls.Dialer{Config: &tls.Config{
		NextProtos: []string{stream.ALPNRaw}, MinVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // MTRP authenticates the relay with Noise, not TLS
	}}
	nc, err := d.DialContext(t.Context(), "tcp", f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, ok := nc.(*tls.Conn)
	if !ok {
		t.Fatal("not a TLS connection")
	}
	if c.ConnectionState().NegotiatedProtocol != stream.ALPNRaw {
		t.Fatalf("ALPN = %q", c.ConnectionState().NegotiatedProtocol)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawClient{c: c}
}

func (r *rawClient) send(t *testing.T, frame []byte) {
	t.Helper()
	b := binary.BigEndian.AppendUint16(nil, uint16(len(frame))) //nolint:gosec // test frames are small
	if _, err := r.c.Write(append(b, frame...)); err != nil {
		t.Fatal(err)
	}
}

func (r *rawClient) recv(t *testing.T) []byte {
	t.Helper()
	_ = r.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(r.c, hdr[:]); err != nil {
		t.Fatalf("recv: %v", err)
	}
	b := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r.c, b); err != nil {
		t.Fatalf("recv body: %v", err)
	}
	return b
}

func (r *rawClient) close() { _ = r.c.Close() }

type wsClient struct{ c *websocket.Conn }

func dialWS(t *testing.T, f *fixture) *wsClient {
	t.Helper()
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{stream.ALPNHTTP},
		InsecureSkipVerify: true, //nolint:gosec // MTRP authenticates the relay with Noise, not TLS
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, "wss://"+f.ln.Addr().String()+stream.WebSocketPath, &websocket.DialOptions{
		HTTPClient: httpClient, Subprotocols: []string{stream.WebSocketSubpro},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return &wsClient{c: c}
}

func (w *wsClient) send(t *testing.T, frame []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.c.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatal(err)
	}
}

func (w *wsClient) recv(t *testing.T) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := w.c.Read(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return b
}

func (w *wsClient) close() { _ = w.c.CloseNow() }

// mtrpClient is an MTRP session over a stream transport.
type mtrpClient struct {
	tr      transport
	session *mtrp.Session
	node    key.NodePublic
}

func connect(t *testing.T, f *fixture, tr transport, node byte) *mtrpClient {
	t.Helper()
	disco, _ := key.NewDiscoPrivate()
	now := time.Now()
	ticket, err := mtrp.Ticket{
		ID: [16]byte{node}, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(10 * time.Minute).UnixMilli(),
		Node: key.NodePublic{0x4e, node}, Disco: disco.Public(), Deployment: [16]byte{1},
		Zones: []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{7}}},
	}.Sign(f.signer)
	if err != nil {
		t.Fatal(err)
	}
	hs, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: disco, Relay: f.relay.PublicKey(), Index: uint32(node),
		Hello: mtrp.ClientHello{TimestampMS: now.UnixMilli(), Ticket: ticket, Caps: mtrp.CapWebSocket},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr.send(t, init)
	session, _, err := hs.Finish(tr.recv(t))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	c := &mtrpClient{tr: tr, session: session, node: key.NodePublic{0x4e, node}}
	c.control(t, mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	if m := c.expect(t); m.Type != mtrp.ControlKeepalive {
		t.Fatalf("keepalive reply %+v", m)
	}
	return c
}

func (c *mtrpClient) control(t *testing.T, msg mtrp.ControlMessage) {
	t.Helper()
	plain, _ := mtrp.AppendControlMessage(nil, msg)
	frame, err := c.session.SealControl(nil, plain)
	if err != nil {
		t.Fatal(err)
	}
	c.tr.send(t, frame)
}

func (c *mtrpClient) expect(t *testing.T) mtrp.ControlMessage {
	t.Helper()
	plain, err := c.session.OpenControl(nil, c.tr.recv(t))
	if err != nil {
		t.Fatal(err)
	}
	m, err := mtrp.ParseControlMessage(plain)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRawAndWebSocketClientsTalkThroughRelay(t *testing.T) {
	t.Parallel()
	f := start(t, nil)
	a := connect(t, f, dialRaw(t, f), 1)
	b := connect(t, f, dialWS(t, f), 2)

	a.control(t, mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 1, Peer: b.node})
	incoming := b.expect(t)
	ok := a.expect(t)
	if ok.Type != mtrp.ControlRouteOK || incoming.Type != mtrp.ControlRouteIncoming {
		t.Fatalf("route: %+v / %+v", ok, incoming)
	}
	for i := range 20 {
		payload := bytes.Repeat([]byte{byte(i)}, 1400)
		frame, _ := mtrp.AppendData(nil, a.session.RemoteIndex(), ok.Route, payload)
		a.tr.send(t, frame)
		d, err := mtrp.ParseData(b.tr.recv(t))
		if err != nil || d.Route != incoming.Route || !bytes.Equal(d.Payload, payload) {
			t.Fatalf("raw→ws frame %d: %v", i, err)
		}
		frame, _ = mtrp.AppendData(nil, b.session.RemoteIndex(), incoming.Route, payload)
		b.tr.send(t, frame)
		if d, err := mtrp.ParseData(a.tr.recv(t)); err != nil || !bytes.Equal(d.Payload, payload) {
			t.Fatalf("ws→raw frame %d: %v", i, err)
		}
	}

	// Closing a's connection ends its session at once; b is told.
	a.tr.close()
	if m := b.expect(t); m.Type != mtrp.ControlRouteClose || m.RouteClose != mtrp.RouteClosePeerLeft {
		t.Fatalf("b after a left: %+v", m)
	}
	if n := f.relay.SessionCount(); n != 1 {
		t.Fatalf("sessions after disconnect = %d", n)
	}
}

func TestStreamRejectsOversizedFrames(t *testing.T) {
	t.Parallel()
	f := start(t, nil)
	r := dialRaw(t, f)
	hdr := binary.BigEndian.AppendUint16(nil, mtrp.MaxStreamFrame+1)
	if _, err := r.c.Write(hdr); err != nil {
		t.Fatal(err)
	}
	_ = r.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection stayed open after an oversized frame")
	}
}

func TestStreamConnectionLimits(t *testing.T) {
	t.Parallel()
	f := start(t, func(c *stream.Config) { c.MaxConnsPerIP = 2 })
	dialRaw(t, f)
	dialRaw(t, f)
	var nd net.Dialer
	c, err := nd.DialContext(t.Context(), "tcp", f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) //nolint:gosec // test
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.HandshakeContext(t.Context()); err == nil {
		t.Fatal("third connection from one address was admitted")
	}
}

func TestStreamShutdownClosesWebSockets(t *testing.T) {
	t.Parallel()
	f := start(t, nil)
	w := dialWS(t, f)
	connect(t, f, w, 9)
	var wg sync.WaitGroup
	wg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := w.c.Read(ctx); err == nil {
			t.Error("WebSocket stayed open after shutdown")
		}
	})
	f.cancel()
	select {
	case err := <-f.done:
		f.done <- err // let the cleanup check it
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return with a WebSocket connected")
	}
	wg.Wait()
}

func TestStreamClosesUnauthenticatedConnections(t *testing.T) {
	t.Parallel()
	f := start(t, func(c *stream.Config) { c.HandshakeTimeout = 300 * time.Millisecond })
	r := dialRaw(t, f)
	_ = r.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection without a session stayed open")
	}

	// Junk INITs beyond the per-connection limit close the connection too.
	r = dialRaw(t, f)
	junk := append([]byte{mtrp.Version, byte(mtrp.TypeInit), 0, 0}, bytes.Repeat([]byte{1}, 200)...)
	for range 9 {
		r.send(t, junk)
	}
	if _, err := r.c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection survived nine INITs")
	}
}

func TestStreamDoesNotNegotiateHTTP2(t *testing.T) {
	t.Parallel()
	f := start(t, nil)
	d := tls.Dialer{Config: &tls.Config{
		NextProtos: []string{"h2", stream.ALPNHTTP}, MinVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // test
	}}
	nc, err := d.DialContext(t.Context(), "tcp", f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nc.Close() }()
	c, ok := nc.(*tls.Conn)
	if !ok || c.ConnectionState().NegotiatedProtocol != stream.ALPNHTTP {
		t.Fatalf("negotiated %q", c.ConnectionState().NegotiatedProtocol)
	}
}
