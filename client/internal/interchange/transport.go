package interchange

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"meshtransit.net/client/internal/underlay"
	"meshtransit.net/shared/mtrp"
)

// Transport identifiers (MTRP §1).
const (
	alpnMTRP      = "mtrp/1"
	wsPath        = "/mtrp/v1"
	wsSubprotocol = "mtrp.v1"
	streamDialTO  = 10 * time.Second
	streamWriteTO = 10 * time.Second
)

// TransportKind names how a session reaches its relay.
type TransportKind string

// Transport kinds, in order of preference.
const (
	TransportUDP       TransportKind = "udp"
	TransportTLS       TransportKind = "tls"
	TransportWebSocket TransportKind = "websocket"
)

var errFrameSize = errors.New("interchange: frame size out of range")

// transport carries whole MTRP frames to one relay node.
type transport interface {
	send(frame []byte) error
	// receive reads one frame into buf and returns its length.
	receive(buf []byte) (int, error)
	close() error
	kind() TransportKind
}

// endpoint is a dialable relay node.
type endpoint struct {
	host    string // DNS name, for TLS SNI and WebSocket
	addr    netip.Addr
	udpPort uint16
	tlsPort uint16
}

func (e endpoint) udpAddr() netip.AddrPort { return netip.AddrPortFrom(e.addr, e.udpPort) }

func (e endpoint) tlsAddr() string {
	return net.JoinHostPort(e.addr.String(), strconv.Itoa(int(e.tlsPort)))
}

// udpTransport is a connected UDP socket: the kernel drops datagrams from
// any other source, and each read is one frame.
type udpTransport struct{ conn *net.UDPConn }

func dialUDP(ctx context.Context, e endpoint) (transport, error) {
	conn, err := underlay.Dialer(0).DialContext(ctx, "udp", e.udpAddr().String())
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("interchange: not a UDP connection")
	}
	return &udpTransport{conn: udp}, nil
}

func (t *udpTransport) send(frame []byte) error {
	if len(frame) > mtrp.MaxUDPFrame {
		return errFrameSize
	}
	_, err := t.conn.Write(frame)
	return err
}

func (t *udpTransport) receive(buf []byte) (int, error) { return t.conn.Read(buf) }
func (t *udpTransport) close() error                    { return t.conn.Close() }
func (*udpTransport) kind() TransportKind               { return TransportUDP }

// tlsConfig skips certificate verification on purpose: the Noise IK
// handshake authenticates the relay key from the signed relay map, so TLS
// only has to get through middleboxes and proxies (MTRP §1).
func tlsConfig(serverName, protocol string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		NextProtos:         []string{protocol},
		InsecureSkipVerify: true, //nolint:gosec // the Noise handshake authenticates the relay (MTRP §1)
	}
}

// streamTransport is TLS 1.3 with ALPN mtrp/1 and u16-length framing.
type streamTransport struct {
	conn    net.Conn
	writeMu sync.Mutex
	out     []byte
}

func dialTLS(ctx context.Context, e endpoint) (transport, error) {
	ctx, cancel := context.WithTimeout(ctx, streamDialTO)
	defer cancel()
	d := tls.Dialer{NetDialer: underlay.Dialer(0), Config: tlsConfig(e.host, alpnMTRP)}
	conn, err := d.DialContext(ctx, "tcp", e.tlsAddr())
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != alpnMTRP {
		_ = conn.Close()
		return nil, errors.New("interchange: relay did not select ALPN mtrp/1")
	}
	return &streamTransport{conn: conn}, nil
}

func (t *streamTransport) send(frame []byte) error {
	if len(frame) == 0 || len(frame) > mtrp.MaxStreamFrame {
		return errFrameSize
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.out = binary.BigEndian.AppendUint16(t.out[:0], uint16(len(frame))) //nolint:gosec // bounded above
	t.out = append(t.out, frame...)
	if err := t.conn.SetWriteDeadline(time.Now().Add(streamWriteTO)); err != nil {
		return err
	}
	_, err := t.conn.Write(t.out)
	return err
}

func (t *streamTransport) receive(buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(t.conn, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > mtrp.MaxStreamFrame || n > len(buf) {
		return 0, errFrameSize
	}
	return io.ReadFull(t.conn, buf[:n])
}

func (t *streamTransport) close() error      { return t.conn.Close() }
func (*streamTransport) kind() TransportKind { return TransportTLS }

// wsTransport carries one frame per binary WebSocket message.
type wsTransport struct {
	conn *websocket.Conn
	ctx  context.Context // ends when the transport is closed
	stop context.CancelFunc
}

func dialWebSocket(ctx context.Context, e endpoint) (transport, error) {
	dialCtx, cancel := context.WithTimeout(ctx, streamDialTO)
	defer cancel()
	tlsCfg := tlsConfig(e.host, "http/1.1")
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: false,
		Proxy:             http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return underlay.Dialer(0).DialContext(ctx, network, e.tlsAddr())
		},
	}}
	url := "wss://" + net.JoinHostPort(e.host, strconv.Itoa(int(e.tlsPort))) + wsPath
	conn, resp, err := websocket.Dial(dialCtx, url, &websocket.DialOptions{
		HTTPClient:   client,
		Subprotocols: []string{wsSubprotocol},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if conn.Subprotocol() != wsSubprotocol {
		_ = conn.CloseNow()
		return nil, fmt.Errorf("interchange: relay chose WebSocket subprotocol %q", conn.Subprotocol())
	}
	conn.SetReadLimit(mtrp.MaxStreamFrame)
	life, stop := context.WithCancel(context.Background())
	return &wsTransport{conn: conn, ctx: life, stop: stop}, nil
}

func (t *wsTransport) send(frame []byte) error {
	if len(frame) == 0 || len(frame) > mtrp.MaxStreamFrame {
		return errFrameSize
	}
	ctx, cancel := context.WithTimeout(t.ctx, streamWriteTO)
	defer cancel()
	return t.conn.Write(ctx, websocket.MessageBinary, frame)
}

func (t *wsTransport) receive(buf []byte) (int, error) {
	kind, data, err := t.conn.Read(t.ctx)
	if err != nil {
		return 0, err
	}
	if kind != websocket.MessageBinary || len(data) > len(buf) {
		return 0, errFrameSize
	}
	return copy(buf, data), nil
}

func (t *wsTransport) close() error {
	t.stop()
	return t.conn.CloseNow()
}

func (*wsTransport) kind() TransportKind { return TransportWebSocket }

// pump is the single reader of a transport: the handshake and then the
// session consume its frames, so no frame is read twice or lost between
// them. It ends when the transport fails or stop is called.
type pump struct {
	frames chan []byte
	err    chan error
	stop   chan struct{}
	once   sync.Once
}

func startPump(t transport) *pump {
	p := &pump{frames: make(chan []byte, 64), err: make(chan error, 1), stop: make(chan struct{})}
	go func() {
		defer close(p.frames)
		buf := make([]byte, mtrp.MaxStreamFrame)
		for {
			n, err := t.receive(buf)
			if err != nil {
				p.err <- err
				return
			}
			select {
			case p.frames <- append([]byte(nil), buf[:n]...):
			case <-p.stop:
				return
			}
		}
	}()
	return p
}

// close stops delivery; the reader exits once the transport is closed too.
func (p *pump) close() { p.once.Do(func() { close(p.stop) }) }
