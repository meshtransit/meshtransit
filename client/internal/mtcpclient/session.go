package mtcpclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 10 * time.Second
	// clientCapabilities are what meshd implements (mtcp-v1 §13).
	pongNonceLimit = 32
)

var (
	// errSessionRefused reports an upgrade the origin answered without
	// switching protocols; the WebSocket fallback may still work.
	errSessionRefused = errors.New("mtcp: upgrade refused")
	// errUnknownKey reports that the origin does not hold the chosen key.
	errUnknownKey = errors.New("mtcp: control key unknown to the origin")
	// errOverloaded reports an origin shedding load; retry later.
	errOverloaded = errors.New("mtcp: control origin overloaded")
)

// recordConn carries MTCP records over a byte stream or WebSocket.
type recordConn interface {
	write(t sharedmtcp.RecordType, body []byte) error
	read(deadline time.Time) (sharedmtcp.RecordType, []byte, error)
	close() error
}

type streamConn struct {
	conn   net.Conn
	reader *sharedmtcp.RecordReader
}

func (s *streamConn) write(t sharedmtcp.RecordType, body []byte) error {
	record, err := sharedmtcp.AppendRecord(nil, t, body)
	if err != nil {
		return err
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = s.conn.Write(record)
	return err
}

func (s *streamConn) read(deadline time.Time) (sharedmtcp.RecordType, []byte, error) {
	_ = s.conn.SetReadDeadline(deadline)
	return s.reader.Next()
}

func (s *streamConn) close() error { return s.conn.Close() }

type webSocketConn struct{ conn *websocket.Conn }

func (w *webSocketConn) write(t sharedmtcp.RecordType, body []byte) error {
	message, err := sharedmtcp.AppendMessageRecord(nil, t, body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return w.conn.Write(ctx, websocket.MessageBinary, message)
}

func (w *webSocketConn) read(deadline time.Time) (sharedmtcp.RecordType, []byte, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	kind, message, err := w.conn.Read(ctx)
	if err != nil {
		return 0, nil, err
	}
	if kind != websocket.MessageBinary {
		return 0, nil, sharedmtcp.ErrMalformed
	}
	return sharedmtcp.ParseMessageRecord(message)
}

func (w *webSocketConn) close() error { return w.conn.CloseNow() }

// session is one established MTCP session. send is safe for concurrent
// use; receive is called by one goroutine.
type session struct {
	conn      recordConn
	noise     *sharedmtcp.Session
	reply     *mtcpv1.ServerHello
	control   key.ControlPublic
	assembler *sharedmtcp.Assembler
	sendMu    sync.Mutex
	keepalive time.Duration
	idle      time.Duration
}

// sessionOptions describe the node opening a session.
type sessionOptions struct {
	machine      key.MachinePrivate
	control      key.ControlPublic
	nodeKey      []byte // the Device's node key when it has one
	capabilities []string
	version      string
}

// open dials origin, tries the HTTP upgrade and falls back to WebSocket
// when the upgrade is refused, then completes the handshake (mtcp-v1 §2–3).
func (c *Client) open(ctx context.Context, origin *url.URL, options sessionOptions) (*session, error) {
	hello := &mtcpv1.ClientHello{
		ProtocolVersion: sharedmtcp.Version, TimestampMs: c.now().UnixMilli(), NodeKey: options.nodeKey,
		Capabilities: options.capabilities,
		Client:       &mtcpv1.ClientInfo{Product: "meshd", Version: options.version, Os: runtime.GOOS, Arch: runtime.GOARCH},
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	start := func() (*sharedmtcp.ClientHandshake, []byte, error) {
		return sharedmtcp.StartClient(sharedmtcp.ClientConfig{
			Machine: options.machine, Control: options.control,
			Hello: hello,
		})
	}
	handshake, init, err := start()
	if err != nil {
		return nil, err
	}
	conn, response, err := c.upgrade(handshakeCtx, origin, options.control, init)
	if errors.Is(err, errSessionRefused) {
		// A fresh INIT: the refused one may have been seen by a middlebox.
		hello.TimestampMs = c.now().UnixMilli()
		if handshake, init, err = start(); err != nil {
			return nil, err
		}
		conn, response, err = c.webSocket(handshakeCtx, origin, options.control, init)
	}
	if err != nil {
		return nil, err
	}
	noise, reply, err := handshake.Finish(response)
	if err != nil {
		_ = conn.close()
		return nil, fmt.Errorf("mtcp: handshake: %w", err)
	}
	if reply.GetReject() != mtcpv1.ServerHello_REJECT_UNSPECIFIED {
		_ = conn.close()
		return nil, fmt.Errorf("%w: control refused the session (%v)", controlplane.ErrRegistration, reply.GetReject())
	}
	keepalive := time.Duration(reply.GetLimits().GetKeepaliveS()) * time.Second
	idle := time.Duration(reply.GetLimits().GetIdleTimeoutS()) * time.Second
	if keepalive <= 0 || keepalive > time.Minute {
		keepalive = 25 * time.Second
	}
	if idle <= keepalive {
		idle = 3 * keepalive
	}
	return &session{
		conn: conn, noise: noise, reply: reply, control: options.control,
		assembler: sharedmtcp.NewAssembler(sharedmtcp.CoreToNode), keepalive: keepalive, idle: idle,
	}, nil
}

func (c *Client) upgrade(ctx context.Context, origin *url.URL, control key.ControlPublic, init []byte) (
	recordConn, []byte, error,
) {
	conn, err := c.dialTLS(ctx, origin.Host, c.tlsFor(origin))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", controlplane.ErrRegistrationTemporary, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	id := control.ID()
	request := "POST " + sharedmtcp.UpgradePath + " HTTP/1.1\r\nHost: " + origin.Hostname() +
		"\r\nUser-Agent: " + userAgent + "\r\nUpgrade: " + sharedmtcp.UpgradeToken +
		"\r\nConnection: Upgrade\r\n" + sharedmtcp.HeaderKey + ": " + id.String() + "\r\n" +
		sharedmtcp.HeaderHandshake + ": " + base64.RawURLEncoding.EncodeToString(init) +
		"\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("%w: %w", controlplane.ErrRegistrationTemporary, err)
	}
	buffered := bufio.NewReader(conn)
	response, err := http.ReadResponse(buffered, nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("%w: %w", errSessionRefused, err)
	}
	_ = response.Body.Close()
	if err := refusal(response.StatusCode); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	body, err := decodeHandshake(response.Header.Values(sharedmtcp.HeaderHandshake))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &streamConn{conn: conn, reader: sharedmtcp.NewRecordReader(buffered)}, body, nil
}

// refusal classifies an upgrade answer (mtcp-v1 §2.2).
func refusal(status int) error {
	switch status {
	case http.StatusSwitchingProtocols:
		return nil
	case http.StatusMisdirectedRequest:
		return errUnknownKey
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		return fmt.Errorf("%w: %w", controlplane.ErrRegistrationTemporary, errOverloaded)
	default:
		return fmt.Errorf("%w: http %d", errSessionRefused, status)
	}
}

func decodeHandshake(values []string) ([]byte, error) {
	if len(values) != 1 || len(values[0]) == 0 ||
		len(values[0]) > base64.RawURLEncoding.EncodedLen(sharedmtcp.MaxHandshakeRecord) {
		return nil, sharedmtcp.ErrMalformed
	}
	body, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(body) == 0 {
		return nil, sharedmtcp.ErrMalformed
	}
	return body, nil
}

func (c *Client) webSocket(ctx context.Context, origin *url.URL, control key.ControlPublic, init []byte) (
	recordConn, []byte, error,
) {
	header := http.Header{}
	id := control.ID()
	header.Set(sharedmtcp.HeaderKey, id.String())
	header.Set("User-Agent", userAgent)
	conn, response, err := websocket.Dial(ctx, "wss://"+origin.Host+sharedmtcp.WebSocketPath, &websocket.DialOptions{
		HTTPClient: c.httpClient, HTTPHeader: header, Subprotocols: []string{sharedmtcp.WebSocketProtocol},
	})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		if response != nil {
			if refused := refusal(response.StatusCode); refused != nil {
				return nil, nil, refused
			}
		}
		return nil, nil, fmt.Errorf("%w: %w", controlplane.ErrRegistrationTemporary, err)
	}
	conn.SetReadLimit(sharedmtcp.MaxRecord + 1)
	transport := &webSocketConn{conn: conn}
	if err := transport.write(sharedmtcp.RecordInit, init); err != nil {
		_ = transport.close()
		return nil, nil, err
	}
	deadline, _ := ctx.Deadline()
	recordType, body, err := transport.read(deadline)
	if err != nil || recordType != sharedmtcp.RecordResponse {
		_ = transport.close()
		return nil, nil, fmt.Errorf("mtcp: WebSocket handshake: %w", errors.Join(err, sharedmtcp.ErrMalformed))
	}
	return transport, body, nil
}

func (c *Client) tlsFor(origin *url.URL) *tls.Config {
	config := c.tlsConfig.Clone()
	config.ServerName = origin.Hostname()
	config.NextProtos = []string{"http/1.1"}
	return config
}

// send encodes, fragments and seals one message.
func (s *session) send(t sharedmtcp.MessageType, message proto.Message) error {
	fragments, err := sharedmtcp.EncodeMessage(t, message, sharedmtcp.NodeToCore, sharedmtcp.EncodeOptions{})
	if err != nil {
		return err
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
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

// receive returns the next complete message; nothing for the idle timeout
// is an error.
func (s *session) receive() (sharedmtcp.MessageType, proto.Message, error) {
	for {
		recordType, body, err := s.conn.read(time.Now().Add(s.idle))
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
		if !complete {
			continue
		}
		message, err := sharedmtcp.DecodeMessage(t, payload)
		if err != nil {
			return 0, nil, err
		}
		if ping, ok := message.(*mtcpv1.Ping); ok {
			// Liveness is answered here; callers never see Pings.
			if len(ping.GetNonce()) > pongNonceLimit {
				return 0, nil, sharedmtcp.ErrMalformed
			}
			if err := s.send(sharedmtcp.MessagePong, &mtcpv1.Pong{Nonce: ping.GetNonce()}); err != nil {
				return 0, nil, err
			}
			continue
		}
		return t, message, nil
	}
}

func (s *session) close() { _ = s.conn.close() }

// ping opens a session and exchanges one Ping: proof that the origin holds
// control and accepts machine.
func (c *Client) ping(ctx context.Context, origin *url.URL, machine key.MachinePrivate,
	control key.ControlPublic,
) error {
	s, err := c.open(ctx, origin, sessionOptions{machine: machine, control: control})
	if err != nil {
		return err
	}
	defer s.close()
	nonce := []byte("meshd-probe")
	if err := s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{Nonce: nonce}); err != nil {
		return err
	}
	deadline := time.Now().Add(requestTimeout)
	for time.Now().Before(deadline) {
		t, message, err := s.receive()
		if err != nil {
			return fmt.Errorf("%w: %w", controlplane.ErrRegistrationTemporary, err)
		}
		if pong, ok := message.(*mtcpv1.Pong); ok && string(pong.GetNonce()) == string(nonce) {
			return nil
		}
		if t == sharedmtcp.MessageError {
			return fmt.Errorf("%w: %v", controlplane.ErrRegistrationTemporary, message)
		}
	}
	return controlplane.ErrRegistrationTemporary
}
