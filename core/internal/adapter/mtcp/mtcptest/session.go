package mtcptest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	operationTimeout = 10 * time.Second
	// streamIdleTimeout bounds a read without a context deadline; Core
	// sends a Ping at least every keepalive interval (mtcp-v1 §5).
	streamIdleTimeout = 75 * time.Second
	keyDocumentLimit  = 4 << 10 // mtcp-v1 §2.1
	maxControlKeys    = 2
	maxPongNonce      = 32
	maxErrorText      = 512
)

// capabilities are what this client implements (mtcp-v1 §13). It does not
// offer device-alias.v1, so Core never sends it alias peers.
var capabilities = []string{"map.zstd"}

// session is one established MTCP session. send is safe for concurrent use;
// receive has a single caller.
type session struct {
	conn      net.Conn
	reader    *sharedmtcp.RecordReader
	noise     *sharedmtcp.Session
	control   key.ControlPublic
	assembler *sharedmtcp.Assembler
	sendMu    sync.Mutex
	closeOnce sync.Once
}

// controlKey returns the pinned control key, reading the key document the
// first time (mtcp-v1 §2.1). The key with the latest not_after is pinned.
func (client *Client) controlKey(ctx context.Context) (key.ControlPublic, error) {
	if pinned := client.PinnedControlKey(); pinned.Public != ([32]byte{}) {
		return key.ControlPublic(pinned.Public), nil
	}
	keys, err := client.fetchKeyDocument(ctx)
	if err != nil {
		return key.ControlPublic{}, errors.Join(ErrSession, err)
	}
	chosen := keys[0]
	for _, candidate := range keys[1:] {
		if candidate.NotAfter.After(chosen.NotAfter) {
			chosen = candidate
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.control = chosen
	return key.ControlPublic(chosen.Public), nil
}

type keyDocument struct {
	Version int                `json:"version"`
	Keys    []keyDocumentEntry `json:"keys"`
}

type keyDocumentEntry struct {
	Key         key.ControlPublic `json:"key"`
	NotAfter    time.Time         `json:"not_after"`
	Fingerprint string            `json:"fingerprint"`
}

func (client *Client) fetchKeyDocument(ctx context.Context) ([]ControlKey, error) {
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: operationTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, client.controlAddress)
		},
		TLSClientConfig:       client.tlsConfig.Clone(),
		TLSHandshakeTimeout:   operationTimeout,
		ResponseHeaderTimeout: operationTimeout,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("mtcptest: redirect rejected")
		},
	}
	request, err := http.NewRequestWithContext(operationCtx, http.MethodGet,
		"https://"+client.serverName+sharedmtcp.KeyPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build key document request: %w", err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request key document: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, keyDocumentLimit+1))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return nil, fmt.Errorf("read key document: %w", err)
	}
	if response.StatusCode != http.StatusOK || len(body) > keyDocumentLimit ||
		!strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return nil, fmt.Errorf("key document: status %d, %d bytes", response.StatusCode, len(body))
	}
	var document keyDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode key document: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("key document has trailing data")
	}
	return validKeyDocument(document, time.Now())
}

// validKeyDocument checks the document's bounds. The test client verifies
// each fingerprint itself, as a node does with a ck= link.
func validKeyDocument(document keyDocument, now time.Time) ([]ControlKey, error) {
	if document.Version != sharedmtcp.Version || len(document.Keys) == 0 || len(document.Keys) > maxControlKeys {
		return nil, errors.New("key document is not a version 1 list of one or two keys")
	}
	keys := make([]ControlKey, 0, len(document.Keys))
	for _, entry := range document.Keys {
		if entry.Key.IsZero() || !entry.NotAfter.After(now) ||
			!sharedmtcp.FingerprintMatches(entry.Key, entry.Fingerprint) {
			return nil, errors.New("key document lists an invalid key")
		}
		keys = append(keys, ControlKey{Public: entry.Key, NotAfter: entry.NotAfter.UTC()})
	}
	return keys, nil
}

// openSession dials the control origin, upgrades to MTCP and completes the
// Noise handshake (mtcp-v1 §2.2, §3). A non-empty nodeKey is announced in
// the ClientHello. The caller must send the first TRANSPORT record, which
// establishes the session.
func (client *Client) openSession(ctx context.Context, nodeKey []byte) (*session, error) {
	control, err := client.controlKey(ctx)
	if err != nil {
		return nil, err
	}
	handshake, init, err := sharedmtcp.StartClient(sharedmtcp.ClientConfig{
		Machine: client.machine, Control: control,
		Hello: &mtcpv1.ClientHello{
			ProtocolVersion: sharedmtcp.Version, TimestampMs: client.nextTimestamp(), NodeKey: nodeKey,
			Capabilities: capabilities,
			Client:       &mtcpv1.ClientInfo{Product: "mtcptest", Version: "0", Os: runtime.GOOS, Arch: runtime.GOARCH},
		},
	})
	if err != nil {
		return nil, errors.Join(ErrSession, err)
	}
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	conn, err := client.dialTLS(operationCtx)
	if err != nil {
		return nil, errors.Join(ErrSession, err)
	}
	reader, response, err := client.upgrade(conn, control, init)
	if err != nil {
		_ = conn.Close()
		return nil, errors.Join(ErrSession, err)
	}
	noise, hello, err := handshake.Finish(response)
	if err != nil {
		_ = conn.Close()
		return nil, errors.Join(ErrSession, fmt.Errorf("finish handshake: %w", err))
	}
	if hello.GetReject() != mtcpv1.ServerHello_REJECT_UNSPECIFIED {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: control refused the session: %v", ErrSession, hello.GetReject())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, errors.Join(ErrSession, err)
	}
	return &session{conn: conn, reader: sharedmtcp.NewRecordReader(reader), noise: noise, control: control,
		assembler: sharedmtcp.NewAssembler(sharedmtcp.CoreToNode)}, nil
}

func (client *Client) dialTLS(ctx context.Context) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: operationTimeout, KeepAlive: -1}
	raw, err := dialer.DialContext(ctx, "tcp", client.controlAddress)
	if err != nil {
		return nil, fmt.Errorf("dial control origin: %w", err)
	}
	conn := tls.Client(raw, client.tlsConfig.Clone())
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("bound control origin connection: %w", err)
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("authenticate control origin: %w", err)
	}
	return conn, nil
}

// upgrade sends the MTCP upgrade request and returns the reader positioned
// after the 101 response, with the RESPONSE record body.
func (client *Client) upgrade(conn net.Conn, control key.ControlPublic, init []byte) (*bufio.Reader, []byte, error) {
	keyID := control.ID()
	request := "POST " + sharedmtcp.UpgradePath + " HTTP/1.1\r\nHost: " + client.serverName +
		"\r\nUpgrade: " + sharedmtcp.UpgradeToken + "\r\nConnection: Upgrade\r\n" +
		sharedmtcp.HeaderKey + ": " + keyID.String() + "\r\n" +
		sharedmtcp.HeaderHandshake + ": " + base64.RawURLEncoding.EncodeToString(init) +
		"\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, nil, fmt.Errorf("write upgrade request: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("read upgrade response: %w", err)
	}
	// A 1xx response has no body; the reader keeps any record already read.
	if err := response.Body.Close(); err != nil {
		return nil, nil, fmt.Errorf("close upgrade response: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(response.Header.Get("Upgrade"), sharedmtcp.UpgradeToken) {
		return nil, nil, fmt.Errorf("upgrade refused: status %d", response.StatusCode)
	}
	values := response.Header.Values(sharedmtcp.HeaderHandshake)
	if len(values) != 1 || len(values[0]) > base64.RawURLEncoding.EncodedLen(sharedmtcp.MaxHandshakeRecord) {
		return nil, nil, errors.New("upgrade response carries no valid handshake")
	}
	body, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(body) == 0 {
		return nil, nil, errors.New("upgrade response carries no valid handshake")
	}
	return reader, body, nil
}

// send encodes, fragments, seals and writes one message.
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
		record, err := sharedmtcp.AppendRecord(nil, sharedmtcp.RecordTransport, sealed)
		if err != nil {
			return err
		}
		if err := s.conn.SetWriteDeadline(time.Now().Add(operationTimeout)); err != nil {
			return err
		}
		if _, err := s.conn.Write(record); err != nil {
			return err
		}
	}
	return nil
}

// receive returns the next complete message other than Ping, which it
// answers. It ends at the context's deadline, or after streamIdleTimeout
// without one, and when the context ends.
func (s *session) receive(ctx context.Context) (proto.Message, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamIdleTimeout)
	}
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		recordType, body, err := s.reader.Next()
		if err != nil {
			return nil, errors.Join(err, ctx.Err())
		}
		if recordType != sharedmtcp.RecordTransport {
			return nil, sharedmtcp.ErrMalformed
		}
		fragment, err := s.noise.Open(nil, body)
		if err != nil {
			return nil, err
		}
		t, payload, complete, err := s.assembler.Add(fragment)
		if err != nil {
			return nil, err
		}
		if !complete {
			continue
		}
		message, err := sharedmtcp.DecodeMessage(t, payload)
		if err != nil {
			return nil, err
		}
		if ping, isPing := message.(*mtcpv1.Ping); isPing {
			if len(ping.GetNonce()) > maxPongNonce {
				return nil, sharedmtcp.ErrMalformed
			}
			if err := s.send(sharedmtcp.MessagePong, &mtcpv1.Pong{Nonce: ping.GetNonce()}); err != nil {
				return nil, err
			}
			continue
		}
		return message, nil
	}
}

// acknowledgeKeys checks that a KeyUpdate still lists the pinned control
// key and answers it with Pong{nonce} (mtcp-v1 §11).
func (s *session) acknowledgeKeys(update *mtcpv1.KeyUpdate) error {
	listed := false
	for _, control := range update.GetControlKeys() {
		if bytes.Equal(control.GetKey(), s.control[:]) {
			listed = true
		}
	}
	if !listed || len(update.GetControlKeys()) > maxControlKeys || len(update.GetNonce()) > maxPongNonce {
		return errors.New("key update does not keep the pinned control key")
	}
	return s.send(sharedmtcp.MessagePong, &mtcpv1.Pong{Nonce: update.GetNonce()})
}

func (s *session) close() error {
	var err error
	s.closeOnce.Do(func() { err = s.conn.Close() })
	return err
}

// errorMessage describes an Error from Core. Its message is bounded and
// never carries secrets (mtcp-v1 §15).
func errorMessage(message *mtcpv1.Error) error {
	text := message.GetMessage()
	if len(text) > maxErrorText {
		text = text[:maxErrorText]
	}
	return fmt.Errorf("control sent error %v (%q, fatal=%t, retry after %d ms)",
		message.GetCode(), text, message.GetFatal(), message.GetRetryAfterMs())
}
