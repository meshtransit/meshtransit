package mtcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// Session defaults (mtcp-v1 §3, §5).
const (
	DefaultKeepalive   = 25 * time.Second
	DefaultIdleTimeout = 75 * time.Second
	// DefaultUnprovenLimit is how long a session may stay open without
	// proving a Device (mtcp-v1 §14): longer than a browser approval
	// (10 min), so an approval requested when the session opens is never
	// cut off. Nodes send each registration on a fresh session.
	DefaultUnprovenLimit = 15 * time.Minute
	DefaultMaxSessions   = 4096
	handshakeDeadline    = 10 * time.Second
	writeTimeout         = 10 * time.Second
	timestampWindow      = 10 * time.Minute
	maxUnackedMap        = 8
	maxKeyDocument       = 4 << 10
)

var (
	// ErrInvalidServer reports missing dependencies or unsafe bounds.
	ErrInvalidServer = errors.New("mtcp: invalid server")
	errShuttingDown  = errors.New("mtcp: server shutting down")
)

// ControlKey is one control key the deployment answers with. At most two
// are active: the current one and the next one (mtcp-v1 §2.2).
type ControlKey struct {
	Private  key.ControlPrivate
	NotAfter time.Time
}

// TimestampGuard accepts a ClientHello timestamp only when it is greater
// than the last accepted one for the machine key, durably for keys bound to
// a Device (mtcp-v1 §3, step 3), and says what the keys are. The machine key
// is given as its node domain fingerprint, the index Core's Device bindings
// use. A Kubernetes gateway's timestamp is only compared; it is written by
// CommitGatewayTimestamp once the session proved its node key (§6.7).
type TimestampGuard interface {
	AcceptTimestamp(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
		timestampMS int64) (TimestampCheck, error)
	CommitGatewayTimestamp(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
		timestampMS int64) (bool, error)
}

// MachineState is what a handshake's machine key is to Core.
type MachineState uint8

// Machine key states.
const (
	// MachineUnbound: no Device holds or held it.
	MachineUnbound MachineState = iota
	// MachineCurrent: an active Device holds it now.
	MachineCurrent
	// MachineRetired: a Device held it once, or a gateway did.
	MachineRetired
)

// TimestampCheck is a TimestampGuard's answer for one handshake.
type TimestampCheck struct {
	Accepted bool
	// Gateway: the machine key belongs, or belonged, to a Kubernetes
	// gateway, which must prove its node key before anything else.
	Gateway bool
	Machine MachineState
	// NodeCurrent: the ClientHello node key is the current key of the
	// Device that holds the machine key.
	NodeCurrent bool
}

// SessionHandler gives each established session to the application.
type SessionHandler interface {
	Open(session *Session) Conversation
}

// Conversation is the application side of one session. Run owns the
// session until it returns or ctx ends, so it must block while the session
// should stay open; Receive gets every message from the node other than
// Ping and Error, in order, including the RegisterRequest that established
// the session and each Pong (KeyUpdate acknowledgements).
type Conversation interface {
	Run(ctx context.Context) error
	Receive(ctx context.Context, t sharedmtcp.MessageType, message proto.Message) error
}

// Options configures a Server.
type Options struct {
	Keys         []ControlKey
	ClientIPs    clientip.Resolver
	Handler      SessionHandler
	Guard        TimestampGuard // nil keeps only a per-replica cache
	Capabilities []string       // what this Core supports (mtcp-v1 §13)
	Logger       *slog.Logger
	Metrics      *Metrics
	MaxSessions  int
	// HandshakeRate and HandshakeBurst bound handshakes per source (zero
	// uses the mtcp-v1 §14 defaults).
	HandshakeRate  int
	HandshakeBurst int
	// UnauthenticatedPerSource bounds a source's connections that serve no
	// Device yet (zero derives it from the handshake rate and burst,
	// mtcp-v1 §14).
	UnauthenticatedPerSource int
	Keepalive                time.Duration
	IdleTimeout              time.Duration
	// UnprovenLimit closes a session that has not proved a Device within it
	// (zero: DefaultUnprovenLimit).
	UnprovenLimit time.Duration
	// DrainWindow spreads the reconnects of a shutdown: each session is told
	// to come back after a random delay within it (zero: at once).
	DrainWindow time.Duration
	Now         func() time.Time
}

// Server serves MTCP on the control listener. It is an http.Handler for
// the /mtcp/v1 paths; Shutdown closes and joins every session.
type Server struct {
	options    Options
	keys       map[key.KeyID]ControlKey
	admission  *admission
	recent     *timestampCache
	forwarding forwardingWarning

	mu        sync.Mutex
	shutdown  bool
	slots     int
	byMachine map[key.MachinePublic]*Session
	live      map[*Session]struct{}
	wg        sync.WaitGroup
}

// NewServer validates options without starting anything.
func NewServer(options Options) (*Server, error) {
	if len(options.Keys) == 0 || len(options.Keys) > 2 || options.Handler == nil || options.Logger == nil ||
		options.Metrics == nil {
		return nil, ErrInvalidServer
	}
	if options.MaxSessions <= 0 {
		options.MaxSessions = DefaultMaxSessions
	}
	if options.Keepalive <= 0 {
		options.Keepalive = DefaultKeepalive
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = DefaultIdleTimeout
	}
	if options.IdleTimeout <= options.Keepalive {
		return nil, ErrInvalidServer
	}
	if options.UnprovenLimit <= 0 {
		options.UnprovenLimit = DefaultUnprovenLimit
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	keys := make(map[key.KeyID]ControlKey, len(options.Keys))
	for _, controlKey := range options.Keys {
		if controlKey.Private.IsZero() || controlKey.NotAfter.IsZero() {
			return nil, ErrInvalidServer
		}
		keys[controlKey.Private.Public().ID()] = controlKey
	}
	if len(keys) != len(options.Keys) {
		return nil, ErrInvalidServer
	}
	options.Metrics.controlKeysExpire(options.Keys)
	rate := handshakeLimit(options.HandshakeRate, defaultHandshakeRate)
	burst := handshakeLimit(options.HandshakeBurst, defaultHandshakeBurst)
	server := &Server{options: options, keys: keys,
		admission: newAdmission(rate, burst,
			positiveOr(options.UnauthenticatedPerSource, defaultUnauthenticated(rate, burst)), options.Now),
		recent: newTimestampCache(), byMachine: make(map[key.MachinePublic]*Session),
		live: make(map[*Session]struct{})}
	options.Metrics.countExpiringDevices(server.expiringDevices)
	return server, nil
}

// Expiry windows of the expiring-Device gauge; the client warns at the same.
const (
	deviceExpirySoonWindow     = 14 * 24 * time.Hour
	deviceExpiryImminentWindow = 24 * time.Hour
)

// expiringDevices counts live sessions whose Device expires within 14 days
// and within one day and has not expired yet. The lock is held only for a
// read of each session's last expiry.
func (server *Server) expiringDevices() (within14d, within1d int) {
	now := server.options.Now()
	soon := now.Add(deviceExpirySoonWindow).UnixMilli()
	imminent := now.Add(deviceExpiryImminentWindow).UnixMilli()
	current := now.UnixMilli()
	server.mu.Lock()
	defer server.mu.Unlock()
	for session := range server.live {
		expiry := session.deviceKeyExpiry.Load()
		if expiry <= current || expiry > soon {
			continue
		}
		within14d++
		if expiry <= imminent {
			within1d++
		}
	}
	return within14d, within1d
}

// Handles reports whether the server owns a request path.
func Handles(path string) bool {
	return path == sharedmtcp.UpgradePath || path == sharedmtcp.WebSocketPath || path == sharedmtcp.KeyPath
}

// ServeHTTP serves control key discovery, the upgrade and the WebSocket
// fallback.
func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	switch request.URL.Path {
	case sharedmtcp.KeyPath:
		server.serveKeys(response, request)
	case sharedmtcp.UpgradePath:
		server.serveUpgrade(response, request)
	case sharedmtcp.WebSocketPath:
		server.serveWebSocket(response, request)
	default:
		http.NotFound(response, request)
	}
}

type keyDocument struct {
	Version int              `json:"version"`
	Keys    []keyDocumentKey `json:"keys"`
}

type keyDocumentKey struct {
	Key      key.ControlPublic `json:"key"`
	NotAfter time.Time         `json:"not_after"`
	// Fingerprint is the ck= value install commands carry (mtcp-v1 §2.1).
	Fingerprint string `json:"fingerprint"`
}

func (server *Server) serveKeys(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	document := keyDocument{Version: sharedmtcp.Version}
	for _, controlKey := range server.options.Keys {
		public := controlKey.Private.Public()
		document.Keys = append(document.Keys, keyDocumentKey{Key: public,
			NotAfter: controlKey.NotAfter.UTC().Truncate(time.Second), Fingerprint: sharedmtcp.ControlFingerprint(public)})
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > maxKeyDocument {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	_, _ = response.Write(encoded)
}

// pendingHandshake is an INIT admitted before cryptography. The source
// stays counted as unauthenticated until the session proves a Device (its
// first map snapshot) or ends; the slot is held for the whole session.
type pendingHandshake struct {
	init          []byte
	control       ControlKey
	releaseSource func()
	releaseSlot   func()
}

func (pending *pendingHandshake) release() {
	pending.releaseSource()
	pending.releaseSlot()
}

// admit applies admission and key selection, answering the HTTP error
// itself when it refuses (mtcp-v1 §2.2, §14).
func (server *Server) admit(response http.ResponseWriter, request *http.Request, init []byte) (*pendingHandshake, bool) {
	address, err := server.options.ClientIPs.Resolve(request)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return nil, false
	}
	if server.options.ClientIPs.ForwardedByUntrustedPeer(request) {
		server.noteUntrustedForwarding(request.Context())
	}
	keyID, err := hex.DecodeString(request.Header.Get(sharedmtcp.HeaderKey))
	if err != nil || len(keyID) != key.KeyIDSize {
		server.options.Metrics.handshake("invalid")
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return nil, false
	}
	control, known := server.keys[key.KeyID(keyID)]
	if !known {
		server.options.Metrics.handshake("unknown_key")
		http.Error(response, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return nil, false
	}
	release, admitted := server.admission.begin(address)
	if !admitted || !server.takeSlot() {
		if admitted {
			release()
		}
		server.options.Metrics.handshake("shed")
		response.Header().Set("Retry-After", "5")
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return nil, false
	}
	var slotOnce sync.Once
	return &pendingHandshake{init: init, control: control, releaseSource: release,
		releaseSlot: func() { slotOnce.Do(server.releaseSlot) }}, true
}

func (server *Server) serveUpgrade(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if !strings.EqualFold(request.Header.Get("Upgrade"), sharedmtcp.UpgradeToken) ||
		!headerContainsToken(request.Header, "Connection", "upgrade") || request.ContentLength > 0 {
		server.options.Metrics.handshake("invalid")
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	init, err := decodeHandshakeHeader(request.Header.Values(sharedmtcp.HeaderHandshake))
	if err != nil {
		server.options.Metrics.handshake("invalid")
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	pending, ok := server.admit(response, request, init)
	if !ok {
		return
	}
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		pending.release()
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		pending.release()
		return
	}
	started := server.options.Now()
	transport := newStreamConn(conn, buffered.Reader)
	server.handshake(request.Context(), transport, pending, started, func(responseBody []byte) error {
		_ = conn.SetWriteDeadline(started.Add(handshakeDeadline))
		_, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+sharedmtcp.UpgradeToken+
			"\r\nConnection: Upgrade\r\n"+sharedmtcp.HeaderHandshake+": "+
			base64.RawURLEncoding.EncodeToString(responseBody)+"\r\n\r\n")
		return err
	})
}

func (server *Server) serveWebSocket(response http.ResponseWriter, request *http.Request) {
	if !headerContainsToken(request.Header, "Sec-WebSocket-Protocol", sharedmtcp.WebSocketProtocol) {
		server.options.Metrics.handshake("invalid")
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	pending, ok := server.admit(response, request, nil)
	if !ok {
		return
	}
	conn, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols: []string{sharedmtcp.WebSocketProtocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		pending.release()
		return
	}
	conn.SetReadLimit(sharedmtcp.MaxRecord + 1)
	started := server.options.Now()
	transport := &webSocketConn{conn: conn, ctx: context.WithoutCancel(request.Context())}
	recordType, init, err := transport.ReadRecord(started.Add(handshakeDeadline))
	if err != nil || recordType != sharedmtcp.RecordInit {
		pending.release()
		server.options.Metrics.handshake("invalid")
		_ = transport.Close()
		return
	}
	pending.init = init
	server.handshake(request.Context(), transport, pending, started, func(responseBody []byte) error {
		return transport.WriteRecord(sharedmtcp.RecordResponse, responseBody, started.Add(handshakeDeadline))
	})
}

// handshake decrypts the INIT, applies replay and version policy, answers
// with the RESPONSE and runs the session. Failures before the RESPONSE
// close the connection without an answer (mtcp-v1 §3).
func (server *Server) handshake(parent context.Context, transport recordConn, pending *pendingHandshake,
	started time.Time, respond func([]byte) error) {
	defer pending.release()
	fail := func(result string) {
		server.options.Metrics.handshake(result)
		_ = transport.Close()
	}
	init, err := sharedmtcp.ReadInit(pending.control.Private, pending.init, rand.Reader)
	if err != nil {
		fail("decrypt")
		return
	}
	hello := init.Hello()
	now := server.options.Now()
	timestamp := time.UnixMilli(hello.GetTimestampMs())
	if timestamp.Before(now.Add(-timestampWindow)) || timestamp.After(now.Add(timestampWindow)) {
		fail("replay")
		return
	}
	check, accepted := server.acceptTimestamp(parent, init.Machine(), hello.GetNodeKey(), hello.GetTimestampMs())
	if !accepted {
		fail("replay")
		return
	}
	reply := &mtcpv1.ServerHello{
		ProtocolVersion: sharedmtcp.Version, ServerTimeMs: now.UnixMilli(), SessionId: make([]byte, 16),
		Capabilities: intersect(hello.GetCapabilities(), server.options.Capabilities),
		Limits: &mtcpv1.Limits{KeepaliveS: uint32(server.options.Keepalive / time.Second), //nolint:gosec // bounded
			IdleTimeoutS: uint32(server.options.IdleTimeout / time.Second), MaxUnackedMap: maxUnackedMap}, //nolint:gosec // bounded
	}
	if _, err := rand.Read(reply.SessionId); err != nil {
		fail("internal")
		return
	}
	if hello.GetProtocolVersion() != sharedmtcp.Version {
		reply.Reject = mtcpv1.ServerHello_VERSION_UNSUPPORTED
	}
	noise, responseBody, err := init.Respond(reply)
	if err != nil || respond(responseBody) != nil {
		fail("respond")
		return
	}
	if reply.Reject != mtcpv1.ServerHello_REJECT_UNSPECIFIED {
		fail("rejected")
		return
	}
	session := newSession(server, transport, noise, pending.control.Private, init.Machine(), hello, reply)
	session.gate = check
	server.options.Metrics.handshake("responded")
	session.run(parent, started.Add(handshakeDeadline), pending.releaseSource)
}

// acceptTimestamp applies replay protection: the replica's cache, then the
// durable guard. A gateway's timestamp enters neither before its proof
// (commitGatewayTimestamp).
func (server *Server) acceptTimestamp(ctx context.Context, machine key.MachinePublic, nodeKey []byte,
	timestampMS int64) (TimestampCheck, bool) {
	if !server.recent.newer(machine, timestampMS) {
		return TimestampCheck{}, false
	}
	check := TimestampCheck{Accepted: true}
	if server.options.Guard != nil {
		guardCtx, cancel := context.WithTimeout(ctx, writeTimeout)
		defer cancel()
		var err error
		check, err = server.options.Guard.AcceptTimestamp(guardCtx, node.MachineKey(machine).Fingerprint(), nodeKey,
			timestampMS)
		if err != nil {
			server.options.Logger.WarnContext(ctx, "mtcp timestamp check failed",
				"error_code", "mtcp_timestamp_unavailable")
			return TimestampCheck{}, false
		}
	}
	if !check.Accepted || !check.Gateway && !server.recent.accept(machine, timestampMS) {
		return TimestampCheck{}, false
	}
	return check, true
}

// commitGatewayTimestamp records a gateway's handshake timestamp after its
// proof, durably and in the replica's cache; false is a replay.
func (server *Server) commitGatewayTimestamp(ctx context.Context, machine key.MachinePublic, nodeKey []byte,
	timestampMS int64) bool {
	if server.options.Guard == nil {
		return server.recent.accept(machine, timestampMS)
	}
	guardCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	committed, err := server.options.Guard.CommitGatewayTimestamp(guardCtx, node.MachineKey(machine).Fingerprint(),
		nodeKey, timestampMS)
	if err != nil {
		server.options.Logger.WarnContext(ctx, "mtcp gateway timestamp failed",
			"error_code", "mtcp_timestamp_unavailable")
		return false
	}
	return committed && server.recent.accept(machine, timestampMS)
}

func (server *Server) takeSlot() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.shutdown || server.slots >= server.options.MaxSessions {
		return false
	}
	server.slots++
	server.wg.Add(1)
	return true
}

func (server *Server) releaseSlot() {
	server.mu.Lock()
	server.slots--
	server.mu.Unlock()
	server.wg.Done()
}

// establish registers a session for its machine key; a newer established
// session replaces an older one (mtcp-v1 §5).
func (server *Server) establish(session *Session) error {
	server.mu.Lock()
	if server.shutdown {
		server.mu.Unlock()
		return errShuttingDown
	}
	previous := server.byMachine[session.machine]
	server.byMachine[session.machine] = session
	server.live[session] = struct{}{}
	session.established.Store(server.options.Now().UnixNano())
	server.mu.Unlock()
	server.options.Metrics.sessionOpened()
	if previous != nil {
		previous.replace()
	}
	return nil
}

func (server *Server) forget(session *Session) {
	server.mu.Lock()
	if server.byMachine[session.machine] == session {
		delete(server.byMachine, session.machine)
	}
	_, registered := server.live[session]
	delete(server.live, session)
	server.mu.Unlock()
	if registered {
		server.options.Metrics.sessionClosed()
	}
}

// Shutdown stops admission, tells every session to reconnect within the
// drain window (so the other replicas take them over gradually, not all
// at once), ends them and waits for them.
func (server *Server) Shutdown(ctx context.Context) error {
	server.mu.Lock()
	server.shutdown = true
	sessions := server.liveSessionsLocked()
	server.mu.Unlock()
	server.sayGoodbye(ctx, sessions, server.options.DrainWindow, "the control replica is shutting down",
		errShuttingDown)
	done := make(chan struct{})
	go func() {
		server.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func decodeHandshakeHeader(values []string) ([]byte, error) {
	if len(values) != 1 || len(values[0]) == 0 ||
		len(values[0]) > base64.RawURLEncoding.EncodedLen(sharedmtcp.MaxHandshakeRecord) {
		return nil, sharedmtcp.ErrMalformed
	}
	decoded, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(decoded) == 0 || len(decoded) > sharedmtcp.MaxHandshakeRecord {
		return nil, sharedmtcp.ErrMalformed
	}
	return decoded, nil
}

func headerContainsToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func intersect(offered, supported []string) []string {
	var both []string
	for _, name := range offered {
		if slices.Contains(supported, name) && !slices.Contains(both, name) {
			both = append(both, name)
		}
	}
	return both
}

// positiveOr returns configured, or fallback when it is not positive.
func positiveOr(configured, fallback int) int {
	if configured <= 0 {
		return fallback
	}
	return configured
}

func handshakeLimit(configured int, fallback float64) float64 {
	if configured <= 0 {
		return fallback
	}
	return float64(configured)
}
