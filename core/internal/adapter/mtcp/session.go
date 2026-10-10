package mtcp

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

var (
	// ErrSessionReplaced ends a session that a newer one for the same
	// machine key replaced.
	ErrSessionReplaced = errors.New("mtcp: session replaced")
	// ErrIdle ends a session that received nothing within the idle timeout.
	ErrIdle = errors.New("mtcp: session idle")
	// ErrProtocol ends a session whose peer broke the protocol.
	ErrProtocol = errors.New("mtcp: protocol violation")
)

// Session is one established MTCP session. Its send methods are safe for
// concurrent use.
type Session struct {
	server       *Server
	transport    recordConn
	noise        *sharedmtcp.Session
	machine      key.MachinePublic
	hello        *mtcpv1.ClientHello
	reply        *mtcpv1.ServerHello
	capabilities []string

	sendMu   sync.Mutex
	lastSend atomic.Int64 // Unix nanoseconds of the last record sent

	ctx    context.Context
	cancel context.CancelCauseFunc
	once   sync.Once
}

func newSession(server *Server, transport recordConn, noise *sharedmtcp.Session, machine key.MachinePublic,
	hello *mtcpv1.ClientHello, reply *mtcpv1.ServerHello) *Session {
	return &Session{server: server, transport: transport, noise: noise, machine: machine, hello: hello,
		reply: reply, capabilities: reply.GetCapabilities()}
}

// Machine returns the session's authenticated machine key.
func (session *Session) Machine() key.MachinePublic { return session.machine }

// Hello returns the node's ClientHello.
func (session *Session) Hello() *mtcpv1.ClientHello { return session.hello }

// SessionID returns the random session ID both sides log.
func (session *Session) SessionID() []byte { return session.reply.GetSessionId() }

// HandshakeHash returns the channel binding of proofs of possession.
func (session *Session) HandshakeHash() [32]byte { return session.noise.HandshakeHash() }

// Supports reports whether both sides negotiated a capability.
func (session *Session) Supports(capability string) bool {
	return slices.Contains(session.capabilities, capability)
}

// Context ends when the session ends.
func (session *Session) Context() context.Context { return session.ctx }

// Send encodes, fragments, seals and writes one message.
func (session *Session) Send(t sharedmtcp.MessageType, message proto.Message) error {
	compress := session.Supports("map.zstd") && (t == sharedmtcp.MessageMapSnapshot || t == sharedmtcp.MessageMapDelta)
	fragments, err := sharedmtcp.EncodeMessage(t, message, sharedmtcp.CoreToNode,
		sharedmtcp.EncodeOptions{Compress: compress})
	if err != nil {
		return err
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	for _, fragment := range fragments {
		record, err := session.noise.Seal(nil, fragment)
		if err != nil {
			return err
		}
		if err := session.transport.WriteRecord(sharedmtcp.RecordTransport, record,
			session.server.options.Now().Add(writeTimeout)); err != nil {
			return err
		}
	}
	session.lastSend.Store(session.server.options.Now().UnixNano())
	session.server.options.Metrics.sent(t)
	return nil
}

// SendError sends an Error and, when fatal, ends the session.
func (session *Session) SendError(code mtcpv1.Error_Code, message string, fatal bool) {
	_ = session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Code: code, Message: message, Fatal: fatal})
	if fatal {
		session.close(ErrProtocol)
	}
}

func (session *Session) close(cause error) {
	session.once.Do(func() {
		if session.cancel != nil {
			session.cancel(cause)
		}
		_ = session.transport.Close()
	})
}

func (session *Session) replace() {
	_ = session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Code: mtcpv1.Error_SESSION_REPLACED,
		Message: "a newer session for this machine key exists", Fatal: true})
	session.close(ErrSessionReplaced)
}

type inbound struct {
	t       sharedmtcp.MessageType
	message proto.Message
}

// run waits for the first TRANSPORT record, which establishes the session,
// then serves it until either side ends it (mtcp-v1 §3, §5).
func (session *Session) run(parent context.Context, establishBy time.Time, established func()) {
	session.ctx, session.cancel = context.WithCancelCause(context.WithoutCancel(parent))
	defer session.close(context.Canceled)
	assembler := sharedmtcp.NewAssembler(sharedmtcp.NodeToCore)
	first, err := session.receive(assembler, establishBy)
	if err != nil {
		session.server.options.Metrics.handshake("not_established")
		return
	}
	if first.t != sharedmtcp.MessagePing && first.t != sharedmtcp.MessageRegisterRequest {
		session.server.options.Metrics.handshake("not_established")
		return
	}
	if err := session.server.establish(session); err != nil {
		return
	}
	defer session.server.forget(session)
	established()
	session.server.options.Metrics.handshake("established")

	conversation := session.server.options.Handler.Open(session)
	messages := make(chan inbound, 16)
	readerDone := make(chan error, 1)
	go func() { readerDone <- session.readLoop(assembler, messages) }()
	runDone := make(chan error, 1)
	go func() { runDone <- conversation.Run(session.ctx) }()

	// Checked five times per interval, a Ping leaves at most a fifth of the
	// interval late (mtcp-v1 §5: after keepalive_s without sending).
	keepalive := time.NewTicker(session.server.options.Keepalive / 5)
	defer keepalive.Stop()
	pending := []inbound{first}
	for {
		for len(pending) > 0 {
			message := pending[0]
			pending = pending[1:]
			if !session.dispatch(conversation, message) {
				return
			}
		}
		select {
		case <-session.ctx.Done():
			return
		case err := <-runDone:
			if err != nil && session.ctx.Err() == nil {
				session.server.options.Logger.DebugContext(session.ctx, "mtcp conversation ended", "error", err)
			}
			return
		case err := <-readerDone:
			session.close(err)
			return
		case message := <-messages:
			pending = append(pending, message)
		case now := <-keepalive.C:
			last := time.Unix(0, session.lastSend.Load())
			if now.Sub(last) >= session.server.options.Keepalive {
				if err := session.Send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
					return
				}
			}
		}
	}
}

// dispatch answers Ping, ignores Pong and gives everything else to the
// conversation. It reports false when the session must end.
func (session *Session) dispatch(conversation Conversation, message inbound) bool {
	switch message.t {
	case sharedmtcp.MessagePing:
		ping, _ := message.message.(*mtcpv1.Ping)
		if len(ping.GetNonce()) > 32 {
			session.SendError(mtcpv1.Error_INVALID, "ping nonce too long", true)
			return false
		}
		return session.Send(sharedmtcp.MessagePong, &mtcpv1.Pong{Nonce: ping.GetNonce()}) == nil
	case sharedmtcp.MessageError:
		return true
	}
	if err := conversation.Receive(session.ctx, message.t, message.message); err != nil {
		var violation protocolError
		if errors.As(err, &violation) {
			session.SendError(violation.code, violation.message, true)
		}
		return false
	}
	return true
}

// readLoop decrypts records and hands complete messages to run. Pong is
// delivered too, so a conversation can match KeyUpdate acknowledgements.
func (session *Session) readLoop(assembler *sharedmtcp.Assembler, messages chan<- inbound) error {
	for {
		message, err := session.receive(assembler, session.server.options.Now().Add(session.server.options.IdleTimeout))
		if err != nil {
			return err
		}
		select {
		case messages <- message:
		case <-session.ctx.Done():
			return context.Cause(session.ctx)
		}
	}
}

// receive reads records until one message is complete.
func (session *Session) receive(assembler *sharedmtcp.Assembler, deadline time.Time) (inbound, error) {
	for {
		recordType, body, err := session.transport.ReadRecord(deadline)
		if err != nil {
			return inbound{}, err
		}
		if recordType != sharedmtcp.RecordTransport {
			return inbound{}, ErrProtocol
		}
		fragment, err := session.noise.Open(nil, body)
		if err != nil {
			return inbound{}, err
		}
		t, payload, complete, err := assembler.Add(fragment)
		if err != nil {
			code := mtcpv1.Error_INVALID
			if errors.Is(err, sharedmtcp.ErrUnsupported) {
				code = mtcpv1.Error_UNSUPPORTED
			}
			session.SendError(code, "malformed message", true)
			return inbound{}, err
		}
		if !complete {
			continue
		}
		message, err := sharedmtcp.DecodeMessage(t, payload)
		if err != nil {
			session.SendError(mtcpv1.Error_INVALID, "malformed message", true)
			return inbound{}, err
		}
		session.server.options.Metrics.received(t)
		return inbound{t: t, message: message}, nil
	}
}

// protocolError lets a conversation end a session with a specific Error.
type protocolError struct {
	code    mtcpv1.Error_Code
	message string
}

func (err protocolError) Error() string { return "mtcp: " + err.message }

// Violation returns an error that ends the session with a fatal Error of
// code; message must not carry secrets or other tenants' data.
func Violation(code mtcpv1.Error_Code, message string) error {
	return protocolError{code: code, message: message}
}

// timestampCache keeps the last accepted ClientHello timestamp per machine
// key on this replica, bounded; durable state for bound keys lives behind
// TimestampGuard.
type timestampCache struct {
	mu   sync.Mutex
	last map[key.MachinePublic]int64
}

const maxCachedTimestamps = 1 << 16

func newTimestampCache() *timestampCache {
	return &timestampCache{last: make(map[key.MachinePublic]int64)}
}

func (cache *timestampCache) accept(machine key.MachinePublic, timestampMS int64) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if previous, found := cache.last[machine]; found && timestampMS <= previous {
		return false
	}
	if len(cache.last) >= maxCachedTimestamps {
		clear(cache.last) // the durable guard still protects bound keys
	}
	cache.last[machine] = timestampMS
	return true
}
