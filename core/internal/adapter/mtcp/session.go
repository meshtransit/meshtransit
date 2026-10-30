package mtcp

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

var (
	// ErrSessionReplaced ends a session that a newer one for the same
	// machine key replaced.
	ErrSessionReplaced = errors.New("mtcp: session replaced")
	// errSessionUnproven ends a session that proved no Device within the
	// unproven limit (mtcp-v1 §14).
	errSessionUnproven = errors.New("mtcp: session proved no Device in time")
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
	control      key.ControlPrivate     // the key the node chose; proofs bind to it
	openedBy     sharedmtcp.MessageType // the message that established the session
	// gate is what the handshake's keys are (TimestampGuard); provenNodeKey
	// is the ClientHello node key once a NodeKeyProof proved it (§6.7). Both
	// are set before the session is established and never change.
	gate          TimestampCheck
	provenNodeKey node.Key

	sendMu   sync.Mutex
	lastSend atomic.Int64 // Unix nanoseconds of the last record sent
	// lastReceive is when the last message arrived (Unix nanoseconds), and
	// streaming whether the session started a map stream: together they
	// tell a gateway's live stream from a probe or a half-open session.
	lastReceive atomic.Int64
	streaming   atomic.Bool
	// established is when the session was registered with the server
	// (Unix nanoseconds); rebalancing leaves young sessions alone.
	established atomic.Int64
	// deviceKeyExpiry is the served Device's key expiry (Unix ms) in the
	// last map sent; zero before one. It feeds the expiring-Device gauge.
	deviceKeyExpiry atomic.Int64

	ctx    context.Context
	cancel context.CancelCauseFunc
	once   sync.Once

	// releaseSource stops counting the session against its source's
	// unauthenticated connections (mtcp-v1 §14); proveDevice runs it once.
	releaseSource func()
	proveOnce     sync.Once
	proven        atomic.Bool

	// inboundMessages and inboundBytes bound everything the node sends
	// (rate_budget.go); only the run loop uses them.
	inboundMessages rateBudget
	inboundBytes    rateBudget
	// auditBytes and auditCeiling bound gateway.audit1 messages instead
	// (rate_budget.go); auditOver says the message being handled is over
	// auditBytes. Only the run loop uses them.
	auditBytes   rateBudget
	auditCeiling rateBudget
	auditOver    bool
	// joinedGateway: the session joined a Kubernetes cluster, so it serves
	// a gateway whatever its hello said.
	joinedGateway atomic.Bool
	// token is a gateway session's pod token (gateway.token1); the run
	// loop alone uses it. tokenProven mirrors token.proven for the session
	// that replaces this one.
	token       gatewayTokenState
	tokenProven atomic.Bool
	// joinedAt (Unix ns) and joinedNodeKey are set once the session's
	// cluster join ratcheted its Device (ratchetJoinedGateway, which runs
	// off the run loop).
	joinedAt      atomic.Int64
	joinedNodeKey atomic.Pointer[node.Key]
	// groupsAt is when the session's last kept group report came (§6.11).
	groupsAt time.Time
}

func newSession(server *Server, transport recordConn, noise *sharedmtcp.Session, control key.ControlPrivate,
	machine key.MachinePublic, hello *mtcpv1.ClientHello, reply *mtcpv1.ServerHello) *Session {
	return &Session{server: server, transport: transport, noise: noise, control: control, machine: machine,
		hello: hello, reply: reply, capabilities: reply.GetCapabilities(),
		inboundMessages: newRateBudget(inboundMessageBurst, inboundMessageRate),
		inboundBytes:    newRateBudget(inboundByteBurst, inboundByteRate),
		auditBytes:      newRateBudget(auditByteBurst, auditByteRate),
		auditCeiling:    newRateBudget(auditCeilingBurst, auditCeilingRate),
		token:           gatewayTokenState{refresh: newRateBudget(gatewayTokenRefreshBurst, gatewayTokenRefreshRate)},
	}
}

// isAuditMessage reports a gateway.audit1 message from the node.
func isAuditMessage(t sharedmtcp.MessageType) bool {
	return t == sharedmtcp.MessageKubeAuditIntents || t == sharedmtcp.MessageKubeAuditOutcomes
}

// auditCost is what an audit message spends of the audit budget: its
// records or its decoded size, whichever is more (a compressed message
// costs what Core decodes), and never less than auditMessageFloor.
func auditCost(message inbound) float64 {
	return float64(max(message.size, proto.Size(message.message), auditMessageFloor))
}

// AuditOverBudget reports whether the gateway.audit1 message being handled
// is over the session's audit budget: its intents are refused limited and
// its outcomes dropped (K1b0 §3.5). Only the conversation's Receive, on the
// run loop, may call it.
func (session *Session) AuditOverBudget() bool { return session.auditOver }

// Machine returns the session's authenticated machine key.
func (session *Session) Machine() key.MachinePublic { return session.machine }

// Hello returns the node's ClientHello.
func (session *Session) Hello() *mtcpv1.ClientHello { return session.hello }

// SessionID returns the random session ID both sides log.
func (session *Session) SessionID() []byte { return session.reply.GetSessionId() }

// HandshakeHash returns the channel binding of proofs of possession.
func (session *Session) HandshakeHash() [32]byte { return session.noise.HandshakeHash() }

// OpenedBy returns the type of the message that established the session:
// MessagePing or MessageRegisterRequest.
func (session *Session) OpenedBy() sharedmtcp.MessageType { return session.openedBy }

// VerifyKeyProof checks a proof of possession of a node or disco key, bound
// to this session's handshake and control key (mtcp-v1 §6.4).
func (session *Session) VerifyKeyProof(public []byte, proof []byte) bool {
	if len(public) != key.Size {
		return false
	}
	return sharedmtcp.VerifyKeyProof(session.control, session.noise.HandshakeHash(), [key.Size]byte(public), proof)
}

// ProvenNodeKey returns the ClientHello node key when the session proved it
// as its first record (mtcp-v1 §6.7).
func (session *Session) ProvenNodeKey() (node.Key, bool) {
	return session.provenNodeKey, session.provenNodeKey.IsValid()
}

// RotationWait is how long the session must wait before it rotates a key:
// non-zero while a gateway session of its machine key lately pushed out a
// live one on this replica (mtcp-v1 §6.8).
func (session *Session) RotationWait() time.Duration {
	return session.server.rotationWait(session.machine)
}

// IsGateway reports whether the machine key belongs to a Kubernetes
// gateway: then the session proved its node key before anything else.
func (session *Session) IsGateway() bool { return session.gate.Gateway }

// servesGateway reports a gateway's session: by its hello, or since it
// joined a cluster in it (review b0b3 L4).
func (session *Session) servesGateway() bool {
	return session.gate.Gateway || session.joinedGateway.Load()
}

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
	size := 0
	for _, fragment := range fragments {
		size += len(fragment)
	}
	// Each record still has writeTimeout, but the whole message must also go
	// out by its send deadline: a node that reads one record every few
	// seconds cannot hold a large map in memory for an hour (mtcp-v1 §14).
	overall := sendDeadline(session.server.options.Now(), size)
	for _, fragment := range fragments {
		record, err := session.noise.Seal(nil, fragment)
		if err != nil {
			return err
		}
		deadline := session.server.options.Now().Add(writeTimeout)
		if deadline.After(overall) {
			deadline = overall
		}
		if err := session.transport.WriteRecord(sharedmtcp.RecordTransport, record, deadline); err != nil {
			if !session.server.options.Now().Before(overall) &&
				(errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)) {
				session.server.options.Metrics.limited(limitSendDeadline)
				session.close(errSendDeadline)
				return errors.Join(errSendDeadline, err)
			}
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

// Send deadline (mtcp-v1 §14): every message gets sendDeadlineBase plus the
// time to send it at sendMinimumRate, at most sendDeadlineMaximum.
const (
	sendDeadlineBase    = 30 * time.Second
	sendMinimumRate     = 64 * 1024 // bytes per second
	sendDeadlineMaximum = 10 * time.Minute
)

// errSendDeadline ends a session that did not take a message by its send
// deadline; the node reconnects.
var errSendDeadline = errors.New("mtcp: message not sent by its deadline")

func sendDeadline(start time.Time, size int) time.Time {
	limit := sendDeadlineBase + time.Duration(size)*time.Second/sendMinimumRate
	return start.Add(min(limit, sendDeadlineMaximum))
}

// errSessionLimited ends a session that went over one of its limits.
var errSessionLimited = errors.New("mtcp: session over its limits")

// endOverloaded ends a session that sends more than the protocol allows:
// the node reconnects after wait (mtcp-v1 §14).
func (session *Session) endOverloaded(message string, wait time.Duration) {
	_ = session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Code: mtcpv1.Error_OVERLOADED, Message: message,
		Fatal: true, RetryAfterMs: retryAfterMS(wait)})
	session.close(errSessionLimited)
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
	size    int // bytes of the records that carried it
}

// run waits for the first TRANSPORT record, which establishes the session,
// then serves it until either side ends it (mtcp-v1 §3, §5).
// proveDevice records that the session serves an authorized Device: it no
// longer counts against its source, and it may stay open past the
// unproven limit. Sending the first map snapshot proves it.
func (session *Session) proveDevice() {
	session.proveOnce.Do(func() {
		session.proven.Store(true)
		if session.releaseSource != nil {
			session.releaseSource()
		}
	})
}

// closeUnproven ends a session that did not prove a Device in time.
func (session *Session) closeUnproven() {
	if session.proven.Load() || session.ctx.Err() != nil {
		return // proved, or already ending for another reason
	}
	session.server.options.Metrics.unprovenClosed()
	session.close(errSessionUnproven)
}

// run serves the session. releaseSource is called once the session proves a
// Device; the caller releases the source again, idempotently, when run ends.
func (session *Session) run(parent context.Context, establishBy time.Time, releaseSource func()) {
	session.ctx, session.cancel = context.WithCancelCause(context.WithoutCancel(parent))
	defer session.close(context.Canceled)
	assembler := sharedmtcp.NewAssembler(sharedmtcp.NodeToCore)
	first, err := session.receive(assembler, establishBy)
	if err != nil {
		session.server.options.Metrics.handshake("not_established")
		return
	}
	// A node may prove its node key as its first record; a gateway must
	// (mtcp-v1 §6.7). Nothing is established, replaced or sent before.
	if first.t == sharedmtcp.MessageNodeKeyProof {
		if !session.checkNodeKeyProof(first.message) {
			return
		}
		if first, err = session.receive(assembler, establishBy); err != nil {
			session.server.options.Metrics.handshake("not_established")
			return
		}
	} else if session.gate.Gateway {
		session.server.options.Metrics.handshake("gateway_unproven")
		session.SendError(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateProveFirst, true)
		return
	}
	if first.t != sharedmtcp.MessagePing && first.t != sharedmtcp.MessageRegisterRequest {
		session.server.options.Metrics.handshake("not_established")
		return
	}
	session.openedBy = first.t
	if err := session.server.establish(session); err != nil {
		return
	}
	defer session.server.forget(session)
	session.releaseSource = releaseSource
	unproven := time.AfterFunc(session.server.options.UnprovenLimit, session.closeUnproven)
	defer unproven.Stop()
	session.server.options.Metrics.handshake("established")

	conversation := session.server.options.Handler.Open(session)
	messages := make(chan inbound, 16)
	readerDone := make(chan error, 1)
	go func() { readerDone <- session.readLoop(assembler, messages) }()
	runDone := make(chan error, 1)
	go func() { runDone <- conversation.Run(session.ctx) }()
	runJoined := false
	defer func() {
		// The conversation ends with the session: join it, so Shutdown
		// waits for its work too.
		session.close(context.Canceled)
		if !runJoined {
			<-runDone
		}
	}()

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
			runJoined = true
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
			if !session.gatewayTokenClock(session.server.options.Now()) {
				return
			}
			last := time.Unix(0, session.lastSend.Load())
			if now.Sub(last) >= session.server.options.Keepalive {
				if err := session.Send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
					return
				}
			}
		}
	}
}

// gatewayFutureSkew is how far ahead of Core a gateway's handshake
// timestamp may be (mtcp-v1 §6.7).
const gatewayFutureSkew = 5 * time.Second

// checkNodeKeyProof checks a session's first record (mtcp-v1 §6.7). A
// gateway's session ends unless the proof holds for its current keys and
// its timestamp is recorded; an ordinary node only learns the answer. It
// reports whether the session goes on.
func (session *Session) checkNodeKeyProof(message proto.Message) bool {
	proof, _ := message.(*mtcpv1.NodeKeyProof)
	nodeKey := session.hello.GetNodeKey()
	valid := len(nodeKey) == key.Size && sharedmtcp.VerifyNodeKeySessionProof(session.control,
		session.noise.HandshakeHash(), [key.Size]byte(nodeKey), proof.GetProof())
	gate := session.gate
	if !gate.Gateway {
		switch {
		case gate.Machine == MachineUnbound:
			session.SendError(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateMachineUnbound, false)
		case !valid:
			session.SendError(mtcpv1.Error_INVALID, sharedmtcp.GateInvalidProof, false)
		case gate.Machine != MachineCurrent || !gate.NodeCurrent:
			session.SendError(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateNodeNotCurrent, false)
		default:
			session.provenNodeKey = node.Key(nodeKey)
		}
		return true
	}
	refuse := func(result, message string) bool {
		session.server.options.Metrics.handshake(result)
		session.SendError(mtcpv1.Error_NOT_AUTHORIZED, message, true)
		return false
	}
	// Each of these is audited off the handshake path (schema 229).
	report := func(reason kubecluster.KeyEventReason) {
		session.server.keyReports.report(node.MachineKey(session.machine).Fingerprint(), reason)
	}
	switch {
	case gate.Machine != MachineCurrent:
		report(kubecluster.KeyEventRetiredMachineKey)
		return refuse("gateway_retired", sharedmtcp.GateMachineRetired)
	case !gate.NodeCurrent:
		report(kubecluster.KeyEventStaleNodeKey)
		return refuse("gateway_stale_node_key", sharedmtcp.GateNodeNotCurrent)
	case !valid:
		return refuse("gateway_bad_proof", sharedmtcp.GateInvalidProof)
	case time.UnixMilli(session.hello.GetTimestampMs()).After(session.server.options.Now().Add(gatewayFutureSkew)):
		// A gateway's clock is synchronized: a timestamp far ahead would
		// shut its real pod out as a replay until time caught up.
		return refuse("gateway_future_timestamp", sharedmtcp.GateAhead)
	}
	// The pod token before the replay check: a copy of the Secret without
	// one neither contests the keys nor records its timestamp (K1c-T §3.3).
	tokens := session.server.options.GatewayTokens
	tokenProven := false
	if tokens != nil {
		var result, refused string
		tokenProven, result, refused = session.handshakeToken(proof.GetPodToken(), node.Key(nodeKey))
		if refused != "" {
			return refuse(result, refused)
		}
	}
	if !gate.Accepted {
		// A valid proof cannot be replayed (it binds this handshake): a
		// second holder of the keys took a newer timestamp, so the key is
		// contested and neither holder rotates (§6.8).
		session.server.contest(session.machine)
		report(kubecluster.KeyEventReplayedHandshake)
		return refuse("replay", sharedmtcp.GateReplayed)
	}
	if tokens != nil {
		if !session.commitGatewayTokenTimestamp(nodeKey, tokenProven, refuse) {
			return false
		}
		session.provenNodeKey = node.Key(nodeKey)
		session.markGroupsUnsupported()
		return true
	}
	committed, err := session.server.commitGatewayTimestamp(session.ctx, session.machine, nodeKey,
		session.hello.GetTimestampMs())
	switch {
	case err != nil:
		return refuse("internal", sharedmtcp.GateUnavailable)
	case !committed:
		// The commit also fails when the keys stopped being current since
		// the gate (a rotation, a revocation): not a replay worth auditing.
		session.server.contest(session.machine)
		return refuse("replay", sharedmtcp.GateReplayed)
	}
	session.provenNodeKey = node.Key(nodeKey)
	session.markGroupsUnsupported()
	return true
}

// admitInbound spends a message's share of the session's inbound budget,
// ending the session when it is over.
func (session *Session) admitInbound(now time.Time, message inbound) bool {
	// A MapAck answers map messages Core chose to send, and a node may ack
	// each one (older nodes do), so acks follow Core's own rate: they count only as bytes.
	cost := 1.0
	if message.t == sharedmtcp.MessageMapAck {
		cost = 0
	}
	wait, ok := session.inboundMessages.spend(now, cost)
	if ok {
		var byteWait time.Duration
		if byteWait, ok = session.inboundBytes.spend(now, float64(message.size)); !ok {
			wait = byteWait
			session.inboundMessages.refund(cost) // the message was not admitted
		}
	}
	if !ok {
		session.server.options.Metrics.limited(limitInbound)
		session.endOverloaded("too many messages", wait)
	}
	return ok
}

// dispatch answers Ping, ignores Pong and gives everything else to the
// conversation. It reports false when the session must end.
func (session *Session) dispatch(conversation Conversation, message inbound) bool {
	now := session.server.options.Now()
	session.auditOver = false
	// A gateway past its pod token's deadline is cut before anything it
	// sends is served (mtcp-v1 §6.7); the keepalive tick checks too.
	if !session.gatewayTokenClock(now) {
		return false
	}
	if isAuditMessage(message.t) && session.servesGateway() && session.Supports(CapabilityKubeAudit) {
		// A gateway's own budget (K1b0 §3.5): never the inbound one, so audit
		// never ends its map stream; the ceiling bounds the work it makes.
		// Any other sender spends the inbound budget, and the conversation
		// refuses the message (review b0b1 H1).
		cost := auditCost(message)
		if wait, ok := session.auditCeiling.spend(now, cost); !ok {
			session.server.options.Metrics.limited(limitAuditCeiling)
			session.endOverloaded("too many audit records", wait)
			return false
		}
		if _, ok := session.auditBytes.spend(now, cost); !ok {
			session.server.options.Metrics.limited(limitAudit)
			session.auditOver = true
		}
	} else if !session.admitInbound(now, message) {
		return false
	}
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
	case sharedmtcp.MessageNodeKeyProof:
		session.SendError(mtcpv1.Error_INVALID, "a node key proof must be the first record", false)
		return true
	case sharedmtcp.MessageGatewayPodToken:
		token, _ := message.message.(*mtcpv1.GatewayPodToken)
		return session.refreshGatewayToken(now, token)
	case sharedmtcp.MessageGatewayGroupReport:
		report, _ := message.message.(*mtcpv1.GatewayGroupReport)
		return session.receiveGroupReport(now, report)
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
		session.lastReceive.Store(session.server.options.Now().UnixNano())
		select {
		case messages <- message:
		case <-session.ctx.Done():
			return context.Cause(session.ctx)
		}
	}
}

// receive reads records until one message is complete.
func (session *Session) receive(assembler *sharedmtcp.Assembler, deadline time.Time) (inbound, error) {
	size := 0
	for {
		recordType, body, err := session.transport.ReadRecord(deadline)
		if err != nil {
			return inbound{}, err
		}
		size += len(body)
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
		return inbound{t: t, message: message, size: size}, nil
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

// newer reports whether timestampMS is newer than the cached one, without
// recording it.
func (cache *timestampCache) newer(machine key.MachinePublic, timestampMS int64) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	previous, found := cache.last[machine]
	return !found || timestampMS > previous
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
