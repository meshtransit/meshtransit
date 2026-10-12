package interchange

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// Session behaviour (MTRP §5).
const (
	defaultKeepalive = 25 * time.Second
	// A session that hears nothing for probeAfter sends a KEEPALIVE every
	// probeEvery and is declared dead after three unanswered probes plus a
	// round-trip allowance, so a relay that dies silently is replaced in
	// seconds (production criterion: failover within 5 s). An idle session
	// costs one probe and one answer every probeAfter.
	probeAfter         = 1200 * time.Millisecond
	probeEvery         = 800 * time.Millisecond
	probeTick          = 200 * time.Millisecond
	minProbeAnswer     = 400 * time.Millisecond
	maxProbeAnswer     = 2 * time.Second
	probesBeforeDead   = 3
	routeOpenTimeout   = 5 * time.Second
	routeRefusalPause  = 2 * time.Second
	maxPendingPackets  = 8
	credentialInterval = 30 * time.Second
	eventQueue         = 256
	// An MTT2 ticket's ZONES frames are sent again, backing off, until the
	// relay acknowledges the ticket; datagrams may be lost.
	zonesResendFirst = time.Second
	zonesResendMax   = time.Minute
)

var (
	// ErrClosed reports use of a closed client.
	ErrClosed = errors.New("interchange: client closed")
	// ErrRelayUnresponsive reports a relay that stopped answering keepalives.
	ErrRelayUnresponsive = errors.New("interchange: relay unresponsive")
)

// SessionClosedError reports that the relay ended the session.
type SessionClosedError struct {
	Reason     mtrp.SessionCloseReason
	RetryAfter time.Duration
}

func (e *SessionClosedError) Error() string {
	return fmt.Sprintf("interchange: relay closed the session (reason %d, retry after %s)", e.Reason, e.RetryAfter)
}

type routeState struct {
	number   uint32 // 0 while an open is pending
	request  uint32
	opened   time.Time
	refused  time.Time
	pending  [][]byte
	incoming bool
}

// Client is one authenticated MTRP session with a relay node. It implements
// relay.Client: peers are addressed by node key, and routes are opened on
// first use.
type Client struct {
	transport   transport
	frames      *pump
	session     *mtrp.Session
	disco       key.DiscoPublic
	credentials Credentials
	now         func() time.Time
	keepalive   time.Duration

	mu          sync.Mutex
	byPeer      map[relay.Key]*routeState
	byRoute     map[uint32]relay.Key
	nextRequest uint32
	ticket      []byte
	lastRecv    time.Time
	probeSent   time.Time     // last unanswered KEEPALIVE, zero when answered
	rtt         time.Duration // smoothed KEEPALIVE round trip
	// zones are the ZONES frames of the ticket in force at the relay that
	// it has not acknowledged, sent again at zonesNext.
	zones     []mtrp.ControlMessage
	zonesAck  uint64 // the not_after of the TICKET_ACK that ends them
	zonesNext time.Time
	zonesWait time.Duration
	lastAck   uint64 // not_after of the last TICKET_ACK
	closed    bool
	closeErr  error

	events chan relay.ReceiveEvent
	done   chan struct{}
	wg     sync.WaitGroup
	buf    []byte // send buffer, guarded by sendMu
	sendMu sync.Mutex
}

func newClient(t transport, frames *pump, s *mtrp.Session, hello mtrp.ServerHello, disco key.DiscoPublic,
	ticket []byte, creds Credentials, now func() time.Time,
) *Client {
	keepalive := hello.Keepalive()
	if keepalive <= 0 {
		keepalive = defaultKeepalive
	}
	c := &Client{
		transport: t, frames: frames, session: s, disco: disco, credentials: creds, now: now, keepalive: keepalive,
		byPeer: make(map[relay.Key]*routeState), byRoute: make(map[uint32]relay.Key),
		ticket: bytes.Clone(ticket), lastRecv: now(),
		events: make(chan relay.ReceiveEvent, eventQueue), done: make(chan struct{}),
	}
	c.wg.Add(2)
	go c.readLoop()
	go c.tickLoop()
	return c
}

// Transport reports how the session reaches its relay.
func (c *Client) Transport() TransportKind { return c.transport.kind() }

// Send forwards one encrypted packet to a peer, opening a route first when
// needed. Packets for a pending route are queued (a few) or dropped; a peer
// the relay refused is retried after a short pause.
func (c *Client) Send(destination relay.Key, packet []byte) error {
	if destination == (relay.Key{}) || len(packet) == 0 || len(packet) > mtrp.MaxDataPayload {
		return errors.New("interchange: outbound packet is invalid")
	}
	now := c.now()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	state := c.byPeer[destination]
	if state != nil && state.number != 0 {
		route := state.number
		c.mu.Unlock()
		return c.sendData(route, packet)
	}
	if state == nil {
		state = &routeState{}
		c.byPeer[destination] = state
	}
	if !state.refused.IsZero() && now.Sub(state.refused) < routeRefusalPause {
		c.mu.Unlock()
		return nil // the peer is not on this relay yet; WireGuard retries
	}
	if len(state.pending) < maxPendingPackets {
		state.pending = append(state.pending, bytes.Clone(packet))
	}
	var open *mtrp.ControlMessage
	if state.request == 0 || now.Sub(state.opened) >= routeOpenTimeout {
		c.nextRequest++
		if c.nextRequest == 0 {
			c.nextRequest = 1
		}
		state.request, state.opened, state.refused = c.nextRequest, now, time.Time{}
		open = &mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: state.request, Peer: key.NodePublic(destination)}
	}
	c.mu.Unlock()
	if open != nil {
		return c.sendControl(*open)
	}
	return nil
}

// Receive returns the next packet or liveness event. It fails once the
// session has ended; Close interrupts it.
func (c *Client) Receive() (relay.ReceiveEvent, error) {
	select {
	case event := <-c.events:
		return event, nil
	case <-c.done:
		select {
		case event := <-c.events:
			return event, nil
		default:
		}
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		return relay.ReceiveEvent{}, err
	}
}

// Close ends the session.
func (c *Client) Close() error {
	c.shutdown(ErrClosed)
	c.wg.Wait()
	return nil
}

func (c *Client) shutdown(cause error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed, c.closeErr = true, cause
	c.mu.Unlock()
	close(c.done)
	c.frames.close()
	_ = c.transport.close()
}

func (c *Client) sendData(route uint32, payload []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	frame, err := mtrp.AppendData(c.buf[:0], c.session.RemoteIndex(), route, payload)
	if err != nil {
		return err
	}
	c.buf = frame
	return c.transport.send(frame)
}

func (c *Client) sendControl(msg mtrp.ControlMessage) error {
	plain, err := mtrp.AppendControlMessage(nil, msg)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	frame, err := c.session.SealControl(c.buf[:0], plain)
	if err != nil {
		return err
	}
	c.buf = frame
	return c.transport.send(frame)
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	plain := make([]byte, 0, mtrp.MaxControlPlaintext)
	for {
		var frame []byte
		select {
		case <-c.done:
			return
		case f, ok := <-c.frames.frames:
			if !ok {
				c.shutdown(fmt.Errorf("interchange: receive: %w", <-c.frames.err))
				return
			}
			frame = f
		}
		typ, err := mtrp.PeekType(frame)
		if err != nil {
			continue
		}
		switch typ {
		case mtrp.TypeData:
			c.handleData(frame)
		case mtrp.TypeControl:
			msg, err := c.session.OpenControl(plain[:0], frame)
			if err != nil {
				continue // forged, replayed or for another session
			}
			c.touch()
			parsed, err := mtrp.ParseControlMessage(msg)
			if err != nil {
				continue
			}
			if !c.handleControl(parsed) {
				return
			}
		default:
			// Handshake frames after the session exists are ignored.
		}
	}
}

func (c *Client) touch() {
	c.mu.Lock()
	now := c.now()
	c.lastRecv = now
	if !c.probeSent.IsZero() {
		sample := now.Sub(c.probeSent)
		if c.rtt == 0 {
			c.rtt = sample
		} else {
			c.rtt = (7*c.rtt + sample) / 8
		}
		c.probeSent = time.Time{}
	}
	c.mu.Unlock()
}

// deadAfter is how long a session may hear nothing before its relay is
// declared unresponsive: the silence before the first probe, the spacing of
// the probes, and an allowance for the last probe's answer.
func (c *Client) deadAfter() time.Duration {
	c.mu.Lock()
	answer := min(max(4*c.rtt, minProbeAnswer), maxProbeAnswer)
	c.mu.Unlock()
	return probeAfter + (probesBeforeDead-1)*probeEvery + answer
}

func (c *Client) handleData(frame []byte) {
	data, err := mtrp.ParseData(frame)
	if err != nil || data.ReceiverIndex != c.session.LocalIndex() || len(data.Payload) == 0 {
		return
	}
	c.mu.Lock()
	peer, ok := c.byRoute[data.Route]
	if ok {
		c.lastRecv = c.now()
	}
	c.mu.Unlock()
	if !ok {
		return
	}
	c.deliver(relay.ReceiveEvent{Kind: relay.ReceivePacket, Source: peer, Data: bytes.Clone(data.Payload)})
}

// deliver queues an event, dropping it when the consumer lags: the payload
// is WireGuard traffic, which tolerates loss.
func (c *Client) deliver(event relay.ReceiveEvent) {
	select {
	case c.events <- event:
	default:
	}
}

// handleControl applies one authenticated CONTROL message. It returns false
// when the session has ended.
func (c *Client) handleControl(msg mtrp.ControlMessage) bool {
	switch msg.Type {
	case mtrp.ControlKeepalive:
		c.deliver(relay.ReceiveEvent{Kind: relay.ReceiveActivity})
	case mtrp.ControlRouteOK:
		c.establish(msg.Request, msg.Route, nil)
	case mtrp.ControlRouteIncoming:
		peer := relay.Key(msg.Peer)
		c.establish(0, msg.Route, &peer)
	case mtrp.ControlRouteError:
		c.mu.Lock()
		for _, state := range c.byPeer {
			if state.number == 0 && state.request == msg.Request {
				state.request, state.refused, state.pending = 0, c.now(), nil
			}
		}
		c.mu.Unlock()
	case mtrp.ControlRouteClose:
		c.mu.Lock()
		if peer, ok := c.byRoute[msg.Route]; ok {
			delete(c.byRoute, msg.Route)
			delete(c.byPeer, peer)
		}
		c.mu.Unlock()
	case mtrp.ControlPathChallenge:
		_ = c.sendControl(mtrp.ControlMessage{Type: mtrp.ControlPathResponse, Nonce: msg.Nonce})
	case mtrp.ControlSessionClose:
		c.shutdown(&SessionClosedError{
			Reason: msg.SessionClose, RetryAfter: time.Duration(msg.RetryAfterMS) * time.Millisecond,
		})
		return false
	case mtrp.ControlTicketAck:
		// The relay enforces the renewed ticket from now on.
		c.mu.Lock()
		c.lastAck = msg.NotAfterMS
		if c.zones != nil && msg.NotAfterMS == c.zonesAck {
			c.zones = nil
		}
		c.mu.Unlock()
	default:
	}
	return true
}

// establish records a route granted to this client (ROUTE_OK, matched by
// request) or announced by the relay (ROUTE_INCOMING, naming the peer), and
// flushes packets queued for it.
func (c *Client) establish(request, route uint32, incoming *relay.Key) {
	if route == 0 {
		return
	}
	c.mu.Lock()
	var peer relay.Key
	var state *routeState
	if incoming != nil {
		peer = *incoming
		state = c.byPeer[peer]
		if state == nil {
			state = &routeState{}
			c.byPeer[peer] = state
		}
		state.incoming = true
	} else {
		for candidate, s := range c.byPeer {
			if s.number == 0 && s.request == request {
				peer, state = candidate, s
				break
			}
		}
		if state == nil {
			c.mu.Unlock()
			return
		}
	}
	if state.number != 0 && state.number != route {
		delete(c.byRoute, state.number)
	}
	state.number, state.request, state.refused = route, 0, time.Time{}
	c.byRoute[route] = peer
	pending := state.pending
	state.pending = nil
	c.mu.Unlock()
	for _, packet := range pending {
		_ = c.sendData(route, packet)
	}
}

// tickLoop sends keepalives, probes a silent relay, notices a dead one, and
// hands the relay a renewed ticket when Core issues one.
func (c *Client) tickLoop() {
	defer c.wg.Done()
	_ = c.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive}) // verifies the binding (§5.2)
	c.mu.Lock()
	ticket := c.ticket
	c.mu.Unlock()
	c.startZones(ticket)
	lastKeepalive := c.now()
	ticker := time.NewTicker(probeTick)
	defer ticker.Stop()
	credentials := time.NewTicker(credentialInterval)
	defer credentials.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			now := c.now()
			c.mu.Lock()
			silent := now.Sub(c.lastRecv)
			c.mu.Unlock()
			if silent >= c.deadAfter() {
				c.shutdown(ErrRelayUnresponsive)
				return
			}
			c.resendZones(now)
			sinceKeepalive := now.Sub(lastKeepalive)
			if sinceKeepalive < c.keepalive && (silent < probeAfter || sinceKeepalive < probeEvery) {
				continue
			}
			c.mu.Lock()
			if c.probeSent.IsZero() {
				c.probeSent = now
			}
			c.mu.Unlock()
			if err := c.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive}); err != nil {
				c.shutdown(fmt.Errorf("interchange: keepalive: %w", err))
				return
			}
			lastKeepalive = now
		case <-credentials.C:
			if !c.refreshTicket() {
				return
			}
		}
	}
}

// refreshTicket sends TICKET_UPDATE when Core issued a new ticket for the
// same disco key, and ends the session when the disco key changed (a new
// session must prove the new key). It returns false when the session ended.
func (c *Client) refreshTicket() bool {
	disco, ticket, ok := c.credentials.RelayCredentials()
	if !ok {
		return true // keep the current ticket until the relay expires it
	}
	if disco.Public() != c.disco {
		c.shutdown(errors.New("interchange: disco key changed"))
		return false
	}
	c.mu.Lock()
	changed := !bytes.Equal(ticket, c.ticket)
	if changed {
		c.ticket = bytes.Clone(ticket)
	}
	c.mu.Unlock()
	if changed {
		_ = c.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: ticket})
		c.startZones(ticket)
	}
	return true
}

// startZones sends the ZONES frames of an MTT2 ticket just handed to the
// relay (mtrp-v1 §5.4). A ticket whose zones are all inline needs none.
func (c *Client) startZones(ticket []byte) {
	var frames []mtrp.ControlMessage
	var notAfter uint64
	if source, ok := c.credentials.(ZoneCredentials); ok {
		if zones := source.RelayTicketZones(ticket); zones != nil {
			if complete, err := mtrp.CompleteTicket(ticket, zones); err == nil {
				frames, notAfter = mtrp.ZoneFrames(complete), uint64(complete.NotAfterMS) //nolint:gosec // positive by validation
			}
		}
	}
	c.mu.Lock()
	if notAfter != 0 && c.lastAck == notAfter {
		frames = nil // acknowledged already (a relay that will not hold them)
	}
	c.zones, c.zonesAck = frames, notAfter
	c.zonesNext, c.zonesWait = time.Time{}, zonesResendFirst
	c.mu.Unlock()
	c.resendZones(c.now())
}

// resendZones sends the unacknowledged ZONES frames when they are due.
func (c *Client) resendZones(now time.Time) {
	c.mu.Lock()
	frames := c.zones
	if len(frames) == 0 || now.Before(c.zonesNext) {
		c.mu.Unlock()
		return
	}
	c.zonesNext = now.Add(c.zonesWait)
	c.zonesWait = min(2*c.zonesWait, zonesResendMax)
	c.mu.Unlock()
	for _, frame := range frames {
		if err := c.sendControl(frame); err != nil {
			return
		}
	}
}

var _ relay.Client = (*Client)(nil)
