package interchange

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

type testCreds struct {
	mu     sync.Mutex
	disco  key.DiscoPrivate
	ticket []byte
	ok     bool
}

func (c *testCreds) RelayCredentials() (key.DiscoPrivate, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disco, c.ticket, c.ok
}

func (c *testCreds) set(ticket []byte) {
	c.mu.Lock()
	c.ticket = ticket
	c.mu.Unlock()
}

func newCreds(t *testing.T, r *fakeRelay, node key.NodePublic) *testCreds {
	t.Helper()
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return &testCreds{disco: disco, ticket: r.ticket(node, disco.Public(), 10*time.Minute), ok: true}
}

func dial(t *testing.T, r *fakeRelay, creds Credentials) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	c, err := NewDialer(creds).Dial(ctx, relay.Key{}, relay.Region{ID: 1, Nodes: []relay.Node{r.node()}})
	if err != nil {
		t.Fatal(err)
	}
	client, ok := c.(*Client)
	if !ok {
		t.Fatalf("Dial returned %T", c)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// receivePacket waits for the next packet, skipping liveness events.
func receivePacket(t *testing.T, c *Client) relay.ReceiveEvent {
	t.Helper()
	result := make(chan relay.ReceiveEvent, 1)
	go func() {
		for {
			event, err := c.Receive()
			if err != nil {
				close(result)
				return
			}
			if event.Kind == relay.ReceivePacket {
				result <- event
				return
			}
		}
	}()
	select {
	case event, ok := <-result:
		if !ok {
			t.Fatal("session ended before a packet arrived")
		}
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("no packet received")
	}
	return relay.ReceiveEvent{}
}

func TestClientsExchangeThroughRelay(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	nodeA, nodeB := key.NodePublic{0xa1}, key.NodePublic{0xb2}
	a := dial(t, r, newCreds(t, r, nodeA))
	b := dial(t, r, newCreds(t, r, nodeB))
	if a.Transport() != TransportUDP {
		t.Fatalf("transport %s, want udp", a.Transport())
	}

	// The first packet waits for ROUTE_OK; the peer learns the route from
	// ROUTE_INCOMING and can answer without opening one.
	if err := a.Send(relay.Key(nodeB), []byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := receivePacket(t, b)
	if got.Source != relay.Key(nodeA) || string(got.Data) != "ping" {
		t.Fatalf("b received %+v", got)
	}
	if err := b.Send(relay.Key(nodeA), []byte("pong")); err != nil {
		t.Fatal(err)
	}
	if got := receivePacket(t, a); got.Source != relay.Key(nodeB) || string(got.Data) != "pong" {
		t.Fatalf("a received %+v", got)
	}
}

func TestDialFallsBackToTLS(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	r.ignoreU.Store(true) // UDP blocked
	nodeA, nodeB := key.NodePublic{0xa1}, key.NodePublic{0xb2}
	a := dial(t, r, newCreds(t, r, nodeA))
	if a.Transport() != TransportTLS {
		t.Fatalf("transport %s, want tls", a.Transport())
	}
	b := dial(t, r, newCreds(t, r, nodeB))
	if err := a.Send(relay.Key(nodeB), []byte("over tls")); err != nil {
		t.Fatal(err)
	}
	if got := receivePacket(t, b); string(got.Data) != "over tls" {
		t.Fatalf("b received %+v", got)
	}
}

func TestDialFallsBackToWebSocket(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	r.ignoreU.Store(true)
	node := r.node()
	node.Port = r.serveWebSocket() // this port refuses ALPN mtrp/1
	creds := newCreds(t, r, key.NodePublic{0xa1})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	c, err := NewDialer(creds).Dial(ctx, relay.Key{}, relay.Region{ID: 1, Nodes: []relay.Node{node}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if client, ok := c.(*Client); !ok || client.Transport() != TransportWebSocket {
		t.Fatalf("dialled %T over the wrong transport", c)
	}
	b := dial(t, r, newCreds(t, r, key.NodePublic{0xb2}))
	if err := c.Send(relay.Key{0xb2}, []byte("over ws")); err != nil {
		t.Fatal(err)
	}
	if got := receivePacket(t, b); string(got.Data) != "over ws" {
		t.Fatalf("b received %+v", got)
	}
}

func TestDialAnswersCookie(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	r.cookies.Store(true)
	a := dial(t, r, newCreds(t, r, key.NodePublic{0xa1}))
	if a.Transport() != TransportUDP {
		t.Fatalf("transport %s, want udp after the cookie round trip", a.Transport())
	}
}

func TestDialWithoutTicket(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	creds := newCreds(t, r, key.NodePublic{0xa1})
	creds.ok = false
	_, err := NewDialer(creds).Dial(t.Context(), relay.Key{}, relay.Region{ID: 1, Nodes: []relay.Node{r.node()}})
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("Dial without ticket: %v", err)
	}
	node := r.node()
	node.RelayKey = [32]byte{}
	creds.ok = true
	if _, err := NewDialer(creds).Dial(t.Context(), relay.Key{}, relay.Region{ID: 1, Nodes: []relay.Node{node}}); err == nil {
		t.Fatal("dialled a node without a relay key")
	}
}

func TestAbsentPeerIsRetriedLater(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	nodeB := key.NodePublic{0xb2}
	a := dial(t, r, newCreds(t, r, key.NodePublic{0xa1}))
	if err := a.Send(relay.Key(nodeB), []byte("early")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // ROUTE_ERROR arrives
	a.mu.Lock()
	refused := !a.byPeer[relay.Key(nodeB)].refused.IsZero()
	a.mu.Unlock()
	if !refused {
		t.Fatal("ROUTE_ERROR not recorded")
	}
	b := dial(t, r, newCreds(t, r, nodeB))
	time.Sleep(routeRefusalPause)
	if err := a.Send(relay.Key(nodeB), []byte("later")); err != nil {
		t.Fatal(err)
	}
	if got := receivePacket(t, b); string(got.Data) != "later" {
		t.Fatalf("b received %+v", got)
	}
}

func TestTicketRenewalAndSessionClose(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	node := key.NodePublic{0xa1}
	creds := newCreds(t, r, node)
	a := dial(t, r, creds)

	// Unchanged credentials send nothing; a new ticket is handed over.
	a.refreshTicket()
	creds.set(r.ticket(node, creds.disco.Public(), 15*time.Minute))
	a.refreshTicket()
	deadline := time.Now().Add(3 * time.Second)
	for {
		r.mu.Lock()
		updates := r.updates
		r.mu.Unlock()
		if updates == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ticket updates = %d", updates)
		}
		time.Sleep(20 * time.Millisecond)
	}

	r.closeAll(mtrp.SessionCloseDraining)
	for {
		_, err := a.Receive()
		if err == nil {
			continue
		}
		var closed *SessionClosedError
		if !errors.As(err, &closed) || closed.Reason != mtrp.SessionCloseDraining || closed.RetryAfter != 3*time.Second {
			t.Fatalf("Receive after SESSION_CLOSE: %v", err)
		}
		break
	}
	if err := a.Send(relay.Key{1}, []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after close: %v", err)
	}
}

func TestDiscoKeyChangeEndsSession(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	creds := newCreds(t, r, key.NodePublic{0xa1})
	a := dial(t, r, creds)
	fresh, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	creds.mu.Lock()
	creds.disco = fresh
	creds.mu.Unlock()
	if a.refreshTicket() {
		t.Fatal("session kept running with a stale disco key")
	}
	for range eventQueue + 1 { // queued events drain first
		if _, err := a.Receive(); err != nil {
			return
		}
	}
	t.Fatal("Receive kept succeeding after the disco key changed")
}

// TestSilentRelayIsDetectedWithinSeconds: an idle session probes its relay
// once it has heard nothing for a moment, so a relay that dies without
// closing anything is noticed in seconds, not after the 25 s keepalive.
func TestSilentRelayIsDetectedWithinSeconds(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	a := dial(t, r, newCreds(t, r, key.NodePublic{0xa2}))
	time.Sleep(3 * time.Second) // idle: probes keep the session alive
	errs := make(chan error, 1)
	go func() {
		for {
			if _, err := a.Receive(); err != nil {
				errs <- err
				return
			}
		}
	}()
	select {
	case err := <-errs:
		t.Fatalf("an answering relay was declared dead: %v", err)
	default:
	}
	r.mute.Store(true)
	muted := time.Now()
	select {
	case err := <-errs:
		if !errors.Is(err, ErrRelayUnresponsive) {
			t.Fatalf("error = %v, want ErrRelayUnresponsive", err)
		}
		if elapsed := time.Since(muted); elapsed > 5*time.Second {
			t.Fatalf("silent relay noticed after %v", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("silent relay never noticed")
	}
}

func TestKeepaliveActivity(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	a := dial(t, r, newCreds(t, r, key.NodePublic{0xa1}))
	deadline := time.After(5 * time.Second)
	for {
		events := make(chan relay.ReceiveEvent, 1)
		go func() {
			if event, err := a.Receive(); err == nil {
				events <- event
			}
		}()
		select {
		case event := <-events:
			if event.Kind == relay.ReceiveActivity {
				return // the relay answered a keepalive
			}
		case <-deadline:
			t.Fatal("no keepalive answer")
		}
	}
}

// zoneCreds are testCreds whose ticket is MTT2.
type zoneCreds struct {
	*testCreds
	zones    []byte
	fallback []byte
}

func (c *zoneCreds) RelayFallbackTicket(ticket []byte) []byte {
	if bytes.Equal(ticket, c.ticket) {
		return c.fallback
	}
	return nil
}

func (c *zoneCreds) RelayTicketZones(ticket []byte) []byte {
	if current, _, _ := c.RelayCredentials(); !current.IsZero() && bytes.Equal(ticket, c.ticket) {
		return c.zones
	}
	return nil
}

// TestClientSendsTicketZonesUntilAcknowledged: with an MTT2 ticket for 300
// contracts the client hands the relay the zones past the inline ones after
// its handshake, sends them again when frames were lost, and stops once the
// relay acknowledges the ticket.
func TestClientSendsTicketZonesUntilAcknowledged(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	r.dropZones.Store(1) // the first pass loses a frame
	base := newCreds(t, r, key.NodePublic{0x5a})
	ticket, zones := r.ticketV2(key.NodePublic{0x5a}, base.disco.Public(), 300)
	base.ticket = ticket
	creds := &zoneCreds{testCreds: base, zones: zones}
	dial(t, r, creds)
	want := (301 - mtrp.MaxZones + mtrp.MaxControlZones - 1) / mtrp.MaxControlZones
	deadline := time.Now().Add(10 * time.Second)
	for {
		frames, done := r.zoneCounts()
		if done == 1 {
			if frames < want {
				t.Fatalf("completed after %d frames, want at least %d", frames, want)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("zones not completed: %d frames, want %d per pass", frames, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Acknowledged: no further passes.
	frames, _ := r.zoneCounts()
	time.Sleep(2500 * time.Millisecond)
	if again, _ := r.zoneCounts(); again != frames {
		t.Fatalf("client kept sending ZONES after the acknowledgement: %d then %d", frames, again)
	}
}

// TestDialFallsBackToMTT1ForAnOldRelay: a relay that drops MTT2 INITs (one
// not yet upgraded) is reached with the MTT1 fallback ticket.
func TestDialFallsBackToMTT1ForAnOldRelay(t *testing.T) {
	t.Parallel()
	r := newFakeRelay(t)
	r.oldRelay.Store(true)
	base := newCreds(t, r, key.NodePublic{0x5b})
	ticket, zones := r.ticketV2(key.NodePublic{0x5b}, base.disco.Public(), 100)
	base.ticket = ticket
	creds := &zoneCreds{testCreds: base, zones: zones, fallback: r.fallbackFor(ticket)}
	client := dial(t, r, creds)
	client.mu.Lock()
	used := client.ticket
	client.mu.Unlock()
	if !bytes.Equal(used, creds.fallback) {
		t.Fatal("session not on the fallback ticket")
	}
	if frames, _ := r.zoneCounts(); frames != 0 {
		t.Fatalf("%d ZONES frames sent for an MTT1 session", frames)
	}
}
