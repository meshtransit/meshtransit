package server

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

func TestRelayForwardsWithinSharedZone(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneA, zoneB)
	if a.hello.KeepaliveS != 25 || a.hello.IdleTimeoutS != 90 || h.srv.SessionCount() != 2 {
		t.Fatalf("hello %+v sessions %d", a.hello, h.srv.SessionCount())
	}
	ra, rb := openRoute(t, a, b)

	a.sendData(a.addr, ra, []byte("ping"))
	d, ok := b.recvData()
	if !ok || d.ReceiverIndex != b.session.LocalIndex() || d.Route != rb || !bytes.Equal(d.Payload, []byte("ping")) {
		t.Fatalf("b received %+v (%v)", d, ok)
	}
	b.sendData(b.addr, rb, []byte("pong"))
	d, ok = a.recvData()
	if !ok || d.Route != ra || !bytes.Equal(d.Payload, []byte("pong")) {
		t.Fatalf("a received %+v (%v)", d, ok)
	}

	// Opening again, from either side, returns the existing route.
	a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 8, Peer: b.node})
	if again := a.expectControl(mtrp.ControlRouteOK); again.Route != ra {
		t.Fatalf("second open gave route %d, want %d", again.Route, ra)
	}
	if dup := b.expectControl(mtrp.ControlRouteIncoming); dup.Route != rb {
		t.Fatalf("repeated ROUTE_INCOMING %+v", dup)
	}
	b.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 9, Peer: a.node})
	a.expectControl(mtrp.ControlRouteIncoming)
	if back := b.expectControl(mtrp.ControlRouteOK); back.Route != rb {
		t.Fatalf("reverse open gave route %d, want %d", back.Route, rb)
	}
	if h.metrics.routes != 1 {
		t.Fatalf("active routes = %d", h.metrics.routes)
	}
}

func TestRelayRefusesRoutes(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneB)
	ghost := h.newClient(zoneA)
	ghostNode := ghost.node
	h.srv.closeSession(h.srv.lookup(ghost.session.RemoteIndex()), mtrp.SessionClosePolicy, 0)

	for _, peer := range [][32]byte{b.node, ghostNode} {
		a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 3, Peer: peer})
		// Absent and unauthorised peers are indistinguishable.
		if e := a.expectControl(mtrp.ControlRouteError); e.RouteError != mtrp.RouteErrorPeerAbsent {
			t.Fatalf("route to %x: %+v", peer[:2], e)
		}
	}
	a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 4, Peer: a.node})
	if e := a.expectControl(mtrp.ControlRouteError); e.RouteError != mtrp.RouteErrorInvalid {
		t.Fatalf("route to self: %+v", e)
	}
	if _, ok := b.recvControl(); ok {
		t.Fatal("unauthorised peer was told about the request")
	}
}

func TestRelayBindingAndRoaming(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneA)
	ra, _ := openRoute(t, a, b)

	spoofed := netip.MustParseAddrPort("203.0.113.66:40000")
	a.sendData(spoofed, ra, []byte("x"))
	if _, ok := b.recvData(); ok || h.metrics.get("data:wrong_source") != 1 {
		t.Fatal("DATA from an unbound address was forwarded")
	}

	// An authenticated CONTROL frame from a new address moves the binding,
	// unverified, and the relay challenges the new address.
	roamed := netip.MustParseAddrPort("192.0.2.77:51000")
	a.sendControlFrom(roamed, mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	a.addr = roamed
	challenge := a.expectControl(mtrp.ControlPathChallenge)
	a.expectControl(mtrp.ControlKeepalive)
	a.sendData(roamed, ra, []byte("after roam"))
	if d, ok := b.recvData(); !ok || !bytes.Equal(d.Payload, []byte("after roam")) {
		t.Fatal("DATA after roaming was not forwarded")
	}

	// Until the challenge is answered, traffic towards a is capped.
	var rb uint32
	b.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 2, Peer: a.node})
	a.expectControl(mtrp.ControlRouteIncoming)
	rb = b.expectControl(mtrp.ControlRouteOK).Route
	big := bytes.Repeat([]byte{1}, 2000)
	for range 40 { // 80 kB against a 32 kB burst
		b.sendData(b.addr, rb, big)
	}
	if h.metrics.get("data:unverified_peer") == 0 {
		t.Fatal("traffic to an unverified binding was not capped")
	}
	for a.h.net.next(a.addr) != nil {
	}

	// A wrong nonce does not verify; the right one does.
	a.sendControlFrom(roamed, mtrp.ControlMessage{Type: mtrp.ControlPathResponse, Nonce: challenge.Nonce + 2})
	if bnd := h.srv.lookup(a.session.RemoteIndex()).binding.Load(); bnd.verified {
		t.Fatal("wrong nonce verified the binding")
	}
	a.sendControlFrom(roamed, mtrp.ControlMessage{Type: mtrp.ControlPathResponse, Nonce: challenge.Nonce})
	if bnd := h.srv.lookup(a.session.RemoteIndex()).binding.Load(); !bnd.verified || bnd.udp != roamed {
		t.Fatalf("binding after PATH_RESPONSE = %+v", bnd)
	}
}

func TestRelayHandshakeRejects(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a := h.newClient(zoneA)

	// A replayed INIT (same timestamp) gets no answer.
	hs, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: a.disco, Relay: h.srv.PublicKey(), Index: 99, PadUDP: true,
		Hello: mtrp.ClientHello{TimestampMS: a.ts, Ticket: a.ticket(zoneA)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = hs
	h.srv.HandleUDP(init, a.addr)
	if h.net.next(a.addr) != nil || h.metrics.get("handshake:replay") != 1 {
		t.Fatal("replayed INIT answered")
	}

	// A ticket for another disco key.
	other := h.newClient(zoneA)
	_, init, err = mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: a.disco, Relay: h.srv.PublicKey(), Index: 98, PadUDP: true,
		Hello: mtrp.ClientHello{TimestampMS: a.ts + 10, Ticket: other.ticket(zoneA)},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.srv.HandleUDP(init, a.addr)
	if h.net.next(a.addr) != nil || h.metrics.get("handshake:ticket_mismatch") != 1 {
		t.Fatal("borrowed ticket accepted")
	}

	// A corrupted mac1 is dropped before any public-key work.
	_, init, _ = mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: a.disco, Relay: h.srv.PublicKey(), Index: 97, PadUDP: true,
		Hello: mtrp.ClientHello{TimestampMS: a.ts + 20, Ticket: a.ticket(zoneA)},
	})
	init[len(init)-2*mtrp.MACSize] ^= 1
	h.srv.HandleUDP(init, a.addr)
	if h.metrics.get("handshake:bad_mac1") != 1 || h.metrics.get("handshake:bad_noise") != 0 {
		t.Fatal("bad mac1 not rejected first")
	}

	// Revoked nodes cannot connect.
	h.revoked.revoke(a.node)
	if a.connect(nil, zoneA) {
		t.Fatal("revoked node connected")
	}
}

func TestRelaySessionReplacement(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneA)
	_, rb := openRoute(t, a, b)
	oldSession := a.session
	if !a.connect(nil, zoneA) {
		t.Fatal("reconnect failed")
	}
	if h.srv.SessionCount() != 2 {
		t.Fatalf("sessions = %d after replacement", h.srv.SessionCount())
	}
	if c := b.expectControl(mtrp.ControlRouteClose); c.Route != rb || c.RouteClose != mtrp.RouteClosePeerLeft {
		t.Fatalf("peer notification %+v", c)
	}
	// The old session's SESSION_CLOSE was sealed with the old keys.
	frame := h.net.next(a.addr)
	plain, err := oldSession.OpenControl(nil, frame)
	if err != nil {
		t.Fatalf("old session close: %v", err)
	}
	if msg, _ := mtrp.ParseControlMessage(plain); msg.Type != mtrp.ControlSessionClose {
		t.Fatalf("old session got %+v", msg)
	}
}

func TestRelayJanitor(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneA)
	openRoute(t, a, b)

	h.clock.advance(60 * time.Second)
	b.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	b.expectControl(mtrp.ControlKeepalive)
	h.clock.advance(40 * time.Second) // a has been silent 100 s, b 40 s
	h.srv.sweep()
	if c := a.expectControl(mtrp.ControlSessionClose); c.SessionClose != mtrp.SessionCloseIdle {
		t.Fatalf("idle close %+v", c)
	}
	b.expectControl(mtrp.ControlRouteClose)
	if h.srv.SessionCount() != 1 {
		t.Fatalf("sessions = %d", h.srv.SessionCount())
	}

	h.clock.advance(10 * time.Minute)
	b.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive}) // not idle, but expired
	b.expectControl(mtrp.ControlKeepalive)
	h.srv.sweep()
	if c := b.expectControl(mtrp.ControlSessionClose); c.SessionClose != mtrp.SessionCloseExpired {
		t.Fatalf("expiry close %+v", c)
	}
}

func TestRelayCookieMode(t *testing.T) {
	t.Parallel()
	h := newRelay(t, func(c *Config) { c.HandshakeRate = 1 })
	h.newClient(zoneA) // uses the only token
	c := h.newClient(zoneA)
	if h.metrics.get("handshake:cookie_sent") != 1 || c.session == nil {
		t.Fatal("second handshake did not go through cookie mode")
	}
}

func TestRelayLimits(t *testing.T) {
	t.Parallel()
	h := newRelay(t, func(c *Config) { c.MaxSessions = 2; c.PacketRate = 2 })
	a, b := h.newClient(zoneA), h.newClient(zoneA)
	if extra := h.newClientOrNil(zoneA); extra != nil || h.metrics.get("handshake:full") != 1 {
		t.Fatal("session limit exceeded")
	}

	ra, _ := openRoute(t, a, b)
	for range 5 {
		a.sendData(a.addr, ra, []byte("x"))
	}
	if got := h.metrics.get("data:rate_limited"); got != 3 {
		t.Fatalf("rate limited %d frames, want 3", got)
	}
}

func (h *relayHarness) newClientOrNil(zones ...mtrp.Zone) *testClient {
	h.t.Helper()
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		h.t.Fatal(err)
	}
	c := &testClient{h: h, disco: disco, node: key.NodePublic{0xdd}, index: 0x777, addr: netip.MustParseAddrPort("198.51.100.251:1"), ts: baseTime.UnixMilli()}
	if !c.connect(nil, zones...) {
		return nil
	}
	return c
}

func TestRelayTicketUpdateAndRouteClose(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b, c := h.newClient(zoneA, zoneB), h.newClient(zoneA), h.newClient(zoneB)
	rab, rba := openRoute(t, a, b)
	rac, rca := openRoute(t, a, c)

	// Renew a's ticket without zone A: the route to b closes, the one to c stays.
	a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: a.ticket(zoneB)})
	if m := a.expectControl(mtrp.ControlRouteClose); m.Route != rab || m.RouteClose != mtrp.RouteCloseRevoked {
		t.Fatalf("a: %+v", m)
	}
	a.expectControl(mtrp.ControlTicketAck)
	if m := b.expectControl(mtrp.ControlRouteClose); m.Route != rba {
		t.Fatalf("b: %+v", m)
	}
	a.sendData(a.addr, rac, []byte("still"))
	if d, ok := c.recvData(); !ok || d.Route != rca {
		t.Fatal("unaffected route stopped forwarding")
	}

	// A client closes its route; the peer is told.
	a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: rac, RouteClose: mtrp.RouteCloseByClient})
	if m := c.expectControl(mtrp.ControlRouteClose); m.Route != rca || m.RouteClose != mtrp.RouteCloseByClient {
		t.Fatalf("c: %+v", m)
	}
	c.sendData(c.addr, rca, []byte("gone"))
	if _, ok := a.recvData(); ok || h.metrics.get("data:no_route") != 1 {
		t.Fatal("closed route still forwards")
	}
}

func TestRelayDrainAndRevocation(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneA)

	h.revoked.revoke(b.node)
	h.srv.sweep()
	if m := b.expectControl(mtrp.ControlSessionClose); m.SessionClose != mtrp.SessionCloseRevoked {
		t.Fatalf("revoked: %+v", m)
	}

	h.srv.Drain(30 * time.Second)
	if m := a.expectControl(mtrp.ControlSessionClose); m.SessionClose != mtrp.SessionCloseDraining || m.RetryAfterMS != 30000 {
		t.Fatalf("drain: %+v", m)
	}
	// Draining keeps existing sessions forwarding but admits no new ones.
	if a.connect(nil, zoneA) || h.srv.SessionCount() != 1 {
		t.Fatalf("draining relay accepted a session (%d sessions)", h.srv.SessionCount())
	}
}

func TestRelayIgnoresGarbage(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	for _, frame := range [][]byte{nil, {1}, {1, 9, 0, 0}, {1, 2, 0, 0, 1, 2, 3}, bytes.Repeat([]byte{1}, 300)} {
		h.srv.HandleUDP(frame, netip.MustParseAddrPort("192.0.2.1:1"))
	}
	if h.srv.SessionCount() != 0 {
		t.Fatal("garbage created state")
	}
}

func FuzzHandleUDP(f *testing.F) {
	h := newRelay(f, nil)
	f.Add([]byte{1, 1, 0, 0})
	f.Add([]byte{1, 5, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 9})
	f.Fuzz(func(t *testing.T, frame []byte) {
		h.srv.HandleUDP(frame, netip.MustParseAddrPort("192.0.2.1:1")) // must never panic
	})
}

func TestRelayTimestampWindowAndSourceLimit(t *testing.T) {
	t.Parallel()
	h := newRelay(t, func(c *Config) { c.SourceHandshakeRate = 1 })
	a := h.newClient(zoneA) // first handshake from this source
	src := netip.MustParseAddrPort("203.0.113.9:1")
	try := func(ts int64) bool {
		_, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
			Disco: a.disco, Relay: h.srv.PublicKey(), Index: 55, PadUDP: true,
			Hello: mtrp.ClientHello{TimestampMS: ts, Ticket: a.ticket(zoneA)},
		})
		if err != nil {
			t.Fatal(err)
		}
		for h.net.next(src) != nil { // drop SESSION_CLOSE of a replaced session
		}
		h.srv.HandleUDP(init, src)
		return h.net.next(src) != nil
	}
	now := h.clock.now().UnixMilli()
	if try(now + 2*MaxTimestampSkew.Milliseconds()) {
		t.Fatal("future timestamp accepted")
	}
	src = netip.MustParseAddrPort("203.0.113.10:1")
	if try(now - 1) { // before the relay started
		t.Fatal("pre-start timestamp accepted")
	}
	if h.metrics.get("handshake:stale_timestamp") != 2 {
		t.Fatalf("stale_timestamp = %d", h.metrics.get("handshake:stale_timestamp"))
	}
	src = netip.MustParseAddrPort("203.0.113.11:1")
	if !try(now + 5) {
		t.Fatal("valid timestamp refused")
	}
	// The source's burst is two handshakes; the third within the second is
	// refused before any Noise work.
	try(now + 6)
	if try(now+7) || h.metrics.get("handshake:source_limited") != 1 {
		t.Fatal("per-source limit not applied")
	}
}

func TestRelayControlRateAndStaleTicket(t *testing.T) {
	t.Parallel()
	h := newRelay(t, func(c *Config) { c.ControlRate = 2 })
	a := h.newClient(zoneA) // newClient's KEEPALIVE used one token
	h.clock.advance(time.Second)
	for range 6 {
		a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	}
	if h.metrics.get("control:rate_limited") == 0 {
		t.Fatal("CONTROL not rate limited")
	}
	for a.recvAny() {
	}
	h.clock.advance(5 * time.Second)
	older := a.ticketAt(h.clock.now().Add(-time.Minute), zoneA)
	a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: older})
	if h.metrics.get("control:stale_ticket_update") != 1 {
		t.Fatal("older ticket accepted as an update")
	}
}

func TestRelayRouteNumbersNotReused(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneA)
	seen := map[uint32]bool{}
	for range 5 {
		ra, _ := openRoute(t, a, b)
		if seen[ra] {
			t.Fatalf("route number %d reused", ra)
		}
		seen[ra] = true
		a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: ra, RouteClose: mtrp.RouteCloseByClient})
		b.expectControl(mtrp.ControlRouteClose)
	}
}

// discardUDP is a UDPSender that does nothing, for allocation tests.
type discardUDP struct{}

func (discardUDP) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) { return len(b), nil }

func TestRelayDataPathDoesNotAllocate(t *testing.T) {
	h := newRelay(t, nil)
	a, b := h.newClient(zoneA), h.newClient(zoneA)
	ra, _ := openRoute(t, a, b)
	h.srv.cfg.UDP = discardUDP{}
	h.srv.cfg.Metrics = nopMetrics{} // the counting test metrics allocate label strings
	frame, err := mtrp.AppendData(nil, a.session.RemoteIndex(), ra, bytes.Repeat([]byte{1}, 1200))
	if err != nil {
		t.Fatal(err)
	}
	h.srv.HandleUDP(frame, a.addr) // warm the buffer pool
	if n := testing.AllocsPerRun(200, func() { h.srv.HandleUDP(frame, a.addr) }); n != 0 {
		t.Fatalf("DATA forwarding allocates %.1f times per frame", n)
	}
}

// fakeStream is a stream connection with a known remote address.
type fakeStream struct{ remote netip.Addr }

func (f *fakeStream) Send([]byte) error      { return nil }
func (f *fakeStream) Close() error           { return nil }
func (f *fakeStream) RemoteAddr() netip.Addr { return f.remote }

func TestRelayStreamHandshakesShareSourceLimit(t *testing.T) {
	t.Parallel()
	h := newRelay(t, func(c *Config) { c.SourceHandshakeRate = 1 })
	conn := &fakeStream{remote: netip.MustParseAddr("192.0.2.200")}
	a := h.newClient(zoneA)
	for i := range 5 {
		_, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
			Disco: a.disco, Relay: h.srv.PublicKey(), Index: uint32(100 + i),
			Hello: mtrp.ClientHello{TimestampMS: a.ts + int64(10+i), Ticket: a.ticket(zoneA)},
		})
		if err != nil {
			t.Fatal(err)
		}
		h.srv.HandleStream(init, conn)
	}
	if h.metrics.get("handshake:source_limited") != 3 {
		t.Fatalf("source_limited = %d, want 3 (burst 2)", h.metrics.get("handshake:source_limited"))
	}
}
