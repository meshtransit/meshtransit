package server

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// contracts returns n Trust Contract zones in canonical order.
func contracts(n int) []mtrp.Zone {
	zones := make([]mtrp.Zone, n)
	for i := range zones {
		var id [16]byte
		binary.BigEndian.PutUint32(id[:], uint32(i+1))
		id[15] = 0xc0
		zones[i] = mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: id}
	}
	return zones
}

var ticketSeq atomic.Uint32

// ticketV2 signs an MTT2 ticket for c granting zones and returns it with
// the complete ticket the client holds.
func (c *testClient) ticketV2(zones ...mtrp.Zone) ([]byte, mtrp.Ticket) {
	c.h.t.Helper()
	seq := ticketSeq.Add(1)
	now := c.h.clock.now().UnixMilli()
	t := mtrp.Ticket{
		IssuedAtMS: now, NotAfterMS: now + (10 * time.Minute).Milliseconds(),
		Node: c.node, Disco: c.disco.Public(), Deployment: [16]byte{0x01, 0x99}, Zones: zones,
	}
	binary.BigEndian.PutUint32(t.ID[:], seq)
	t.ID[15] = 0x2
	raw, encoded, err := t.SignZones(c.h.signer)
	if err != nil {
		c.h.t.Fatal(err)
	}
	parsed, err := mtrp.ParseTicketUnverified(raw)
	if err != nil {
		c.h.t.Fatal(err)
	}
	all, err := mtrp.ParseZones(encoded)
	if err != nil {
		c.h.t.Fatal(err)
	}
	complete, err := parsed.WithZones(all)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return raw, complete
}

// newClientV2 connects a client with an MTT2 ticket (zones not yet sent).
// The caller confirms the binding after any acknowledgement it expects.
func (h *relayHarness) newClientV2(zones ...mtrp.Zone) (*testClient, mtrp.Ticket) {
	h.t.Helper()
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		h.t.Fatal(err)
	}
	n := clientSeq.Add(1)
	c := &testClient{
		h: h, disco: disco, index: 0x100 + n, ts: baseTime.UnixMilli(),
		addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(n)}), 40000), //nolint:gosec // test counter
	}
	c.node[0], c.node[1] = 0x4e, byte(n) //nolint:gosec // test counter
	return c, h.connectV2(c, zones...)
}

// newClientV2For connects again as the same node and disco key, which
// replaces its session.
func (h *relayHarness) newClientV2For(c *testClient, zones ...mtrp.Zone) mtrp.Ticket {
	h.t.Helper()
	return h.connectV2(c, zones...)
}

func (h *relayHarness) connectV2(c *testClient, zones ...mtrp.Zone) mtrp.Ticket {
	h.t.Helper()
	raw, complete := c.ticketV2(zones...)
	c.ts++
	hs, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: c.disco, Relay: h.srv.PublicKey(), Index: c.index, PadUDP: true,
		Hello: mtrp.ClientHello{TimestampMS: c.ts, Ticket: raw},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.srv.HandleUDP(init, c.addr)
	resp := h.net.next(c.addr)
	if resp == nil {
		h.t.Fatal("no handshake response for the MTT2 ticket")
	}
	if c.session, c.hello, err = hs.Finish(resp); err != nil {
		h.t.Fatal(err)
	}
	return complete
}

func (c *testClient) sendZones(t mtrp.Ticket) {
	for _, frame := range mtrp.ZoneFrames(t) {
		c.sendControl(frame)
	}
}

func (c *testClient) routeOpenResult(peer *testClient, request uint32) mtrp.ControlMessage {
	c.h.t.Helper()
	c.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: request, Peer: peer.node})
	msg, ok := c.recvControl()
	if !ok {
		c.h.t.Fatal("no answer to ROUTE_OPEN")
	}
	return msg
}

// TestRelayAssemblesZonesOfALargeTicket: a provider with 10,000 Trust
// Contracts reaches a consumer whose contract is not inline only after its
// ZONES frames arrive; the relay then acknowledges the ticket, ignores
// resent frames and never charged the CONTROL allowance for them.
func TestRelayAssemblesZonesOfALargeTicket(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	all := append([]mtrp.Zone{zoneA}, contracts(10_000)...)
	last := all[len(all)-1]
	provider, complete := h.newClientV2(all...)
	provider.confirm()
	consumer := h.newClient(zoneB, last)
	inlineConsumer := h.newClient(zoneB, all[5])

	if m := consumer.routeOpenResult(provider, 1); m.Type != mtrp.ControlRouteError {
		t.Fatalf("route over a zone not yet received: %+v", m)
	}
	// Inline zones are in force from the handshake.
	openRoute(t, inlineConsumer, provider)

	provider.sendZones(complete)
	if ack := provider.expectControl(mtrp.ControlTicketAck); ack.NotAfterMS != uint64(complete.NotAfterMS) { //nolint:gosec // test value
		t.Fatalf("ack %+v", ack)
	}
	if got := h.srv.zonesHeld.Load(); got != int64(len(all)) {
		t.Fatalf("zones held %d, want %d", got, len(all))
	}
	rc, rp := openRoute(t, consumer, provider)
	consumer.sendData(consumer.addr, rc, []byte("over contract 10000"))
	if d, ok := provider.recvData(); !ok || d.Route != rp {
		t.Fatal("no forwarding over the assembled zone")
	}
	// A resend after completion (the node missed the acknowledgement) is
	// acknowledged again, once a second; the CONTROL allowance is intact.
	provider.sendZones(complete)
	if ack := provider.expectControl(mtrp.ControlTicketAck); ack.NotAfterMS != uint64(complete.NotAfterMS) { //nolint:gosec // test value
		t.Fatalf("repeated ack %+v", ack)
	}
	if h.metrics.get("control:zones_unexpected") != len(mtrp.ZoneFrames(complete))-1 || h.metrics.get("control:rate_limited") != 0 {
		t.Fatalf("resend: unexpected %d, rate limited %d", h.metrics.get("control:zones_unexpected"),
			h.metrics.get("control:rate_limited"))
	}
	provider.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	provider.expectControl(mtrp.ControlKeepalive)

	// Closing the session returns its zones to the budget.
	h.srv.closeSession(h.srv.byNode[provider.node], mtrp.SessionClosePolicy, 0, "test")
	if got := h.srv.zonesHeld.Load(); got != 0 {
		t.Fatalf("zones held after close: %d", got)
	}
}

// TestRelayZonesCorruptPassAndUpdate: a corrupt zone list is not put in
// force; a later ticket without a contract replaces the assembled one only
// once its own zones are complete, then the route over that contract closes.
func TestRelayZonesCorruptPassAndUpdate(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	all := append([]mtrp.Zone{zoneA}, contracts(200)...)
	target := all[150]
	provider, complete := h.newClientV2(all...)
	provider.confirm()
	consumer := h.newClient(zoneB, target)

	frames := mtrp.ZoneFrames(complete)
	bad := frames[len(frames)-1]
	bad.Zones = append([]mtrp.Zone(nil), bad.Zones...)
	bad.Zones[len(bad.Zones)-1].ID[14] = 0xff
	for _, frame := range append(frames[:len(frames)-1:len(frames)-1], bad) {
		provider.sendControl(frame)
	}
	if _, ok := provider.recvControl(); ok || h.metrics.get("control:zones_digest_mismatch") != 1 {
		t.Fatal("corrupt zone list acknowledged")
	}
	provider.sendZones(complete)
	provider.expectControl(mtrp.ControlTicketAck)
	rc, _ := openRoute(t, consumer, provider)

	// The next ticket drops the target contract; until its zones arrive the
	// route stays up, then it closes as revoked.
	h.clock.advance(time.Second)
	without := append(append([]mtrp.Zone(nil), all[:150]...), all[151:]...)
	raw, next := provider.ticketV2(without...)
	provider.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: raw})
	if _, ok := provider.recvControl(); ok {
		t.Fatal("pending ticket acknowledged before its zones")
	}
	consumer.sendData(consumer.addr, rc, []byte("still"))
	if _, ok := provider.recvData(); !ok {
		t.Fatal("route closed before the new ticket was complete")
	}
	provider.sendZones(next)
	provider.expectControl(mtrp.ControlRouteClose)
	provider.expectControl(mtrp.ControlTicketAck)
	if m := consumer.expectControl(mtrp.ControlRouteClose); m.RouteClose != mtrp.RouteCloseRevoked {
		t.Fatalf("consumer: %+v", m)
	}
	if got := h.srv.zonesHeld.Load(); got != int64(len(without)) {
		t.Fatalf("zones held %d, want %d (the replaced ticket released)", got, len(without))
	}
}

// TestRelayZonesOverLimitUseInlineZones: a ticket above the relay's zone
// limit, or one the budget cannot hold, is put in force with its inline
// zones and acknowledged at once, so the node stops sending ZONES.
func TestRelayZonesOverLimitUseInlineZones(t *testing.T) {
	t.Parallel()
	for name, tune := range map[string]func(*Config){
		"session limit": func(c *Config) { c.MaxSessionZones = 100 },
		"relay budget":  func(c *Config) { c.ZoneBudget = 500 },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newRelay(t, tune)
			all := append([]mtrp.Zone{zoneA}, contracts(1000)...)
			provider, _ := h.newClientV2(all...)
			provider.expectControl(mtrp.ControlTicketAck)
			provider.confirm()
			inline, beyond := h.newClient(zoneB, all[mtrp.MaxZones-1]), h.newClient(zoneB, all[mtrp.MaxZones])
			openRoute(t, inline, provider)
			if m := beyond.routeOpenResult(provider, 3); m.Type != mtrp.ControlRouteError {
				t.Fatalf("route beyond the inline zones: %+v", m)
			}
			if h.metrics.get("control:zones_refused") != 1 || h.srv.zonesHeld.Load() != 0 {
				t.Fatalf("refused %d, held %d", h.metrics.get("control:zones_refused"), h.srv.zonesHeld.Load())
			}
		})
	}
}

// TestRelayWithdrawnContractRechecksRouteZone: withdrawing the contract a
// route rests on closes it; a route that can rest on another shared zone is
// kept on that zone.
func TestRelayWithdrawnContractRechecksRouteZone(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	all := append([]mtrp.Zone{zoneA}, contracts(300)...)
	provider, complete := h.newClientV2(all...)
	provider.confirm()
	provider.sendZones(complete)
	provider.expectControl(mtrp.ControlTicketAck)
	only := h.newClient(zoneB, all[200])
	both := h.newClient(zoneB, all[100], all[250])
	ro, _ := openRoute(t, only, provider)
	rb, rbp := openRoute(t, both, provider)

	h.revoked.withdraw(all[100]) // the zone the second route opened on
	h.revoked.withdraw(all[200])
	h.srv.sweep()
	if m := only.expectControl(mtrp.ControlRouteClose); m.Route != ro {
		t.Fatalf("only: %+v", m)
	}
	provider.expectControl(mtrp.ControlRouteClose)
	both.sendData(both.addr, rb, []byte("on contract 250"))
	if d, ok := provider.recvData(); !ok || d.Route != rbp {
		t.Fatal("route with another live shared zone closed")
	}
}

// TestRelayZonesRecheckedAtCompletion: a ticket revoked while its zones are
// in flight is not put in force when they complete; its zones return to the
// budget and the node is told to stop.
func TestRelayZonesRecheckedAtCompletion(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	all := append([]mtrp.Zone{zoneA}, contracts(200)...)
	provider, complete := h.newClientV2(all...)
	provider.confirm()
	h.revoked.revoke(provider.node)
	provider.sendZones(complete)
	provider.expectControl(mtrp.ControlTicketAck)
	if h.metrics.get("control:zones_ticket_ended") != 1 || h.srv.zonesHeld.Load() != 0 {
		t.Fatalf("ended %d, held %d", h.metrics.get("control:zones_ticket_ended"), h.srv.zonesHeld.Load())
	}
	if sess := h.srv.byNode[provider.node]; sess.currentTicket().ZonesComplete() {
		t.Fatal("a revoked ticket came into force")
	}
}

// TestRelayZonesRenewAtAFullBudget: renewing a ticket of thousands of
// zones needs only the growth from the budget, so a session that holds most
// of it renews without losing routes, and ends up charged once.
func TestRelayZonesRenewAtAFullBudget(t *testing.T) {
	t.Parallel()
	all := append([]mtrp.Zone{zoneA}, contracts(2000)...)
	h := newRelay(t, func(c *Config) { c.ZoneBudget = len(all) + 100 })
	provider, complete := h.newClientV2(all...)
	provider.confirm()
	provider.sendZones(complete)
	provider.expectControl(mtrp.ControlTicketAck)
	consumer := h.newClient(zoneB, all[1500])
	rc, rp := openRoute(t, consumer, provider)

	h.clock.advance(time.Second)
	raw, next := provider.ticketV2(append(append([]mtrp.Zone(nil), all...), contracts(2050)[2000:]...)...)
	provider.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: raw})
	provider.sendZones(next)
	if ack := provider.expectControl(mtrp.ControlTicketAck); ack.NotAfterMS != uint64(next.NotAfterMS) { //nolint:gosec // test value
		t.Fatalf("renewal ack %+v", ack)
	}
	consumer.sendData(consumer.addr, rc, []byte("after renewal"))
	if d, ok := provider.recvData(); !ok || d.Route != rp {
		t.Fatal("route lost on renewal at a full budget")
	}
	if got := h.srv.zonesHeld.Load(); got != int64(next.ZoneTotal) {
		t.Fatalf("zones held %d, want %d", got, next.ZoneTotal)
	}
}

// TestRelayPendingZonesAcrossReplacementAndUpdates: an older ticket does
// not replace a newer one being assembled, a repeated update is ignored
// before verification, and a replaced session returns all its zones.
func TestRelayPendingZonesAcrossReplacementAndUpdates(t *testing.T) {
	t.Parallel()
	h := newRelay(t, nil)
	all := append([]mtrp.Zone{zoneA}, contracts(300)...)
	provider, _ := h.newClientV2(all...)
	provider.confirm()
	h.clock.advance(time.Second)
	older, _ := provider.ticketV2(all[:200]...)
	h.clock.advance(time.Second)
	newer, _ := provider.ticketV2(all[:250]...)
	provider.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: newer})
	provider.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: newer})
	if h.metrics.get("control:repeated_ticket_update") != 1 {
		t.Fatalf("repeats %d", h.metrics.get("control:repeated_ticket_update"))
	}
	provider.sendControl(mtrp.ControlMessage{Type: mtrp.ControlTicketUpdate, Ticket: older})
	provider.expectControl(mtrp.ControlTicketAck) // the older one is acknowledged, not staged
	sess := h.srv.byNode[provider.node]
	sess.mu.Lock()
	pendingTotal := sess.pending.Ticket().ZoneTotal
	sess.mu.Unlock()
	if pendingTotal != 250 {
		t.Fatalf("pending ticket of %d zones, want the newer 250", pendingTotal)
	}
	// A new session for the same node replaces this one and its zones.
	h.newClientV2For(provider, all...)
	if got := h.srv.zonesHeld.Load(); got != int64(len(all)) {
		t.Fatalf("zones held %d after replacement, want only the new session's %d", got, len(all))
	}
}

// TestRelayZoneFramesHaveTheirOwnAllowance: ZONES frames beyond their rate
// are dropped without touching the CONTROL allowance.
func TestRelayZoneFramesHaveTheirOwnAllowance(t *testing.T) {
	t.Parallel()
	h := newRelay(t, func(c *Config) { c.ZoneFrameRate = 2 })
	all := append([]mtrp.Zone{zoneA}, contracts(1000)...)
	provider, complete := h.newClientV2(all...)
	provider.confirm()
	provider.sendZones(complete)
	if h.metrics.get("control:zones_rate_limited") == 0 || h.metrics.get("control:rate_limited") != 0 {
		t.Fatalf("zones limited %d, control limited %d", h.metrics.get("control:zones_rate_limited"),
			h.metrics.get("control:rate_limited"))
	}
	provider.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	provider.expectControl(mtrp.ControlKeepalive)
}
