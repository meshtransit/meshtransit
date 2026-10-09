package server

import (
	"bytes"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

var baseTime = time.UnixMilli(1760000000000)

// fakeNet captures what the relay sends, per destination address.
type fakeNet struct {
	mu     sync.Mutex
	queues map[netip.AddrPort]chan []byte
}

func newFakeNet() *fakeNet { return &fakeNet{queues: make(map[netip.AddrPort]chan []byte)} }

func (n *fakeNet) queue(addr netip.AddrPort) chan []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	q, ok := n.queues[addr]
	if !ok {
		q = make(chan []byte, 256)
		n.queues[addr] = q
	}
	return q
}

func (n *fakeNet) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	n.queue(addr) <- bytes.Clone(b)
	return len(b), nil
}

// next returns the next frame sent to addr, or nil if none is queued.
func (n *fakeNet) next(addr netip.AddrPort) []byte {
	select {
	case b := <-n.queue(addr):
		return b
	default:
		return nil
	}
}

type clock struct{ ns atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.ns.Store(baseTime.UnixNano())
	return c
}

func (c *clock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *clock) advance(d time.Duration) { c.ns.Add(int64(d)) }

type countingMetrics struct {
	mu     sync.Mutex
	counts map[string]int
	routes int
}

func (m *countingMetrics) add(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = make(map[string]int)
	}
	m.counts[name]++
}

func (m *countingMetrics) Handshake(r string) { m.add("handshake:" + r) }
func (m *countingMetrics) Control(r string)   { m.add("control:" + r) }
func (m *countingMetrics) Data(r string, _ int) {
	m.add("data:" + r)
}
func (m *countingMetrics) Sessions(int)             {}
func (m *countingMetrics) SessionClosed(why string) { m.add("closed:" + why) }
func (m *countingMetrics) Routes(d int) {
	m.mu.Lock()
	m.routes += d
	m.mu.Unlock()
}

func (m *countingMetrics) get(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[name]
}

type relayHarness struct {
	t       testing.TB
	srv     *Server
	net     *fakeNet
	clock   *clock
	signer  key.SigningPrivate
	metrics *countingMetrics
	revoked *revokedNodes
}

type revokedNodes struct {
	mu    sync.Mutex
	nodes map[key.NodePublic]bool
	zones map[mtrp.Zone]bool
}

func (r *revokedNodes) ZoneRevoked(z mtrp.Zone) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.zones[z]
}

func (r *revokedNodes) withdraw(z mtrp.Zone) {
	r.mu.Lock()
	r.zones[z] = true
	r.mu.Unlock()
}

func (r *revokedNodes) Revoked(t mtrp.Ticket) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nodes[t.Node]
}

func (r *revokedNodes) revoke(n key.NodePublic) {
	r.mu.Lock()
	r.nodes[n] = true
	r.mu.Unlock()
}

func newRelay(t testing.TB, tune func(*Config)) *relayHarness {
	t.Helper()
	relayKey, err := key.NewRelayPrivate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	h := &relayHarness{
		t: t, net: newFakeNet(), clock: newClock(), signer: signer,
		metrics: &countingMetrics{}, revoked: &revokedNodes{nodes: map[key.NodePublic]bool{}, zones: map[mtrp.Zone]bool{}},
	}
	cfg := Config{
		Key:         relayKey,
		Keys:        mtrp.NewStaticKeys(signer.Public()),
		Revocations: h.revoked,
		UDP:         h.net,
		Now:         h.clock.now,
		Metrics:     h.metrics,
	}
	if tune != nil {
		tune(&cfg)
	}
	if h.srv, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	return h
}

var (
	zoneA = mtrp.Zone{Kind: mtrp.ZoneNetwork, ID: [16]byte{0xa}}
	zoneB = mtrp.Zone{Kind: mtrp.ZoneNetwork, ID: [16]byte{0xb}}
)

type testClient struct {
	h       *relayHarness
	addr    netip.AddrPort
	disco   key.DiscoPrivate
	node    key.NodePublic
	index   uint32
	session *mtrp.Session
	hello   mtrp.ServerHello
	ts      int64
}

var clientSeq atomic.Uint32

func (h *relayHarness) newClient(zones ...mtrp.Zone) *testClient {
	h.t.Helper()
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		h.t.Fatal(err)
	}
	n := clientSeq.Add(1)
	var node key.NodePublic
	node[0], node[1] = 0x4e, byte(n) //nolint:gosec // test counter
	c := &testClient{
		h: h, disco: disco, node: node, index: 0x100 + n,
		addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(n)}), 40000), //nolint:gosec // test counter
		ts:   baseTime.UnixMilli(),
	}
	if !c.connect(nil, zones...) {
		h.t.Fatal("handshake failed")
	}
	c.confirm()
	return c
}

// confirm sends the KEEPALIVE a client sends right after its handshake,
// which verifies its binding (mtrp-v1 §5.2), and consumes the reply.
func (c *testClient) confirm() {
	c.h.t.Helper()
	c.sendControl(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	c.expectControl(mtrp.ControlKeepalive)
}

func (c *testClient) ticket(zones ...mtrp.Zone) []byte {
	c.h.t.Helper()
	return c.ticketAt(c.h.clock.now(), zones...)
}

// recvAny consumes one queued frame; it reports whether there was one.
func (c *testClient) recvAny() bool { return c.h.net.next(c.addr) != nil }

func (c *testClient) ticketAt(issued time.Time, zones ...mtrp.Zone) []byte {
	c.h.t.Helper()
	now := issued.UnixMilli()
	t := mtrp.Ticket{
		ID:         [16]byte{byte(c.index)}, //nolint:gosec // test value
		IssuedAtMS: now,
		NotAfterMS: now + (10 * time.Minute).Milliseconds(),
		Node:       c.node,
		Disco:      c.disco.Public(),
		Deployment: [16]byte{0x01, 0x99},
		Zones:      zones,
	}
	signed, err := t.Sign(c.h.signer)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return signed
}

// connect runs a handshake; it reports whether the relay answered.
func (c *testClient) connect(cookie *[mtrp.MACSize]byte, zones ...mtrp.Zone) bool {
	c.h.t.Helper()
	c.ts++
	hs, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: c.disco, Relay: c.h.srv.PublicKey(), Index: c.index, PadUDP: true, Cookie: cookie,
		Hello: mtrp.ClientHello{TimestampMS: c.ts, Ticket: c.ticket(zones...)},
	})
	if err != nil {
		c.h.t.Fatal(err)
	}
	c.h.srv.HandleUDP(init, c.addr)
	resp := c.h.net.next(c.addr)
	if resp == nil {
		return false
	}
	if t, _ := mtrp.PeekType(resp); t == mtrp.TypeCookie {
		got, err := hs.OpenCookie(resp)
		if err != nil {
			c.h.t.Fatal(err)
		}
		return c.connect(&got, zones...)
	}
	c.session, c.hello, err = hs.Finish(resp)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return true
}

func (c *testClient) sendControl(msg mtrp.ControlMessage) { c.sendControlFrom(c.addr, msg) }

func (c *testClient) sendControlFrom(addr netip.AddrPort, msg mtrp.ControlMessage) {
	c.h.t.Helper()
	plain, err := mtrp.AppendControlMessage(nil, msg)
	if err != nil {
		c.h.t.Fatal(err)
	}
	frame, err := c.session.SealControl(nil, plain)
	if err != nil {
		c.h.t.Fatal(err)
	}
	c.h.srv.HandleUDP(frame, addr)
}

// recvControl returns the next CONTROL message sent to the client.
func (c *testClient) recvControl() (mtrp.ControlMessage, bool) {
	c.h.t.Helper()
	for {
		frame := c.h.net.next(c.addr)
		if frame == nil {
			return mtrp.ControlMessage{}, false
		}
		if t, _ := mtrp.PeekType(frame); t != mtrp.TypeControl {
			continue
		}
		plain, err := c.session.OpenControl(nil, frame)
		if err != nil {
			c.h.t.Fatalf("open control: %v", err)
		}
		msg, err := mtrp.ParseControlMessage(plain)
		if err != nil {
			c.h.t.Fatalf("parse control: %v", err)
		}
		return msg, true
	}
}

func (c *testClient) expectControl(want mtrp.ControlType) mtrp.ControlMessage {
	c.h.t.Helper()
	msg, ok := c.recvControl()
	if !ok || msg.Type != want {
		c.h.t.Fatalf("expected control %d, got %+v (received %v)", want, msg, ok)
	}
	return msg
}

func (c *testClient) sendData(from netip.AddrPort, route uint32, payload []byte) {
	c.h.t.Helper()
	frame, err := mtrp.AppendData(nil, c.session.RemoteIndex(), route, payload)
	if err != nil {
		c.h.t.Fatal(err)
	}
	c.h.srv.HandleUDP(frame, from)
}

func (c *testClient) recvData() (mtrp.Data, bool) {
	frame := c.h.net.next(c.addr)
	if frame == nil {
		return mtrp.Data{}, false
	}
	d, err := mtrp.ParseData(frame)
	if err != nil {
		return mtrp.Data{}, false
	}
	return d, true
}

// openRoute asks for a route to peer and returns both route numbers.
func openRoute(t *testing.T, a, b *testClient) (uint32, uint32) {
	t.Helper()
	a.sendControl(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 7, Peer: b.node})
	ok := a.expectControl(mtrp.ControlRouteOK)
	in := b.expectControl(mtrp.ControlRouteIncoming)
	if ok.Request != 7 || in.Peer != a.node {
		t.Fatalf("route grant: ok %+v incoming %+v", ok, in)
	}
	return ok.Route, in.Route
}
