package interchange

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// fakeRelay is a minimal MTRP relay built on shared/mtrp's server side:
// handshake, cookies, keepalive answers, routes between two sessions, DATA
// forwarding and ticket updates. It is enough to exercise the client.
type fakeRelay struct {
	t       testing.TB
	key     key.RelayPrivate
	macs    mtrp.RelayMACKeys
	signer  key.SigningPrivate
	jar     *mtrp.CookieJar
	udp     *net.UDPConn
	tls     net.Listener
	ignoreU atomic.Bool // drop UDP INITs (UDP blocked)
	mute    atomic.Bool // stop answering anything (a relay that died silently)
	cookies atomic.Bool // demand mac2

	mu        sync.Mutex
	byIndex   map[uint32]*fakeSession
	byNode    map[key.NodePublic]*fakeSession
	nextIndex uint32
	updates   int
	challenge uint64
}

type fakeSession struct {
	session *mtrp.Session
	node    key.NodePublic
	send    func([]byte)
	routes  map[uint32]*fakeSession // by this session's route number
	byPeer  map[key.NodePublic]uint32
	answers int
}

func newFakeRelay(t testing.TB) *fakeRelay {
	t.Helper()
	relayKey, err := key.NewRelayPrivate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	jar, err := mtrp.NewCookieJar(rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)}, NextProtos: []string{alpnMTRP}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRelay{
		t: t, key: relayKey, macs: mtrp.NewRelayMACKeys(relayKey.Public()), signer: signer, jar: jar,
		udp: udp, tls: ln, byIndex: map[uint32]*fakeSession{}, byNode: map[key.NodePublic]*fakeSession{},
		nextIndex: 100,
	}
	t.Cleanup(func() { _ = udp.Close(); _ = ln.Close() })
	go r.serveUDP()
	go r.serveTLS()
	return r
}

func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"}, DNSNames: []string{"relay.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func (r *fakeRelay) node() relay.Node {
	return relay.Node{
		Name: "fake", HostName: "relay.test", IPv4: "127.0.0.1",
		Port:     portOf(r.tls.Addr()),
		UDPPort:  portOf(r.udp.LocalAddr()),
		RelayKey: r.key.Public(),
	}
}

func portOf(addr net.Addr) uint16 {
	return netip.MustParseAddrPort(addr.String()).Port()
}

// ticket signs a ticket for a node and disco key in one Network zone.
func (r *fakeRelay) ticket(node key.NodePublic, disco key.DiscoPublic, lifetime time.Duration) []byte {
	now := time.Now()
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[0] |= 1
	b, err := mtrp.Ticket{
		ID: id, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(lifetime).UnixMilli(),
		Node: node, Disco: disco, Deployment: [16]byte{0x01, 0x99, 6: 0x70, 8: 0x80},
		Zones: []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{1}}},
	}.Sign(r.signer)
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

func (r *fakeRelay) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, from, err := r.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		frame := append([]byte(nil), buf[:n]...)
		r.handle(frame, from, func(out []byte) { _, _ = r.udp.WriteToUDPAddrPort(out, from) }, true)
	}
}

func (r *fakeRelay) serveTLS() {
	for {
		conn, err := r.tls.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			var writeMu sync.Mutex
			send := func(out []byte) {
				writeMu.Lock()
				defer writeMu.Unlock()
				_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...)) //nolint:gosec // test frames
			}
			for {
				var hdr [2]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				frame := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(conn, frame); err != nil {
					return
				}
				r.handle(frame, netip.AddrPort{}, send, false)
			}
		}()
	}
}

func (r *fakeRelay) handle(frame []byte, from netip.AddrPort, send func([]byte), udp bool) {
	if r.mute.Load() {
		return
	}
	typ, err := mtrp.PeekType(frame)
	if err != nil {
		return
	}
	switch typ {
	case mtrp.TypeInit:
		if udp && r.ignoreU.Load() {
			return
		}
		r.handshake(frame, from, send, udp)
	case mtrp.TypeControl:
		c, err := mtrp.ParseControl(frame)
		if err != nil {
			return
		}
		r.mu.Lock()
		sess := r.byIndex[c.ReceiverIndex]
		r.mu.Unlock()
		if sess == nil {
			return
		}
		plain, err := sess.session.OpenControl(nil, frame)
		if err != nil {
			return
		}
		msg, err := mtrp.ParseControlMessage(plain)
		if err != nil {
			return
		}
		r.control(sess, msg)
	case mtrp.TypeData:
		d, err := mtrp.ParseData(frame)
		if err != nil {
			return
		}
		r.mu.Lock()
		sess := r.byIndex[d.ReceiverIndex]
		var peer *fakeSession
		var peerRoute uint32
		if sess != nil {
			peer = sess.routes[d.Route]
			if peer != nil {
				peerRoute = peer.byPeer[sess.node]
			}
		}
		r.mu.Unlock()
		if peer == nil {
			return
		}
		out, _ := mtrp.AppendData(nil, peer.session.RemoteIndex(), peerRoute, d.Payload)
		peer.send(out)
	default:
	}
}

func (r *fakeRelay) handshake(frame []byte, from netip.AddrPort, send func([]byte), udp bool) {
	if udp && r.cookies.Load() {
		init, err := mtrp.ParseInit(frame)
		if err != nil {
			return
		}
		cookie, _ := r.jar.Cookie(from)
		_, beforeMAC2, _ := mtrp.MACInput(frame)
		if !mtrp.CheckMAC2(cookie, beforeMAC2, init.MAC2) {
			nonce, enc, err := r.macs.SealCookie(cookie, init.MAC1, rand.Reader)
			if err != nil {
				return
			}
			out, _ := mtrp.AppendCookie(nil, mtrp.Cookie{ReceiverIndex: init.SenderIndex, Nonce: nonce, EncryptedCookie: enc})
			send(out)
			return
		}
	}
	hs, err := mtrp.ReadInit(r.key, frame)
	if err != nil {
		return
	}
	ticket, err := mtrp.Verifier{Keys: mtrp.NewStaticKeys(r.signer.Public())}.Verify(hs.Hello().Ticket)
	if err != nil || ticket.Disco != hs.Peer() {
		return
	}
	r.mu.Lock()
	r.nextIndex++
	index := r.nextIndex
	r.mu.Unlock()
	out, session, err := hs.Respond(index, mtrp.ServerHello{KeepaliveS: 1, IdleTimeoutS: 5, MaxRoutes: 16, NotAfterMS: ticket.NotAfterMS}, r.macs)
	if err != nil {
		return
	}
	sess := &fakeSession{session: session, node: ticket.Node, send: send, routes: map[uint32]*fakeSession{}, byPeer: map[key.NodePublic]uint32{}}
	r.mu.Lock()
	r.byIndex[index] = sess
	r.byNode[ticket.Node] = sess
	r.mu.Unlock()
	send(out)
}

func (r *fakeRelay) sendControl(sess *fakeSession, msg mtrp.ControlMessage) {
	plain, _ := mtrp.AppendControlMessage(nil, msg)
	out, err := sess.session.SealControl(nil, plain)
	if err == nil {
		sess.send(out)
	}
}

func (r *fakeRelay) control(sess *fakeSession, msg mtrp.ControlMessage) {
	switch msg.Type {
	case mtrp.ControlKeepalive:
		r.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	case mtrp.ControlRouteOpen:
		r.mu.Lock()
		peer := r.byNode[msg.Peer]
		if peer == nil {
			r.mu.Unlock()
			r.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlRouteError, Request: msg.Request, RouteError: mtrp.RouteErrorPeerAbsent})
			return
		}
		srcRoute, ok := sess.byPeer[peer.node]
		if !ok {
			r.nextIndex++
			srcRoute = r.nextIndex
			r.nextIndex++
			peerRoute := r.nextIndex
			sess.routes[srcRoute], sess.byPeer[peer.node] = peer, srcRoute
			peer.routes[peerRoute], peer.byPeer[sess.node] = sess, peerRoute
		}
		peerRoute := peer.byPeer[sess.node]
		r.mu.Unlock()
		r.sendControl(peer, mtrp.ControlMessage{Type: mtrp.ControlRouteIncoming, Route: peerRoute, Peer: sess.node})
		r.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlRouteOK, Request: msg.Request, Route: srcRoute})
	case mtrp.ControlTicketUpdate:
		r.mu.Lock()
		r.updates++
		r.mu.Unlock()
		r.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlTicketAck, NotAfterMS: 1})
	case mtrp.ControlPathResponse:
		r.mu.Lock()
		if msg.Nonce == r.challenge {
			sess.answers++
		}
		r.mu.Unlock()
	default:
	}
}

func (r *fakeRelay) closeAll(reason mtrp.SessionCloseReason) {
	r.mu.Lock()
	sessions := make([]*fakeSession, 0, len(r.byIndex))
	for _, s := range r.byIndex {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		r.sendControl(s, mtrp.ControlMessage{Type: mtrp.ControlSessionClose, SessionClose: reason, RetryAfterMS: 3000})
	}
}

// serveWebSocket adds a TLS listener that speaks only HTTP/1.1 with the
// MTRP WebSocket upgrade, like a relay reached through an HTTP-only path.
// It returns the listener's port.
func (r *fakeRelay) serveWebSocket() uint16 {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(r.t)}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != wsPath {
			http.NotFound(w, req)
			return
		}
		conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{Subprotocols: []string{wsSubprotocol}})
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		ctx := context.Background()
		var writeMu sync.Mutex
		send := func(out []byte) {
			writeMu.Lock()
			defer writeMu.Unlock()
			_ = conn.Write(ctx, websocket.MessageBinary, out)
		}
		for {
			_, frame, err := conn.Read(ctx)
			if err != nil {
				return
			}
			r.handle(frame, netip.AddrPort{}, send, false)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	r.t.Cleanup(func() { _ = srv.Close() })
	return portOf(ln.Addr())
}
