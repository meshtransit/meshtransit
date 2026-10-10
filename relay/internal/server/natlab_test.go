package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/relay/internal/server"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
	"meshtransit.net/test/natlab"
)

// The relay cells of the traversal matrix (test/natlab/testdata/matrix.md):
// both sides behind endpoint-dependent mapping, where no direct technique
// connects them and traffic must go through the relay.
var relayProfiles = []natlab.Profile{
	natlab.SymmetricSequential, natlab.SymmetricRandom, natlab.CGNATSymmetric,
}

// labRelay runs a real relay server on a public host of a NAT lab.
type labRelay struct {
	addr   netip.AddrPort
	key    key.RelayPublic
	signer key.SigningPrivate
}

func startLabRelay(t *testing.T, lab *natlab.Lab) labRelay {
	t.Helper()
	host, err := lab.AddNode("relay", natlab.Public)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := host.Listen(3340)
	if err != nil {
		t.Fatal(err)
	}
	relayKey, _ := key.NewRelayPrivate()
	signer, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{5}, 32))
	relay, err := server.New(server.Config{Key: relayKey, Keys: mtrp.NewStaticKeys(signer.Public()), UDP: conn})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, mtrp.MaxUDPFrame+1)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			relay.HandleUDP(buf[:n], from)
		}
	})
	wg.Go(func() {
		if err := relay.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = conn.Close()
		wg.Wait()
	})
	return labRelay{addr: conn.LocalAddrPort(), key: relayKey.Public(), signer: signer}
}

// labClient is a minimal MTRP client on a NAT lab host.
type labClient struct {
	t       *testing.T
	conn    *natlab.Conn
	relay   netip.AddrPort
	session *mtrp.Session
	node    key.NodePublic
}

func dialLabRelay(t *testing.T, lab *natlab.Lab, relay labRelay, name string, profile natlab.Profile,
	node byte,
) *labClient {
	t.Helper()
	host, err := lab.AddNode(name, profile)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := host.Listen(41641)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	c := &labClient{t: t, conn: conn, relay: relay.addr, node: key.NodePublic{0x4e, node}}
	now := time.Now()
	ticket, err := mtrp.Ticket{
		ID: [16]byte{node}, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(10 * time.Minute).UnixMilli(),
		Node: c.node, Disco: disco.Public(), Deployment: [16]byte{1},
		Zones: []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{7}}},
	}.Sign(relay.signer)
	if err != nil {
		t.Fatal(err)
	}
	hs, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: disco, Relay: relay.key, Index: uint32(node) + 1, PadUDP: true,
		Hello: mtrp.ClientHello{TimestampMS: now.UnixMilli(), Ticket: ticket},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.send(init)
	if c.session, _, err = hs.Finish(c.recv()); err != nil {
		t.Fatalf("%s handshake: %v", name, err)
	}
	c.control(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	if msg := c.expectControl(); msg.Type != mtrp.ControlKeepalive {
		t.Fatalf("%s keepalive reply %+v", name, msg)
	}
	return c
}

func (c *labClient) send(frame []byte) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDPAddrPort(frame, c.relay); err != nil {
		c.t.Fatal(err)
	}
}

func (c *labClient) recv() []byte {
	c.t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		c.t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, from, err := c.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	if from != c.relay {
		c.t.Fatalf("frame from %s, not the relay", from)
	}
	return buf[:n]
}

func (c *labClient) control(msg mtrp.ControlMessage) {
	c.t.Helper()
	plain, err := mtrp.AppendControlMessage(nil, msg)
	if err != nil {
		c.t.Fatal(err)
	}
	frame, err := c.session.SealControl(nil, plain)
	if err != nil {
		c.t.Fatal(err)
	}
	c.send(frame)
}

func (c *labClient) expectControl() mtrp.ControlMessage {
	c.t.Helper()
	plain, err := c.session.OpenControl(nil, c.recv())
	if err != nil {
		c.t.Fatal(err)
	}
	msg, err := mtrp.ParseControlMessage(plain)
	if err != nil {
		c.t.Fatal(err)
	}
	return msg
}

// route opens a route from a to b and returns the route IDs on each side.
func route(t *testing.T, a, b *labClient) (uint32, uint32) {
	t.Helper()
	a.control(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 1, Peer: b.node})
	ok, incoming := a.expectControl(), b.expectControl()
	if ok.Type != mtrp.ControlRouteOK || incoming.Type != mtrp.ControlRouteIncoming {
		t.Fatalf("route: %+v / %+v", ok, incoming)
	}
	return ok.Route, incoming.Route
}

// exchange sends payloads from one side and checks each arrives on the other.
func exchange(t *testing.T, from, to *labClient, fromRoute, toRoute uint32, count int, tag byte) {
	t.Helper()
	for i := range count {
		payload := bytes.Repeat([]byte{tag, byte(i)}, 300)
		frame, err := mtrp.AppendData(nil, from.session.RemoteIndex(), fromRoute, payload)
		if err != nil {
			t.Fatal(err)
		}
		from.send(frame)
		d, err := mtrp.ParseData(to.recv())
		if err != nil || d.Route != toRoute || !bytes.Equal(d.Payload, payload) {
			t.Fatalf("frame %d: route %d (want %d), %v", i, d.Route, toRoute, err)
		}
	}
}

// TestRelayCellsOfTraversalMatrix runs the real relay on a NAT lab Internet
// and connects every pair the traversal matrix marks "relay": both nodes
// reach the relay from behind endpoint-dependent NATs, open a route and
// exchange data both ways (P2f).
func TestRelayCellsOfTraversalMatrix(t *testing.T) {
	t.Parallel()
	for i, a := range relayProfiles {
		for _, b := range relayProfiles[i:] {
			t.Run(a.Name+"/"+b.Name, func(t *testing.T) {
				t.Parallel()
				lab, err := natlab.NewLab(nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(lab.Close)
				relay := startLabRelay(t, lab)
				left := dialLabRelay(t, lab, relay, "a", a, 1)
				right := dialLabRelay(t, lab, relay, "b", b, 2)
				leftRoute, rightRoute := route(t, left, right)
				exchange(t, left, right, leftRoute, rightRoute, 20, 0xa1)
				exchange(t, right, left, rightRoute, leftRoute, 20, 0xb2)
			})
		}
	}
}

// withTimeout returns profile with every NAT mapping expiring after idle.
func withTimeout(profile natlab.Profile, idle time.Duration) natlab.Profile {
	nats := make([]natlab.NATConfig, len(profile.NATs))
	for i, nat := range profile.NATs {
		nat.Timeout = idle
		nats[i] = nat
	}
	return natlab.Profile{Name: fmt.Sprintf("%s-%s", profile.Name, idle), NATs: nats}
}

// TestRelayFollowsNATRebinding lets a symmetric NAT forget a node's mapping.
// The node's next CONTROL frame arrives from a new external port; the relay
// moves the session there, proves the path with PATH_CHALLENGE, and data
// reaches the node again without a new handshake.
func TestRelayFollowsNATRebinding(t *testing.T) {
	t.Parallel()
	lab, err := natlab.NewLab(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	const idle = 300 * time.Millisecond
	relay := startLabRelay(t, lab)
	roamer := dialLabRelay(t, lab, relay, "roamer", withTimeout(natlab.SymmetricRandom, idle), 1)
	peer := dialLabRelay(t, lab, relay, "peer", natlab.CGNATSymmetric, 2)
	roamerRoute, peerRoute := route(t, roamer, peer)
	exchange(t, peer, roamer, peerRoute, roamerRoute, 5, 0xc3)

	time.Sleep(3 * idle) // the roamer's NAT drops its idle mapping
	roamer.control(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	var challenged, answered bool
	for range 2 {
		msg := roamer.expectControl()
		switch msg.Type {
		case mtrp.ControlPathChallenge:
			challenged = true
			roamer.control(mtrp.ControlMessage{Type: mtrp.ControlPathResponse, Nonce: msg.Nonce})
		case mtrp.ControlKeepalive:
			answered = true
		default:
			t.Fatalf("unexpected control %+v", msg)
		}
	}
	if !challenged || !answered {
		t.Fatalf("challenged %t answered %t: the relay did not follow the new mapping", challenged, answered)
	}
	exchange(t, peer, roamer, peerRoute, roamerRoute, 20, 0xd4)
	exchange(t, roamer, peer, roamerRoute, peerRoute, 5, 0xe5)
}
