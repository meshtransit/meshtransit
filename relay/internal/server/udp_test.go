package server_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/relay/internal/server"
	"meshtransit.net/relay/internal/udp"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// udpClient is a minimal MTRP client over a real loopback socket.
type udpClient struct {
	conn    *net.UDPConn
	relay   netip.AddrPort
	session *mtrp.Session
	node    key.NodePublic
}

func dialRelay(t *testing.T, relayAddr netip.AddrPort, relayKey key.RelayPublic, signer key.SigningPrivate, node byte) *udpClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	c := &udpClient{conn: conn, relay: relayAddr, node: key.NodePublic{0x4e, node}}
	now := time.Now()
	ticket, err := mtrp.Ticket{
		ID: [16]byte{node}, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(10 * time.Minute).UnixMilli(),
		Node: c.node, Disco: disco.Public(), Deployment: [16]byte{1},
		Zones: []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{7}}},
	}.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	hs, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: disco, Relay: relayKey, Index: uint32(node) + 1, PadUDP: true,
		Hello: mtrp.ClientHello{TimestampMS: now.UnixMilli(), Ticket: ticket},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.send(t, init)
	if c.session, _, err = hs.Finish(c.recv(t)); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// The KEEPALIVE right after the handshake verifies the binding.
	c.control(t, mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	if msg := c.expectControl(t); msg.Type != mtrp.ControlKeepalive {
		t.Fatalf("keepalive reply %+v", msg)
	}
	return c
}

func (c *udpClient) send(t *testing.T, frame []byte) {
	t.Helper()
	if _, err := c.conn.WriteToUDPAddrPort(frame, c.relay); err != nil {
		t.Fatal(err)
	}
}

func (c *udpClient) recv(t *testing.T) []byte {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := c.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return buf[:n]
}

func (c *udpClient) control(t *testing.T, msg mtrp.ControlMessage) {
	t.Helper()
	plain, err := mtrp.AppendControlMessage(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := c.session.SealControl(nil, plain)
	if err != nil {
		t.Fatal(err)
	}
	c.send(t, frame)
}

func (c *udpClient) expectControl(t *testing.T) mtrp.ControlMessage {
	t.Helper()
	plain, err := c.session.OpenControl(nil, c.recv(t))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mtrp.ParseControlMessage(plain)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestRelayOverUDP(t *testing.T) {
	t.Parallel()
	relayKey, _ := key.NewRelayPrivate()
	signer, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{3}, 32))
	listener, err := udp.Listen("127.0.0.1:0", mtrp.MaxUDPFrame)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := server.New(server.Config{Key: relayKey, Keys: mtrp.NewStaticKeys(signer.Public()), UDP: listener})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := listener.Serve(ctx, 2, relay.HandleUDP); err != nil {
			t.Error(err)
		}
	})
	wg.Go(func() {
		if err := relay.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	a := dialRelay(t, listener.LocalAddr(), relayKey.Public(), signer, 1)
	b := dialRelay(t, listener.LocalAddr(), relayKey.Public(), signer, 2)
	a.control(t, mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 1, Peer: b.node})
	ok := a.expectControl(t)
	incoming := b.expectControl(t)
	if ok.Type != mtrp.ControlRouteOK || incoming.Type != mtrp.ControlRouteIncoming {
		t.Fatalf("route: %+v / %+v", ok, incoming)
	}
	for i := range 50 {
		payload := bytes.Repeat([]byte{byte(i)}, 1200)
		frame, _ := mtrp.AppendData(nil, a.session.RemoteIndex(), ok.Route, payload)
		a.send(t, frame)
		d, err := mtrp.ParseData(b.recv(t))
		if err != nil || d.Route != incoming.Route || !bytes.Equal(d.Payload, payload) {
			t.Fatalf("frame %d: %+v, %v", i, d.Route, err)
		}
	}
}
