//go:build linux || darwin || windows

package dataplane

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
)

// The real-device tests run two engines over wireguard-go with in-memory
// TUNs and a paired in-memory bind; a packet must arrive on the first try,
// with no retransmission, whichever side holds the other installed.

type channelTUNOpener struct{ tunnel *tuntest.ChannelTUN }

func (o *channelTUNOpener) OpenTUN(_ context.Context, config netadmin.TUNConfig) (netadmin.TUN, error) {
	return netadmin.TUN{
		Device: o.tunnel.TUN(), Name: "mesh-test", MTU: 1280,
		Addresses: append([]netip.Prefix(nil), config.Addresses...),
		Routes:    append([]netip.Prefix(nil), config.Routes...),
	}, nil
}

type lazyDeviceNode struct {
	engine  *WireGuardEngine
	tunnel  *tuntest.ChannelTUN
	clock   *testClock
	key     NodePrivateKey
	address netip.Addr
}

// newLazyDevicePair returns engines A and B whose maps hold each other plus
// fillers peers that never send. A lazy engine installs peers on demand.
func newLazyDevicePair(t *testing.T, lazyA, lazyB bool, fillers int) (*lazyDeviceNode, *lazyDeviceNode) {
	t.Helper()
	binds := bindtest.NewChannelBinds()
	nodes := [2]*lazyDeviceNode{}
	for index, lazy := range []bool{lazyA, lazyB} {
		bind := binds[index]
		tunnel := tuntest.NewChannelTUN()
		factory := &officialWireGuardFactory{
			generations: &socketGenerationSource{},
			acquire:     func(value netadmin.TUN, _ *slog.Logger) (tun.Device, error) { return value.Device, nil },
			newBind:     func() conn.Bind { return bind },
		}
		engine, err := newWireGuardEngine(&channelTUNOpener{tunnel: tunnel}, 41641, factory, nil)
		if err != nil {
			t.Fatal(err)
		}
		clock := newTestClock()
		engine.clock = clock.Now

		if lazy {
			engine.lazyThreshold = 0
		} else {
			engine.SetLazyPeers(false)
		}
		t.Cleanup(func() { _ = engine.Close() })
		var key NodePrivateKey
		for byteIndex := range key {
			key[byteIndex] = byte(index*32 + byteIndex + 1) //nolint:gosec // below 256
		}
		nodes[index] = &lazyDeviceNode{
			engine: engine, tunnel: tunnel, clock: clock, key: key,
			address: netip.AddrFrom4([4]byte{100, 64, 0, byte(3 + index)}),
		}
	}
	// bindtest delivers to the other bind when sent to port 1 (A to B) or 2
	// (B to A); the address only needs to pass map validation.
	ports := [2]uint16{2, 1}
	for index, node := range nodes {
		other := nodes[1-index]
		snapshot := lazyDeviceSnapshot(t, node, other, netip.AddrPortFrom(netip.MustParseAddr("203.0.113.20"), ports[1-index]))
		snapshot.Peers = append(snapshot.Peers, scalePeers(t, snapshot.Peers[0], 0, fillers)...)
		if _, err := node.engine.Apply(t.Context(), snapshot, node.key); err != nil {
			t.Fatalf("Apply(node %d) error = %v", index, err)
		}
	}
	return nodes[0], nodes[1]
}

func lazyDeviceSnapshot(t *testing.T, self, peer *lazyDeviceNode, endpoint netip.AddrPort) networkmap.Snapshot {
	t.Helper()
	publicText := func(private NodePrivateKey) string {
		key, err := ecdh.X25519().NewPrivateKey(private[:])
		if err != nil {
			t.Fatal(err)
		}
		return "nodekey:" + hex.EncodeToString(key.PublicKey().Bytes())
	}
	selfPrefix, peerPrefix := netip.PrefixFrom(self.address, 32), netip.PrefixFrom(peer.address, 32)
	return networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			ID: uint64(self.address.As4()[3]), PublicKey: publicText(self.key), Addresses: []netip.Prefix{selfPrefix},
		},
		Peers: []networkmap.Node{{
			ID: uint64(peer.address.As4()[3]), PublicKey: publicText(peer.key),
			Addresses: []netip.Prefix{peerPrefix}, AllowedIPs: []netip.Prefix{peerPrefix},
			Endpoints: []netip.AddrPort{endpoint}, MachineAuthorized: true,
		}},
		Policy: []networkmap.Rule{{
			Sources: []networkmap.Selector{{Kind: networkmap.SelectorPrefix, Prefix: peerPrefix}},
			Destinations: []networkmap.Destination{{
				Selector: networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: selfPrefix},
				PortTo:   65535,
			}},
		}},
	}
}

// sendOnce sends one packet and requires it to arrive, unretried.
func sendOnce(t *testing.T, from, to *lazyDeviceNode) {
	t.Helper()
	packet := tuntest.Ping(to.address, from.address)
	from.tunnel.Outbound <- packet
	deadline := time.After(5 * time.Second)
	for {
		select {
		case received := <-to.tunnel.Inbound:
			if bytes.Equal(received, packet) {
				return
			}
		case <-deadline:
			t.Fatalf("the first packet %s -> %s did not arrive", from.address, to.address)
		}
	}
}

func installedCount(t *testing.T, node *lazyDeviceNode) int {
	t.Helper()
	node.engine.mu.Lock()
	defer node.engine.mu.Unlock()
	official, ok := node.engine.device.(*officialWireGuardDevice)
	if !ok {
		t.Fatalf("%s has no wireguard-go device", node.address)
	}
	return len(installedPeerKeys(t, official.device))
}

// evictAll ages both nodes past the idle timeout and evicts their peers.
func evictAll(t *testing.T, nodes ...*lazyDeviceNode) {
	t.Helper()
	for _, node := range nodes {
		node.clock.Advance(lazyIdleTimeout + time.Minute)
		node.engine.evictIdleLazyPeers(node.clock.Now())
		if count := installedCount(t, node); count != 0 {
			t.Fatalf("%s still holds %d peers after eviction", node.address, count)
		}
	}
}

func TestLazyPeersFirstPacketArrivesOnRealDevices(t *testing.T) {
	t.Parallel()
	a, b := newLazyDevicePair(t, true, true, 3)
	if installedCount(t, a) != 0 || installedCount(t, b) != 0 {
		t.Fatal("lazy engines installed peers before any packet")
	}
	sendOnce(t, a, b)
	sendOnce(t, b, a)
	if installedCount(t, a) != 1 || installedCount(t, b) != 1 {
		t.Fatalf("installed %d and %d peers, want only each other", installedCount(t, a), installedCount(t, b))
	}

	// Both evicted, the other side may send first.
	evictAll(t, a, b)
	sendOnce(t, b, a)
	sendOnce(t, a, b)
	evictAll(t, a, b)
	sendOnce(t, a, b)
	if paths := a.engine.PeerPaths(); paths.LazyActivationCount != 3 || paths.LazyEvictionCount != 2 ||
		paths.InactiveCount != 3 || paths.PeerCount != 4 {
		t.Fatalf("A's PeerPaths() = %+v", paths)
	}
}

func TestLazyPeersInteroperateWithEagerPeers(t *testing.T) {
	t.Parallel()
	// The eager side sends first: the lazy side learns it from the
	// handshake initiation.
	lazy, eager := newLazyDevicePair(t, true, false, 2)
	sendOnce(t, eager, lazy)
	sendOnce(t, lazy, eager)

	// An eager peer starts a handshake as soon as it is up (persistent
	// keepalive): the lazy side installs it from that initiation alone. The
	// test waits for it rather than sending at the same moment, since two
	// crossing initiations cost wireguard-go a 5 s retry, lazy or not.
	lazy, eager = newLazyDevicePair(t, true, false, 2)
	waitForHandshake(t, lazy)
	sendOnce(t, lazy, eager)
	sendOnce(t, eager, lazy)
}

// waitForHandshake waits until node holds one peer with a completed
// handshake.
func waitForHandshake(t *testing.T, node *lazyDeviceNode) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		node.engine.mu.Lock()
		official, ok := node.engine.device.(*officialWireGuardDevice)
		var traffic map[[32]byte]peerTraffic
		if ok {
			traffic, _ = official.PeerTraffic()
		}
		node.engine.mu.Unlock()
		for _, counters := range traffic {
			if counters.handshake != 0 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s completed no handshake (peers %v)", node.address, traffic)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLazyPeersCloseWhileTrafficFlows(t *testing.T) {
	t.Parallel()
	a, b := newLazyDevicePair(t, true, true, 0)
	sendOnce(t, a, b)
	stop := make(chan struct{})
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for {
			select {
			case <-stop:
				return
			case a.tunnel.Outbound <- tuntest.Ping(b.address, a.address):
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- b.engine.Close() }()
	go func() { closed <- a.engine.Close() }()
	for range 2 {
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not return while packets were flowing")
		}
	}
	close(stop)
	<-sent
}
