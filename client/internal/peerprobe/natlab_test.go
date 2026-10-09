package peerprobe

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/stun"
	"meshtransit.net/test/natlab"
)

// labNode runs meshd's real probe runtime on a natlab host. CALL_ME_MAYBE
// travels through a simulated relay that attests the sender's node key.
type labNode struct {
	t        *testing.T
	conn     *natlab.Conn
	socket   pathdiscovery.Socket
	runtime  *Runtime
	disco    key.DiscoPrivate
	node     key.NodePublic
	srflx    netip.AddrPort
	host     netip.AddrPort
	paths    chan pathdiscovery.PathObservation
	peerMu   sync.Mutex
	peerNode *labNode
}

func (n *labNode) Socket() pathdiscovery.Socket { return n.socket }

func (n *labNode) SendDatagram(packet []byte, destination netip.AddrPort) (pathdiscovery.Socket, error) {
	_, err := n.conn.WriteToUDPAddrPort(packet, destination)
	return n.socket, err
}

func (n *labNode) SendRelayDatagram(packet []byte, peerNode [32]byte) error {
	n.peerMu.Lock()
	peer := n.peerNode
	n.peerMu.Unlock()
	if peer == nil || peer.node != key.NodePublic(peerNode) {
		return errors.New("no route")
	}
	peer.runtime.HandleRelayDatagram(packet, [32]byte(n.node))
	return nil
}

func (n *labNode) ObservePath(observation pathdiscovery.PathObservation) {
	select {
	case n.paths <- observation:
	default:
	}
}

func newLabNode(t *testing.T, lab *natlab.Lab, name string, profile natlab.Profile) *labNode {
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
	var node key.NodePublic
	_, _ = rand.Read(node[:])
	n := &labNode{
		t: t, conn: conn, socket: pathdiscovery.Socket{Port: 41641, Generation: 1},
		disco: disco, node: node, host: conn.LocalAddrPort(),
		paths: make(chan pathdiscovery.PathObservation, 64),
	}
	n.srflx = n.stunMapping(lab.STUN()[0])
	return n
}

// stunMapping learns the node's server-reflexive endpoint, as meshd does
// before it reports endpoints to Core.
func (n *labNode) stunMapping(server netip.AddrPort) netip.AddrPort {
	n.t.Helper()
	var id stun.TxID
	_, _ = rand.Read(id[:])
	if _, err := n.conn.WriteToUDPAddrPort(stun.AppendBindingRequest(nil, id, stun.ChangeRequest{}), server); err != nil {
		n.t.Fatal(err)
	}
	buf := make([]byte, 1500)
	for {
		if err := n.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			n.t.Fatal(err)
		}
		size, _, err := n.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			n.t.Fatalf("STUN: %v", err)
		}
		if message, err := stun.Parse(buf[:size]); err == nil && message.TxID == id {
			_ = n.conn.SetReadDeadline(time.Time{})
			return message.XORMapped
		}
	}
}

func (n *labNode) start(peer *labNode) {
	n.t.Helper()
	n.peerMu.Lock()
	n.peerNode = peer
	n.peerMu.Unlock()
	runtime, err := newRuntime(n.t.Context(), n.disco, n, n, pathdiscovery.NewProbeTelemetry(),
		time.Now, time.Millisecond, 500*time.Millisecond)
	if err != nil {
		n.t.Fatal(err)
	}
	n.runtime = runtime
	n.t.Cleanup(runtime.Close)
	go func() {
		buf := make([]byte, 2048)
		for {
			size, source, err := n.conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			runtime.HandleDatagram(buf[:size], source, n.socket)
		}
	}()
}

func (n *labNode) activate(peer *labNode) {
	n.t.Helper()
	snapshot := networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			ID: 1, PublicKey: "nodekey:" + hex.EncodeToString(n.node[:]),
			DiscoveryKey: MapDiscoveryKey(n.disco.Public()), MachineAuthorized: true,
		},
		Peers: []networkmap.Node{{
			ID: 2, PublicKey: "nodekey:" + hex.EncodeToString(peer.node[:]),
			DiscoveryKey: MapDiscoveryKey(peer.disco.Public()), MachineAuthorized: true,
			// What Core publishes: the peer's STUN-observed endpoint.
			Endpoints: []netip.AddrPort{peer.srflx},
		}},
	}
	generation := pathdiscovery.ProbeGeneration{Scope: 1, MapRevision: 1, Socket: n.socket}
	if _, _, err := n.runtime.Activate(snapshot, generation); err != nil {
		n.t.Fatal(err)
	}
	n.runtime.SetLocalEndpoints([]disco.Endpoint{
		{Kind: disco.EndpointServerReflex, Addr: n.srflx},
		{Kind: disco.EndpointHost, Addr: n.host},
	}, disco.NATInfo{})
}

// meshdTraverses reports whether meshd's probe runtime finds a direct path
// between two nodes behind the given profiles within timeout.
func meshdTraverses(t *testing.T, a, b natlab.Profile, timeout time.Duration) (bool, uint64) {
	t.Helper()
	lab, err := natlab.NewLab(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	na, nb := newLabNode(t, lab, "a", a), newLabNode(t, lab, "b", b)
	na.start(nb)
	nb.start(na)
	na.activate(nb)
	nb.activate(na)
	learned := func() uint64 {
		return na.runtime.telemetry.Snapshot().PeerReflexiveLearned + nb.runtime.telemetry.Snapshot().PeerReflexiveLearned
	}
	deadline := time.After(timeout)
	var gotA, gotB bool
	for !gotA || !gotB {
		select {
		case <-na.paths:
			gotA = true
		case <-nb.paths:
			gotB = true
		case <-deadline:
			return false, learned()
		}
	}
	return true, learned()
}

// TestMeshdTraversalP0 runs meshd's real disco v2 runtime through the NAT
// lab cells the traversal plan marks P0: one side behind an endpoint-
// dependent NAT, the other public or behind an address-filtering cone, which
// only peer-reflexive learning and CALL_ME_MAYBE can connect. Easy pairs must
// stay direct and two hard sides must stay relayed (port prediction is P1).
func TestMeshdTraversalP0(t *testing.T) {
	if testing.Short() {
		t.Skip("NAT lab traversal takes a few seconds")
	}
	cases := []struct {
		a, b          natlab.Profile
		direct, prflx bool // prflx: only a peer-reflexive candidate can connect the pair
	}{
		{natlab.Public, natlab.SymmetricRandom, true, true},
		{natlab.FullCone, natlab.SymmetricRandom, true, true},
		{natlab.RestrictedCone, natlab.SymmetricRandom, true, true},
		{natlab.Public, natlab.CGNATSymmetric, true, true},
		{natlab.RestrictedCone, natlab.CGNATSymmetric, true, true},
		{natlab.FullCone, natlab.PortRestrictedCone, true, false},
		{natlab.DoubleNAT, natlab.PortRestrictedCone, true, false},
		{natlab.SymmetricRandom, natlab.SymmetricRandom, false, false},
	}
	for _, c := range cases {
		t.Run(c.a.Name+"/"+c.b.Name, func(t *testing.T) {
			t.Parallel()
			timeout := 8 * time.Second
			if !c.direct {
				timeout = 4 * time.Second
			}
			got, learned := meshdTraverses(t, c.a, c.b, timeout)
			if got != c.direct {
				t.Fatalf("direct path = %v, want %v", got, c.direct)
			}
			if c.prflx && learned == 0 {
				t.Fatal("connected without learning a peer-reflexive candidate")
			}
		})
	}
}
