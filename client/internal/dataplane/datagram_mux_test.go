package dataplane

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"

	"meshtransit.net/client/internal/pathdiscovery"
)

func TestControlDatagramMuxRoutesAndDetachesPeerHandler(t *testing.T) {
	t.Parallel()

	stun := &typedDatagramHandler{prefix: 0x01}
	peer := &typedDatagramHandler{prefix: 0x02}
	mux, err := newControlDatagramMux(stun)
	if err != nil {
		t.Fatalf("newControlDatagramMux() error = %v", err)
	}
	mux.setPeerHandler(peer)
	source := netip.MustParseAddrPort("203.0.113.10:41641")
	socket := pathdiscovery.Socket{Port: 41641, Generation: 1}

	if !mux.MatchesDatagram([]byte{0x01}) {
		t.Fatal("MatchesDatagram(stun) = false")
	}
	mux.HandleDatagram([]byte{0x01}, source, socket)
	if stun.handled != 1 || peer.handled != 0 {
		t.Fatalf("stun=%d peer=%d after stun", stun.handled, peer.handled)
	}
	if !mux.MatchesDatagram([]byte{0x02}) {
		t.Fatal("MatchesDatagram(peer) = false")
	}
	mux.HandleDatagram([]byte{0x02}, source, socket)
	if stun.handled != 1 || peer.handled != 1 {
		t.Fatalf("stun=%d peer=%d after peer", stun.handled, peer.handled)
	}

	mux.setPeerHandler(nil)
	if !mux.MatchesDatagram([]byte{0x02}) {
		t.Fatal("MatchesDatagram(detached peer) = false")
	}
	mux.HandleDatagram([]byte{0x02}, source, socket)
	if peer.handled != 1 {
		t.Fatalf("detached peer handled=%d", peer.handled)
	}
}

func TestControlDatagramMuxRequiresSTUNHandler(t *testing.T) {
	t.Parallel()

	if _, err := newControlDatagramMux(nil); err == nil {
		t.Fatal("newControlDatagramMux(nil) error = nil")
	}
}

type typedDatagramHandler struct {
	prefix  byte
	handled int
}

func (h *typedDatagramHandler) MatchesDatagram(packet []byte) bool {
	return len(packet) != 0 && packet[0] == h.prefix
}

func (h *typedDatagramHandler) HandleDatagram(
	[]byte,
	netip.AddrPort,
	pathdiscovery.Socket,
) {
	h.handled++
}

var _ pathdiscovery.DatagramHandler = (*typedDatagramHandler)(nil)

type relayRecordingHandler struct {
	typedDatagramHandler
	relayed []([32]byte)
}

func (h *relayRecordingHandler) HandleRelayDatagram(_ []byte, peerNode [32]byte) {
	h.relayed = append(h.relayed, peerNode)
}

func TestRelayedDiscoReachesProbeHandlerWithPeerNode(t *testing.T) {
	t.Parallel()

	stun := &typedDatagramHandler{prefix: 0x01}
	peer := &relayRecordingHandler{typedDatagramHandler: typedDatagramHandler{prefix: 0x02}}
	mux, err := newControlDatagramMux(stun)
	if err != nil {
		t.Fatal(err)
	}
	mux.setPeerHandler(peer)
	shared, err := newSharedBind(newFakeInnerBind())
	if err != nil {
		t.Fatal(err)
	}
	if err := shared.setDatagramHandler(mux); err != nil {
		t.Fatal(err)
	}
	node := [32]byte{0x07}
	relayed := func(packet []byte) (conn.ReceiveFunc, *int) {
		calls := 0
		return func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			calls++
			sizes[0] = copy(packets[0], packet)
			endpoints[0] = &relayEndpoint{regionID: 1, peerKey: node}
			return 1, nil
		}, &calls
	}
	receive, _ := relayed([]byte{0x02, 0xaa})
	wrapped := shared.wrapReceiver(receive, mux, pathdiscovery.Socket{Port: 41641, Generation: 1})
	packets, sizes, endpoints := receiveBuffers()
	if count, err := wrapped(packets, sizes, endpoints); err != nil || count != 1 || sizes[0] != 0 || endpoints[0] != nil {
		t.Fatalf("relayed control datagram reached WireGuard: count %d size %d", count, sizes[0])
	}
	if len(peer.relayed) != 1 || peer.relayed[0] != node || stun.handled != 0 || peer.handled != 0 {
		t.Fatalf("relayed=%v stun=%d peer direct=%d", peer.relayed, stun.handled, peer.handled)
	}

	// Relayed WireGuard traffic passes through untouched.
	receive, _ = relayed([]byte{0x04, 0, 0, 0})
	wrapped = shared.wrapReceiver(receive, mux, pathdiscovery.Socket{Port: 41641, Generation: 1})
	packets, sizes, endpoints = receiveBuffers()
	if count, err := wrapped(packets, sizes, endpoints); err != nil || count != 1 || sizes[0] != 4 || endpoints[0] == nil {
		t.Fatalf("relayed tunnel packet dropped: count %d size %d", count, sizes[0])
	}
}
