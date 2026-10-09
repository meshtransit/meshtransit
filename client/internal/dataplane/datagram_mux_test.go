package dataplane

import (
	"net/netip"
	"testing"

	"github.com/meshtransit/meshtransit/client/internal/pathdiscovery"
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
