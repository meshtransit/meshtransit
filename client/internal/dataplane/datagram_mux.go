package dataplane

import (
	"errors"
	"net/netip"
	"sync"

	"meshtransit.net/client/internal/pathdiscovery"
)

// controlDatagramMux keeps the fixed STUN handler ahead of one dynamically
// attached session probe handler. Both protocols are consumed before WireGuard.
type controlDatagramMux struct {
	stun        pathdiscovery.DatagramHandler
	mu          sync.RWMutex
	peer        pathdiscovery.DatagramHandler
	peerMatches func([]byte) bool
}

var _ pathdiscovery.DatagramHandler = (*controlDatagramMux)(nil)

func newControlDatagramMux(
	stun pathdiscovery.DatagramHandler,
) (*controlDatagramMux, error) {
	if stun == nil {
		return nil, errors.New("dataplane: stun datagram handler is required")
	}

	return &controlDatagramMux{stun: stun}, nil
}

func (m *controlDatagramMux) setPeerHandler(
	handler pathdiscovery.DatagramHandler,
) {
	m.mu.Lock()
	m.peer = handler
	if handler != nil {
		m.peerMatches = handler.MatchesDatagram
	}
	m.mu.Unlock()
}

func (m *controlDatagramMux) MatchesDatagram(packet []byte) bool {
	if m == nil {
		return false
	}
	if m.stun.MatchesDatagram(packet) {
		return true
	}
	_, matches := m.peerHandler()

	return matches != nil && matches(packet)
}

func (m *controlDatagramMux) HandleDatagram(
	packet []byte,
	source netip.AddrPort,
	socket pathdiscovery.Socket,
) {
	if m == nil {
		return
	}
	if m.stun.MatchesDatagram(packet) {
		m.stun.HandleDatagram(packet, source, socket)

		return
	}
	peer, matches := m.peerHandler()
	if matches != nil && matches(packet) && peer != nil {
		peer.HandleDatagram(packet, source, socket)
	}
}

func (m *controlDatagramMux) peerHandler() (
	pathdiscovery.DatagramHandler,
	func([]byte) bool,
) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.peer, m.peerMatches
}
