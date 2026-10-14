package dataplane

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/relay"
)

const maxControlDatagramSize = 2048

// sharedBind demultiplexes bounded control datagrams before WireGuard sees
// them and exposes the same sockets to the discovery scheduler.
type sharedBind struct {
	inner       conn.Bind
	relay       *relay.Pool
	generations *socketGenerationSource
	mu          sync.RWMutex
	handler     pathdiscovery.DatagramHandler
	// lazy, when set, sees each WireGuard datagram the handler does not take
	// before wireguard-go does, to install the sender of an initiation.
	lazy       *lazyPeers
	isOpen     bool
	port       uint16
	generation uint64
}

// socketGenerationSource provides one monotonic namespace across every bind
// created during a WireGuard engine's lifetime. Gaps are safe; reuse is not.
type socketGenerationSource struct {
	mu     sync.Mutex
	latest uint64
}

var (
	_ conn.Bind                       = (*sharedBind)(nil)
	_ pathdiscovery.DatagramTransport = (*sharedBind)(nil)
)

func newSharedBind(inner conn.Bind) (*sharedBind, error) {
	return newSharedBindWithGenerationSource(inner, &socketGenerationSource{})
}

func newSharedBindWithGenerationSource(
	inner conn.Bind,
	generations *socketGenerationSource,
) (*sharedBind, error) {
	return newSharedBindWithRelay(inner, generations, nil)
}

func newSharedBindWithRelay(
	inner conn.Bind,
	generations *socketGenerationSource,
	relayPool *relay.Pool,
) (*sharedBind, error) {
	if inner == nil {
		return nil, errors.New("dataplane: inner wireguard bind is required")
	}
	if generations == nil {
		return nil, errors.New("dataplane: socket generation source is required")
	}

	return &sharedBind{
		inner:       inner,
		generations: generations,
		relay:       relayPool,
	}, nil
}

func (s *socketGenerationSource) next() (uint64, error) {
	if s == nil {
		return 0, errors.New("dataplane: socket generation source is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latest == math.MaxUint64 {
		return 0, errors.New("dataplane: socket generation is exhausted")
	}
	s.latest++

	return s.latest, nil
}

func (b *sharedBind) setDatagramHandler(handler pathdiscovery.DatagramHandler) error {
	if handler == nil {
		return errors.New("dataplane: datagram handler is required")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.isOpen {
		return errors.New("dataplane: datagram handler cannot change on an open bind")
	}
	if b.handler != nil {
		return errors.New("dataplane: datagram handler is already configured")
	}
	b.handler = handler

	return nil
}

func (b *sharedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	receivers, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, fmt.Errorf("dataplane: opening wireguard bind: %w", err)
	}
	if actualPort == 0 || len(receivers) == 0 {
		_ = b.inner.Close()

		return nil, 0, errors.New("dataplane: wireguard bind returned invalid socket metadata")
	}
	// Before Open returns: wireguard-go sends nothing on a bind until then.
	if err := protectBindSockets(b.inner); err != nil {
		_ = b.inner.Close()

		return nil, 0, err
	}
	if b.relay != nil {
		if err := b.relay.Open(); err != nil {
			_ = b.inner.Close()

			return nil, 0, fmt.Errorf("dataplane: opening relay pool: %w", err)
		}
		receivers = append(receivers, b.receiveRelay)
	}
	generation, err := b.generations.next()
	if err != nil {
		_ = b.inner.Close()
		_ = b.closeRelay()

		return nil, 0, err
	}
	b.generation = generation
	b.port = actualPort
	b.isOpen = true
	socket := pathdiscovery.Socket{
		Port:       actualPort,
		Generation: b.generation,
	}
	for index, receiver := range receivers {
		if receiver == nil {
			_ = b.inner.Close()
			_ = b.closeRelay()
			b.isOpen = false
			b.port = 0

			return nil, 0, errors.New("dataplane: wireguard bind returned a nil receiver")
		}
		receivers[index] = b.wrapReceiver(receiver, b.handler, socket)
	}

	return receivers, actualPort, nil
}

func (b *sharedBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := errors.Join(b.inner.Close(), b.closeRelay())
	b.isOpen = false
	b.port = 0

	return err
}

func (b *sharedBind) SetMark(mark uint32) error { return b.inner.SetMark(mark) }

func (b *sharedBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	if relayDestination, ok := endpoint.(*relayEndpoint); ok {
		if b.relay == nil {
			return conn.ErrWrongEndpointType
		}

		return b.relay.Send(
			relayDestination.regionID,
			relayDestination.peerKey,
			buffers,
		)
	}

	return b.inner.Send(buffers, endpoint)
}

func (b *sharedBind) RelayHealth() relay.HealthSnapshot {
	if b == nil || b.relay == nil {
		return relay.HealthSnapshot{}
	}

	return b.relay.Health()
}

// SetRelayFailureHook forwards relay connection failures to hook.
func (b *sharedBind) SetRelayFailureHook(hook func()) {
	if b == nil || b.relay == nil {
		return
	}
	b.relay.SetFailureHook(hook)
}

func (b *sharedBind) PrepareRelayRegion(regionID int) error {
	if b == nil || b.relay == nil {
		return pathdiscovery.ErrTransportClosed
	}

	return b.relay.PrepareRegion(regionID)
}

func (b *sharedBind) ReplaceRelayAuthority(homeRegion int, peers []relay.Peer) error {
	if b == nil || b.relay == nil {
		return pathdiscovery.ErrTransportClosed
	}

	return b.relay.ReplaceAuthority(homeRegion, peers)
}

func (b *sharedBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	if strings.HasPrefix(value, relayEndpointPrefix) {
		return parseRelayEndpoint(value, b.relay)
	}

	return b.inner.ParseEndpoint(value)
}

func (b *sharedBind) BatchSize() int { return b.inner.BatchSize() }

func (b *sharedBind) Socket() pathdiscovery.Socket {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.isOpen {
		return pathdiscovery.Socket{}
	}

	return pathdiscovery.Socket{
		Port:       b.port,
		Generation: b.generation,
	}
}

func (b *sharedBind) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	if len(packet) == 0 || len(packet) > maxControlDatagramSize {
		return pathdiscovery.Socket{}, errors.New("dataplane: control datagram size is invalid")
	}
	if !validDatagramEndpoint(destination) {
		return pathdiscovery.Socket{}, errors.New("dataplane: control datagram destination is invalid")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.isOpen {
		return pathdiscovery.Socket{}, pathdiscovery.ErrTransportClosed
	}
	socket := pathdiscovery.Socket{
		Port:       b.port,
		Generation: b.generation,
	}
	endpoint, err := b.inner.ParseEndpoint(destination.String())
	if err != nil {
		return pathdiscovery.Socket{}, fmt.Errorf(
			"dataplane: parsing control destination: %w",
			err,
		)
	}
	if err := b.inner.Send([][]byte{packet}, endpoint); err != nil {
		return pathdiscovery.Socket{}, fmt.Errorf("dataplane: sending control datagram: %w", err)
	}

	return socket, nil
}

// SendRelayDatagram sends one control datagram to a peer through its home
// relay region.
func (b *sharedBind) SendRelayDatagram(packet []byte, peerNode [32]byte) error {
	if len(packet) == 0 || len(packet) > maxControlDatagramSize {
		return errors.New("dataplane: control datagram size is invalid")
	}
	if b == nil || b.relay == nil {
		return pathdiscovery.ErrTransportClosed
	}
	peer, ok := b.relay.Peer(relay.Key(peerNode))
	if !ok {
		return errors.New("dataplane: relay peer is not authorized")
	}

	return b.relay.Send(peer.HomeRegion, peer.Key, [][]byte{packet})
}

func (b *sharedBind) wrapReceiver(
	receive conn.ReceiveFunc,
	handler pathdiscovery.DatagramHandler,
	socket pathdiscovery.Socket,
) conn.ReceiveFunc {
	return func(
		packets [][]byte,
		sizes []int,
		endpoints []conn.Endpoint,
	) (int, error) {
		count, err := receive(packets, sizes, endpoints)
		if handler == nil && b.lazy == nil {
			return count, err
		}
		for index := 0; index < count; index++ {
			if index >= len(packets) || index >= len(sizes) || index >= len(endpoints) ||
				sizes[index] <= 0 || sizes[index] > len(packets[index]) {
				continue
			}
			packet := packets[index][:sizes[index]]
			if handler == nil || !handler.MatchesDatagram(packet) {
				b.observeWireGuard(packet, endpoints[index])
				continue
			}
			if through, viaRelay := endpoints[index].(*relayEndpoint); viaRelay {
				if relayed, ok := handler.(pathdiscovery.RelayDatagramHandler); ok {
					relayed.HandleRelayDatagram(packet, through.peerKey)
				}
				sizes[index] = 0
				endpoints[index] = nil
				continue
			}
			source, valid := datagramSource(endpoints[index])
			if valid {
				handler.HandleDatagram(packet, source, socket)
			}
			sizes[index] = 0
			endpoints[index] = nil
		}

		return count, err
	}
}

// observeWireGuard passes a WireGuard datagram to the lazy peer hook, with
// the sender's node key when a relay delivered it.
func (b *sharedBind) observeWireGuard(packet []byte, endpoint conn.Endpoint) {
	if b.lazy == nil || !isInitiation(packet) {
		return
	}
	if through, viaRelay := endpoint.(*relayEndpoint); viaRelay {
		key := through.peerKey
		b.lazy.initiation(packet, &key, netip.Addr{})

		return
	}
	source, _ := datagramSource(endpoint)
	b.lazy.initiation(packet, nil, source.Addr())
}

func datagramSource(endpoint conn.Endpoint) (netip.AddrPort, bool) {
	if endpoint == nil {
		return netip.AddrPort{}, false
	}
	source, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil {
		return netip.AddrPort{}, false
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())

	return source, validDatagramEndpoint(source)
}

func validDatagramEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()

	return endpoint.IsValid() && endpoint.Port() != 0 && address.IsValid() &&
		!address.Is4In6() && address.Zone() == "" && address == address.Unmap() &&
		address.IsGlobalUnicast() && !address.IsUnspecified() && !address.IsMulticast() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func (b *sharedBind) receiveRelay(
	packets [][]byte,
	sizes []int,
	endpoints []conn.Endpoint,
) (int, error) {
	if b.relay == nil {
		return 0, net.ErrClosed
	}
	for {
		packet, err := b.relay.Receive()
		if err != nil {
			return 0, err
		}
		if len(packets) == 0 || len(sizes) == 0 || len(endpoints) == 0 ||
			len(packet.Data) > len(packets[0]) {
			continue
		}
		endpoint, err := receivedRelayEndpoint(packet, b.relay)
		if err != nil {
			continue
		}
		sizes[0] = copy(packets[0], packet.Data)
		endpoints[0] = endpoint

		return 1, nil
	}
}

func (b *sharedBind) closeRelay() error {
	if b.relay == nil {
		return nil
	}

	return b.relay.Stop()
}

func (b *sharedBind) closeRelayPermanently() error {
	if b.relay == nil {
		return nil
	}

	return b.relay.Close()
}
