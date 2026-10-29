package meshgw

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The gateway's TCP sizes (K1b design §8; TD-CLI-82): what one connection
// holds at worst, whatever its client does, is bounded here rather than
// by gVisor's 1 MiB defaults.
const (
	tcpReceiveBuffer = 256 << 10
	tcpSendBuffer    = 96 << 10
	tcpMinimumBuffer = 4 << 10
	// A peer gone without a word is found within a minute and a half:
	// probes after 30 s idle, every 15 s, four unanswered close it.
	keepaliveIdle     = 30 * time.Second
	keepaliveInterval = 15 * time.Second
	keepaliveCount    = 4
	// listenBacklog bounds connections waiting to be accepted; past it SYN
	// cookies take over. Every source is a mesh peer the map admits.
	listenBacklog = 1024
	// linkQueue bounds packets the stack sent and the data plane did not
	// take yet; past it the stack drops them and TCP sends them again.
	linkQueue = 1024
	nicID     = 1
)

// errNotIP is a packet that is neither IPv4 nor IPv6.
var errNotIP = errors.New("meshgw: a packet that is not IP")

// meshStack is the gateway's own userspace stack: gVisor with the sizes
// above, behind a TUN the data plane reads and writes, and a listener whose
// connections keep TCP keepalive. It replaces wireguard-go's netstack, whose
// stack the gateway cannot configure (Q70, TD-CLI-82).
type meshStack struct {
	stack  *stack.Stack
	link   *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
}

// newMeshStack makes a stack holding addresses, sending packets of at most
// mtu bytes.
func newMeshStack(addresses []netip.Addr, mtu int) (*meshStack, error) {
	created := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol,
			icmp.NewProtocol4, icmp.NewProtocol6,
		},
		HandleLocal: true,
	})
	fail := func(what string, err tcpip.Error) (*meshStack, error) {
		created.Close()
		return nil, fmt.Errorf("meshgw: %s: %s", what, err)
	}
	sack := tcpip.TCPSACKEnabled(true)
	moderate := tcpip.TCPModerateReceiveBufferOption(false)
	receive := tcpip.TCPReceiveBufferSizeRangeOption{
		Min: tcpMinimumBuffer, Default: tcpReceiveBuffer,
		Max: tcpReceiveBuffer,
	}
	send := tcpip.TCPSendBufferSizeRangeOption{Min: tcpMinimumBuffer, Default: tcpSendBuffer, Max: tcpSendBuffer}
	for _, option := range []tcpip.SettableTransportProtocolOption{&sack, &moderate, &receive, &send} {
		if err := created.SetTransportProtocolOption(tcp.ProtocolNumber, option); err != nil {
			return fail("setting a TCP option", err)
		}
	}
	link := channel.New(linkQueue, uint32(mtu), "") //nolint:gosec // the MTU is 1280
	if err := created.CreateNIC(nicID, link); err != nil {
		return fail("creating the stack's interface", err)
	}
	for _, address := range addresses {
		address = address.Unmap()
		protocol := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
		if address.Is6() {
			protocol = ipv6.ProtocolNumber
		}
		if err := created.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          protocol,
			AddressWithPrefix: tcpip.AddrFromSlice(address.AsSlice()).WithPrefix(),
		},
			stack.AddressProperties{}); err != nil {
			return fail("adding "+address.String(), err)
		}
	}
	created.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	ctx, cancel := context.WithCancel(context.Background())
	return &meshStack{stack: created, link: link, ctx: ctx, cancel: cancel}, nil
}

// Read gives the next packet the stack sent, waiting for one; os.ErrClosed
// once the stack closed.
func (s *meshStack) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := s.link.ReadContext(s.ctx)
	if pkt == nil {
		return 0, os.ErrClosed
	}
	defer pkt.DecRef()
	if size := pkt.Size(); size > len(bufs[0])-offset {
		return 0, fmt.Errorf("meshgw: a packet of %d bytes past the buffer", size)
	}
	n := 0
	for _, part := range pkt.AsSlices() {
		n += copy(bufs[0][offset+n:], part)
	}
	sizes[0] = n
	return 1, nil
}

// Write gives the stack packets for it.
func (s *meshStack) Write(bufs [][]byte, offset int) (int, error) {
	if s.ctx.Err() != nil {
		return 0, os.ErrClosed
	}
	var failed error
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch packet[0] >> 4 {
		case 4:
			protocol = ipv4.ProtocolNumber
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			// The rest of the batch still goes in.
			failed = errNotIP
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		s.link.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
	return len(bufs), failed
}

// Close stops the stack; Read returns os.ErrClosed.
func (s *meshStack) Close() error {
	s.cancel()
	s.link.Close()
	s.stack.Close()
	s.stack.Wait()
	return nil
}

// ListenTCPAddrPort listens on one of the stack's addresses. Its
// connections keep TCP keepalive and the stack's buffer sizes.
func (s *meshStack) ListenTCPAddrPort(address netip.AddrPort) (net.Listener, error) {
	address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	protocol := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if address.Addr().Is6() {
		protocol = ipv6.ProtocolNumber
	}
	var queue waiter.Queue
	endpoint, err := s.stack.NewEndpoint(tcp.ProtocolNumber, protocol, &queue)
	if err != nil {
		return nil, fmt.Errorf("meshgw: a TCP endpoint: %s", err)
	}
	// Accepted connections take the listener's receive buffer.
	endpoint.SocketOptions().SetReceiveBufferSize(tcpReceiveBuffer, false)
	full := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(address.Addr().AsSlice()), Port: address.Port()}
	if err := endpoint.Bind(full); err != nil {
		endpoint.Close()
		return nil, fmt.Errorf("meshgw: binding %s: %s", address, err)
	}
	if err := endpoint.Listen(listenBacklog); err != nil {
		endpoint.Close()
		return nil, fmt.Errorf("meshgw: listening on %s: %s", address, err)
	}
	return &meshListener{
		endpoint: endpoint, queue: &queue, address: net.TCPAddrFromAddrPort(address),
		closed: make(chan struct{}),
	}, nil
}

// meshListener accepts the stack's TCP connections, each with keepalive.
type meshListener struct {
	endpoint tcpip.Endpoint
	queue    *waiter.Queue
	address  net.Addr
	closed   chan struct{}
	once     sync.Once
}

// Accept waits for the next connection.
func (l *meshListener) Accept() (net.Conn, error) {
	entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents)
	l.queue.EventRegister(&entry)
	defer l.queue.EventUnregister(&entry)
	for {
		accepted, queue, err := l.endpoint.Accept(nil)
		if _, wait := err.(*tcpip.ErrWouldBlock); wait {
			select {
			case <-l.closed:
				return nil, net.ErrClosed
			case <-notify:
				continue
			}
		}
		if err != nil {
			select {
			case <-l.closed:
				return nil, net.ErrClosed
			default:
			}
			// The stack closed under the listener: as closed, not a fault
			// to retry (review TD-CLI-82 L5).
			if _, invalid := err.(*tcpip.ErrInvalidEndpointState); invalid {
				return nil, net.ErrClosed
			}
			return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.address, Err: errors.New(err.String())}
		}
		keepAlive(accepted)
		return gonet.NewTCPConn(queue, accepted), nil
	}
}

// keepAlive has a connection probe an idle peer, so one gone without a word
// does not hold the gateway's limits for good (review b6b M2).
func keepAlive(endpoint tcpip.Endpoint) {
	idle, interval := tcpip.KeepaliveIdleOption(keepaliveIdle), tcpip.KeepaliveIntervalOption(keepaliveInterval)
	_ = endpoint.SetSockOpt(&idle)
	_ = endpoint.SetSockOpt(&interval)
	_ = endpoint.SetSockOptInt(tcpip.KeepaliveCountOption, keepaliveCount)
	endpoint.SocketOptions().SetKeepAlive(true)
}

// Close stops accepting; connections accepted stay open.
func (l *meshListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.endpoint.Close()
		l.queue.Notify(waiter.ReadableEvents)
	})
	return nil
}

// Addr is the address listened on.
func (l *meshListener) Addr() net.Addr { return l.address }
