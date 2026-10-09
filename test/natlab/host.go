package natlab

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"
)

const (
	// connQueue is the receive buffer of a Conn, in datagrams. A full queue
	// drops packets, as a kernel socket buffer does.
	connQueue = 512
	// maxDatagram is the largest UDP payload accepted.
	maxDatagram    = 65507
	firstEphemeral = 40000
)

// Host is a machine with one or more addresses on a segment.
type Host struct {
	name  string
	seg   *Segment
	addrs []netip.Addr

	mu       sync.Mutex
	conns    map[uint16]*Conn
	nextPort uint16
}

// NewHost attaches a host with the given addresses to seg.
func (n *Network) NewHost(name string, seg *Segment, addrs ...netip.Addr) (*Host, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("natlab: host %s needs an address", name)
	}
	h := &Host{name: name, seg: seg, conns: make(map[uint16]*Conn), nextPort: firstEphemeral}
	for _, a := range addrs {
		a = a.Unmap()
		if err := seg.attach(a, h); err != nil {
			return nil, err
		}
		h.addrs = append(h.addrs, a)
	}
	return h, nil
}

// Name returns the host name.
func (h *Host) Name() string { return h.name }

// Addrs returns the host addresses.
func (h *Host) Addrs() []netip.Addr { return slices.Clone(h.addrs) }

// Listen opens a UDP socket on every host address. Port 0 picks a free one.
func (h *Host) Listen(port uint16) (*Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if port == 0 {
		for range 1 << 16 {
			p := h.nextPort
			h.nextPort++
			if h.nextPort < firstEphemeral {
				h.nextPort = firstEphemeral
			}
			if _, used := h.conns[p]; !used {
				port = p
				break
			}
		}
		if port == 0 {
			return nil, ErrAddressInUse
		}
	}
	if _, used := h.conns[port]; used {
		return nil, fmt.Errorf("%w: %s port %d", ErrAddressInUse, h.name, port)
	}
	c := &Conn{
		host:   h,
		port:   port,
		queue:  make(chan packet, connQueue),
		closed: make(chan struct{}),
		kick:   make(chan struct{}, 1),
	}
	h.conns[port] = c
	return c, nil
}

func (h *Host) receive(p packet) {
	h.mu.Lock()
	c := h.conns[p.dst.Port()]
	h.mu.Unlock()
	if c != nil {
		c.enqueue(p)
	}
}

func (h *Host) release(port uint16) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.conns, port)
}

// source picks the host address used to reach dst.
func (h *Host) source(dst netip.Addr) (netip.Addr, bool) {
	for _, a := range h.addrs {
		if a.Is4() == dst.Is4() {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// Conn is a UDP socket on a Host. Its methods mirror *net.UDPConn and are
// safe for concurrent use.
type Conn struct {
	host *Host
	port uint16

	queue     chan packet
	closed    chan struct{}
	closeOnce sync.Once
	kick      chan struct{} // wakes a blocked reader after SetReadDeadline

	mu       sync.Mutex
	deadline time.Time
}

// LocalAddrPort returns the socket's first address and port.
func (c *Conn) LocalAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(c.host.addrs[0], c.port)
}

// LocalAddrPorts returns every address the socket is reachable on locally.
func (c *Conn) LocalAddrPorts() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(c.host.addrs))
	for _, a := range c.host.addrs {
		out = append(out, netip.AddrPortFrom(a, c.port))
	}
	return out
}

// WriteToUDPAddrPort sends b to dst.
func (c *Conn) WriteToUDPAddrPort(b []byte, dst netip.AddrPort) (int, error) {
	src, ok := c.host.source(dst.Addr().Unmap())
	if !ok {
		return 0, ErrNoRoute
	}
	return c.writeFrom(src, b, dst)
}

// writeFrom sends b from a specific host address (used by STUNServer).
func (c *Conn) writeFrom(src netip.Addr, b []byte, dst netip.AddrPort) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if len(b) > maxDatagram {
		return 0, errors.New("natlab: datagram too large")
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	c.host.seg.send(packet{
		src:     netip.AddrPortFrom(src, c.port),
		dst:     dst,
		payload: bytes.Clone(b),
		ttl:     defaultTTL,
	})
	return len(b), nil
}

func (c *Conn) enqueue(p packet) {
	select {
	case <-c.closed:
	case c.queue <- p:
	default: // buffer full: drop
	}
}

// ReadFromUDPAddrPort reads one datagram into b.
func (c *Conn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	p, err := c.readPacket()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return copy(b, p.payload), p.src, nil
}

// readPacket blocks for the next datagram, honouring the read deadline.
func (c *Conn) readPacket() (packet, error) {
	for {
		p, retry, err := c.waitOnce()
		if !retry {
			return p, err
		}
	}
}

// waitOnce waits under the current deadline. retry reports a deadline change.
func (c *Conn) waitOnce() (_ packet, retry bool, _ error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var expired <-chan time.Time
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return packet{}, false, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		expired = t.C
	}
	select {
	case p := <-c.queue:
		return p, false, nil
	case <-c.closed:
		return packet{}, false, net.ErrClosed
	case <-expired:
		return packet{}, false, os.ErrDeadlineExceeded
	case <-c.kick:
		return packet{}, true, nil
	}
}

// SetReadDeadline sets the deadline for future and pending reads.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return nil
}

// Close releases the port and unblocks readers.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.host.release(c.port)
	})
	return nil
}
