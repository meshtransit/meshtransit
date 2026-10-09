// Package natlab is an in-memory IP/UDP network for testing NAT traversal.
//
// A Network is made of Segments (routing domains). Hosts own addresses on a
// segment and open UDP sockets (Conn) that look like *net.UDPConn. A NAT joins
// an inside segment to an outside segment and implements the mapping,
// filtering and port allocation behaviours of RFC 4787; with mapping "none"
// it is an IPv6-style stateful firewall. NATs chain, so carrier-grade NAT is
// a NAT whose inside segment holds another NAT's outside address.
//
// Delivery is synchronous and lossless unless a NAT drops the packet, which
// makes traversal outcomes deterministic for fixed seeds. No lock is held
// while a packet moves between nodes.
package natlab

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// defaultTTL bounds forwarding hops, so a misconfigured topology cannot loop.
const defaultTTL = 16

var (
	// ErrAddressInUse reports an address or port that is already taken.
	ErrAddressInUse = errors.New("natlab: address in use")
	// ErrNoRoute reports a destination the host has no source address for.
	ErrNoRoute = errors.New("natlab: no route to host")
)

// Clock is the time source of a Network.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ManualClock is a Clock that moves only when advanced.
type ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewManualClock returns a clock reading start.
func NewManualClock(start time.Time) *ManualClock { return &ManualClock{now: start} }

// Now implements Clock.
func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// packet is a UDP datagram in flight. payload is never modified after send.
type packet struct {
	src, dst netip.AddrPort
	payload  []byte
	ttl      int
}

// node receives packets routed to it.
type node interface{ receive(p packet) }

// Network is a set of segments sharing a clock. Internet is the public segment.
type Network struct {
	clock    Clock
	Internet *Segment
}

// NewNetwork returns a network with an empty Internet segment. A nil clock
// means wall time.
func NewNetwork(clock Clock) *Network {
	if clock == nil {
		clock = realClock{}
	}
	n := &Network{clock: clock}
	n.Internet = n.NewSegment("internet")
	return n
}

// NewSegment returns an empty segment.
func (n *Network) NewSegment(name string) *Segment {
	return &Segment{name: name, addrs: make(map[netip.Addr]node)}
}

// Segment delivers a packet to the node owning its destination address, to
// the most specific matching route, or to the gateway.
type Segment struct {
	name string

	mu      sync.RWMutex
	addrs   map[netip.Addr]node
	routes  []route
	gateway node
}

type route struct {
	prefix netip.Prefix
	to     node
}

func (s *Segment) String() string { return s.name }

func (s *Segment) attach(a netip.Addr, n node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.addrs[a]; ok {
		return fmt.Errorf("%w: %s on %s", ErrAddressInUse, a, s.name)
	}
	s.addrs[a] = n
	return nil
}

func (s *Segment) addRoute(p netip.Prefix, n node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = append(s.routes, route{prefix: p.Masked(), to: n})
}

func (s *Segment) setGateway(n node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gateway != nil {
		return fmt.Errorf("%w: gateway of %s", ErrAddressInUse, s.name)
	}
	s.gateway = n
	return nil
}

func (s *Segment) lookup(a netip.Addr) node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n, ok := s.addrs[a]; ok {
		return n
	}
	var best node
	bits := -1
	for _, r := range s.routes {
		if r.prefix.Contains(a) && r.prefix.Bits() > bits {
			best, bits = r.to, r.prefix.Bits()
		}
	}
	if best != nil {
		return best
	}
	return s.gateway
}

func (s *Segment) send(p packet) {
	p.ttl--
	if p.ttl <= 0 {
		return
	}
	if n := s.lookup(p.dst.Addr()); n != nil {
		n.receive(p)
	}
}
