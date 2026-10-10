package portmap

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sync"
	"time"
)

var (
	testGateway  = Gateway{Addr: netip.MustParseAddr("192.168.1.1"), Local: netip.MustParseAddr("192.168.1.10")}
	testExternal = netip.MustParseAddr("203.0.113.7")
)

// datagram is one packet in the fake network.
type datagram struct {
	payload []byte
	from    netip.AddrPort
}

// fakeNet answers datagrams sent by the clients with a handler that plays
// the gateway. Every Listen returns a new socket on the fake network.
type fakeNet struct {
	mu      sync.Mutex
	handler func(request []byte, to netip.AddrPort) []datagram
	sent    []datagram // requests, with from = destination
}

func (n *fakeNet) listen(context.Context, netip.Addr) (PacketConn, error) {
	return &fakeConn{net: n, inbox: make(chan datagram, 16)}, nil
}

type fakeConn struct {
	net      *fakeNet
	inbox    chan datagram
	mu       sync.Mutex
	deadline time.Time
}

func (c *fakeConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	request := append([]byte(nil), b...)
	c.net.mu.Lock()
	c.net.sent = append(c.net.sent, datagram{payload: request, from: to})
	handler := c.net.handler
	c.net.mu.Unlock()
	if handler != nil {
		for _, reply := range handler(request, to) {
			c.inbox <- reply
		}
	}

	return len(b), nil
}

func (c *fakeConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	wait := time.Until(deadline)
	if deadline.IsZero() {
		wait = time.Hour
	}
	if wait <= 0 {
		return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case d := <-c.inbox:
		return copy(b, d.payload), d.from, nil
	case <-timer.C:
		return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
	}
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()

	return nil
}

func (c *fakeConn) Close() error { return nil }

func fromGateway(payload []byte) datagram {
	return datagram{payload: payload, from: netip.AddrPortFrom(testGateway.Addr, gatewayPort)}
}

// fixedClock is a settable clock.
type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFixedClock() *fixedClock {
	return &fixedClock{now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

var errFake = errors.New("fake failure")
