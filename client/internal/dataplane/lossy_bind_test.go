package dataplane

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
)

// lossyBind is bindtest.ChannelBind (wireguard-go, MIT) with UDP's send
// semantics: a full queue drops the datagram instead of blocking. With the
// original, a sender towards a peer that already closed blocks forever while
// holding its device's lock, so closing engines that still carry traffic
// deadlocks the test (a real socket never blocks that way).
type lossyBind struct {
	rx4, tx4         *chan []byte
	rx6, tx6         *chan []byte
	closeSignal      chan bool
	source4, source6 bindtest.ChannelEndpoint
	target4, target6 bindtest.ChannelEndpoint
}

var _ conn.Bind = (*lossyBind)(nil)

// newLossyChannelBinds returns two binds wired to each other.
func newLossyChannelBinds() [2]conn.Bind {
	arx4, brx4 := make(chan []byte, 8192), make(chan []byte, 8192)
	arx6, brx6 := make(chan []byte, 8192), make(chan []byte, 8192)
	var binds [2]lossyBind
	binds[0].rx4, binds[0].tx4 = &arx4, &brx4
	binds[1].rx4, binds[1].tx4 = &brx4, &arx4
	binds[0].rx6, binds[0].tx6 = &arx6, &brx6
	binds[1].rx6, binds[1].tx6 = &brx6, &arx6
	binds[0].target4, binds[1].target4 = bindtest.ChannelEndpoint(1), bindtest.ChannelEndpoint(2)
	binds[0].target6, binds[1].target6 = bindtest.ChannelEndpoint(3), bindtest.ChannelEndpoint(4)
	binds[0].source4, binds[0].source6 = binds[1].target4, binds[1].target6
	binds[1].source4, binds[1].source6 = binds[0].target4, binds[0].target6
	return [2]conn.Bind{&binds[0], &binds[1]}
}

func (c *lossyBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.closeSignal = make(chan bool)
	fns := []conn.ReceiveFunc{c.receiver(*c.rx4), c.receiver(*c.rx6)}
	if rand.Uint32()&1 == 0 { //nolint:gosec // test port choice
		return fns, uint16(c.source4), nil
	}
	return fns, uint16(c.source6), nil
}

func (c *lossyBind) Close() error {
	if c.closeSignal != nil {
		select {
		case <-c.closeSignal:
		default:
			close(c.closeSignal)
		}
	}
	return nil
}

func (c *lossyBind) BatchSize() int { return 1 }

func (c *lossyBind) SetMark(uint32) error { return nil }

func (c *lossyBind) receiver(ch chan []byte) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-c.closeSignal:
			return 0, net.ErrClosed
		case rx := <-ch:
			sizes[0] = copy(bufs[0], rx)
			eps[0] = c.target6
			return 1, nil
		}
	}
}

func (c *lossyBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, b := range bufs {
		select {
		case <-c.closeSignal:
			return net.ErrClosed
		default:
		}
		var tx chan []byte
		switch endpoint, _ := ep.(bindtest.ChannelEndpoint); endpoint {
		case c.target4:
			tx = *c.tx4
		case c.target6:
			tx = *c.tx6
		default:
			return os.ErrInvalid
		}
		select {
		case tx <- append([]byte(nil), b...):
		default: // full: lost, as a datagram would be
		}
	}
	return nil
}

func (c *lossyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return bindtest.ChannelEndpoint(addr.Port()), nil
}
