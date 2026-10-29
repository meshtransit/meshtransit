package meshgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
)

// tunName names the gateway's TUN in status and logs; it is no interface.
const tunName = "meshgw"

// generationQueue is how many packets a TUN generation holds for the data
// plane; past it packets are dropped, as a kernel TUN's queue drops them.
const generationQueue = 256

var errStacksClosed = errors.New("meshgw: the stacks are closed")

// Stacks is the gateway's TUN opener for the data plane. Each address set
// gets one long-lived userspace TCP/IP stack; the data plane gets a fresh TUN
// generation over it every time it opens one. The data plane closes and
// reopens its TUN whenever the relays change or its device rebuilds, so
// keeping the stack keeps every connection and listener open across that.
// Only a new address set makes a new stack (k8s-gateway-plan §4.4).
type Stacks struct {
	mtu     int
	logger  *slog.Logger
	changes chan struct{}
	buffers *sync.Pool
	dropped atomic.Uint64

	mu      sync.Mutex
	current *netStack
	closed  bool
}

// Stack is one address set's stack, for the forwarder: it dials and listens
// on Net until Retired closes, then binds again on the next Current.
type Stack struct {
	Net       *meshStack
	Addresses []netip.Addr
	Retired   <-chan struct{}
}

// NewStacks returns an opener whose stacks carry packets up to mtu bytes.
func NewStacks(mtu int, logger *slog.Logger) *Stacks {
	buffers := &sync.Pool{New: func() any {
		buffer := make([]byte, mtu)
		return &buffer
	}}
	return &Stacks{mtu: mtu, logger: logger, changes: make(chan struct{}, 1), buffers: buffers}
}

// OpenTUN returns a TUN with exactly the map's addresses and routes. The
// routes need nothing: the stack sends every packet to the data plane, whose
// filter and peers decide where it goes.
func (s *Stacks) OpenTUN(_ context.Context, config netadmin.TUNConfig) (netadmin.TUN, error) {
	addresses := make([]netip.Addr, 0, len(config.Addresses))
	for _, prefix := range config.Addresses {
		addresses = append(addresses, prefix.Addr())
	}
	if len(addresses) == 0 {
		return netadmin.TUN{}, errors.New("meshgw: the map gives the gateway no address")
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return netadmin.TUN{}, errStacksClosed
	}
	var retired *netStack
	started := s.current == nil || !slices.Equal(s.current.addresses, addresses)
	if started {
		next, err := newNetStack(addresses, s.mtu, s.buffers, &s.dropped)
		if err != nil {
			s.mu.Unlock()
			return netadmin.TUN{}, err
		}
		retired, s.current = s.current, next
		s.logger.Info("gateway stack started", "addresses", addresses)
	}
	generation := s.current.attach()
	s.mu.Unlock()

	if retired != nil {
		retired.close()
		s.logger.Info("gateway stack retired", "addresses", retired.addresses)
	}
	if started {
		select {
		case s.changes <- struct{}{}:
		default:
		}
	}
	return netadmin.TUN{
		Device:    generation,
		Name:      tunName,
		MTU:       s.mtu,
		Addresses: slices.Clone(config.Addresses),
		Routes:    slices.Clone(config.Routes),
	}, nil
}

// ConfigureTUNRoutes takes the map's new routes, which a stack does not
// need. Having it keeps the data plane from rebuilding the TUN, and so the
// device, each time a peer joins or leaves.
func (s *Stacks) ConfigureTUNRoutes(context.Context, netadmin.TUNConfig) error { return nil }

// Current returns the stack the forwarder should use, if the map has given
// the gateway addresses yet.
func (s *Stacks) Current() (Stack, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return Stack{}, false
	}
	return Stack{Net: s.current.net, Addresses: slices.Clone(s.current.addresses), Retired: s.current.retired}, true
}

// Changes signals, coalesced, that Current may have changed.
func (s *Stacks) Changes() <-chan struct{} { return s.changes }

// Dropped counts packets the stacks sent while the data plane held no TUN or
// did not keep up.
func (s *Stacks) Dropped() uint64 { return s.dropped.Load() }

// Close retires the current stack and refuses new TUNs.
func (s *Stacks) Close() error {
	s.mu.Lock()
	current := s.current
	s.current, s.closed = nil, true
	s.mu.Unlock()
	if current != nil {
		current.close()
	}
	return nil
}

// netStack is one gVisor stack and the goroutine that reads every packet it
// sends. The reader runs for the stack's whole life, so the stack's own
// goroutines never wait on the data plane (TD-CLI-74).
type netStack struct {
	device    *meshStack
	net       *meshStack
	addresses []netip.Addr
	mtu       int
	buffers   *sync.Pool
	dropped   *atomic.Uint64
	attached  atomic.Pointer[generation]
	retired   chan struct{}
	reading   chan struct{}
	closeOnce sync.Once
}

// packet is a buffer from the stacks' pool holding n bytes.
type packet struct {
	buffer *[]byte
	n      int
}

func newNetStack(addresses []netip.Addr, mtu int, buffers *sync.Pool, dropped *atomic.Uint64) (*netStack, error) {
	device, err := newMeshStack(addresses, mtu)
	if err != nil {
		return nil, fmt.Errorf("meshgw: creating the gateway stack: %w", err)
	}
	created := &netStack{
		device: device, net: device, addresses: slices.Clone(addresses), mtu: mtu, buffers: buffers,
		dropped: dropped, retired: make(chan struct{}), reading: make(chan struct{}),
	}
	go created.read()
	return created, nil
}

// read hands each packet the stack sends to the generation the data plane
// holds; with none, or a full queue, the packet is dropped and TCP sends it
// again. It never waits on the data plane, which may itself be writing into
// the stack, and stops only once the stack is closed.
func (s *netStack) read() {
	defer close(s.reading)
	sizes := []int{0}
	for {
		buffer := s.buffer()
		n, err := s.device.Read([][]byte{*buffer}, sizes, 0)
		if errors.Is(err, os.ErrClosed) {
			s.buffers.Put(buffer)
			return
		}
		if err != nil || n == 0 {
			s.buffers.Put(buffer)
			if err != nil {
				// A packet that did not fit: counted, never silent.
				s.dropped.Add(1)
			}
			continue
		}
		current := s.attached.Load()
		if current == nil || !current.deliver(packet{buffer: buffer, n: sizes[0]}) {
			s.buffers.Put(buffer)
			s.dropped.Add(1)
		}
	}
}

func (s *netStack) buffer() *[]byte {
	buffer, ok := s.buffers.Get().(*[]byte)
	if !ok || len(*buffer) < s.mtu {
		made := make([]byte, s.mtu)
		return &made
	}
	return buffer
}

// attach starts a generation; one the data plane still holds stops getting
// packets but stays open until the data plane closes it.
func (s *netStack) attach() *generation {
	next := &generation{
		stack:   s,
		packets: make(chan packet, generationQueue),
		events:  make(chan tun.Event, 1),
		closed:  make(chan struct{}),
	}
	next.events <- tun.EventUp
	s.attached.Store(next)
	return next
}

// close retires the stack while its reader still runs, then waits for the
// reader to end.
func (s *netStack) close() {
	s.closeOnce.Do(func() {
		close(s.retired)
		if current := s.attached.Swap(nil); current != nil {
			_ = current.Close()
		}
		_ = s.device.Close()
		<-s.reading
	})
}

// generation is the TUN the data plane holds over a stack, from one OpenTUN
// to its Close. Closing it leaves the stack running.
type generation struct {
	stack     *netStack
	packets   chan packet
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

var _ tun.Device = (*generation)(nil)

// deliver queues a packet for the data plane and reports whether it did:
// a closed generation or a full queue takes none.
func (g *generation) deliver(p packet) bool {
	select {
	case <-g.closed:
		return false
	default:
	}
	select {
	case g.packets <- p:
		return true
	default:
		return false
	}
}

// File returns nil: the TUN is in this process.
func (g *generation) File() *os.File { return nil }

// Read gives the data plane the next packet the stack sent.
func (g *generation) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-g.packets:
		sizes[0] = copy(bufs[0][offset:], (*p.buffer)[:p.n])
		g.stack.buffers.Put(p.buffer)
		return 1, nil
	case <-g.closed:
		return 0, os.ErrClosed
	}
}

// Write gives the stack packets the data plane decrypted.
func (g *generation) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-g.closed:
		return 0, os.ErrClosed
	default:
	}
	return g.stack.device.Write(bufs, offset)
}

// MTU returns the stack's MTU.
func (g *generation) MTU() (int, error) { return g.stack.mtu, nil }

// Name returns the TUN's name in status and logs.
func (g *generation) Name() (string, error) { return tunName, nil }

// Events reports EventUp once, and ends when the generation closes.
func (g *generation) Events() <-chan tun.Event { return g.events }

// Close ends the generation: Read returns os.ErrClosed and the stack's
// packets go to the next one. Packets still queued go back to the pool.
func (g *generation) Close() error {
	g.closeOnce.Do(func() {
		close(g.closed)
		g.stack.attached.CompareAndSwap(g, nil)
		close(g.events)
		for {
			select {
			case p := <-g.packets:
				g.stack.buffers.Put(p.buffer)
			default:
				return
			}
		}
	})
	return nil
}

// BatchSize is one packet per call, as the stack reads and writes.
func (g *generation) BatchSize() int { return 1 }
