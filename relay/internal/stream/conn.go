package stream

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/relay/internal/server"
	"meshtransit.net/shared/mtrp"
)

// Handler receives frames from stream connections and learns when they end.
type Handler interface {
	HandleStream(frame []byte, conn server.StreamConn)
	StreamClosed(conn server.StreamConn)
}

// framer reads and writes whole MTRP frames on one transport.
type framer interface {
	// ReadFrame returns the next frame, valid until the next call. It
	// enforces the idle timeout.
	ReadFrame() ([]byte, error)
	// WriteFrame writes one frame, enforcing the write timeout.
	WriteFrame(frame []byte) error
	Close() error
}

var errQueueFull = errors.New("stream: send queue full")

// Connection limits.
const (
	// maxQueuedBytes bounds the frames waiting for one slow client.
	maxQueuedBytes = 64 << 10
	queueSlots     = maxQueuedBytes / 512
	// maxInits bounds handshake attempts on one connection; a client needs
	// one, or two with a retry.
	maxInits = 8
)

// conn is one stream connection. Sends are queued and written by a single
// writer goroutine, so a slow client never blocks the relay; when its queue
// is full, frames are dropped as a congested UDP path would drop them. A
// connection that has no session after the handshake timeout is closed, so
// it cannot hold an admission slot without authenticating.
type conn struct {
	framer    framer
	remote    netip.Addr
	queue     chan []byte
	queued    atomic.Int64 // bytes waiting in queue
	bound     atomic.Bool  // a session has bound to this connection
	inits     int          // INIT frames seen (reader goroutine only)
	done      chan struct{}
	closeOnce sync.Once
	metrics   func(string)
}

var _ server.StreamConn = (*conn)(nil)

func newConn(f framer, remote netip.Addr, metrics func(string)) *conn {
	return &conn{framer: f, remote: remote, queue: make(chan []byte, queueSlots), done: make(chan struct{}), metrics: metrics}
}

// RemoteAddr returns the client address, for per-source limits.
func (c *conn) RemoteAddr() netip.Addr { return c.remote }

// SessionBound records that a session now uses this connection.
func (c *conn) SessionBound() { c.bound.Store(true) }

// Send queues a copy of frame.
func (c *conn) Send(frame []byte) error {
	if len(frame) == 0 || len(frame) > mtrp.MaxStreamFrame {
		return mtrp.ErrMalformed
	}
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	if c.queued.Add(int64(len(frame))) > maxQueuedBytes {
		c.queued.Add(-int64(len(frame)))
		c.metrics("send_dropped")
		return errQueueFull
	}
	select {
	case c.queue <- bytes.Clone(frame):
		return nil
	default:
		c.queued.Add(-int64(len(frame)))
		c.metrics("send_dropped")
		return errQueueFull
	}
}

// Close ends the connection; the reader and writer exit.
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.framer.Close()
	})
	return nil
}

// run serves the connection until it fails or closes, then tells the
// handler. It returns after both directions have stopped.
func (c *conn) run(h Handler, bindTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Go(c.write)
	unbound := time.AfterFunc(bindTimeout, func() {
		if !c.bound.Load() {
			c.metrics("closed_unbound")
			_ = c.Close()
		}
	})
	for {
		frame, err := c.framer.ReadFrame()
		if err != nil {
			break
		}
		if t, _ := mtrp.PeekType(frame); t == mtrp.TypeInit {
			if c.inits++; c.inits > maxInits {
				c.metrics("closed_init_limit")
				break
			}
		}
		h.HandleStream(frame, c)
	}
	unbound.Stop()
	_ = c.Close()
	wg.Wait()
	h.StreamClosed(c)
}

func (c *conn) write() {
	for {
		select {
		case <-c.done:
			return
		case frame := <-c.queue:
			c.queued.Add(-int64(len(frame)))
			if err := c.framer.WriteFrame(frame); err != nil {
				_ = c.Close()
				return
			}
		}
	}
}
