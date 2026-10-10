// Package udp runs the relay's UDP sockets: a bounded read loop per reader
// goroutine that hands each datagram to a handler synchronously.
package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// socketBuffer is the receive and send buffer the listener asks for. A
// relay forwards bursts from many sessions through one socket; the kernel
// caps the request at net.core.rmem_max / wmem_max.
const socketBuffer = 4 << 20

// Handler processes one datagram. It must not retain frame.
type Handler func(frame []byte, from netip.AddrPort)

// Listener is a UDP socket shared by its readers and by senders.
type Listener struct {
	conn     *net.UDPConn
	maxFrame int
}

// Listen opens a UDP socket on addr ("host:port"). Datagrams larger than
// maxFrame are dropped unread by the handler.
func Listen(addr string, maxFrame int) (*Listener, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("udp: listen address %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, fmt.Errorf("udp: listen %s: %w", addr, err)
	}
	// Best effort: a smaller buffer still works, it only drops bursts sooner.
	_ = conn.SetReadBuffer(socketBuffer)
	_ = conn.SetWriteBuffer(socketBuffer)
	return &Listener{conn: conn, maxFrame: maxFrame}, nil
}

// LocalAddr returns the bound address.
func (l *Listener) LocalAddr() netip.AddrPort {
	if a, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return a.AddrPort()
	}
	return netip.AddrPort{}
}

// WriteToUDPAddrPort sends a datagram.
func (l *Listener) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return l.conn.WriteToUDPAddrPort(b, addr)
}

// Serve reads with readers goroutines until ctx is done or the socket
// closes, then closes the socket and waits for the readers.
func (l *Listener) Serve(ctx context.Context, readers int, handle Handler) error {
	if readers < 1 {
		readers = 1
	}
	stop := context.AfterFunc(ctx, func() { _ = l.conn.Close() })
	defer stop()
	var wg sync.WaitGroup
	errs := make([]error, readers)
	for i := range readers {
		wg.Go(func() { errs[i] = l.read(handle) })
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(errs...)
}

func (l *Listener) read(handle Handler) error {
	buf := make([]byte, l.maxFrame+1) // one spare byte detects oversize datagrams
	failures := 0
	for {
		n, from, err := l.conn.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			// Usually transient (an ICMP unreachable on Linux); a persistent
			// error must not spin a core, so repeats back off up to 100 ms.
			failures++
			if failures > 1 {
				time.Sleep(min(time.Millisecond<<min(failures-2, 7), 100*time.Millisecond))
			}
			continue
		}
		failures = 0
		if n > l.maxFrame {
			continue
		}
		handle(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
	}
}

// Close closes the socket.
func (l *Listener) Close() error { return l.conn.Close() }
