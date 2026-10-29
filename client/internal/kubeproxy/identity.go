package kubeproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// clientWriteTimeout bounds a write to a client that does not read.
const clientWriteTimeout = 60 * time.Second

// ConnectionReceiveWindow is what HTTP/2 may queue from one client
// connection; the gateway's memory sizing counts it (K1b design §8).
const ConnectionReceiveWindow = 256 << 10

// identified is a connection and the Device it serves (K1-I1): named in
// its TLS handshake, from the key its packets come under, then held for
// every request after. Naming it there, not in Accept, keeps one slow
// lookup from holding other connections back (review b5a M2).
type identified struct {
	net.Conn
	source netip.Addr

	once     sync.Once
	deviceID string
	key      [32]byte
	known    bool

	// gate counts the connection; joined: it counts against deviceID too;
	// closed: its counts went (review b6b M1).
	gate         *gate
	countMu      sync.Mutex
	joined       bool
	closed       bool
	writeTimeout time.Duration
	// writeDeadline is the last deadline set on the connection (time.Time).
	writeDeadline atomic.Value
}

// join counts the connection against its Device's, once. It names the
// limit it is past; false with none once the connection closed.
func (conn *identified) join() (string, bool) {
	conn.countMu.Lock()
	defer conn.countMu.Unlock()
	switch {
	case conn.closed:
		return "", false
	case conn.joined:
		return "", true
	case !conn.gate.joinDevice(conn.deviceID, conn.source):
		return limitDeviceConnections, false
	}
	conn.joined = true
	return "", true
}

// Write gives each write writeTimeout to make progress: a client that
// stops reading cannot hold the connection's buffers for good, HTTP/1.1
// watches and upgrades included (review b6b H2). A sooner deadline set on
// the connection, such as TLS's 5 s for its close alert, holds (N2).
func (conn *identified) Write(data []byte) (int, error) {
	if conn.writeTimeout > 0 {
		deadline := time.Now().Add(conn.writeTimeout)
		if set, ok := conn.writeDeadline.Load().(time.Time); ok && !set.IsZero() && set.Before(deadline) {
			deadline = set
		}
		_ = conn.Conn.SetWriteDeadline(deadline)
	}
	return conn.Conn.Write(data)
}

// SetWriteDeadline keeps the deadline for Write, which honours it.
func (conn *identified) SetWriteDeadline(deadline time.Time) error {
	conn.writeDeadline.Store(deadline)
	return conn.Conn.SetWriteDeadline(deadline)
}

// SetDeadline keeps the write deadline for Write, which honours it.
func (conn *identified) SetDeadline(deadline time.Time) error {
	conn.writeDeadline.Store(deadline)
	return conn.Conn.SetDeadline(deadline)
}

// Close lets the connection's counts go, once.
func (conn *identified) Close() error {
	conn.countMu.Lock()
	if !conn.closed && conn.gate != nil {
		conn.closed = true
		conn.gate.release(conn.source, !conn.joined)
		if conn.joined {
			conn.gate.leaveDevice(conn.deviceID)
		}
	}
	conn.countMu.Unlock()
	return conn.Conn.Close()
}

// bind names the connection's Device the first time it is asked.
func (conn *identified) bind(peer func(netip.Addr) (Peer, bool)) (string, [32]byte, bool) {
	conn.once.Do(func() {
		if found, ok := peer(conn.source); ok {
			conn.deviceID, conn.key, conn.known = found.DeviceID, found.Key, true
		}
	})
	return conn.deviceID, conn.key, conn.known
}

// identifying wraps each accepted connection with its source; one whose
// source cannot be read, or past the replica's or its source's limits, is
// closed at once.
type identifying struct {
	net.Listener
	gate   *gate
	logger *slog.Logger
}

func (listener identifying) Accept() (net.Conn, error) {
	for {
		conn, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source, ok := sourceOf(conn.RemoteAddr())
		if !ok {
			_ = conn.Close()
			continue
		}
		if limit := listener.gate.accept(source); limit != "" {
			listener.gate.count(limit)
			listener.logger.Debug("kube connection refused", "source", source, "limit", limit)
			_ = conn.Close()
			continue
		}
		return &identified{Conn: conn, source: source, gate: listener.gate, writeTimeout: clientWriteTimeout}, nil
	}
}

func sourceOf(address net.Addr) (netip.Addr, bool) {
	switch typed := address.(type) {
	case *net.TCPAddr:
		source, ok := netip.AddrFromSlice(typed.IP)
		return source.Unmap(), ok
	default:
		port, err := netip.ParseAddrPort(address.String())
		return port.Addr().Unmap(), err == nil
	}
}

type identityKey struct{}

// withIdentity puts a connection in its requests' context.
func withIdentity(ctx context.Context, conn net.Conn) context.Context {
	if secured, ok := conn.(*tls.Conn); ok {
		conn = secured.NetConn()
	}
	if held, ok := conn.(*identified); ok {
		return context.WithValue(ctx, identityKey{}, held)
	}
	return ctx
}

var errNoIdentity = errors.New("kubeproxy: a request without its connection")

func identityOf(ctx context.Context) (*identified, error) {
	held, ok := ctx.Value(identityKey{}).(*identified)
	if !ok {
		return nil, errNoIdentity
	}
	return held, nil
}
