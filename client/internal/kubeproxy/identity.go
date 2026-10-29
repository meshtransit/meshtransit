package kubeproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
)

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
// source cannot be read is closed.
type identifying struct {
	net.Listener
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
		return &identified{Conn: conn, source: source}, nil
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
