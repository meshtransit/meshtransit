// Package stream serves MTRP over TLS on one TCP port (mtrp-v1 §1): after
// the TLS handshake, ALPN "mtrp/1" selects length-prefixed frames and
// "http/1.1" selects WebSocket at /mtrp/v1, for networks that only pass
// HTTP(S) or require a proxy. TLS is not part of MTRP's trust model; the
// Noise handshake inside authenticates the relay.
package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"meshtransit.net/shared/mtrp"

	"meshtransit.net/relay/internal/logging"
)

// ALPN identifiers and the WebSocket endpoint.
const (
	ALPNRaw         = "mtrp/1"
	ALPNHTTP        = "http/1.1"
	alpnACME        = "acme-tls/1"
	WebSocketPath   = "/mtrp/v1"
	WebSocketSubpro = "mtrp.v1"
)

// Defaults.
const (
	DefaultMaxConns = 10_000
	// DefaultMaxConnsPerIP leaves room for many clients behind one proxy or
	// carrier NAT, which is exactly who needs the TLS fallback.
	DefaultMaxConnsPerIP    = 64
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultIdleTimeout      = 120 * time.Second // above the relay's 90 s session idle timeout
	DefaultWriteTimeout     = 10 * time.Second
	acceptBackoffMax        = time.Second
)

// Config configures a Listener. Zero values take the defaults.
type Config struct {
	Addr          string
	TLS           *tls.Config // certificates (or GetCertificate); NextProtos are added
	Handler       Handler
	MaxConns      int
	MaxConnsPerIP int // IPv6 counted per /64
	// TrustedProxies are reverse proxies (the self-host Caddy) whose
	// connections carry many clients: they count only toward MaxConns, and
	// a WebSocket from them takes the client address from the last
	// X-Forwarded-For entry, the one the proxy itself added. Raw MTRP from
	// them is refused (a proxy cannot carry it).
	TrustedProxies []netip.Prefix
	// ProxyOnly refuses every peer but the trusted proxies at accept: a
	// listener only a proxy should reach (the self-host relay's).
	ProxyOnly        bool
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	WriteTimeout     time.Duration
	Logger           *slog.Logger
	Metrics          func(result string)
}

// Listener accepts stream connections.
type Listener struct {
	cfg  Config
	ln   net.Listener
	tls  *tls.Config
	http *http.Server
	hand *chanListener

	mu      sync.Mutex
	total   int
	perIP   map[netip.Addr]int
	live    map[*conn]struct{} // every serving connection, closed on shutdown
	stopped bool
	active  sync.WaitGroup // serving connections
}

// Listen opens the TCP socket.
func Listen(ctx context.Context, cfg Config) (*Listener, error) {
	if cfg.TLS == nil || cfg.Handler == nil {
		return nil, errors.New("stream: TLS configuration and handler are required")
	}
	if cfg.ProxyOnly && len(cfg.TrustedProxies) == 0 {
		return nil, errors.New("stream: proxy-only needs trusted proxies")
	}
	setDefault(&cfg.MaxConns, DefaultMaxConns)
	setDefault(&cfg.MaxConnsPerIP, DefaultMaxConnsPerIP)
	setDefault(&cfg.HandshakeTimeout, DefaultHandshakeTimeout)
	setDefault(&cfg.IdleTimeout, DefaultIdleTimeout)
	setDefault(&cfg.WriteTimeout, DefaultWriteTimeout)
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = func(string) {}
	}
	tlsConf := cfg.TLS.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	// Exactly these protocols, in this order: no HTTP/2 (it cannot carry a
	// WebSocket upgrade here) and the ACME challenge only when configured.
	protos := []string{ALPNRaw, ALPNHTTP}
	if slices.Contains(cfg.TLS.NextProtos, alpnACME) {
		protos = append(protos, alpnACME)
	}
	tlsConf.NextProtos = protos
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("stream: listen %s: %w", cfg.Addr, err)
	}
	l := &Listener{cfg: cfg, ln: ln, tls: tlsConf, perIP: make(map[netip.Addr]int), live: make(map[*conn]struct{})}
	l.hand = newChanListener(ln.Addr())
	mux := http.NewServeMux()
	mux.HandleFunc(WebSocketPath, l.serveWebSocket)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	l.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.HandshakeTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
		// An empty map disables HTTP/2.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	return l, nil
}

func setDefault[T int | time.Duration](v *T, d T) {
	if *v <= 0 {
		*v = d
	}
}

// Close closes the socket; Serve closes everything else on shutdown.
func (l *Listener) Close() error { return l.ln.Close() }

// Addr returns the bound address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Serve accepts connections until ctx is done, then closes every
// connection and waits for them.
func (l *Listener) Serve(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Go(func() { _ = l.http.Serve(l.hand) })
	stop := context.AfterFunc(ctx, func() {
		_ = l.ln.Close()
		_ = l.http.Close() // hijacked WebSocket connections are closed through l.live
	})
	defer stop()
	var backoff time.Duration
	for {
		c, acceptErr := l.ln.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				break
			}
			// Temporary failures (descriptor exhaustion, aborted
			// connections) must not stop the relay: back off and retry.
			backoff = min(max(2*backoff, 5*time.Millisecond), acceptBackoffMax)
			l.cfg.Metrics("accept_error")
			l.cfg.Logger.Warn("stream accept failed", append(logging.ErrorAttrs(acceptErr), "retry_in", backoff.String())...)
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		proxied := l.trustedProxy(tcpAddr(c.RemoteAddr()))
		if l.cfg.ProxyOnly && !proxied {
			l.cfg.Metrics("refused_not_proxy")
			_ = c.Close()
			continue
		}
		release, ok := l.admit(remoteAddr(c.RemoteAddr()), !proxied)
		if !ok {
			l.cfg.Metrics("refused_limit")
			_ = c.Close()
			continue
		}
		tracked := &trackedConn{Conn: c, release: release, remote: tcpAddr(c.RemoteAddr()), proxied: proxied}
		wg.Go(func() { l.serveConn(ctx, tracked) })
	}
	_ = l.ln.Close()
	_ = l.http.Close()
	l.hand.close()
	l.closeLive()
	wg.Wait()
	l.active.Wait()
	return nil
}

// serve runs a connection, registered so shutdown can close it. It refuses
// connections that arrive after shutdown began.
func (l *Listener) serve(c *conn) {
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		_ = c.Close()
		return
	}
	l.live[c] = struct{}{}
	l.active.Add(1)
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.live, c)
		l.mu.Unlock()
		l.active.Done()
	}()
	c.run(l.cfg.Handler, l.cfg.HandshakeTimeout)
}

func (l *Listener) closeLive() {
	l.mu.Lock()
	l.stopped = true
	live := make([]*conn, 0, len(l.live))
	for c := range l.live {
		live = append(live, c)
	}
	l.mu.Unlock()
	for _, c := range live {
		_ = c.Close()
	}
}

func (l *Listener) serveConn(ctx context.Context, c *trackedConn) {
	tc := tls.Server(c, l.tls)
	hsCtx, cancel := context.WithTimeout(ctx, l.cfg.HandshakeTimeout)
	err := tc.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		l.cfg.Metrics("tls_failed")
		_ = tc.Close()
		return
	}
	switch tc.ConnectionState().NegotiatedProtocol {
	case ALPNRaw:
		if c.proxied {
			l.cfg.Metrics("raw_from_proxy")
			_ = tc.Close()
			return
		}
		l.cfg.Metrics("raw")
		l.serve(newConn(newRawFramer(tc, l.cfg.IdleTimeout, l.cfg.WriteTimeout), c.remote, l.cfg.Metrics))
	case alpnACME:
		_ = tc.Close() // certificate validation only
	default:
		// HTTP: the http.Server takes the connection and owns its lifetime.
		if !l.hand.deliver(ctx, tc) {
			_ = tc.Close()
		}
	}
}

// serveWebSocket upgrades /mtrp/v1 and serves MTRP frames on it.
func (l *Listener) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	client, release, refused := l.websocketClient(r)
	if refused != "" {
		l.cfg.Metrics(refused)
		status := http.StatusServiceUnavailable
		if refused != "refused_limit" {
			status = http.StatusBadRequest
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer release() // serve returns when the connection ends
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{WebSocketSubpro},
		// MTRP clients are not browsers and carry no ambient credentials;
		// authentication happens in the Noise handshake, so origin checks
		// protect nothing here.
		InsecureSkipVerify: true,
	})
	if err != nil {
		l.cfg.Metrics("websocket_failed")
		return
	}
	if ws.Subprotocol() != WebSocketSubpro {
		_ = ws.Close(websocket.StatusPolicyViolation, "subprotocol mtrp.v1 required")
		return
	}
	ws.SetReadLimit(mtrp.MaxStreamFrame)
	l.cfg.Metrics("websocket")
	l.serve(newConn(&wsFramer{c: ws, idle: l.cfg.IdleTimeout, writes: l.cfg.WriteTimeout}, client, l.cfg.Metrics))
}

// websocketClient is the client address of an upgrade request and, for a
// request through a trusted proxy, the per-address admission it took. A
// refusal names its metric.
func (l *Listener) websocketClient(r *http.Request) (netip.Addr, func(), string) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, nil, "websocket_bad_peer"
	}
	address := peer.Addr().Unmap()
	if !l.trustedProxy(address) {
		return address, func() {}, ""
	}
	forwarded := r.Header.Values("X-Forwarded-For")
	if len(forwarded) == 0 {
		return netip.Addr{}, nil, "websocket_bad_forwarded"
	}
	entries := strings.Split(forwarded[len(forwarded)-1], ",")
	client, err := netip.ParseAddr(strings.TrimSpace(entries[len(entries)-1]))
	if err != nil || client.Zone() != "" {
		return netip.Addr{}, nil, "websocket_bad_forwarded"
	}
	client = client.Unmap()
	release, ok := l.admitPerIP(admissionKey(client))
	if !ok {
		return netip.Addr{}, nil, "refused_limit"
	}
	return client, release, ""
}

func (l *Listener) trustedProxy(address netip.Addr) bool {
	for _, prefix := range l.cfg.TrustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// admit applies the connection limits, the per-address one only when
// perAddress is set; release undoes the admission.
func (l *Listener) admit(addr netip.Addr, perAddress bool) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.cfg.MaxConns || perAddress && l.perIP[addr] >= l.cfg.MaxConnsPerIP {
		return nil, false
	}
	l.total++
	if perAddress {
		l.perIP[addr]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if perAddress {
				l.releasePerIPLocked(addr)
			}
		})
	}, true
}

// admitPerIP applies the per-address limit alone: to the client behind a
// trusted proxy, whose connection already counted toward the total.
func (l *Listener) admitPerIP(addr netip.Addr) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP[addr] >= l.cfg.MaxConnsPerIP {
		return nil, false
	}
	l.perIP[addr]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.releasePerIPLocked(addr)
		})
	}, true
}

func (l *Listener) releasePerIPLocked(addr netip.Addr) {
	if l.perIP[addr]--; l.perIP[addr] <= 0 {
		delete(l.perIP, addr)
	}
}

func tcpAddr(a net.Addr) netip.Addr {
	if tcp, ok := a.(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// remoteAddr is the admission key of a connection's peer.
func remoteAddr(a net.Addr) netip.Addr { return admissionKey(tcpAddr(a)) }

// admissionKey is an address for the per-address limit, IPv6 grouped by /64.
func admissionKey(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
}

// trackedConn releases its admission slot when closed.
type trackedConn struct {
	net.Conn
	release func()
	remote  netip.Addr
	proxied bool // from a trusted proxy: no per-address admission yet
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

// chanListener hands TLS connections that negotiated HTTP to http.Server.
type chanListener struct {
	addr      net.Addr
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) deliver(ctx context.Context, c net.Conn) bool {
	select {
	case l.conns <- c:
		return true
	case <-l.done:
		return false
	case <-ctx.Done():
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) close() { l.closeOnce.Do(func() { close(l.done) }) }

func (l *chanListener) Close() error { l.close(); return nil }

func (l *chanListener) Addr() net.Addr { return l.addr }
