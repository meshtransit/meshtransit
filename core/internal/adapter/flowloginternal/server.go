package flowloginternal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

const (
	// maxConnectionAge closes a connection after it served this long, so a
	// revoked receiver certificate stops being honoured (C38a): the next
	// connection verifies again.
	maxConnectionAge = 10 * time.Minute
	// maxConnections only bounds file descriptors: it counts connections
	// before their handshake, so a low cap would let any peer that reaches
	// the port lock the receiver out (review s4c1a). Who may connect is
	// NetworkPolicy's and mutual TLS's to decide; an idle handshake lasts
	// at most ReadHeaderTimeout.
	maxConnections = 4096
	// handshakeLogInterval bounds how often failed handshakes are logged;
	// every one is counted.
	handshakeLogInterval = time.Minute
)

// ErrInvalidServer reports a server built from incomplete options or
// started twice.
var ErrInvalidServer = errors.New("flowloginternal: invalid server")

// TokenKey is one public token signing key and its state (C45): one of
// "current", "next", "retiring", "revoked".
type TokenKey struct {
	State string
	Key   ed25519.PublicKey
}

// Options build a Server.
type Options struct {
	Address      string
	CertFile     string
	KeyFile      string
	ClientCAFile string
	// ClientURI is the receiver's identity, a URI SAN of its certificate.
	ClientURI *url.URL
	TokenKeys []TokenKey
	// Reader reads Core's database for the API; Status writes the
	// receiver's reports.
	Reader  Reader
	Status  StatusWriter
	Metrics *Metrics
	Logger  *slog.Logger
	Now     func() time.Time
}

// Server is an app.Service serving the internal API on its own listener.
type Server struct {
	address string
	server  *http.Server
	tls     *tls.Config
	source  *credentials

	mu       sync.Mutex
	done     chan error
	listener net.Addr
}

type connectionStart struct{}

// NewServer reads the TLS files once (a missing or invalid one fails
// startup) and builds a stopped server.
func NewServer(options Options) (*Server, error) {
	if options.Address == "" || options.Metrics == nil || options.Now == nil || options.Logger == nil {
		return nil, ErrInvalidServer
	}
	source, err := newCredentials(options.CertFile, options.KeyFile, options.ClientCAFile, options.ClientURI,
		options.Now, options.Metrics, options.Logger)
	if err != nil {
		return nil, err
	}
	handler, err := newHandler(options)
	if err != nil {
		return nil, err
	}
	now := options.Now
	return &Server{address: options.Address, tls: source.serverConfig(), source: source, server: &http.Server{
		Handler:           withConnectionAge(handler, now),
		ErrorLog:          log.New(&handshakeLog{logger: options.Logger, metrics: options.Metrics, now: now}, "", 0),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, connectionStart{}, now())
		},
	}}, nil
}

// withConnectionAge asks the client to close a connection older than
// maxConnectionAge: HTTP/1.1 closes after the answer, HTTP/2 sends GOAWAY.
func withConnectionAge(next http.Handler, now func() time.Time) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if started, ok := request.Context().Value(connectionStart{}).(time.Time); ok &&
			now().Sub(started) >= maxConnectionAge {
			response.Header().Set("Connection", "close")
		}
		next.ServeHTTP(response, request)
	})
}

// Start opens the listener and serves in one goroutine.
func (server *Server) Start(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidServer
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.done != nil {
		return ErrInvalidServer
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", server.address)
	if err != nil {
		return err
	}
	server.done, server.listener = make(chan error, 1), listener.Addr()
	go server.source.run()
	go func() {
		err := server.server.Serve(tls.NewListener(netutil.LimitListener(listener, maxConnections), server.tls))
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		server.source.close()
		<-server.source.stopped
		server.done <- err
		close(server.done)
	}()
	return nil
}

// handshakeLog takes net/http's error lines (failed handshakes): it counts
// each and logs at most one per handshakeLogInterval, so a peer cannot
// flood the log.
type handshakeLog struct {
	logger  *slog.Logger
	metrics *Metrics
	now     func() time.Time

	mu       sync.Mutex
	loggedAt time.Time
	dropped  int
}

func (sink *handshakeLog) Write(line []byte) (int, error) {
	if bytes.HasPrefix(line, []byte("http: panic serving")) {
		// A handler's panic is Core's own fault: log it whole, with its stack.
		sink.logger.Error("connection log receiver API handler panicked", "error_code", "flowlog_internal_panic",
			"panic", string(line))
		return len(line), nil
	}
	sink.metrics.serverError()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if now := sink.now(); now.Sub(sink.loggedAt) >= handshakeLogInterval {
		sink.logger.Warn("connection log receiver API connection failed", "error_code", "flowlog_internal_connection",
			"suppressed", sink.dropped)
		sink.loggedAt, sink.dropped = now, 0
	} else {
		sink.dropped++
	}
	return len(line), nil
}

// Address is the address the server listens on after Start.
func (server *Server) Address() net.Addr {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.listener
}

// Done returns the join channel after Start.
func (server *Server) Done() <-chan error {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.done
}

// Shutdown stops serving.
func (server *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidServer
	}
	defer server.source.close()
	if err := server.server.Shutdown(ctx); err != nil {
		return errors.Join(err, server.server.Close())
	}
	return nil
}
