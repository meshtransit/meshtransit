package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

const (
	managementReadHeaderTimeout  = 5 * time.Second
	managementReadTimeout        = 35 * time.Second
	managementWriteTimeout       = 35 * time.Second
	managementIdleTimeout        = 60 * time.Second
	managementMaxHeaderBytes     = 16 * 1024
	maximumManagementConnections = 4096
)

var (
	// ErrInvalidManagementServer reports missing dependencies or unsafe bounds.
	ErrInvalidManagementServer = errors.New("invalid management server")
	// ErrManagementServerStarted reports an attempt to start a server more than once.
	ErrManagementServerStarted = errors.New("management server already started")
	// ErrManagementServerNotStarted reports shutdown before successful startup.
	ErrManagementServerNotStarted = errors.New("management server not started")
)

// ManagementServerOptions contains immutable public TLS listener dependencies.
type ManagementServerOptions struct {
	Address        string
	Certificate    tls.Certificate
	Handler        http.Handler
	MaxConnections int
}

// ManagementServer owns the public management TLS listener and serving goroutine.
type ManagementServer struct {
	mu          sync.Mutex
	server      *http.Server
	tlsConfig   *tls.Config
	address     string
	connections int
	listen      func(context.Context, string, string) (net.Listener, error)
	done        chan error
	starting    bool
	started     bool
	stopping    bool
	startCancel context.CancelFunc
	startDone   chan struct{}
}

// NewManagementServer constructs a TLS-only server without opening a socket.
func NewManagementServer(options ManagementServerOptions) (*ManagementServer, error) {
	if options.Address == "" || len(options.Certificate.Certificate) == 0 ||
		options.Certificate.PrivateKey == nil || options.Handler == nil ||
		options.MaxConnections <= 0 || options.MaxConnections > maximumManagementConnections {
		return nil, ErrInvalidManagementServer
	}
	listenConfig := &net.ListenConfig{}
	return &ManagementServer{
		server: &http.Server{
			Handler:           withNoTransform(options.Handler),
			ReadHeaderTimeout: managementReadHeaderTimeout,
			ReadTimeout:       managementReadTimeout,
			WriteTimeout:      managementWriteTimeout,
			IdleTimeout:       managementIdleTimeout,
			MaxHeaderBytes:    managementMaxHeaderBytes,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
		tlsConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{options.Certificate},
			NextProtos:   []string{"http/1.1"},
		},
		address:     options.Address,
		connections: options.MaxConnections,
		listen:      listenConfig.Listen,
	}, nil
}

// Start opens the public TLS socket and starts exactly one owned goroutine.
func (server *ManagementServer) Start(ctx context.Context) error {
	if server == nil || ctx == nil {
		return ErrInvalidManagementServer
	}
	server.mu.Lock()
	if server.started || server.starting || server.stopping {
		server.mu.Unlock()
		return ErrManagementServerStarted
	}
	startCtx, startCancel := context.WithCancel(ctx)
	startDone := make(chan struct{})
	server.starting = true
	server.startCancel = startCancel
	server.startDone = startDone
	listen := server.listen
	address := server.address
	server.mu.Unlock()

	rawListener, err := listen(startCtx, "tcp", address)
	if err != nil {
		return server.finishFailedStart(startCancel, startDone, err)
	}

	server.mu.Lock()
	if server.stopping || startCtx.Err() != nil {
		server.starting = false
		server.startCancel = nil
		server.startDone = nil
		server.mu.Unlock()
		closeErr := rawListener.Close()
		startCancel()
		close(startDone)
		return errors.Join(context.Canceled, closeErr)
	}
	server.done = make(chan error, 1)
	server.starting = false
	server.started = true
	server.startCancel = nil
	server.startDone = nil
	server.server.BaseContext = func(net.Listener) context.Context { return ctx }
	done := server.done
	boundedListener := netutil.LimitListener(rawListener, server.connections)
	tlsListener := tls.NewListener(boundedListener, server.tlsConfig)
	go serveManagement(server.server, tlsListener, done)
	close(startDone)
	server.mu.Unlock()
	startCancel()
	return nil
}

func (server *ManagementServer) finishFailedStart(
	cancel context.CancelFunc,
	done chan struct{},
	startErr error,
) error {
	cancel()
	server.mu.Lock()
	stopping := server.stopping
	server.starting = false
	server.startCancel = nil
	server.startDone = nil
	close(done)
	server.mu.Unlock()
	if stopping || errors.Is(startErr, context.Canceled) {
		return context.Canceled
	}
	return fmt.Errorf("listen for management requests: %w", startErr)
}

func serveManagement(server *http.Server, listener net.Listener, done chan<- error) {
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	done <- err
	close(done)
}

// Done returns the serving goroutine join channel after successful startup.
func (server *ManagementServer) Done() <-chan error {
	if server == nil {
		return nil
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.done
}

// Shutdown drains requests within ctx and force-closes sockets after expiry.
func (server *ManagementServer) Shutdown(ctx context.Context) error {
	if server == nil || ctx == nil {
		return ErrInvalidManagementServer
	}
	server.mu.Lock()
	if server.starting {
		server.stopping = true
		cancel := server.startCancel
		startDone := server.startDone
		server.mu.Unlock()
		cancel()
		select {
		case <-startDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	started := server.started
	if started {
		server.stopping = true
	}
	server.mu.Unlock()
	if !started {
		return ErrManagementServerNotStarted
	}

	shutdownErr := server.server.Shutdown(ctx)
	if shutdownErr == nil {
		return nil
	}
	return errors.Join(shutdownErr, server.server.Close())
}

var _ interface {
	Start(context.Context) error
	Done() <-chan error
	Shutdown(context.Context) error
} = (*ManagementServer)(nil)
