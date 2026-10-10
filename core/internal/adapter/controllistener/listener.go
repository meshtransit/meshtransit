package controllistener

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
)

var (
	// ErrInvalid reports missing dependencies or unsafe bounds.
	ErrInvalid = errors.New("controllistener: invalid control listener")
	// ErrStarted reports an attempt to start a listener more than once.
	ErrStarted = errors.New("controllistener: control listener already started")
	// ErrNotStarted reports shutdown before a successful start.
	ErrNotStarted = errors.New("controllistener: control listener not started")
)

// Routes serves the control paths and owns the sessions they hijack; the
// listener shuts it down before draining ordinary requests.
type Routes interface {
	http.Handler
	Shutdown(context.Context) error
}

// Options contains immutable TLS-listener dependencies and
// pre-authentication resource bounds.
type Options struct {
	Address          string
	Certificate      tls.Certificate
	Routes           Routes
	Telemetry        *Telemetry
	MaxConnections   int
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

// Listener owns the public TLS listener and its single serving
// goroutine. Its routes own every hijacked session connection.
type Listener struct {
	mu          sync.Mutex
	server      *http.Server
	routes      Routes
	telemetry   *Telemetry
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

// New constructs a TLS-only public listener without opening a socket.
func New(options Options) (*Listener, error) {
	if options.Address == "" || len(options.Certificate.Certificate) == 0 ||
		options.Certificate.PrivateKey == nil || options.Routes == nil || options.Telemetry == nil ||
		options.Telemetry.connectionCapacity != options.MaxConnections ||
		options.MaxConnections < 1 || options.MaxConnections > MaxConnections ||
		options.HandshakeTimeout < minTimeout ||
		options.HandshakeTimeout > maxHandshake ||
		options.IdleTimeout < minTimeout ||
		options.IdleTimeout > maxSessionTimeout {
		return nil, ErrInvalid
	}

	listenConfig := &net.ListenConfig{}
	return &Listener{
		server: &http.Server{
			Handler:           options.Routes,
			ReadHeaderTimeout: options.HandshakeTimeout,
			ReadTimeout:       options.HandshakeTimeout,
			WriteTimeout:      options.HandshakeTimeout,
			IdleTimeout:       options.IdleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
		routes:    options.Routes,
		telemetry: options.Telemetry,
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

// Start opens the public socket and starts exactly one owned serving goroutine.
func (listener *Listener) Start(ctx context.Context) error {
	if listener == nil || ctx == nil {
		return ErrInvalid
	}

	listener.mu.Lock()
	if listener.started || listener.starting || listener.stopping {
		listener.mu.Unlock()
		return ErrStarted
	}
	startCtx, startCancel := context.WithCancel(ctx)
	startDone := make(chan struct{})
	listener.starting = true
	listener.startCancel = startCancel
	listener.startDone = startDone
	listen := listener.listen
	address := listener.address
	listener.mu.Unlock()

	rawListener, err := listen(startCtx, "tcp", address)
	if err != nil {
		return listener.finishFailedStart(startCancel, startDone, err)
	}

	listener.mu.Lock()
	if listener.stopping || startCtx.Err() != nil {
		listener.starting = false
		listener.startCancel = nil
		listener.startDone = nil
		listener.mu.Unlock()
		closeErr := rawListener.Close()
		startCancel()
		close(startDone)
		return errors.Join(context.Canceled, closeErr)
	}
	listener.done = make(chan error, 1)
	listener.starting = false
	listener.started = true
	listener.startCancel = nil
	listener.startDone = nil
	listener.server.BaseContext = func(net.Listener) context.Context { return ctx }
	done := listener.done
	bounded := newBoundedListener(rawListener, listener.connections, listener.telemetry)
	tlsListener := tls.NewListener(bounded, listener.tlsConfig)
	go serveControl(listener.server, tlsListener, done)
	close(startDone)
	listener.mu.Unlock()
	startCancel()
	return nil
}

func (listener *Listener) finishFailedStart(
	cancel context.CancelFunc,
	done chan struct{},
	startErr error,
) error {
	cancel()
	listener.mu.Lock()
	stopping := listener.stopping
	listener.starting = false
	listener.startCancel = nil
	listener.startDone = nil
	close(done)
	listener.mu.Unlock()
	if stopping || errors.Is(startErr, context.Canceled) {
		return context.Canceled
	}
	return fmt.Errorf("listen for control sessions: %w", startErr)
}

func serveControl(server *http.Server, socket net.Listener, done chan<- error) {
	err := server.Serve(socket)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	done <- err
	close(done)
}

// Done returns the serving goroutine's join channel after a successful Start.
func (listener *Listener) Done() <-chan error {
	if listener == nil {
		return nil
	}
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.done
}

// Shutdown stops session admission, closes and joins hijacked sessions,
// then drains ordinary TLS requests. A deadline forces remaining HTTP sockets closed.
func (listener *Listener) Shutdown(ctx context.Context) error {
	if listener == nil || ctx == nil {
		return ErrInvalid
	}

	listener.mu.Lock()
	if listener.starting {
		listener.stopping = true
		cancel := listener.startCancel
		startDone := listener.startDone
		listener.mu.Unlock()
		cancel()
		select {
		case <-startDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	started := listener.started
	if started {
		listener.stopping = true
	}
	listener.mu.Unlock()
	if !started {
		return ErrNotStarted
	}

	sessionErr := listener.routes.Shutdown(ctx)
	httpErr := listener.server.Shutdown(ctx)
	if httpErr != nil {
		httpErr = errors.Join(httpErr, listener.server.Close())
	}
	return errors.Join(sessionErr, httpErr)
}

var _ interface {
	Start(context.Context) error
	Done() <-chan error
	Shutdown(context.Context) error
} = (*Listener)(nil)
