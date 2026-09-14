package legacyts2021

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
	// ErrInvalidControlListener reports missing dependencies or unsafe bounds.
	ErrInvalidControlListener = errors.New("legacyts2021: invalid control listener")
	// ErrControlListenerStarted reports an attempt to start a listener more than once.
	ErrControlListenerStarted = errors.New("legacyts2021: control listener already started")
	// ErrControlListenerNotStarted reports shutdown before a successful start.
	ErrControlListenerNotStarted = errors.New("legacyts2021: control listener not started")
)

// ControlSessionServer owns authenticated sessions accepted by ControlListener.
type ControlSessionServer interface {
	http.Handler
	Shutdown(context.Context) error
}

// ControlListenerOptions contains immutable TLS-listener dependencies and
// pre-authentication resource bounds.
type ControlListenerOptions struct {
	Address          string
	Certificate      tls.Certificate
	Sessions         ControlSessionServer
	MaxConnections   int
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

// ControlListener owns the public TLS listener and its single serving
// goroutine. Its session dependency owns all hijacked Noise connections.
type ControlListener struct {
	mu          sync.Mutex
	server      *http.Server
	sessions    ControlSessionServer
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

// NewControlListener constructs a TLS-only public listener without opening a socket.
func NewControlListener(options ControlListenerOptions) (*ControlListener, error) {
	if options.Address == "" || len(options.Certificate.Certificate) == 0 ||
		options.Certificate.PrivateKey == nil || options.Sessions == nil ||
		options.MaxConnections < 1 || options.MaxConnections > maxControlSessions ||
		options.HandshakeTimeout < minControlTimeout ||
		options.HandshakeTimeout > maxControlHandshake ||
		options.IdleTimeout < minControlTimeout ||
		options.IdleTimeout > maxControlSessionTimeout {
		return nil, ErrInvalidControlListener
	}

	listenConfig := &net.ListenConfig{}
	return &ControlListener{
		server: &http.Server{
			Handler:           options.Sessions,
			ReadHeaderTimeout: options.HandshakeTimeout,
			ReadTimeout:       options.HandshakeTimeout,
			WriteTimeout:      options.HandshakeTimeout,
			IdleTimeout:       options.IdleTimeout,
			MaxHeaderBytes:    maxControlHeaderBytes,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
		sessions: options.Sessions,
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
func (listener *ControlListener) Start(ctx context.Context) error {
	if listener == nil || ctx == nil {
		return ErrInvalidControlListener
	}

	listener.mu.Lock()
	if listener.started || listener.starting || listener.stopping {
		listener.mu.Unlock()
		return ErrControlListenerStarted
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
	bounded := newBoundedListener(rawListener, listener.connections)
	tlsListener := tls.NewListener(bounded, listener.tlsConfig)
	go serveControl(listener.server, tlsListener, done)
	close(startDone)
	listener.mu.Unlock()
	startCancel()
	return nil
}

func (listener *ControlListener) finishFailedStart(
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
func (listener *ControlListener) Done() <-chan error {
	if listener == nil {
		return nil
	}
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.done
}

// Shutdown stops session admission, closes and joins hijacked Noise sessions,
// then drains ordinary TLS requests. A deadline forces remaining HTTP sockets closed.
func (listener *ControlListener) Shutdown(ctx context.Context) error {
	if listener == nil || ctx == nil {
		return ErrInvalidControlListener
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
		return ErrControlListenerNotStarted
	}

	sessionErr := listener.sessions.Shutdown(ctx)
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
} = (*ControlListener)(nil)
