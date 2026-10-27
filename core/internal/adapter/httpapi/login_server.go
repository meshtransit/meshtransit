package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

const maximumLoginConnections = 4096

var (
	// ErrInvalidLoginServer conceals rejected graph, certificate and socket input.
	ErrInvalidLoginServer = errors.New("http api: invalid login server")
	// ErrLoginServerStarted reports reuse of a one-shot serving owner.
	ErrLoginServerStarted = errors.New("http api: login server already started")
	// ErrLoginServerNotStarted reports shutdown before a successful start.
	ErrLoginServerNotStarted = errors.New("http api: login server not started")
	// ErrLoginListenerUnavailable conceals socket topology and serving errors.
	ErrLoginListenerUnavailable = errors.New("http api: login listener unavailable")
)

// LoginServerOptions is a source-only TLS profile, not runtime enablement.
// PEM inputs are bounded and parsed into independently owned key/certificate
// material. No alternate handler, forwarded TLS assertion or route is accepted.
type LoginServerOptions struct {
	Address        string
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Dispatcher     *LoginDispatcher
	MaxConnections int
	// Logger, when set, records requests refused before admission by their
	// correlation ID and method only (TD-CORE-79).
	Logger *slog.Logger
}

// LoginServer owns a direct TLS listener and joins every connection handler
// before Done. It does not prove dependency readiness or enable public login.
// Owners must join it before closing the factory's borrowed effect resources.
type LoginServer struct {
	server       *http.Server
	tlsConfig    *tls.Config
	dispatcher   *LoginDispatcher
	logger       *slog.Logger
	address      string
	connections  int
	connectionWG sync.WaitGroup

	mu              sync.Mutex
	isAttempted     bool
	isStarting      bool
	isStarted       bool
	isStopping      bool
	hasAbortFailure bool
	completedError  error
	startCancel     context.CancelFunc
	requestCancel   context.CancelFunc
	startFinished   chan struct{}
	done            chan error
	joined          chan struct{}
	boundAddress    string
}

// NewLoginServer validates an immutable serving profile without opening sockets
// or reading time. A zero-value server is invalid but safe to call.
func NewLoginServer(options LoginServerOptions) (*LoginServer, error) {
	address, err := netip.ParseAddrPort(options.Address)
	validAddress := err == nil && address.String() == options.Address
	if !validAddress || address.Addr().IsMulticast() {
		return nil, ErrInvalidLoginServer
	}
	validGraph := options.Dispatcher != nil && options.Dispatcher.browser != nil && options.Dispatcher.metrics != nil
	validCapacity := options.MaxConnections > 0 && options.MaxConnections <= maximumLoginConnections
	if !validGraph || !validCapacity {
		return nil, ErrInvalidLoginServer
	}
	// Revalidate complete graph custody; do not replace the existing dispatcher.
	if options.Dispatcher.registration != nil {
		if _, err := NewLoginDispatcherWithRegistration(
			options.Dispatcher.browser, options.Dispatcher.management,
			options.Dispatcher.registration,
		); err != nil {
			return nil, ErrInvalidLoginServer
		}
	} else if _, err := NewLoginDispatcher(
		options.Dispatcher.browser, options.Dispatcher.management,
	); err != nil {
		return nil, ErrInvalidLoginServer
	}
	certificate, err := loginServerCertificate(options)
	if err != nil {
		return nil, ErrInvalidLoginServer
	}
	owner := &LoginServer{
		dispatcher: options.Dispatcher, logger: options.Logger, address: options.Address,
		connections: options.MaxConnections,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"},
			// Browser auth has no TLS-resumption requirement or shared ticket-key owner.
			SessionTicketsDisabled: true,
		},
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	owner.server = &http.Server{
		Handler: withNoTransform(http.HandlerFunc(owner.handle)), Protocols: protocols,
		DisableGeneralOptionsHandler: true,
		ConnContext:                  loginConnectionContext,
		ReadHeaderTimeout:            5 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024,
		ErrorLog: log.New(io.Discard, "", 0), ConnState: owner.connectionState,
	}
	return owner, nil
}

// Start makes one cancellable bind attempt using actual system certificate
// validity. The supplied process context remains the request cancellation root.
func (owner *LoginServer) Start(ctx context.Context) error {
	if owner == nil || owner.server == nil || ctx == nil {
		return ErrInvalidLoginServer
	}
	owner.mu.Lock()
	if owner.isAttempted || owner.isStopping {
		owner.mu.Unlock()
		return ErrLoginServerStarted
	}
	startCtx, cancel := context.WithCancel(ctx)
	owner.isAttempted, owner.isStarting = true, true
	owner.startCancel, owner.startFinished = cancel, make(chan struct{})
	owner.mu.Unlock()
	defer cancel()
	defer owner.finishStart()
	if err := startCtx.Err(); err != nil {
		return err
	}
	if !validLoginCertificateTime(owner.tlsConfig.Certificates[0], time.Now()) {
		return ErrInvalidLoginServer
	}
	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(startCtx, "tcp", owner.address)
	if err != nil {
		if startCtx.Err() != nil {
			return startCtx.Err()
		}
		return ErrLoginListenerUnavailable
	}
	owner.mu.Lock()
	if owner.isStopping || startCtx.Err() != nil {
		owner.mu.Unlock()
		if err := listener.Close(); err != nil {
			return errors.Join(context.Canceled, ErrLoginListenerUnavailable)
		}
		return context.Canceled
	}
	requestCtx, requestCancel := context.WithCancel(ctx)
	owner.requestCancel = requestCancel
	owner.server.BaseContext = func(net.Listener) context.Context { return requestCtx }
	owner.done, owner.joined = make(chan error, 1), make(chan struct{})
	owner.isStarted = true
	owner.boundAddress = listener.Addr().String()
	owner.mu.Unlock()
	bounded := netutil.LimitListener(listener, owner.connections)
	go owner.serve(tls.NewListener(bounded, owner.tlsConfig))
	return nil
}

func (owner *LoginServer) finishStart() {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.isStarting = false
	owner.startCancel = nil
	close(owner.startFinished)
}

func (owner *LoginServer) serve(listener net.Listener) {
	err := owner.server.Serve(listener)
	var result error
	if !errors.Is(err, http.ErrServerClosed) {
		result = ErrLoginListenerUnavailable
		owner.mu.Lock()
		owner.isStopping = true
		owner.mu.Unlock()
		owner.requestCancel()
		if err := owner.server.Close(); err != nil {
			result = errors.Join(result, ErrLoginListenerUnavailable)
		}
	}
	// Serve has stopped accepting before Wait: no future StateNew can Add.
	// StateClosed occurs after handler return and connection teardown. Existing
	// sealed graph owners never hijack; no child waiter can outlive this owner.
	owner.connectionWG.Wait()
	owner.requestCancel()
	owner.mu.Lock()
	if owner.hasAbortFailure {
		result = ErrLoginListenerUnavailable
	}
	owner.completedError = result
	owner.mu.Unlock()
	owner.done <- result
	close(owner.done)
	close(owner.joined)
}

func (owner *LoginServer) connectionState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		owner.connectionWG.Add(1)
	case http.StateClosed:
		owner.connectionWG.Done()
	}
}

func (owner *LoginServer) handle(response http.ResponseWriter, request *http.Request) {
	if request == nil {
		owner.recordAbortFailure()
		return
	}
	socket, ok := request.Context().Value(loginSocketContextKey{}).(*loginSocketOwner)
	if !ok || socket == nil || socket.raw == nil {
		// Only the sealed net/http ConnContext installs transport custody. This
		// cannot be removed by client input; never dispatch without that owner.
		owner.recordAbortFailure()
		return
	}
	owner.mu.Lock()
	isStopping := owner.isStopping
	owner.mu.Unlock()
	if isStopping {
		owner.abort(socket)
		return
	}
	if err := owner.dispatcher.Handle(response, request); err != nil {
		// Browser management input refused before admission staged and spent
		// nothing, so it gets a plain 400 while the response is still pristine.
		if errors.Is(err, ErrBrowserManagementRefused) {
			if correlationID, answered := answerRefusedBrowserManagement(response); answered {
				if owner.logger != nil {
					// Neither path nor query: they may carry what a client
					// mistyped. The correlation ID is in the answer.
					method := request.Method
					if len(method) > 16 {
						method = method[:16]
					}
					owner.logger.Info("browser management request refused before admission",
						"correlation_id", correlationID, "method", method)
				}
				return
			}
		}
		// An API path this listener does not serve: 404, as on the bearer
		// listener, so a Console can tell an older Core from a failure.
		if errors.Is(err, ErrUnknownBrowserAPIPath) {
			if _, answered := answerUnknownBrowserAPIPath(response); answered {
				return
			}
		}
		// Returning would implicitly flush any staged cookies with status 200.
		// Abort preserves partial-delivery uncertainty and never retries effects.
		owner.abort(socket)
	}
}

// The private context value is connection-scoped transport custody, not an
// application dependency, authentication claim or alternate effect port.
type loginSocketContextKey struct{}
type loginSocketOwner struct{ raw net.Conn }

func loginConnectionContext(ctx context.Context, connection net.Conn) context.Context {
	raw := connection
	if checked, ok := connection.(*tls.Conn); ok {
		raw = checked.NetConn()
	}
	return context.WithValue(ctx, loginSocketContextKey{}, &loginSocketOwner{raw: raw})
}

func (owner *LoginServer) abort(socket *loginSocketOwner) {
	// Close raw TCP first: no TLS close-notify or Hijack flush can submit staged
	// output. net/http still tears down the original writer/conn with StateClosed.
	if err := socket.raw.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		owner.recordAbortFailure()
	}
}

func (owner *LoginServer) recordAbortFailure() {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.hasAbortFailure = true
}

// Done returns a single serving result only after connection/handler joins.
// Nil before successful Start must never be treated as a completed service.
func (owner *LoginServer) Done() <-chan error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.done
}

// Shutdown stops admission and drains within ctx. Expiry cancels requests and
// force-closes sockets, but callers still must join Done before resource cleanup.
// Successful Shutdown includes the complete join, not just listener closure.
func (owner *LoginServer) Shutdown(ctx context.Context) error {
	if owner == nil || owner.server == nil || ctx == nil {
		return ErrInvalidLoginServer
	}
	owner.mu.Lock()
	if owner.isStarting {
		owner.isStopping = true
		cancel, finished := owner.startCancel, owner.startFinished
		owner.mu.Unlock()
		cancel()
		select {
		case <-finished:
		case <-ctx.Done():
			return ctx.Err()
		}
		owner.mu.Lock()
	}
	if !owner.isStarted {
		owner.mu.Unlock()
		return ErrLoginServerNotStarted
	}
	owner.isStopping = true
	joined, cancel := owner.joined, owner.requestCancel
	owner.mu.Unlock()
	err := owner.server.Shutdown(ctx)
	if err == nil {
		select {
		case <-joined:
			owner.mu.Lock()
			result := owner.completedError
			owner.mu.Unlock()
			return result
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	cancel()
	if closeErr := owner.server.Close(); closeErr != nil {
		return errors.Join(err, ErrLoginListenerUnavailable)
	}
	return err
}

// String conceals certificate, graph and socket custody.
func (*LoginServer) String() string { return "[REDACTED]" }

// GoString conceals detailed certificate, graph and socket custody.
func (*LoginServer) GoString() string { return "httpapi.LoginServer([REDACTED])" }

// LogValue keeps private serving topology out of process diagnostics.
func (*LoginServer) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental serving profile publication.
func (*LoginServer) MarshalJSON() ([]byte, error) { return nil, ErrInvalidLoginServer }

// String conceals resident PEM and serving configuration.
func (LoginServerOptions) String() string { return "[REDACTED]" }

// GoString conceals detailed resident PEM and serving configuration.
func (LoginServerOptions) GoString() string { return "[REDACTED]" }

// LogValue prevents a profile from entering structured diagnostic output.
func (LoginServerOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses resident PEM/configuration serialization.
func (LoginServerOptions) MarshalJSON() ([]byte, error) { return nil, ErrInvalidLoginServer }
