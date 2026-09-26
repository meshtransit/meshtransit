package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

const (
	maximumIdentityConnections    = 4096
	maximumIdentityQueryBytes     = 16 * 1024
	maximumIdentityTokenBodyBytes = 32 * 1024
	identityReadHeaderTimeout     = 5 * time.Second
	identityIdleTimeout           = 60 * time.Second
	identityMaxHeaderBytes        = 16 * 1024
	identityMinimumRequestTimeout = time.Second
	identityMaximumRequestTimeout = 30 * time.Second
	identityFormContentType       = "application/x-www-form-urlencoded"
	identityStrictTransportPolicy = "max-age=31536000"
	identityContentSecurityPolicy = "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
)

var (
	// ErrInvalidIdentityServer conceals rejected graph, certificate and socket input.
	ErrInvalidIdentityServer = errors.New("http api: invalid identity server")
	// ErrIdentityServerStarted reports reuse of a one-shot serving owner.
	ErrIdentityServerStarted = errors.New("http api: identity server already started")
	// ErrIdentityServerNotStarted reports shutdown before a successful start.
	ErrIdentityServerNotStarted = errors.New("http api: identity server not started")
	// ErrIdentityListenerUnavailable conceals socket topology and serving errors.
	ErrIdentityListenerUnavailable = errors.New("http api: identity listener unavailable")
)

// IdentityServerOptions is the private direct-TLS broker serving contract.
// The constructor validates and owns all route, certificate and capacity data
// without opening a socket or reading the clock.
type IdentityServerOptions struct {
	Address               string
	Issuer                string
	CertificatePEM        []byte
	PrivateKeyPEM         []byte
	Handler               http.Handler
	ConnectorIDs          []string
	RequestTimeout        time.Duration
	MaxConnections        int
	MaxConcurrentRequests int
}

type identityRoute struct {
	methods    string
	allowQuery bool
	tokenBody  bool
}

// IdentityServer owns the private broker listener. It exposes only the exact
// OIDC endpoints required by Core and joins all connections before Done.
type IdentityServer struct {
	server       *http.Server
	tlsConfig    *tls.Config
	handler      http.Handler
	routes       map[string]identityRoute
	issuerHost   string
	address      string
	timeout      time.Duration
	connections  int
	concurrency  chan struct{}
	connectionWG sync.WaitGroup

	mu             sync.Mutex
	isAttempted    bool
	isStarting     bool
	isStarted      bool
	isStopping     bool
	completedError error
	startCancel    context.CancelFunc
	requestCancel  context.CancelFunc
	startFinished  chan struct{}
	done           chan error
	joined         chan struct{}
	boundAddress   string
}

// NewIdentityServer validates an immutable private serving profile.
func NewIdentityServer(options IdentityServerOptions) (*IdentityServer, error) {
	address, err := netip.ParseAddrPort(options.Address)
	validAddress := err == nil && address.String() == options.Address &&
		!address.Addr().Is4In6() && address.Addr().Zone() == "" &&
		(address.Addr().IsPrivate() || address.Addr().IsLoopback())
	validCapacity := options.MaxConnections > 0 &&
		options.MaxConnections <= maximumIdentityConnections &&
		options.MaxConcurrentRequests > 0 &&
		options.MaxConcurrentRequests <= options.MaxConnections
	validTimeout := options.RequestTimeout >= identityMinimumRequestTimeout &&
		options.RequestTimeout <= identityMaximumRequestTimeout &&
		options.RequestTimeout%time.Second == 0
	if !validAddress || !validCapacity || !validTimeout || nilHTTPHandler(options.Handler) {
		return nil, ErrInvalidIdentityServer
	}
	issuer, routes, err := identityServerRoutes(options.Issuer, options.ConnectorIDs)
	if err != nil {
		return nil, ErrInvalidIdentityServer
	}
	certificate, err := serverCertificate(
		options.CertificatePEM,
		options.PrivateKeyPEM,
		issuer.Hostname(),
	)
	if err != nil {
		return nil, ErrInvalidIdentityServer
	}
	owner := &IdentityServer{
		handler: options.Handler, routes: routes, issuerHost: issuer.Host,
		address: options.Address, timeout: options.RequestTimeout,
		connections: options.MaxConnections,
		concurrency: make(chan struct{}, options.MaxConcurrentRequests),
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
			NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
		},
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	owner.server = &http.Server{
		Handler: owner, Protocols: protocols, DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout: identityReadHeaderTimeout,
		ReadTimeout:       options.RequestTimeout,
		WriteTimeout:      options.RequestTimeout + identityReadHeaderTimeout,
		IdleTimeout:       identityIdleTimeout,
		MaxHeaderBytes:    identityMaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnState:         owner.connectionState,
	}
	return owner, nil
}

func nilHTTPHandler(handler http.Handler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func identityServerRoutes(issuerValue string, connectorIDs []string) (*url.URL, map[string]identityRoute, error) {
	issuer, err := url.Parse(issuerValue)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.Hostname() == "" ||
		issuer.Opaque != "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" ||
		issuer.RawPath != "" || issuer.Path == "/" || strings.HasSuffix(issuer.Path, "/") ||
		(issuer.Path != "" && path.Clean(issuer.Path) != issuer.Path) || issuer.String() != issuerValue {
		return nil, nil, ErrInvalidIdentityServer
	}
	if len(connectorIDs) == 0 || len(connectorIDs) > 32 {
		return nil, nil, ErrInvalidIdentityServer
	}
	prefix := issuer.Path
	routes := map[string]identityRoute{
		prefix + "/.well-known/openid-configuration": {methods: http.MethodGet + ", " + http.MethodHead},
		prefix + "/auth":     {methods: http.MethodGet, allowQuery: true},
		prefix + "/callback": {methods: http.MethodGet, allowQuery: true},
		prefix + "/token":    {methods: http.MethodPost, tokenBody: true},
		prefix + "/keys":     {methods: http.MethodGet + ", " + http.MethodHead},
	}
	for _, connectorID := range connectorIDs {
		if !validIdentityConnectorID(connectorID) {
			return nil, nil, ErrInvalidIdentityServer
		}
		connectorPath := prefix + "/auth/" + connectorID
		if _, exists := routes[connectorPath]; exists {
			return nil, nil, ErrInvalidIdentityServer
		}
		routes[connectorPath] = identityRoute{methods: http.MethodGet, allowQuery: true}
	}
	return issuer, routes, nil
}

func validIdentityConnectorID(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		isLower := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if !isLower && !isDigit && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

// Start performs one cancellable bind after checking actual certificate time.
func (owner *IdentityServer) Start(ctx context.Context) error {
	if owner == nil || owner.server == nil || ctx == nil {
		return ErrInvalidIdentityServer
	}
	owner.mu.Lock()
	if owner.isAttempted || owner.isStopping {
		owner.mu.Unlock()
		return ErrIdentityServerStarted
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
		return ErrInvalidIdentityServer
	}
	listener, err := (&net.ListenConfig{}).Listen(startCtx, "tcp", owner.address)
	if err != nil {
		if startCtx.Err() != nil {
			return startCtx.Err()
		}
		return ErrIdentityListenerUnavailable
	}
	owner.mu.Lock()
	if owner.isStopping || startCtx.Err() != nil {
		owner.mu.Unlock()
		if err := listener.Close(); err != nil {
			return errors.Join(context.Canceled, ErrIdentityListenerUnavailable)
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

func (owner *IdentityServer) finishStart() {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.isStarting = false
	owner.startCancel = nil
	close(owner.startFinished)
}

func (owner *IdentityServer) serve(listener net.Listener) {
	err := owner.server.Serve(listener)
	var result error
	if !errors.Is(err, http.ErrServerClosed) {
		result = ErrIdentityListenerUnavailable
		owner.mu.Lock()
		owner.isStopping = true
		owner.mu.Unlock()
		owner.requestCancel()
		if err := owner.server.Close(); err != nil {
			result = errors.Join(result, ErrIdentityListenerUnavailable)
		}
	}
	owner.connectionWG.Wait()
	owner.requestCancel()
	owner.mu.Lock()
	owner.completedError = result
	owner.mu.Unlock()
	owner.done <- result
	close(owner.done)
	close(owner.joined)
}

func (owner *IdentityServer) connectionState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		owner.connectionWG.Add(1)
	case http.StateClosed:
		owner.connectionWG.Done()
	}
}

// ServeHTTP applies the fixed private route and transport policy before Dex.
func (owner *IdentityServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	secured := &identityResponseWriter{ResponseWriter: response}
	secured.apply()
	if owner == nil || request == nil || request.URL == nil || request.TLS == nil ||
		request.Host != owner.issuerHost || request.URL.IsAbs() || request.URL.Host != "" ||
		request.URL.Opaque != "" || request.URL.RawPath != "" ||
		request.URL.EscapedPath() != request.URL.Path || request.URL.ForceQuery ||
		len(request.URL.RawQuery) > maximumIdentityQueryBytes {
		http.Error(secured, "not found", http.StatusNotFound)
		return
	}
	route, exists := owner.routes[request.URL.Path]
	if !exists {
		http.Error(secured, "not found", http.StatusNotFound)
		return
	}
	if !identityMethodAllowed(route.methods, request.Method) {
		secured.Header().Set("Allow", route.methods)
		http.Error(secured, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !route.allowQuery && request.URL.RawQuery != "" {
		http.Error(secured, "bad request", http.StatusBadRequest)
		return
	}
	if !route.tokenBody && (request.ContentLength != 0 || len(request.TransferEncoding) != 0) {
		http.Error(secured, "bad request", http.StatusBadRequest)
		return
	}
	if route.tokenBody {
		mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != identityFormContentType || len(parameters) != 0 {
			http.Error(secured, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		if request.ContentLength > maximumIdentityTokenBodyBytes {
			http.Error(secured, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		request.Body = http.MaxBytesReader(secured, request.Body, maximumIdentityTokenBodyBytes)
	}
	stripIdentityForwardingHeaders(request.Header)
	select {
	case owner.concurrency <- struct{}{}:
		defer func() { <-owner.concurrency }()
	default:
		secured.Header().Set("Retry-After", "1")
		http.Error(secured, "too many requests", http.StatusTooManyRequests)
		return
	}
	requestCtx, cancel := context.WithTimeout(request.Context(), owner.timeout)
	defer cancel()
	owner.handler.ServeHTTP(secured, request.WithContext(requestCtx))
}

func identityMethodAllowed(methods, method string) bool {
	if methods == method {
		return true
	}
	return methods == http.MethodGet+", "+http.MethodHead &&
		(method == http.MethodGet || method == http.MethodHead)
}

func stripIdentityForwardingHeaders(header http.Header) {
	for name := range header {
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "x-original-url" || lower == "x-rewrite-url" ||
			lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") ||
			strings.HasPrefix(lower, "x-remote-") {
			header.Del(name)
		}
	}
}

type identityResponseWriter struct {
	http.ResponseWriter
}

func (writer *identityResponseWriter) WriteHeader(statusCode int) {
	writer.apply()
	writer.ResponseWriter.WriteHeader(statusCode)
}

func (writer *identityResponseWriter) Write(contents []byte) (int, error) {
	writer.apply()
	return writer.ResponseWriter.Write(contents)
}

func (writer *identityResponseWriter) apply() {
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy", identityContentSecurityPolicy)
	header.Set("Strict-Transport-Security", identityStrictTransportPolicy)
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
}

// Done reports only after the listener, connections and handlers have joined.
func (owner *IdentityServer) Done() <-chan error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.done
}

// Shutdown stops admission, drains requests, then force-closes on expiry.
func (owner *IdentityServer) Shutdown(ctx context.Context) error {
	if owner == nil || owner.server == nil || ctx == nil {
		return ErrInvalidIdentityServer
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
		return ErrIdentityServerNotStarted
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
		return errors.Join(err, ErrIdentityListenerUnavailable)
	}
	return err
}

// String conceals certificate, route graph and socket custody.
func (*IdentityServer) String() string { return "[REDACTED]" }

// GoString conceals detailed identity listener state.
func (*IdentityServer) GoString() string { return "httpapi.IdentityServer([REDACTED])" }

// LogValue keeps private serving topology out of diagnostics.
func (*IdentityServer) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental serving profile publication.
func (*IdentityServer) MarshalJSON() ([]byte, error) { return nil, ErrInvalidIdentityServer }

// String conceals resident PEM and serving configuration.
func (IdentityServerOptions) String() string { return "[REDACTED]" }

// GoString conceals detailed resident PEM and serving configuration.
func (IdentityServerOptions) GoString() string { return "[REDACTED]" }

// LogValue prevents a profile from entering structured diagnostics.
func (IdentityServerOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses resident PEM/configuration serialization.
func (IdentityServerOptions) MarshalJSON() ([]byte, error) { return nil, ErrInvalidIdentityServer }
