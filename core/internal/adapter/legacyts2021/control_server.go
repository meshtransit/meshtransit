package legacyts2021

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"meshtransit.net/core/internal/control"
)

const (
	controlKeyPath           = "/key"
	noiseUpgradePath         = "/ts2021"
	maxControlHeaderBytes    = 32 << 10
	minControlTimeout        = 100 * time.Millisecond
	maxControlHandshake      = 30 * time.Second
	maxControlSessionTimeout = 5 * time.Minute
	maxControlSessions       = 4096
	maxControlSessionStreams = 64
)

var (
	// ErrInvalidControlServer reports missing dependencies or unsafe resource bounds.
	ErrInvalidControlServer = errors.New("legacyts2021: invalid control server")
	// ErrControlServerShutdown classifies an incomplete bounded session shutdown.
	ErrControlServerShutdown = errors.New("legacyts2021: control server shutdown failed")
)

// AuthenticatedHandlerFactory binds application handlers to the machine
// identity proven by one Noise session.
type AuthenticatedHandlerFactory interface {
	Handler(control.AuthenticatedMachine) (http.Handler, error)
}

// ControlServerOptions contains immutable trust-boundary dependencies and
// resource limits.
type ControlServerOptions struct {
	PrivateKey           ControlPrivateKey
	Sessions             AuthenticatedHandlerFactory
	Logger               *slog.Logger
	Telemetry            *ControlTelemetry
	MaxSessions          int
	MaxConcurrentStreams uint32
	HandshakeTimeout     time.Duration
	ReadIdleTimeout      time.Duration
	PingTimeout          time.Duration
	WriteTimeout         time.Duration
}

// ControlServer serves public key discovery and authenticated HTTP/2 sessions.
// It starts no goroutines. The enclosing HTTP server owns calls to ServeHTTP;
// Shutdown closes and joins every hijacked connection tracked by this server.
type ControlServer struct {
	privateKey       ControlPrivateKey
	publicKey        string
	sessions         AuthenticatedHandlerFactory
	logger           *slog.Logger
	telemetry        *ControlTelemetry
	handshakeTimeout time.Duration
	http2Server      *http2.Server
	slots            chan struct{}

	mu          sync.Mutex
	closing     bool
	active      int
	connections map[net.Conn]struct{}
	drained     chan struct{}
}

// NewControlServer validates and constructs the legacy trust boundary.
func NewControlServer(options ControlServerOptions) (*ControlServer, error) {
	if !validControlServerOptions(options) {
		return nil, ErrInvalidControlServer
	}
	publicKey, err := options.PrivateKey.value.Public().MarshalText()
	if err != nil || len(publicKey) == 0 {
		return nil, ErrInvalidControlServer
	}
	drained := make(chan struct{})
	close(drained)
	server := &ControlServer{
		privateKey:       options.PrivateKey,
		publicKey:        string(publicKey),
		sessions:         options.Sessions,
		logger:           options.Logger,
		telemetry:        options.Telemetry,
		handshakeTimeout: options.HandshakeTimeout,
		http2Server: &http2.Server{
			MaxConcurrentStreams:         options.MaxConcurrentStreams,
			MaxDecoderHeaderTableSize:    4096,
			MaxEncoderHeaderTableSize:    4096,
			MaxReadFrameSize:             1 << 20,
			ReadIdleTimeout:              options.ReadIdleTimeout,
			PingTimeout:                  options.PingTimeout,
			WriteByteTimeout:             options.WriteTimeout,
			MaxUploadBufferPerConnection: 1 << 20,
			MaxUploadBufferPerStream:     256 << 10,
		},
		slots:       make(chan struct{}, options.MaxSessions),
		connections: make(map[net.Conn]struct{}, options.MaxSessions),
		drained:     drained,
	}
	clear(publicKey)
	return server, nil
}

// ServeHTTP exposes only the pinned key-discovery and Noise-upgrade paths.
func (server *ControlServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if server == nil || response == nil || request == nil || request.URL == nil {
		if response != nil {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		}
		return
	}
	if server.isClosing() {
		if request.URL.Path == noiseUpgradePath {
			server.telemetry.recordSessionAttempt(sessionAttemptShutdown)
		}
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	switch request.URL.Path {
	case controlKeyPath:
		server.serveControlKey(response, request)
	case noiseUpgradePath:
		server.serveNoiseUpgrade(response, request)
	default:
		http.NotFound(response, request)
	}
}

func validControlServerOptions(options ControlServerOptions) bool {
	return options.PrivateKey.IsValid() && options.Sessions != nil && options.Logger != nil &&
		options.Telemetry != nil && options.Telemetry.sessionCapacity == options.MaxSessions &&
		options.MaxSessions > 0 && options.MaxSessions <= maxControlSessions &&
		options.MaxConcurrentStreams > 0 &&
		options.MaxConcurrentStreams <= maxControlSessionStreams &&
		options.HandshakeTimeout >= minControlTimeout &&
		options.HandshakeTimeout <= maxControlHandshake &&
		options.ReadIdleTimeout >= minControlTimeout &&
		options.ReadIdleTimeout <= maxControlSessionTimeout &&
		options.PingTimeout >= minControlTimeout &&
		options.PingTimeout <= options.ReadIdleTimeout &&
		options.WriteTimeout >= minControlTimeout &&
		options.WriteTimeout <= maxControlSessionTimeout
}
