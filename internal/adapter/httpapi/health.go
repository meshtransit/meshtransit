// Package httpapi implements bounded HTTP adapters for operator and management
// surfaces. The initial slice contains only the operator health surface.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
)

const (
	readHeaderTimeout = 2 * time.Second
	readTimeout       = 5 * time.Second
	writeTimeout      = 5 * time.Second
	idleTimeout       = 30 * time.Second
	maxHeaderBytes    = 8 * 1024
)

var (
	// ErrInvalidHealthServer indicates missing or invalid server dependencies.
	ErrInvalidHealthServer = errors.New("invalid health server")
	// ErrHealthServerStarted indicates that a health server may only be started once.
	ErrHealthServerStarted = errors.New("health server already started")
	// ErrHealthServerNotStarted indicates that shutdown was requested before start.
	ErrHealthServerNotStarted = errors.New("health server not started")
)

// HealthServer owns the operator listener and its serving goroutine.
type HealthServer struct {
	mu       sync.Mutex
	server   *http.Server
	address  string
	listen   func(network, address string) (net.Listener, error)
	done     chan error
	starting bool
	started  bool
}

// NewHealthServer constructs a bounded operator server without opening a listener.
func NewHealthServer(address string, state *app.RuntimeState, logger *slog.Logger) (*HealthServer, error) {
	if address == "" || state == nil || logger == nil {
		return nil, ErrInvalidHealthServer
	}

	handler := newHealthHandler(state, logger)
	return &HealthServer{
		address: address,
		listen:  net.Listen,
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
	}, nil
}

// Start opens the configured listener and starts exactly one owned serving
// goroutine. Done is the corresponding join path.
func (server *HealthServer) Start() error {
	server.mu.Lock()
	if server.started || server.starting {
		server.mu.Unlock()
		return ErrHealthServerStarted
	}
	server.starting = true
	listen := server.listen
	address := server.address
	server.mu.Unlock()

	listener, err := listen("tcp", address)
	if err != nil {
		server.mu.Lock()
		server.starting = false
		server.mu.Unlock()
		return fmt.Errorf("listen for health requests: %w", err)
	}

	server.mu.Lock()
	server.done = make(chan error, 1)
	server.starting = false
	server.started = true
	done := server.done
	server.mu.Unlock()
	go func() {
		err := server.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
		close(done)
	}()
	return nil
}

// Done returns the join channel for the serving goroutine. It is nil until a
// successful Start call.
func (server *HealthServer) Done() <-chan error {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.done
}

// Shutdown drains the HTTP server within ctx. If the deadline expires, it
// force-closes remaining connections so the serving goroutine can still join.
func (server *HealthServer) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidHealthServer
	}

	server.mu.Lock()
	started := server.started
	server.mu.Unlock()
	if !started {
		return ErrHealthServerNotStarted
	}

	shutdownErr := server.server.Shutdown(ctx)
	if shutdownErr == nil {
		return nil
	}
	closeErr := server.server.Close()
	return errors.Join(shutdownErr, closeErr)
}

type healthHandler struct {
	state  *app.RuntimeState
	logger *slog.Logger
	mux    *http.ServeMux
}

func newHealthHandler(state *app.RuntimeState, logger *slog.Logger) *healthHandler {
	handler := &healthHandler{
		state:  state,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	handler.mux.HandleFunc("GET /live", handler.live)
	handler.mux.HandleFunc("GET /ready", handler.ready)
	handler.mux.HandleFunc("GET /health", handler.health)
	return handler
}

func (handler *healthHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.mux.ServeHTTP(response, request)
}

func (handler *healthHandler) live(response http.ResponseWriter, request *http.Request) {
	handler.writeJSON(request.Context(), response, http.StatusOK, map[string]any{
		"status": "live",
	})
}

func (handler *healthHandler) ready(response http.ResponseWriter, request *http.Request) {
	statusCode := http.StatusServiceUnavailable
	status := "not_ready"
	if handler.state.Ready() {
		statusCode = http.StatusOK
		status = "ready"
	}
	handler.writeJSON(request.Context(), response, statusCode, map[string]any{
		"status": status,
		"roles":  handler.state.Roles(),
	})
}

func (handler *healthHandler) health(response http.ResponseWriter, request *http.Request) {
	status := "degraded"
	runtimeStatus := "not_ready"
	if handler.state.Ready() {
		status = "ok"
		runtimeStatus = "ready"
	}
	handler.writeJSON(request.Context(), response, http.StatusOK, map[string]any{
		"status": status,
		"roles":  handler.state.Roles(),
		"components": map[string]string{
			"runtime": runtimeStatus,
		},
	})
}

func (handler *healthHandler) writeJSON(
	ctx context.Context,
	response http.ResponseWriter,
	statusCode int,
	payload map[string]any,
) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	body = append(body, '\n')

	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(statusCode)
	if _, err := response.Write(body); err != nil {
		handler.logger.DebugContext(ctx, "health response write failed", "error", err)
	}
}
