// Package httpapi implements bounded HTTP adapters for operator and management surfaces.
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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/core/internal/domain/network/revisionworker"
	"github.com/meshtransit/meshtransit/core/internal/platform/app"
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
	mu          sync.Mutex
	server      *http.Server
	address     string
	listen      func(context.Context, string, string) (net.Listener, error)
	done        chan error
	starting    bool
	started     bool
	stopping    bool
	startCancel context.CancelFunc
	startDone   chan struct{}
}

// HealthServerOptions contains the validated dependencies for one operator server.
type HealthServerOptions struct {
	Address                 string
	State                   *app.RuntimeState
	Logger                  *slog.Logger
	Build                   BuildInfo
	RevisionWorkerTelemetry *revisionworker.Telemetry
	AdditionalMetrics       []prometheus.Collector
}

// NewHealthServer constructs a bounded operator server without opening a listener.
func NewHealthServer(options HealthServerOptions) (*HealthServer, error) {
	if options.Address == "" || options.State == nil || options.Logger == nil {
		return nil, ErrInvalidHealthServer
	}
	metrics, err := newOperatorMetrics(
		options.State,
		options.Build,
		options.RevisionWorkerTelemetry,
		options.AdditionalMetrics...,
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidHealthServer, err)
	}

	handler := newHealthHandler(options.State, options.Logger, metrics)
	listenConfig := &net.ListenConfig{}
	return &HealthServer{
		address: options.Address,
		listen:  listenConfig.Listen,
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
func (server *HealthServer) Start(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidHealthServer
	}

	server.mu.Lock()
	if server.started || server.starting || server.stopping {
		server.mu.Unlock()
		return ErrHealthServerStarted
	}
	startCtx, startCancel := context.WithCancel(ctx)
	startDone := make(chan struct{})
	server.starting = true
	server.startCancel = startCancel
	server.startDone = startDone
	listen := server.listen
	address := server.address
	server.mu.Unlock()

	listener, err := listen(startCtx, "tcp", address)
	if err != nil {
		startCancel()
		server.mu.Lock()
		stopping := server.stopping
		server.starting = false
		server.startCancel = nil
		server.startDone = nil
		close(startDone)
		server.mu.Unlock()
		if stopping || errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		return fmt.Errorf("listen for health requests: %w", err)
	}

	server.mu.Lock()
	if server.stopping || startCtx.Err() != nil {
		server.starting = false
		server.startCancel = nil
		server.startDone = nil
		server.mu.Unlock()
		closeErr := listener.Close()
		startCancel()
		close(startDone)
		return errors.Join(context.Canceled, closeErr)
	}
	server.done = make(chan error, 1)
	server.starting = false
	server.started = true
	server.startCancel = nil
	server.startDone = nil
	done := server.done
	go func() {
		err := server.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
		close(done)
	}()
	close(startDone)
	server.mu.Unlock()
	startCancel()
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
		return ErrHealthServerNotStarted
	}

	shutdownErr := server.server.Shutdown(ctx)
	if shutdownErr == nil {
		return nil
	}
	closeErr := server.server.Close()
	return errors.Join(shutdownErr, closeErr)
}

type healthState interface {
	Snapshot() app.HealthSnapshot
}

type healthHandler struct {
	state  healthState
	logger *slog.Logger
	mux    *http.ServeMux
}

func newHealthHandler(state healthState, logger *slog.Logger, metrics *operatorMetrics) http.Handler {
	handler := &healthHandler{
		state:  state,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	handler.mux.HandleFunc("GET /live", handler.live)
	handler.mux.HandleFunc("GET /ready", handler.ready)
	handler.mux.HandleFunc("GET /ready/login", handler.loginReady)
	handler.mux.HandleFunc("GET /health", handler.health)
	handler.mux.Handle("GET /metrics", metrics.handler)
	return metrics.instrument(handler)
}

func (handler *healthHandler) loginReady(response http.ResponseWriter, request *http.Request) {
	snapshot := handler.state.Snapshot()
	statusCode := http.StatusServiceUnavailable
	status := "not_ready"
	if !snapshot.LoginConfigured {
		statusCode = http.StatusNotFound
		status = "not_configured"
	} else if snapshot.LoginReady {
		statusCode = http.StatusOK
		status = "ready"
	}
	handler.writeJSON(request.Context(), response, statusCode, map[string]any{
		"status":     status,
		"roles":      snapshot.Roles,
		"components": snapshot.Components,
	})
}

func (handler *healthHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	handler.mux.ServeHTTP(response, request)
}

func (handler *healthHandler) live(response http.ResponseWriter, request *http.Request) {
	handler.writeJSON(request.Context(), response, http.StatusOK, map[string]any{
		"status": "live",
	})
}

func (handler *healthHandler) ready(response http.ResponseWriter, request *http.Request) {
	snapshot := handler.state.Snapshot()
	statusCode := http.StatusServiceUnavailable
	status := "not_ready"
	if snapshot.Ready {
		statusCode = http.StatusOK
		status = "ready"
	}
	handler.writeJSON(request.Context(), response, statusCode, map[string]any{
		"status":     status,
		"roles":      snapshot.Roles,
		"components": snapshot.Components,
	})
}

func (handler *healthHandler) health(response http.ResponseWriter, request *http.Request) {
	snapshot := handler.state.Snapshot()
	status := "degraded"
	runtimeStatus := "not_ready"
	if snapshot.Ready {
		status = "ok"
		runtimeStatus = "ready"
	}
	for _, componentStatus := range snapshot.Components {
		if componentStatus != "ready" {
			status = "degraded"
			break
		}
	}
	components := make(map[string]string, len(snapshot.Components)+1)
	components["runtime"] = runtimeStatus
	for component, componentStatus := range snapshot.Components {
		components[component] = componentStatus
	}
	handler.writeJSON(request.Context(), response, http.StatusOK, map[string]any{
		"status":     status,
		"roles":      snapshot.Roles,
		"components": components,
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
