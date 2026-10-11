// Package profile serves Go runtime profiles (pprof) for operators on a
// loopback address. It is off unless MESHTRANSIT_PROFILE_ADDRESS is set,
// and config refuses any non-loopback address.
package profile

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/pprof"
	"sync"
	"time"
)

// ErrInvalidServer reports a missing address or a second Start.
var ErrInvalidServer = errors.New("profile: invalid server")

// Server is an app.Service serving /debug/pprof/ on its own mux.
type Server struct {
	address string
	server  *http.Server

	mu   sync.Mutex
	done chan error
}

// NewServer constructs a stopped profile server.
func NewServer(address string) (*Server, error) {
	if address == "" {
		return nil, ErrInvalidServer
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &Server{address: address, server: &http.Server{
		Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		// A CPU profile or trace streams for its requested duration.
		WriteTimeout: 2 * time.Minute,
	}}, nil
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
	server.done = make(chan error, 1)
	go func() {
		err := server.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		server.done <- err
		close(server.done)
	}()
	return nil
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
	if err := server.server.Shutdown(ctx); err != nil {
		return errors.Join(err, server.server.Close())
	}
	return nil
}
