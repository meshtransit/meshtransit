// Package probe answers the captive portal probe of clients that use an
// exit node (exit node design §17.3): GET /generate_204 on plain HTTP, by the
// relay's IP address, answered 204 with the client's nonce echoed, so a
// network that intercepts port 80, or fakes the answer, is told apart from
// one that reaches the Internet.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"

	"meshtransit.net/relay/internal/ratelimit"
)

// Path is the probe's path, and NonceHeader the response header that echoes
// its nonce query parameter.
const (
	Path        = "/generate_204"
	NonceHeader = "Meshtransit-Probe-Nonce"
)

// Probes a second, and in a burst, the relay answers before it refuses with
// 429: a probe is sent at most every 15 seconds by a client behind a portal.
const (
	probesPerSecond = 200
	probeBurst      = 400
)

// nonce is what a client may send: 16 to 64 lowercase hexadecimal digits.
var nonce = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// Metrics counts probe outcomes.
type Metrics func(result string)

// Handler answers the probe and nothing else.
func Handler(metrics Metrics) http.Handler {
	limit := ratelimit.NewShared(probesPerSecond, probeBurst)
	count := func(result string) {
		if metrics != nil {
			metrics(result)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case r.URL.Path != Path:
			count("not_found")
			http.NotFound(w, r)
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			count("method")
			w.WriteHeader(http.StatusMethodNotAllowed)
		case !limit.Allow(time.Now()):
			count("limited")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			if value := r.URL.Query().Get("n"); nonce.MatchString(value) {
				w.Header().Set(NonceHeader, value)
			}
			count("ok")
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

// Server serves the probe on its own listener.
type Server struct {
	server   *http.Server
	listener net.Listener
}

// Listen binds the probe's listener on addr.
func Listen(ctx context.Context, addr string, metrics Metrics) (*Server, error) {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("probe listen %s: %w", addr, err)
	}
	return &Server{
		server: &http.Server{
			Handler:           Handler(metrics),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    4 << 10,
		},
		listener: listener,
	}, nil
}

// Serve serves until Shutdown.
func (s *Server) Serve() error {
	if err := s.server.Serve(s.listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) error { return s.server.Shutdown(ctx) }

// Addr is where the probe listens.
func (s *Server) Addr() net.Addr { return s.listener.Addr() }
