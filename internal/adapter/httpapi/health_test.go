package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
)

func TestHealthHandlerReportsLifecycleState(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleAPI)
	handler := newHealthHandler(state, discardLogger())

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{name: "live before readiness", path: "/live", wantStatus: http.StatusOK, wantBody: "live"},
		{name: "not ready before admission", path: "/ready", wantStatus: http.StatusServiceUnavailable, wantBody: "not_ready"},
		{name: "degraded summary before admission", path: "/health", wantStatus: http.StatusOK, wantBody: "degraded"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			response := request(t, handler, test.path)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if got := responseJSONField(t, response, "status"); got != test.wantBody {
				t.Fatalf("body status = %v, want %s", got, test.wantBody)
			}
		})
	}
}

func TestHealthHandlerReportsReady(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleControl)
	state.SetReady(true)
	handler := newHealthHandler(state, discardLogger())

	response := request(t, handler, "/ready")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := responseJSONField(t, response, "status"); got != "ready" {
		t.Fatalf("body status = %v, want ready", got)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
}

func TestHealthServerStartsAndJoinsOwnedGoroutine(t *testing.T) {
	t.Parallel()

	server, err := NewHealthServer(
		"127.0.0.1:0",
		newRuntimeState(t, app.RoleWorker),
		discardLogger(),
	)
	if err != nil {
		t.Fatalf("NewHealthServer() error = %v", err)
	}
	listener := newBlockingListener()
	server.listen = func(_, _ string) (net.Listener, error) {
		return listener, nil
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := server.Start(); !errors.Is(err, ErrHealthServerStarted) {
		t.Fatalf("second Start() error = %v, want ErrHealthServerStarted", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	select {
	case err := <-server.Done():
		if err != nil {
			t.Fatalf("Done() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("serving goroutine did not join")
	}
}

func request(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func responseJSONField(t *testing.T, response *httptest.ResponseRecorder, field string) any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return body[field]
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func newRuntimeState(t *testing.T, roles ...app.Role) *app.RuntimeState {
	t.Helper()

	state, err := app.NewRuntimeState(roles)
	if err != nil {
		t.Fatalf("app.NewRuntimeState() error = %v", err)
	}
	return state
}

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (listener *blockingListener) Accept() (net.Conn, error) {
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *blockingListener) Close() error {
	listener.once.Do(func() {
		close(listener.closed)
	})
	return nil
}

func (listener *blockingListener) Addr() net.Addr {
	return testAddress("health-test")
}

type testAddress string

func (address testAddress) Network() string {
	return "tcp"
}

func (address testAddress) String() string {
	return string(address)
}
