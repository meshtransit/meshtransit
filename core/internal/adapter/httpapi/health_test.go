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
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/platform/app"
)

func TestHealthHandlerReportsLifecycleState(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleAPI)
	handler := newTestHealthHandler(t, state)

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
	handler := newTestHealthHandler(t, state)

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

func TestHealthHandlerReportsIsolatedLoginReadiness(t *testing.T) {
	t.Parallel()

	state, err := app.NewRuntimeState([]app.Role{app.RoleAPI}, app.ComponentPrivateLogin)
	if err != nil {
		t.Fatal(err)
	}
	state.SetReady(true)
	if err := state.SetComponentStatuses(map[app.Component]app.ComponentStatus{
		app.ComponentPostgreSQL: app.ComponentStatusReady,
		app.ComponentRedis:      app.ComponentStatusReady,
	}); err != nil {
		t.Fatal(err)
	}
	handler := newTestHealthHandler(t, state)

	if response := request(t, handler, "/ready"); response.Code != http.StatusOK {
		t.Fatalf("GET /ready status = %d, want %d", response.Code, http.StatusOK)
	}
	response := request(t, handler, "/ready/login")
	if response.Code != http.StatusServiceUnavailable ||
		responseJSONField(t, response, "status") != "not_ready" {
		t.Fatalf("GET /ready/login = %d %s", response.Code, response.Body.String())
	}
	response = request(t, handler, "/health")
	if response.Code != http.StatusOK || responseJSONField(t, response, "status") != "degraded" {
		t.Fatalf("GET /health = %d %s", response.Code, response.Body.String())
	}

	if err := state.SetComponentStatus(app.ComponentPrivateLogin, app.ComponentStatusReady); err != nil {
		t.Fatal(err)
	}
	response = request(t, handler, "/ready/login")
	if response.Code != http.StatusOK || responseJSONField(t, response, "status") != "ready" {
		t.Fatalf("GET /ready/login = %d %s", response.Code, response.Body.String())
	}
}

func TestHealthHandlerReportsLoginReadinessNotConfigured(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleAPI)
	state.SetReady(true)
	response := request(t, newTestHealthHandler(t, state), "/ready/login")
	if response.Code != http.StatusNotFound ||
		responseJSONField(t, response, "status") != "not_configured" {
		t.Fatalf("GET /ready/login = %d %s", response.Code, response.Body.String())
	}
}

func TestHealthHandlerReportsDegradedIdentityWithoutEvictingCore(t *testing.T) {
	t.Parallel()

	state, err := app.NewRuntimeState([]app.Role{
		app.RoleAPI,
		app.RoleControl,
		app.RoleWorker,
		app.RoleRelay,
		app.RoleIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	state.SetReady(true)
	if err := state.SetComponentStatuses(map[app.Component]app.ComponentStatus{
		app.ComponentPostgreSQL:            app.ComponentStatusReady,
		app.ComponentRedis:                 app.ComponentStatusReady,
		app.ComponentIdentityPostgreSQL:    app.ComponentStatusUnavailable,
		app.ComponentIdentityConfiguration: app.ComponentStatusUnavailable,
		app.ComponentIdentitySigner:        app.ComponentStatusUnavailable,
	}); err != nil {
		t.Fatal(err)
	}
	handler := newTestHealthHandler(t, state)
	if response := request(t, handler, "/ready"); response.Code != http.StatusOK {
		t.Fatalf("GET /ready status = %d, want %d", response.Code, http.StatusOK)
	}
	response := request(t, handler, "/health")
	if response.Code != http.StatusOK || responseJSONField(t, response, "status") != "degraded" {
		t.Fatalf("GET /health = %d %s", response.Code, response.Body.String())
	}
}

func TestHealthHandlerReportsRedactedDependencyStatus(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleAPI)
	state.SetReady(true)
	if err := state.SetComponentStatus(app.ComponentRedis, app.ComponentStatusUnavailable); err != nil {
		t.Fatalf("SetComponentStatus() error = %v", err)
	}
	handler := newTestHealthHandler(t, state)

	response := request(t, handler, "/ready")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if got := responseJSONField(t, response, "components"); !reflect.DeepEqual(got, map[string]any{
		"postgresql": "ready",
		"redis":      "unavailable",
	}) {
		t.Fatalf("components = %v, want stable redacted statuses", got)
	}
	if strings.Contains(response.Body.String(), "error") || strings.Contains(response.Body.String(), "address") {
		t.Fatalf("health response exposed internal detail: %s", response.Body.String())
	}
}

func TestHealthServerStartsAndJoinsOwnedGoroutine(t *testing.T) {
	t.Parallel()

	server, err := NewHealthServer(HealthServerOptions{
		Address: "127.0.0.1:0",
		State:   newRuntimeState(t, app.RoleWorker),
		Logger:  discardLogger(),
		Build:   testBuildInfo(),
	})
	if err != nil {
		t.Fatalf("NewHealthServer() error = %v", err)
	}
	listener := newBlockingListener()
	server.listen = func(context.Context, string, string) (net.Listener, error) {
		return listener, nil
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := server.Start(t.Context()); !errors.Is(err, ErrHealthServerStarted) {
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

func TestHealthServerShutdownDuringStartPreventsLateListener(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		server, err := NewHealthServer(HealthServerOptions{
			Address: "127.0.0.1:0",
			State:   newRuntimeState(t, app.RoleRelay),
			Logger:  discardLogger(),
			Build:   testBuildInfo(),
		})
		if err != nil {
			t.Fatalf("NewHealthServer() error = %v", err)
		}

		listenStarted := make(chan struct{})
		releaseListen := make(chan struct{})
		listener := newBlockingListener()
		server.listen = func(_ context.Context, _, _ string) (net.Listener, error) {
			close(listenStarted)
			<-releaseListen
			return listener, nil
		}

		startResult := make(chan error, 1)
		go func() {
			startResult <- server.Start(t.Context())
		}()
		<-listenStarted

		shutdownResult := make(chan error, 1)
		go func() {
			shutdownResult <- server.Shutdown(t.Context())
		}()
		synctest.Wait()
		earlyShutdown := false
		var earlyShutdownErr error
		select {
		case shutdownErr := <-shutdownResult:
			earlyShutdown = true
			earlyShutdownErr = shutdownErr
		default:
		}

		close(releaseListen)
		synctest.Wait()
		if earlyShutdown {
			startErr := <-startResult
			if startErr == nil {
				if cleanupErr := server.Shutdown(t.Context()); cleanupErr != nil {
					t.Fatalf("cleanup Shutdown() error = %v", cleanupErr)
				}
				<-server.Done()
			}
			t.Fatalf("Shutdown() returned before startup settled: %v", earlyShutdownErr)
		}
		if err := <-shutdownResult; err != nil {
			t.Fatalf("Shutdown() error = %v, want nil", err)
		}
		if err := <-startResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() error = %v, want context canceled", err)
		}
		select {
		case <-listener.closed:
		default:
			t.Fatal("listener remained open after shutdown canceled startup")
		}
		if server.Done() != nil {
			t.Fatal("Done() != nil after shutdown canceled startup")
		}
	})
}

func TestHealthServerStartPropagatesCancellation(t *testing.T) {
	t.Parallel()

	server, err := NewHealthServer(HealthServerOptions{
		Address: "127.0.0.1:0",
		State:   newRuntimeState(t, app.RoleRelay),
		Logger:  discardLogger(),
		Build:   testBuildInfo(),
	})
	if err != nil {
		t.Fatalf("NewHealthServer() error = %v", err)
	}
	server.listen = func(ctx context.Context, _, _ string) (net.Listener, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := server.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context canceled", err)
	}
	if server.Done() != nil {
		t.Fatal("Done() != nil after canceled startup")
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

func newTestHealthHandler(t *testing.T, state *app.RuntimeState) http.Handler {
	t.Helper()

	metrics, err := newOperatorMetrics(state, testBuildInfo(), nil)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	return newHealthHandler(state, discardLogger(), metrics)
}

func newRuntimeState(t *testing.T, roles ...app.Role) *app.RuntimeState {
	t.Helper()

	state, err := app.NewRuntimeState(roles)
	if err != nil {
		t.Fatalf("app.NewRuntimeState() error = %v", err)
	}
	for _, component := range state.RequiredComponents() {
		if err := state.SetComponentStatus(component, app.ComponentStatusReady); err != nil {
			t.Fatalf("SetComponentStatus(%s) error = %v", component, err)
		}
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
