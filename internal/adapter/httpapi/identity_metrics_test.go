package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/meshtransit/meshtransit/internal/app"
)

func TestIdentityServerMetricsExposeBoundedResourceSignals(t *testing.T) {
	t.Parallel()

	entered, release := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		response.WriteHeader(http.StatusNoContent)
	})
	options := identityServerTestOptions(t, handler)
	options.MaxConnections = 7
	options.MaxConcurrentRequests = 1
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal(err)
	}
	collector := server.MetricsCollector()
	if collector == nil {
		t.Fatal("identity listener returned no metrics collector")
	}

	firstResponse := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		server.ServeHTTP(
			firstResponse,
			identityServerTestRequest(t, http.MethodGet, "/oauth2/auth/google-v1", nil),
		)
		close(firstDone)
	}()
	<-entered

	secondResponse := httptest.NewRecorder()
	server.ServeHTTP(
		secondResponse,
		identityServerTestRequest(t, http.MethodGet, "/oauth2/auth/google-v1", nil),
	)
	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("saturated status = %d, want %d", secondResponse.Code, http.StatusTooManyRequests)
	}
	during := gatherIdentityMetrics(t, collector)
	for name, value := range map[string]string{
		"connection limit":  `meshtransit_identity_connections_limit 7`,
		"request limit":     `meshtransit_identity_requests_limit 1`,
		"active request":    `meshtransit_identity_requests_active 1`,
		"saturation":        `meshtransit_identity_saturation_total 1`,
		"bounded rejection": `meshtransit_identity_requests_total{route="connector",status="4xx"} 1`,
	} {
		if !strings.Contains(during, value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}

	close(release)
	<-firstDone
	if firstResponse.Code != http.StatusNoContent {
		t.Fatalf("first status = %d, want %d", firstResponse.Code, http.StatusNoContent)
	}
	after := gatherIdentityMetrics(t, collector)
	for name, value := range map[string]string{
		"closed request": `meshtransit_identity_requests_active 0`,
		"success":        `meshtransit_identity_requests_total{route="connector",status="2xx"} 1`,
		"duration count": `meshtransit_identity_request_duration_seconds_count{route="connector"} 2`,
	} {
		if !strings.Contains(after, value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
	if strings.Contains(after, "google-v1") || strings.Contains(after, "id.example.test") {
		t.Fatalf("identity metrics disclosed connector or host: %s", after)
	}
}

func TestIdentityServerMetricsTrackConnectionsWithoutIdentityLabels(t *testing.T) {
	t.Parallel()

	server, err := NewIdentityServer(identityServerTestOptions(t, http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}
	server.connectionState(nil, http.StateNew)
	opened := gatherIdentityMetrics(t, server.MetricsCollector())
	if !strings.Contains(opened, `meshtransit_identity_connections_active 1`) {
		t.Fatalf("opened connection metric missing: %s", opened)
	}
	server.connectionState(nil, http.StateClosed)
	closed := gatherIdentityMetrics(t, server.MetricsCollector())
	if !strings.Contains(closed, `meshtransit_identity_connections_active 0`) {
		t.Fatalf("closed connection metric missing: %s", closed)
	}
}

func TestIdentityServerMetricsCollectorRejectsUninitializedOwner(t *testing.T) {
	t.Parallel()

	if collector := (*IdentityServer)(nil).MetricsCollector(); collector != nil {
		t.Fatalf("nil listener collector = %v, want nil", collector)
	}
	if collector := (&IdentityServer{}).MetricsCollector(); collector != nil {
		t.Fatalf("uninitialized listener collector = %v, want nil", collector)
	}
}

func TestOperatorMetricsRegistersIdentityResourceCollector(t *testing.T) {
	t.Parallel()

	server, err := NewIdentityServer(identityServerTestOptions(t, http.NotFoundHandler()))
	if err != nil {
		t.Fatal(err)
	}
	state := newRuntimeState(t, app.RoleIdentity)
	state.SetReady(true)
	metrics, err := newOperatorMetrics(state, testBuildInfo(), nil, server.MetricsCollector())
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	response := request(t, metrics.handler, "/metrics")
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `meshtransit_identity_connections_limit 8`) ||
		!strings.Contains(response.Body.String(), `meshtransit_identity_requests_limit 4`) {
		t.Fatalf("operator metrics omitted identity resource limits: %s", response.Body.String())
	}
}

func gatherIdentityMetrics(t testing.TB, collector prometheus.Collector) string {
	t.Helper()
	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	return response.Body.String()
}
