package redis

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
)

func TestClientMetricsTrackCommandsPoolAndSubscriptionLifecycle(t *testing.T) {
	t.Parallel()

	poolStats := &redisclient.PoolStats{
		Timeouts:        4,
		TotalConns:      8,
		IdleConns:       3,
		PendingRequests: 2,
	}
	metrics := newRedisMetrics(10, func() *redisclient.PoolStats {
		return poolStats
	})
	wakeup, err := network.NewRevisionAdvanced(testNetworkPublicID, 42)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	payload, err := encodeRevisionWakeup(wakeup)
	if err != nil {
		t.Fatalf("encodeRevisionWakeup() error = %v", err)
	}
	transport := &fakeMessageSubscription{message: &redisclient.Message{
		Channel: networkRevisionAdvancedChannel,
		Payload: string(payload),
	}}
	client := &Client{
		ping: func(context.Context) error {
			return errors.New("redis unavailable")
		},
		publish: func(context.Context, string, []byte) error {
			return nil
		},
		subscribe: func(context.Context, string) (messageSubscription, error) {
			return transport, nil
		},
		acquirePresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			time.Duration,
			string,
			[]byte,
		) (int64, error) {
			return 1, nil
		},
		renewPresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			time.Duration,
		) (int64, error) {
			return 1, nil
		},
		releasePresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			string,
			[]byte,
		) (int64, error) {
			return 1, nil
		},
		observeEndpoints: func(context.Context, endpointObservation) (int64, int64, error) {
			return 1, 0, nil
		},
		loadEndpoints: func(context.Context, string, int64) ([]byte, error) {
			return encodeEndpointSet(testEndpointObservation(t, 7).Set())
		},
		loadConnectivity: func(context.Context, []string, []int64) ([]any, error) {
			return []any{nil, nil, nil, int64(0)}, nil
		},
		metrics: metrics,
	}

	if err := client.Check(t.Context()); err == nil {
		t.Fatal("Check() error = nil, want dependency failure")
	}
	if err := client.PublishNetworkRevisionAdvanced(t.Context(), wakeup); err != nil {
		t.Fatalf("PublishNetworkRevisionAdvanced() error = %v", err)
	}
	subscription, err := client.SubscribeNetworkRevisionAdvanced(t.Context())
	if err != nil {
		t.Fatalf("SubscribeNetworkRevisionAdvanced() error = %v", err)
	}
	if _, err := subscription.Receive(t.Context()); err != nil {
		t.Fatalf("RevisionSubscription.Receive() error = %v", err)
	}
	lease := testPresenceLease(t, 7, "control-a")
	scope := testNetworkScope(t)
	if acquired, err := client.AcquirePresence(t.Context(), scope, lease); err != nil || !acquired {
		t.Fatalf("AcquirePresence() = (%t, %v), want true", acquired, err)
	}
	if renewed, err := client.RenewPresence(t.Context(), lease); err != nil || !renewed {
		t.Fatalf("RenewPresence() = (%t, %v), want true", renewed, err)
	}
	if released, err := client.ReleasePresence(t.Context(), scope, lease); err != nil || !released {
		t.Fatalf("ReleasePresence() = (%t, %v), want true", released, err)
	}
	observation := testEndpointObservation(t, 7)
	if accepted, _, err := client.ObserveEndpoints(t.Context(), scope, observation, 5*time.Second); err != nil ||
		!accepted {
		t.Fatalf("ObserveEndpoints() = (%t, %v), want true", accepted, err)
	}
	if _, found, err := client.LoadEndpoints(t.Context(), observation.NodeID(), 7); err != nil || !found {
		t.Fatalf("LoadEndpoints() = (_, %t, %v), want found", found, err)
	}
	key, err := mapsession.NewConnectivityKey(observation.NodeID(), 7)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityKey() error = %v", err)
	}
	if values, err := client.LoadConnectivity(t.Context(), []mapsession.ConnectivityKey{key}); err != nil || len(values) != 1 {
		t.Fatalf("LoadConnectivity() = (%+v, %v), want one result", values, err)
	}

	body := gatherRedisMetrics(t, client.MetricsCollector())
	for name, value := range map[string]string{
		"ping error":           `meshtransit_redis_commands_total{operation="ping",result="error"} 1`,
		"publish success":      `meshtransit_redis_commands_total{operation="publish",result="success"} 1`,
		"subscribe success":    `meshtransit_redis_commands_total{operation="subscribe",result="success"} 1`,
		"receive success":      `meshtransit_redis_commands_total{operation="receive",result="success"} 1`,
		"presence acquire":     `meshtransit_redis_commands_total{operation="presence_acquire",result="success"} 1`,
		"presence renew":       `meshtransit_redis_commands_total{operation="presence_renew",result="success"} 1`,
		"presence release":     `meshtransit_redis_commands_total{operation="presence_release",result="success"} 1`,
		"endpoint observe":     `meshtransit_redis_commands_total{operation="endpoints_observe",result="success"} 1`,
		"endpoint load":        `meshtransit_redis_commands_total{operation="endpoints_load",result="success"} 1`,
		"connectivity load":    `meshtransit_redis_commands_total{operation="connectivity_load",result="success"} 1`,
		"ping latency count":   `meshtransit_redis_command_duration_seconds_count{operation="ping",result="error"} 1`,
		"active connections":   `meshtransit_redis_pool_connections{state="active"} 5`,
		"idle connections":     `meshtransit_redis_pool_connections{state="idle"} 3`,
		"connection limit":     `meshtransit_redis_pool_connections_max 10`,
		"pending requests":     `meshtransit_redis_pool_pending_requests 2`,
		"pool timeouts":        `meshtransit_redis_pool_timeouts_total 4`,
		"active subscriptions": `meshtransit_redis_subscriptions_active 1`,
	} {
		if !strings.Contains(body, value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
	if strings.Contains(body, "redis unavailable") {
		t.Fatal("metrics exposed an error value")
	}

	if err := subscription.Close(); err != nil {
		t.Fatalf("RevisionSubscription.Close() error = %v", err)
	}
	if err := subscription.Close(); err != nil {
		t.Fatalf("second RevisionSubscription.Close() error = %v", err)
	}
	body = gatherRedisMetrics(t, client.MetricsCollector())
	if !strings.Contains(body, `meshtransit_redis_subscriptions_active 0`) {
		t.Fatalf("metrics did not release active subscription: %s", body)
	}
}

func TestClientMetricsCollectorRejectsUninitializedClient(t *testing.T) {
	t.Parallel()

	if collector := (*Client)(nil).MetricsCollector(); collector != nil {
		t.Fatalf("nil Client MetricsCollector() = %v, want nil", collector)
	}
	if collector := (&Client{}).MetricsCollector(); collector != nil {
		t.Fatalf("uninitialized Client MetricsCollector() = %v, want nil", collector)
	}
}

func TestRedisMetricsClampInconsistentPoolSnapshot(t *testing.T) {
	t.Parallel()

	metrics := newRedisMetrics(2, func() *redisclient.PoolStats {
		return &redisclient.PoolStats{TotalConns: 2, IdleConns: 3}
	})
	body := gatherRedisMetrics(t, metrics)
	if !strings.Contains(body, `meshtransit_redis_pool_connections{state="active"} 0`) ||
		!strings.Contains(body, `meshtransit_redis_pool_connections{state="idle"} 2`) {
		t.Fatalf("metrics exposed an inconsistent pool snapshot: %s", body)
	}
}

func gatherRedisMetrics(t *testing.T, collector prometheus.Collector) string {
	t.Helper()

	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	return response.Body.String()
}
