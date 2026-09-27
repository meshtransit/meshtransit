//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/network"
)

func TestTLSAuthenticatedDependencies(t *testing.T) {
	if os.Getenv("MESHTRANSIT_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_INTEGRATION=1 with file-backed test credentials")
	}

	processConfig, err := config.Load(os.LookupEnv)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if processConfig.Storage == nil {
		t.Fatal("integration role must require storage")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	postgresConfig := processConfig.Storage.PostgreSQL
	runtimePool := openDependencyRolePool(
		ctx,
		t,
		postgresadapter.PoolRoleRuntime,
		postgresConfig,
		postgresConfig.Runtime,
		processConfig.Dependencies.CheckTimeout,
	)
	workerPool := openDependencyRolePool(
		ctx,
		t,
		postgresadapter.PoolRoleWorker,
		postgresConfig,
		postgresConfig.Worker,
		processConfig.Dependencies.CheckTimeout,
	)
	postgresChecker, err := postgresadapter.NewHealthChecker(runtimePool, workerPool)
	if err != nil {
		t.Fatalf("postgres.NewHealthChecker() error = %v", err)
	}
	if err := postgresChecker.Check(ctx); err != nil {
		t.Fatalf("PostgreSQL HealthChecker.Check() error = %v", err)
	}
	configuredPools := make([]*postgresadapter.Pool, 0, 2)
	if runtimePool != nil {
		configuredPools = append(configuredPools, runtimePool)
	}
	if workerPool != nil {
		configuredPools = append(configuredPools, workerPool)
	}
	postgresMetrics, err := postgresadapter.NewMetricsCollector(configuredPools...)
	if err != nil {
		t.Fatalf("postgres.NewMetricsCollector() error = %v", err)
	}
	postgresMetricsBody := gatherMetrics(t, postgresMetrics)
	expectedMetrics := map[string]string{
		"pool usage": `meshtransit_postgres_pool_connections`,
		"pool wait":  `meshtransit_postgres_pool_empty_acquire_wait_seconds_total`,
	}
	if runtimePool != nil {
		expectedMetrics["runtime ping"] = `meshtransit_postgres_operations_total{operation="ping",pool_role="runtime",result="success"} 1`
		expectedMetrics["runtime schema"] = `meshtransit_postgres_operations_total{operation="schema_check",pool_role="runtime",result="success"} 1`
	}
	if workerPool != nil {
		expectedMetrics["worker ping"] = `meshtransit_postgres_operations_total{operation="ping",pool_role="worker",result="success"} 1`
		expectedMetrics["worker schema"] = `meshtransit_postgres_operations_total{operation="schema_check",pool_role="worker",result="success"} 1`
	}
	for name, value := range expectedMetrics {
		if !strings.Contains(postgresMetricsBody, value) {
			t.Errorf("PostgreSQL metrics missing %s %q", name, value)
		}
	}

	redisClient, err := redisadapter.Open(ctx, redisadapter.Options{
		Address:        processConfig.Storage.Redis.Address,
		Username:       processConfig.Storage.Redis.Username,
		PasswordFile:   processConfig.Storage.Redis.PasswordFile,
		CAFile:         processConfig.Storage.Redis.CAFile,
		PoolSize:       processConfig.Storage.Redis.PoolSize,
		RequestTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		t.Fatalf("redis.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := redisClient.Close(); err != nil {
			t.Errorf("redis Close() error = %v", err)
		}
	})
	if err := redisClient.Check(ctx); err != nil {
		t.Fatalf("redis Check() error = %v", err)
	}
	assertRedisPresenceLeaseFencing(ctx, t, redisClient)
	assertRedisEndpointObservationFencing(ctx, t, redisClient)
	assertRedisRateLimit(ctx, t, redisClient)

	wakeup, err := network.NewRevisionAdvanced(
		"01890f00-0000-7000-8000-000000000201",
		42,
	)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	subscription, err := redisClient.SubscribeNetworkRevisionAdvanced(ctx)
	if err != nil {
		t.Fatalf("redis SubscribeNetworkRevisionAdvanced() error = %v", err)
	}
	t.Cleanup(func() {
		if err := subscription.Close(); err != nil {
			t.Errorf("redis revision subscription Close() error = %v", err)
		}
	})
	if err := redisClient.PublishNetworkRevisionAdvanced(ctx, wakeup); err != nil {
		t.Fatalf("redis PublishNetworkRevisionAdvanced() error = %v", err)
	}
	receiveCtx, receiveCancel := context.WithTimeout(ctx, processConfig.Dependencies.CheckTimeout)
	defer receiveCancel()
	receivedWakeup, err := subscription.Receive(receiveCtx)
	if err != nil {
		t.Fatalf("redis revision subscription Receive() error = %v", err)
	}
	if receivedWakeup.NetworkPublicID() != wakeup.NetworkPublicID() ||
		receivedWakeup.Number() != wakeup.Number() {
		t.Fatalf(
			"redis revision wakeup = (%q, %d), want (%q, %d)",
			receivedWakeup.NetworkPublicID(),
			receivedWakeup.Number(),
			wakeup.NetworkPublicID(),
			wakeup.Number(),
		)
	}
	metricsBody := gatherMetrics(t, redisClient.MetricsCollector())
	for name, value := range map[string]string{
		"successful ping":       `meshtransit_redis_commands_total{operation="ping",result="success"} 1`,
		"successful publish":    `meshtransit_redis_commands_total{operation="publish",result="success"} 1`,
		"successful subscribe":  `meshtransit_redis_commands_total{operation="subscribe",result="success"} 2`,
		"successful receive":    `meshtransit_redis_commands_total{operation="receive",result="success"} 2`,
		"presence acquisitions": `meshtransit_redis_commands_total{operation="presence_acquire",result="success"} 5`,
		"presence renewals":     `meshtransit_redis_commands_total{operation="presence_renew",result="success"} 5`,
		"presence releases":     `meshtransit_redis_commands_total{operation="presence_release",result="success"} 4`,
		"endpoint observations": `meshtransit_redis_commands_total{operation="endpoints_observe",result="success"} 3`,
		"endpoint loads":        `meshtransit_redis_commands_total{operation="endpoints_load",result="success"} 4`,
		"connectivity loads":    `meshtransit_redis_commands_total{operation="connectivity_load",result="success"} 2`,
		"command-pool state":    `meshtransit_redis_pool_connections`,
		"active subscriptions":  `meshtransit_redis_subscriptions_active 1`,
	} {
		if !strings.Contains(metricsBody, value) {
			t.Errorf("Redis metrics missing %s %q", name, value)
		}
	}
}

func gatherMetrics(t *testing.T, collector prometheus.Collector) string {
	t.Helper()

	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatalf("register integration metrics collector: %v", err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	return response.Body.String()
}

func openDependencyRolePool(
	ctx context.Context,
	t *testing.T,
	poolRole postgresadapter.PoolRole,
	postgresConfig config.PostgreSQLConfig,
	roleConfig *config.PostgreSQLRoleConfig,
	connectTimeout time.Duration,
) *postgresadapter.Pool {
	t.Helper()
	if roleConfig == nil {
		return nil
	}
	pool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role:           poolRole,
		Address:        postgresConfig.Address,
		Database:       postgresConfig.Database,
		User:           roleConfig.User,
		PasswordFile:   roleConfig.PasswordFile,
		CAFile:         postgresConfig.CAFile,
		MaxConnections: roleConfig.MaxConnections,
		ConnectTimeout: connectTimeout,
	})
	if err != nil {
		t.Fatalf("postgres.Open() role pool error = %v", err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("postgres role pool Close() error = %v", err)
		}
	})
	return pool
}
