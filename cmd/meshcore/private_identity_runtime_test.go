package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/config"
)

func TestPrivateIdentityConfigValidateRejectsProfileBeforeDependencies(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	profile := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profile, []byte("invalid-private-profile"), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"MESHTRANSIT_ROLE": "api", "MESHTRANSIT_PRIVATE_LOGIN_CONFIG_FILE": profile,
		"MESHTRANSIT_POSTGRES_ADDRESS": "database.invalid:5432", "MESHTRANSIT_POSTGRES_DATABASE": "meshtransit",
		"MESHTRANSIT_POSTGRES_RUNTIME_USER":          "mesh_runtime",
		"MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE": filepath.Join(directory, "pg-password"),
		"MESHTRANSIT_POSTGRES_CA_FILE":               filepath.Join(directory, "pg-ca"),
		"MESHTRANSIT_REDIS_ADDRESS":                  "cache.invalid:6379", "MESHTRANSIT_REDIS_USERNAME": "mesh_worker",
		"MESHTRANSIT_REDIS_PASSWORD_FILE":                        filepath.Join(directory, "redis-password"),
		"MESHTRANSIT_REDIS_CA_FILE":                              filepath.Join(directory, "redis-ca"),
		"MESHTRANSIT_API_TLS_CERTIFICATE_FILE":                   filepath.Join(directory, "api-cert"),
		"MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE":                   filepath.Join(directory, "api-key"),
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID":   "session-v1",
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE": filepath.Join(directory, "session"),
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID":              "idempotency-v1",
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE":            filepath.Join(directory, "idempotency"),
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID":               "rate-limit-v1",
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE":             filepath.Join(directory, "rate-limit"),
	}
	lookup := func(name string) (string, bool) { value, found := values[name]; return value, found }
	process, err := config.Load(lookup)
	if err != nil {
		t.Fatal("fixture process references invalid")
	}
	if err := validateDependencyConfiguration(t.Context(), process); !errors.Is(err, errInvalidPrivateIdentityComposition) {
		t.Fatal("invalid profile did not fail before absent dependency files")
	}
	var output, diagnostics bytes.Buffer
	if runConfigValidate(t.Context(), lookup, &output, &diagnostics) != 1 || output.Len() != 0 {
		t.Fatal("CLI reported invalid profile as valid")
	}
	for _, sensitive := range []string{directory, "invalid-private-profile", "database.invalid", "cache.invalid"} {
		if strings.Contains(diagnostics.String(), sensitive) {
			t.Fatal("CLI reflected private input")
		}
	}
}

func TestPrivateIdentityFactorySharesExactManagementKeyOwners(t *testing.T) {
	t.Parallel()
	fixture, options, dependencies := privateIdentityFactoryFixture(t, postgresadapter.PoolRoleRuntime)
	factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, options, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(factory.Close)
	sharedSessions := factory.managementKeys.sessions == fixture.keys.sessions
	sharedIdempotency := factory.managementKeys.idempotency == fixture.keys.idempotency
	sharedRateLimit := factory.managementKeys.rateLimit == fixture.keys.rateLimit
	if !sharedSessions || !sharedIdempotency || !sharedRateLimit {
		t.Fatal("resident purpose owners forked")
	}
	registry := prometheus.NewPedanticRegistry()
	apiMetrics, err := httpapi.NewManagementTelemetry(16)
	if err != nil {
		t.Fatal(err)
	}
	for _, collector := range []prometheus.Collector{
		prometheus.WrapCollectorWith(
			prometheus.Labels{"auth_profile": "console_cookie_private_v1"}, factory.identity.metrics,
		),
		prometheus.WrapCollectorWith(prometheus.Labels{"auth_profile": "core_session_bearer_v1"}, apiMetrics),
	} {
		if err := registry.Register(collector); err != nil {
			t.Fatal("profile registry collision", err)
		}
	}
	if _, err := registry.Gather(); err != nil {
		t.Fatal("profile series collision", err)
	}
	postgresMetrics, err := postgresadapter.NewMetricsCollector(dependencies.Runtime)
	if err != nil {
		t.Fatal("storage collector construction", err)
	}
	for _, collector := range []prometheus.Collector{
		postgresMetrics,
		dependencies.Redis.MetricsCollector(),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	} {
		if err := registry.Register(collector); err != nil {
			t.Fatal("operator collector collision", err)
		}
	}
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(
		response,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://fixture.test/metrics", nil),
	)
	if response.Code != http.StatusOK || response.Body.Len() > 1024*1024 {
		t.Fatalf("operator profile response outside fixture budget: status=%d bytes=%d", response.Code, response.Body.Len())
	}
}

func TestPrivateIdentityReadinessRejectsIncompleteOrCanceledGraph(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, factory := range []*privateIdentityFactory{nil, {}, {identity: &privateIdentity{}}} {
		if factory.Component() != app.ComponentPrivateLogin {
			t.Fatal("readiness component changed")
		}
		for _, caller := range []context.Context{nil, ctx, t.Context()} {
			err := factory.Check(caller)
			if !errors.Is(err, errInvalidPrivateIdentityComposition) || err.Error() != errInvalidPrivateIdentityComposition.Error() {
				t.Fatal("unsafe readiness released or raw diagnostic disclosed")
			}
		}
	}
}
