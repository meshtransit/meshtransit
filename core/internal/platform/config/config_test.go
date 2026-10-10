package config

import (
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/app"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.Role != app.RoleAll {
		t.Fatalf("Role = %s, want all", got.Role)
	}
	if got.HealthAddress != defaultHealthAddress {
		t.Fatalf("HealthAddress = %q, want %q", got.HealthAddress, defaultHealthAddress)
	}
	if got.ShutdownTimeout != defaultShutdownTimeout {
		t.Fatalf("ShutdownTimeout = %s, want %s", got.ShutdownTimeout, defaultShutdownTimeout)
	}
	if got.LogLevel != slog.LevelInfo {
		t.Fatalf("LogLevel = %s, want info", got.LogLevel)
	}
	if got.Dependencies.CheckTimeout != defaultDependencyCheckTimeout {
		t.Fatalf("dependency check timeout = %s, want %s", got.Dependencies.CheckTimeout, defaultDependencyCheckTimeout)
	}
	if got.Dependencies.CheckInterval != defaultDependencyCheckInterval {
		t.Fatalf("dependency check interval = %s, want %s", got.Dependencies.CheckInterval, defaultDependencyCheckInterval)
	}
	if got.Storage == nil {
		t.Fatal("Storage = nil for all role")
	}
	if got.Identity == nil {
		t.Fatal("Identity = nil for all role")
	}
	if got.Storage.PostgreSQL.Runtime == nil || got.Storage.PostgreSQL.Worker == nil {
		t.Fatal("all role did not load separate runtime and worker PostgreSQL credentials")
	}
	if got.Storage.PostgreSQL.Runtime.MaxConnections != defaultPostgreSQLMaxConnections ||
		got.Storage.PostgreSQL.Worker.MaxConnections != defaultPostgreSQLMaxConnections {
		t.Fatalf("postgres max connections did not use bounded defaults")
	}
	if got.Storage.Redis.PoolSize != defaultRedisPoolSize {
		t.Fatalf("redis pool size = %d, want %d", got.Storage.Redis.PoolSize, defaultRedisPoolSize)
	}
	if got.Enrollment == nil || got.Enrollment.CredentialDigest.Active.ID.String() != "active-v1" ||
		got.Enrollment.CredentialDigest.Previous != nil {
		t.Fatalf("enrollment config = %+v, want active key only", got.Enrollment)
	}
	if got.API == nil || got.API.Address != defaultAPIAddress ||
		got.API.AccountSessionDigest.Active.ID.String() != "session-v1" ||
		got.API.IdempotencyDigest.ID.String() != "idempotency-v1" ||
		got.API.RequestTimeout != defaultAPIRequestTimeout ||
		got.API.MaxConnections != defaultAPIMaxConnections ||
		got.API.MaxConcurrentRequests != defaultAPIMaxConcurrentRequests {
		t.Fatalf("api config = %+v, want bounded defaults", got.API)
	}
	if got.Control == nil || got.Control.Address != defaultControlAddress ||
		got.Control.MaxSessions != defaultControlMaxSessions || got.Control.MTCP.KeyNotAfter.IsZero() {
		t.Fatalf("control config = %+v, want bounded defaults", got.Control)
	}
	if got.RevisionWorker == nil || *got.RevisionWorker != (RevisionWorkerConfig{
		BatchSize:        defaultRevisionWorkerBatchSize,
		Lease:            defaultRevisionWorkerLease,
		PollInterval:     defaultRevisionWorkerPollInterval,
		RetryDelay:       defaultRevisionWorkerRetryDelay,
		OperationTimeout: defaultRevisionWorkerOperationTimeout,
	}) {
		t.Fatalf("revision worker config = %+v, want bounded defaults", got.RevisionWorker)
	}
}

func TestLoadExplicitValues(t *testing.T) {
	t.Parallel()

	values := validProcessValues(map[string]string{
		envRole:                           "worker",
		envHealthAddress:                  "[::1]:9090",
		envShutdownTimeout:                "45s",
		envLogLevel:                       "debug",
		envDependencyCheckTimeout:         "2s",
		envDependencyCheckInterval:        "7s",
		envPostgreSQLWorkerMaxConnections: "17",
		envRedisPoolSize:                  "19",
		envRevisionWorkerBatchSize:        "4",
		envRevisionWorkerLease:            "25s",
		envRevisionWorkerPollInterval:     "3s",
		envRevisionWorkerRetryDelay:       "7s",
		envRevisionWorkerOperationTimeout: "2s",
	})
	got, err := Load(mapLookup(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.Role != app.RoleWorker || got.HealthAddress != "[::1]:9090" {
		t.Fatalf("process selection = (%s, %q), want (worker, [::1]:9090)", got.Role, got.HealthAddress)
	}
	if got.ShutdownTimeout != 45*time.Second || got.LogLevel != slog.LevelDebug {
		t.Fatalf("process controls = (%s, %s), want (45s, debug)", got.ShutdownTimeout, got.LogLevel)
	}
	if got.Dependencies.CheckTimeout != 2*time.Second || got.Dependencies.CheckInterval != 7*time.Second {
		t.Fatalf(
			"dependency controls = (%s, %s), want (2s, 7s)",
			got.Dependencies.CheckTimeout,
			got.Dependencies.CheckInterval,
		)
	}
	if got.Storage == nil || got.Storage.PostgreSQL.Worker == nil ||
		got.Storage.PostgreSQL.Worker.MaxConnections != 17 || got.Storage.Redis.PoolSize != 19 {
		t.Fatalf("storage pool controls were not loaded")
	}
	if got.RevisionWorker == nil || *got.RevisionWorker != (RevisionWorkerConfig{
		BatchSize:        4,
		Lease:            25 * time.Second,
		PollInterval:     3 * time.Second,
		RetryDelay:       7 * time.Second,
		OperationTimeout: 2 * time.Second,
	}) {
		t.Fatalf("revision worker controls = %+v, want explicit values", got.RevisionWorker)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "empty explicit role", key: envRole, value: ""},
		{name: "unknown role", key: envRole, value: "scheduler"},
		{name: "role with whitespace", key: envRole, value: "api "},
		{name: "missing health port", key: envHealthAddress, value: "localhost"},
		{name: "zero health port", key: envHealthAddress, value: "localhost:0"},
		{name: "invalid health host", key: envHealthAddress, value: "bad host:8081"},
		{name: "empty timeout", key: envShutdownTimeout, value: ""},
		{name: "zero timeout", key: envShutdownTimeout, value: "0s"},
		{name: "negative timeout", key: envShutdownTimeout, value: "-1s"},
		{name: "unsafe short timeout", key: envShutdownTimeout, value: "999ms"},
		{name: "unbounded timeout", key: envShutdownTimeout, value: "6m"},
		{name: "unknown log level", key: envLogLevel, value: "trace"},
		{name: "uppercase log level", key: envLogLevel, value: "INFO"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validProcessValues(map[string]string{test.key: test.value})
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestLoadRequiresLookup(t *testing.T) {
	t.Parallel()

	_, err := Load(nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load() error = %v, want ErrInvalid", err)
	}
}

func mapLookup(values map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func validProcessValues(overrides map[string]string) map[string]string {
	// #nosec G101 -- these fixtures are file paths, never credential values.
	values := map[string]string{
		envPostgreSQLAddress:                     "database.internal:5432",
		envPostgreSQLDatabase:                    "meshtransit",
		envPostgreSQLRuntimeUser:                 "mesh_runtime",
		envPostgreSQLRuntimePasswordFile:         "/run/secrets/postgres-runtime-password",
		envPostgreSQLWorkerUser:                  "mesh_worker",
		envPostgreSQLWorkerPasswordFile:          "/run/secrets/postgres-worker-password",
		envPostgreSQLCAFile:                      "/run/secrets/postgres-ca.pem",
		envRedisAddress:                          "cache.internal:6379",
		envRedisUsername:                         "meshcore",
		envRedisPasswordFile:                     "/run/secrets/redis-password",
		envRedisCAFile:                           "/run/secrets/redis-ca.pem",
		envEnrollmentDigestActiveKeyID:           "active-v1",
		envEnrollmentDigestActiveKeyFile:         "/run/secrets/enrollment-digest-active-key",
		envControlTLSCertificateFile:             "/run/secrets/control-tls-certificate.pem",
		envControlTLSPrivateKeyFile:              "/run/secrets/control-tls-private-key.pem",
		envControlNoisePrivateKeyFile:            "/run/secrets/control-noise-private-key",
		envControlMTCPKeyNotAfter:                time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339),
		envRelayDirectoryFile:                    "/etc/meshtransit/relay-directory.json",
		envRelayDirectorySHA256:                  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		envAPITLSCertificateFile:                 "/run/secrets/control-tls-certificate.pem",
		envAPITLSPrivateKeyFile:                  "/run/secrets/control-tls-private-key.pem",
		envAPIAccountSessionDigestActiveKeyID:    "session-v1",
		envAPIAccountSessionDigestActiveKeyFile:  "/run/secrets/account-session-digest-active-key",
		envAPIIdempotencyDigestKeyID:             "idempotency-v1",
		envAPIIdempotencyDigestKeyFile:           "/run/secrets/idempotency-digest-key",
		envAPIRateLimitDigestKeyID:               "rate-limit-v1",
		envAPIRateLimitDigestKeyFile:             "/run/secrets/rate-limit-digest-key",
		envIdentityIssuer:                        "https://id.example.test/oauth2",
		envIdentityConfigurationFingerprint:      identityConfigurationFingerprintPrefix + strings.Repeat("1", 64),
		envIdentityAddress:                       "127.0.0.1:9443",
		envIdentityTLSCertificateFile:            "/run/secrets/identity-tls-certificate.pem",
		envIdentityTLSPrivateKeyFile:             "/run/secrets/identity-tls-private-key.pem",
		envIdentityOIDCConnectorID:               "google-v1",
		envIdentityOIDCConnectorDisplayName:      "Google",
		envIdentityOIDCConnectorGeneration:       "1",
		envIdentityOIDCConnectorIssuer:           identityGoogleIssuer,
		envIdentityOIDCConnectorClientID:         "google-client.apps.googleusercontent.com",
		envIdentityOIDCConnectorClientSecretFile: "/run/secrets/google-oidc-client-secret",
		envIdentityCoreClientID:                  "meshtransit-core",
		envIdentityCoreClientDisplayName:         "MeshTransit Core",
		envIdentityCoreClientGeneration:          "1",
		envIdentityCoreClientSecretFile:          "/run/secrets/meshtransit-core-client-secret",
		envIdentityCoreClientRedirectURI:         "https://app.example.test/auth/v1/callback",
		envIdentityPostgreSQLAddress:             "identity-db.internal:5432",
		envIdentityPostgreSQLDatabase:            "meshtransit_identity",
		envIdentityPostgreSQLRuntimeUser:         "identity_runtime",
		envIdentityPostgreSQLRuntimePasswordFile: "/run/secrets/identity-runtime-password",
		envIdentityPostgreSQLCAFile:              "/run/secrets/identity-postgres-ca.pem",
	}
	for key, value := range overrides {
		values[key] = value
	}
	return values
}
