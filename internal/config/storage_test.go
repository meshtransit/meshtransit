package config

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadRequiresStorageForNonRelayRoles(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		envPostgreSQLAddress,
		envPostgreSQLDatabase,
		envPostgreSQLCAFile,
		envPostgreSQLRuntimeUser,
		envPostgreSQLRuntimePasswordFile,
		envPostgreSQLWorkerUser,
		envPostgreSQLWorkerPasswordFile,
		envRedisAddress,
		envRedisUsername,
		envRedisPasswordFile,
		envRedisCAFile,
	} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			values := validStorageValues(nil)
			delete(values, key)
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), key) {
				t.Fatalf("Load() error = %q, want setting name %s", err, key)
			}
		})
	}
}

func TestLoadRejectsUnsafeStorageSettingsWithoutEchoingValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "postgres missing host", key: envPostgreSQLAddress, value: ":5432"},
		{name: "postgres missing port", key: envPostgreSQLAddress, value: "database.internal"},
		{name: "postgres empty database", key: envPostgreSQLDatabase, value: ""},
		{name: "runtime postgres user whitespace", key: envPostgreSQLRuntimeUser, value: "mesh core"},
		{name: "runtime postgres relative password file", key: envPostgreSQLRuntimePasswordFile, value: "secrets/postgres"},
		{name: "runtime postgres zero pool", key: envPostgreSQLRuntimeMaxConnections, value: "0"},
		{name: "runtime postgres oversized pool", key: envPostgreSQLRuntimeMaxConnections, value: "51"},
		{name: "worker postgres user whitespace", key: envPostgreSQLWorkerUser, value: "mesh core"},
		{name: "worker postgres relative password file", key: envPostgreSQLWorkerPasswordFile, value: "secrets/postgres"},
		{name: "worker postgres zero pool", key: envPostgreSQLWorkerMaxConnections, value: "0"},
		{name: "worker postgres oversized pool", key: envPostgreSQLWorkerMaxConnections, value: "51"},
		{name: "postgres relative ca file", key: envPostgreSQLCAFile, value: "tls/ca.pem"},
		{name: "redis missing host", key: envRedisAddress, value: ":6379"},
		{name: "redis empty username", key: envRedisUsername, value: ""},
		{name: "redis relative password file", key: envRedisPasswordFile, value: "secrets/redis"},
		{name: "redis relative ca file", key: envRedisCAFile, value: "tls/ca.pem"},
		{name: "redis zero pool", key: envRedisPoolSize, value: "0"},
		{name: "redis oversized pool", key: envRedisPoolSize, value: "51"},
		{name: "short dependency timeout", key: envDependencyCheckTimeout, value: "99ms"},
		{name: "long dependency timeout", key: envDependencyCheckTimeout, value: "31s"},
		{name: "short dependency interval", key: envDependencyCheckInterval, value: "999ms"},
		{name: "long dependency interval", key: envDependencyCheckInterval, value: "6m"},
		{name: "timeout not below interval", key: envDependencyCheckTimeout, value: "10s"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validStorageValues(map[string]string{test.key: test.value})
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
			if test.value != "" && strings.Contains(err.Error(), test.value) {
				t.Fatalf("Load() error exposed rejected value %q: %v", test.value, err)
			}
		})
	}
}

func TestLoadRelayDoesNotRequireOrParseStorage(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(map[string]string{
		envRole:                           "relay",
		envPostgreSQLAddress:              "not an address",
		envPostgreSQLRuntimePasswordFile:  "relative-secret",
		envPostgreSQLWorkerMaxConnections: "unbounded",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Storage != nil {
		t.Fatalf("Storage = %v, want nil for relay", got.Storage)
	}
}

func TestLoadRequiresOnlySelectedPostgreSQLCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		role        string
		removeKeys  []string
		wantRuntime bool
		wantWorker  bool
	}{
		{
			name: "api ignores worker credentials",
			role: "api",
			removeKeys: []string{
				envPostgreSQLWorkerUser,
				envPostgreSQLWorkerPasswordFile,
			},
			wantRuntime: true,
		},
		{
			name: "worker ignores runtime credentials",
			role: "worker",
			removeKeys: []string{
				envPostgreSQLRuntimeUser,
				envPostgreSQLRuntimePasswordFile,
			},
			wantWorker: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validStorageValues(map[string]string{envRole: test.role})
			for _, key := range test.removeKeys {
				delete(values, key)
			}
			got, err := Load(mapLookup(values))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Storage == nil || (got.Storage.PostgreSQL.Runtime != nil) != test.wantRuntime ||
				(got.Storage.PostgreSQL.Worker != nil) != test.wantWorker {
				t.Fatalf(
					"PostgreSQL role config = (runtime=%t, worker=%t), want (%t, %t)",
					got.Storage != nil && got.Storage.PostgreSQL.Runtime != nil,
					got.Storage != nil && got.Storage.PostgreSQL.Worker != nil,
					test.wantRuntime,
					test.wantWorker,
				)
			}
		})
	}
}
