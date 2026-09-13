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
		envPostgreSQLUser,
		envPostgreSQLPasswordFile,
		envPostgreSQLCAFile,
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
		{name: "postgres user whitespace", key: envPostgreSQLUser, value: "mesh core"},
		{name: "postgres relative password file", key: envPostgreSQLPasswordFile, value: "secrets/postgres"},
		{name: "postgres relative ca file", key: envPostgreSQLCAFile, value: "tls/ca.pem"},
		{name: "postgres zero pool", key: envPostgreSQLMaxConnections, value: "0"},
		{name: "postgres oversized pool", key: envPostgreSQLMaxConnections, value: "51"},
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
		envRole:                     "relay",
		envPostgreSQLAddress:        "not an address",
		envPostgreSQLPasswordFile:   "relative-secret",
		envPostgreSQLMaxConnections: "unbounded",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Storage != nil {
		t.Fatalf("Storage = %v, want nil for relay", got.Storage)
	}
}
