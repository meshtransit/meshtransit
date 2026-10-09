package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoadMigrationConfig(t *testing.T) {
	t.Parallel()

	values := validMigrationValues(map[string]string{
		envMigrationConnectTimeout:   "3s",
		envMigrationLockTimeout:      "7s",
		envMigrationStatementTimeout: "45s",
	})
	got, err := LoadMigration(mapLookup(values))
	if err != nil {
		t.Fatalf("LoadMigration() error = %v", err)
	}

	if got.PostgreSQL.Address != "database.internal:5432" || got.PostgreSQL.Database != "meshtransit" {
		t.Fatalf("PostgreSQL endpoint = (%q, %q), want configured endpoint", got.PostgreSQL.Address, got.PostgreSQL.Database)
	}
	if got.PostgreSQL.User != "mesh_migrator" || got.Actor != "deployment-controller" {
		t.Fatalf("migration identities = (%q, %q), want configured identities", got.PostgreSQL.User, got.Actor)
	}
	if got.ConnectTimeout != 3*time.Second || got.LockTimeout != 7*time.Second || got.StatementTimeout != 45*time.Second {
		t.Fatalf(
			"migration timeouts = (%s, %s, %s), want (3s, 7s, 45s)",
			got.ConnectTimeout,
			got.LockTimeout,
			got.StatementTimeout,
		)
	}
}

func TestLoadMigrationConfigRejectsUnsafeValuesWithoutEchoingThem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "missing host", key: envMigrationPostgreSQLAddress, value: ":5432"},
		{name: "empty database", key: envMigrationPostgreSQLDatabase, value: ""},
		{name: "unsafe user", key: envMigrationPostgreSQLUser, value: "mesh migrator"},
		{name: "relative credential", key: envMigrationPostgreSQLPasswordFile, value: "secrets/postgres"},
		{name: "relative trust", key: envMigrationPostgreSQLCAFile, value: "tls/ca.pem"},
		{name: "empty actor", key: envMigrationActor, value: ""},
		{name: "multiline actor", key: envMigrationActor, value: "first\nsecond"},
		{name: "short connect timeout", key: envMigrationConnectTimeout, value: "99ms"},
		{name: "long connect timeout", key: envMigrationConnectTimeout, value: "31s"},
		{name: "short lock timeout", key: envMigrationLockTimeout, value: "99ms"},
		{name: "long lock timeout", key: envMigrationLockTimeout, value: "31s"},
		{name: "short statement timeout", key: envMigrationStatementTimeout, value: "999ms"},
		{name: "long statement timeout", key: envMigrationStatementTimeout, value: "11m"},
		{name: "lock not below statement", key: envMigrationLockTimeout, value: "30s"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validMigrationValues(map[string]string{test.key: test.value})
			_, err := LoadMigration(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("LoadMigration() error = %v, want ErrInvalid", err)
			}
			if test.value != "" && strings.Contains(err.Error(), test.value) {
				t.Fatalf("LoadMigration() error exposed rejected value %q: %v", test.value, err)
			}
		})
	}
}

func TestMigrationConfigFileReferencesAlwaysFormatAsRedacted(t *testing.T) {
	t.Parallel()

	values := validMigrationValues(nil)
	got, err := LoadMigration(mapLookup(values))
	if err != nil {
		t.Fatalf("LoadMigration() error = %v", err)
	}
	formatted := fmt.Sprintf("%#v", got)
	for _, path := range []string{
		values[envMigrationPostgreSQLPasswordFile],
		values[envMigrationPostgreSQLCAFile],
	} {
		if strings.Contains(formatted, path) {
			t.Fatalf("formatted migration config exposed file path %q: %s", path, formatted)
		}
	}
}

func TestLoadMigrationConfigRequiresLookup(t *testing.T) {
	t.Parallel()

	if _, err := LoadMigration(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("LoadMigration(nil) error = %v, want ErrInvalid", err)
	}
}

func validMigrationValues(overrides map[string]string) map[string]string {
	values := map[string]string{ //nolint:gosec // G101: fixtures contain file paths, not credentials.
		envMigrationPostgreSQLAddress:      "database.internal:5432",
		envMigrationPostgreSQLDatabase:     "meshtransit",
		envMigrationPostgreSQLUser:         "mesh_migrator",
		envMigrationPostgreSQLPasswordFile: "/run/secrets/migration-postgres-password",
		envMigrationPostgreSQLCAFile:       "/run/secrets/migration-postgres-ca.pem",
		envMigrationActor:                  "deployment-controller",
	}
	for key, value := range overrides {
		values[key] = value
	}
	return values
}
