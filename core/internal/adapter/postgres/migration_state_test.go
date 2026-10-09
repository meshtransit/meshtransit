package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/migrations"
)

func TestBuildMigrationConnectionConfigAppliesDirectConnectionSecurity(t *testing.T) {
	t.Parallel()

	connectionConfig, err := buildMigrationConnectionConfig(MigrationOptions{
		Address:          "database.internal:5432",
		Database:         "meshtransit",
		User:             "mesh_migrator",
		ConnectTimeout:   3 * time.Second,
		LockTimeout:      7 * time.Second,
		StatementTimeout: 45 * time.Second,
		Actor:            "deployment-controller",
		CodeRelease:      "version-test@revision-test",
	}, "credential", testCAPEM(t))
	if err != nil {
		t.Fatalf("buildMigrationConnectionConfig() error = %v", err)
	}

	if connectionConfig.Host != "database.internal" || connectionConfig.Port != 5432 {
		t.Fatalf("endpoint = %s:%d, want database.internal:5432", connectionConfig.Host, connectionConfig.Port)
	}
	if connectionConfig.Database != "meshtransit" || connectionConfig.User != "mesh_migrator" {
		t.Fatalf("identity = (%q, %q), want configured migration identity", connectionConfig.Database, connectionConfig.User)
	}
	if connectionConfig.TLSConfig == nil || connectionConfig.TLSConfig.ServerName != "database.internal" {
		t.Fatal("TLS server identity was not configured")
	}
	if connectionConfig.TLSConfig.MinVersion == 0 || connectionConfig.Fallbacks != nil {
		t.Fatal("TLS minimum or plaintext fallback invariant was not applied")
	}
	if connectionConfig.RequireAuth != "scram-sha-256" {
		t.Fatalf("RequireAuth = %q, want scram-sha-256", connectionConfig.RequireAuth)
	}
	if connectionConfig.RuntimeParams["application_name"] != "meshcore-migrator" {
		t.Fatalf("application_name = %q, want meshcore-migrator", connectionConfig.RuntimeParams["application_name"])
	}
}

func TestValidateMigrationPreflight(t *testing.T) {
	t.Parallel()

	valid := migrationPreflight{
		serverVersion:       160000,
		extensionVersion:    "1.7",
		currentUser:         "mesh_migrator",
		databaseOwner:       true,
		supportRolesSafe:    true,
		roleMembershipsSafe: true,
	}
	tests := []struct {
		name      string
		preflight migrationPreflight
	}{
		{name: "supported", preflight: valid},
		{name: "old postgres", preflight: withServerVersion(valid, 150000)},
		{name: "missing extension", preflight: withExtensionVersion(valid, "")},
		{name: "unknown extension", preflight: withExtensionVersion(valid, "2.0")},
		{name: "unexpected role", preflight: withCurrentUser(valid, "postgres")},
		{name: "not database owner", preflight: withUnsafeRole(valid, func(value *migrationPreflight) { value.databaseOwner = false })},
		{name: "superuser", preflight: withUnsafeRole(valid, func(value *migrationPreflight) { value.superuser = true })},
		{name: "create database", preflight: withUnsafeRole(valid, func(value *migrationPreflight) { value.createDatabase = true })},
		{name: "create role", preflight: withUnsafeRole(valid, func(value *migrationPreflight) { value.createRole = true })},
		{name: "replication", preflight: withUnsafeRole(valid, func(value *migrationPreflight) { value.replication = true })},
		{name: "bypass RLS", preflight: withUnsafeRole(valid, func(value *migrationPreflight) { value.bypassRLS = true })},
		{
			name: "missing or unsafe support role",
			preflight: withUnsafeRole(valid, func(value *migrationPreflight) {
				value.supportRolesSafe = false
			}),
		},
		{
			name: "unsafe role membership",
			preflight: withUnsafeRole(valid, func(value *migrationPreflight) {
				value.roleMembershipsSafe = false
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateMigrationPreflight("mesh_migrator", test.preflight)
			if test.name == "supported" {
				if err != nil {
					t.Fatalf("validateMigrationPreflight() error = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrMigrationPreflight) {
				t.Fatalf("validateMigrationPreflight() error = %v, want ErrMigrationPreflight", err)
			}
		})
	}
}

func TestValidateMigrationState(t *testing.T) {
	t.Parallel()

	catalog := migrations.Catalog()
	applied := make([]appliedMigration, len(catalog))
	for index, migration := range catalog {
		applied[index] = appliedMigration{
			version:  migration.Version,
			checksum: migration.Checksum,
			result:   "succeeded",
		}
	}
	current := migrationDatabaseState{
		initialized: true,
		applied:     applied,
		compatibility: schemaCompatibility{
			currentVersion:          int64(len(catalog)),
			minimumReaderGeneration: 1,
			maximumReaderGeneration: 1,
			minimumWriterGeneration: 1,
			maximumWriterGeneration: 1,
			state:                   "clean",
		},
	}
	tests := []struct {
		name    string
		state   migrationDatabaseState
		want    MigrationStatus
		wantErr bool
	}{
		{
			name:  "uninitialized",
			state: migrationDatabaseState{},
			want: MigrationStatus{
				CurrentVersion: 0,
				LatestVersion:  migrations.LatestVersion(),
				State:          MigrationStateUninitialized,
			},
		},
		{
			name:  "current",
			state: current,
			want: MigrationStatus{
				CurrentVersion: migrations.LatestVersion(),
				LatestVersion:  migrations.LatestVersion(),
				State:          MigrationStateClean,
			},
		},
		{name: "checksum drift", state: withAppliedChecksum(current, "changed"), wantErr: true},
		{
			name:    "future version",
			state:   withCurrentVersion(current, migrations.LatestVersion()+1),
			wantErr: true,
		},
		{name: "dirty state", state: withCompatibilityState(current, "dirty"), wantErr: true},
		{name: "failed record", state: withAppliedResult(current, "failed"), wantErr: true},
		{name: "missing applied record", state: withNoAppliedRecords(current), wantErr: true},
		{name: "reader generation incompatible", state: withReaderRange(current, 2, 3), wantErr: true},
		{name: "writer generation incompatible", state: withWriterRange(current, 2, 3), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateMigrationState(catalog, migrations.ApplicationGeneration, test.state)
			if test.wantErr {
				if !errors.Is(err, ErrMigrationState) {
					t.Fatalf("validateMigrationState() error = %v, want ErrMigrationState", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateMigrationState() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("validateMigrationState() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func withServerVersion(value migrationPreflight, version int) migrationPreflight {
	value.serverVersion = version
	return value
}

func withExtensionVersion(value migrationPreflight, version string) migrationPreflight {
	value.extensionVersion = version
	return value
}

func withCurrentUser(value migrationPreflight, user string) migrationPreflight {
	value.currentUser = user
	return value
}

func withUnsafeRole(value migrationPreflight, modify func(*migrationPreflight)) migrationPreflight {
	modify(&value)
	return value
}

func withAppliedChecksum(value migrationDatabaseState, checksum string) migrationDatabaseState {
	value.applied = append([]appliedMigration(nil), value.applied...)
	value.applied[0].checksum = checksum
	return value
}

func withCurrentVersion(value migrationDatabaseState, version int64) migrationDatabaseState {
	value.compatibility.currentVersion = version
	return value
}

func withCompatibilityState(value migrationDatabaseState, state string) migrationDatabaseState {
	value.compatibility.state = state
	return value
}

func withAppliedResult(value migrationDatabaseState, result string) migrationDatabaseState {
	value.applied = append([]appliedMigration(nil), value.applied...)
	value.applied[0].result = result
	return value
}

func withNoAppliedRecords(value migrationDatabaseState) migrationDatabaseState {
	value.applied = nil
	return value
}

func withReaderRange(value migrationDatabaseState, minimum, maximum int64) migrationDatabaseState {
	value.compatibility.minimumReaderGeneration = minimum
	value.compatibility.maximumReaderGeneration = maximum
	return value
}

func withWriterRange(value migrationDatabaseState, minimum, maximum int64) migrationDatabaseState {
	value.compatibility.minimumWriterGeneration = minimum
	value.compatibility.maximumWriterGeneration = maximum
	return value
}
