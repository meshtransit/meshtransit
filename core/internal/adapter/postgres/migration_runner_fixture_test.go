package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/migrations"
)

func newTestMigrationRunner(t *testing.T, connection migrationConnection) *MigrationRunner {
	t.Helper()

	runner, err := newMigrationRunner(connection, MigrationOptions{
		User:             "mesh_migrator",
		ConnectTimeout:   5 * time.Second,
		LockTimeout:      5 * time.Second,
		StatementTimeout: 30 * time.Second,
		Actor:            "deployment-controller",
		CodeRelease:      "version-test@revision-test",
	}, migrations.Catalog())
	if err != nil {
		t.Fatalf("newMigrationRunner() error = %v", err)
	}
	return runner
}

func currentMigrationDatabaseState() migrationDatabaseState {
	catalog := migrations.Catalog()
	applied := make([]appliedMigration, len(catalog))
	for index, migration := range catalog {
		applied[index] = appliedMigration{
			version:  migration.Version,
			checksum: migration.Checksum,
			result:   "succeeded",
		}
	}
	return migrationDatabaseState{
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
}

type fakeMigrationConnection struct {
	state                 migrationDatabaseState
	preflight             migrationPreflight
	operations            []string
	migrationErr          error
	commitErr             error
	requireBeginDeadline  bool
	requireCommitDeadline bool
	readOnly              bool
	committed             bool
	rolledBack            bool
	closeCalls            int
}

func newFakeMigrationConnection(state migrationDatabaseState) *fakeMigrationConnection {
	return &fakeMigrationConnection{
		state: state,
		preflight: migrationPreflight{
			serverVersion:       160000,
			extensionVersion:    "1.7",
			currentUser:         "mesh_migrator",
			databaseOwner:       true,
			supportRolesSafe:    true,
			roleMembershipsSafe: true,
		},
	}
}

func (connection *fakeMigrationConnection) Begin(
	ctx context.Context,
	readOnly bool,
) (migrationTransaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if connection.requireBeginDeadline {
		if _, bounded := ctx.Deadline(); !bounded {
			return nil, errors.New("begin context has no deadline")
		}
	}
	connection.readOnly = readOnly
	working := cloneMigrationDatabaseState(connection.state)
	return &fakeMigrationTransaction{connection: connection, working: working}, nil
}

func (connection *fakeMigrationConnection) Close(context.Context) error {
	connection.closeCalls++
	return nil
}

type fakeMigrationTransaction struct {
	connection *fakeMigrationConnection
	working    migrationDatabaseState
}

func (transaction *fakeMigrationTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) error {
	for _, migration := range migrations.Catalog() {
		if query != migration.SQL {
			continue
		}
		transaction.connection.operations = append(
			transaction.connection.operations,
			"migration:"+strconv.FormatInt(migration.Version, 10),
		)
		if transaction.connection.migrationErr != nil {
			return transaction.connection.migrationErr
		}
		if migration.Version == migrations.Catalog()[0].Version {
			transaction.working.initialized = true
		}
		return nil
	}

	switch query {
	case migrationTimeoutsSQL:
		transaction.connection.operations = append(transaction.connection.operations, "timeouts")
	case migrationLockSQL:
		transaction.connection.operations = append(transaction.connection.operations, "lock")
	case recordMigrationSQL:
		version := arguments[0].(int64)
		transaction.connection.operations = append(
			transaction.connection.operations,
			"record:"+strconv.FormatInt(version, 10),
		)
		transaction.working.applied = append(transaction.working.applied, appliedMigration{
			version:  version,
			checksum: arguments[1].(string),
			result:   "succeeded",
		})
	case markCompatibilityDirtySQL:
		transaction.connection.operations = append(transaction.connection.operations, "dirty")
		transaction.working.compatibility.state = "dirty"
	case upsertCompatibilitySQL:
		version := arguments[0].(int64)
		minimumReaderGeneration := arguments[1].(int64)
		maximumReaderGeneration := arguments[2].(int64)
		minimumWriterGeneration := arguments[3].(int64)
		maximumWriterGeneration := arguments[4].(int64)
		transaction.connection.operations = append(
			transaction.connection.operations,
			"compatibility:"+strconv.FormatInt(version, 10),
		)
		transaction.working.compatibility = schemaCompatibility{
			currentVersion:          version,
			minimumReaderGeneration: minimumReaderGeneration,
			maximumReaderGeneration: maximumReaderGeneration,
			minimumWriterGeneration: minimumWriterGeneration,
			maximumWriterGeneration: maximumWriterGeneration,
			state:                   "clean",
		}
	default:
		return errors.New("unexpected fake migration exec query")
	}
	return nil
}

func (transaction *fakeMigrationTransaction) QueryRow(
	_ context.Context,
	query string,
	_ ...any,
) migrationRow {
	switch query {
	case migrationPreflightSQL:
		transaction.connection.operations = append(transaction.connection.operations, "preflight")
		value := transaction.connection.preflight
		return fakeMigrationRow{values: []any{
			value.serverVersion,
			value.extensionVersion,
			value.currentUser,
			value.superuser,
			value.createDatabase,
			value.createRole,
			value.replication,
			value.bypassRLS,
			value.databaseOwner,
			value.supportRolesSafe,
			value.roleMembershipsSafe,
		}}
	case migrationObjectsSQL:
		transaction.connection.operations = append(transaction.connection.operations, "objects")
		initialized := transaction.working.initialized
		return fakeMigrationRow{values: []any{initialized, initialized, initialized}}
	case migrationCompatibilitySQL:
		transaction.connection.operations = append(transaction.connection.operations, "compatibility")
		if !transaction.working.initialized || transaction.working.compatibility.currentVersion == 0 {
			return fakeMigrationRow{err: pgx.ErrNoRows}
		}
		value := transaction.working.compatibility
		return fakeMigrationRow{values: []any{
			value.currentVersion,
			value.minimumReaderGeneration,
			value.maximumReaderGeneration,
			value.minimumWriterGeneration,
			value.maximumWriterGeneration,
			value.state,
		}}
	default:
		return fakeMigrationRow{err: errors.New("unexpected fake migration row query")}
	}
}

func (transaction *fakeMigrationTransaction) Query(
	_ context.Context,
	query string,
	_ ...any,
) (migrationRows, error) {
	if query != appliedMigrationsSQL {
		return nil, errors.New("unexpected fake migration rows query")
	}
	transaction.connection.operations = append(transaction.connection.operations, "applied")
	return &fakeMigrationRows{values: append([]appliedMigration(nil), transaction.working.applied...)}, nil
}

func (transaction *fakeMigrationTransaction) Commit(ctx context.Context) error {
	if transaction.connection.requireCommitDeadline {
		if _, bounded := ctx.Deadline(); !bounded {
			return errors.New("commit context has no deadline")
		}
	}
	if transaction.connection.commitErr != nil {
		return transaction.connection.commitErr
	}
	transaction.connection.operations = append(transaction.connection.operations, "commit")
	transaction.connection.state = cloneMigrationDatabaseState(transaction.working)
	transaction.connection.committed = true
	return nil
}

func (transaction *fakeMigrationTransaction) Rollback(context.Context) error {
	transaction.connection.operations = append(transaction.connection.operations, "rollback")
	transaction.connection.rolledBack = true
	return nil
}

type fakeMigrationRow struct {
	values []any
	err    error
}

func (row fakeMigrationRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("fake migration row destination mismatch")
	}
	for index, destination := range destinations {
		if err := assignMigrationValue(destination, row.values[index]); err != nil {
			return err
		}
	}
	return nil
}

type fakeMigrationRows struct {
	values []appliedMigration
	index  int
}

func (rows *fakeMigrationRows) Next() bool {
	return rows.index < len(rows.values)
}

func (rows *fakeMigrationRows) Scan(destinations ...any) error {
	if len(destinations) != 3 || rows.index >= len(rows.values) {
		return errors.New("fake migration rows destination mismatch")
	}
	value := rows.values[rows.index]
	rows.index++
	return errors.Join(
		assignMigrationValue(destinations[0], value.version),
		assignMigrationValue(destinations[1], value.checksum),
		assignMigrationValue(destinations[2], value.result),
	)
}

func (*fakeMigrationRows) Err() error { return nil }

func (*fakeMigrationRows) Close() {}

func assignMigrationValue(destination, value any) error {
	switch typed := destination.(type) {
	case *bool:
		*typed = value.(bool)
	case *int:
		*typed = value.(int)
	case *int64:
		*typed = value.(int64)
	case *string:
		*typed = value.(string)
	default:
		return errors.New("unsupported fake migration destination")
	}
	return nil
}

func cloneMigrationDatabaseState(value migrationDatabaseState) migrationDatabaseState {
	value.applied = append([]appliedMigration(nil), value.applied...)
	return value
}
