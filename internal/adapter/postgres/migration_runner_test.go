package postgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/migrations"
)

func TestMigrationRunnerUpInitializesCatalogAtomically(t *testing.T) {
	t.Parallel()

	connection := newFakeMigrationConnection(migrationDatabaseState{})
	runner := newTestMigrationRunner(t, connection)

	result, err := runner.Up(t.Context())
	if err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	latestVersion := migrations.LatestVersion()
	if result.Applied != len(migrations.Catalog()) || result.Status != (MigrationStatus{
		CurrentVersion: latestVersion,
		LatestVersion:  latestVersion,
		State:          MigrationStateClean,
	}) {
		t.Fatalf("Up() = %+v, want all catalog migrations applied cleanly", result)
	}
	if !connection.committed || connection.rolledBack {
		t.Fatalf("transaction outcome = committed %t, rolled back %t", connection.committed, connection.rolledBack)
	}
	wantOperations := []string{
		"timeouts",
		"lock",
		"preflight",
		"objects",
	}
	for _, migration := range migrations.Catalog() {
		version := strconv.FormatInt(migration.Version, 10)
		wantOperations = append(wantOperations, "migration:"+version, "record:"+version)
	}
	wantOperations = append(
		wantOperations,
		"compatibility:"+strconv.FormatInt(latestVersion, 10),
		"commit",
	)
	if !reflect.DeepEqual(connection.operations, wantOperations) {
		t.Fatalf("operations = %v, want %v", connection.operations, wantOperations)
	}
}

func TestMigrationRunnerUpIsIdempotentWhenCurrent(t *testing.T) {
	t.Parallel()

	connection := newFakeMigrationConnection(currentMigrationDatabaseState())
	runner := newTestMigrationRunner(t, connection)

	result, err := runner.Up(t.Context())
	if err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if result.Applied != 0 || result.Status.State != MigrationStateClean {
		t.Fatalf("Up() = %+v, want clean no-op", result)
	}
	for _, operation := range connection.operations {
		if strings.HasPrefix(operation, "migration:") || strings.HasPrefix(operation, "record:") {
			t.Fatalf("idempotent Up() executed migration work: %v", connection.operations)
		}
	}
}

func TestMigrationRunnerStatusIsReadOnly(t *testing.T) {
	t.Parallel()

	connection := newFakeMigrationConnection(currentMigrationDatabaseState())
	runner := newTestMigrationRunner(t, connection)

	status, err := runner.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != MigrationStateClean || status.CurrentVersion != migrations.LatestVersion() {
		t.Fatalf("Status() = %+v, want current clean schema", status)
	}
	if !connection.readOnly || !connection.committed || connection.rolledBack {
		t.Fatalf(
			"status transaction = readOnly %t, committed %t, rolled back %t",
			connection.readOnly,
			connection.committed,
			connection.rolledBack,
		)
	}
	for _, operation := range connection.operations {
		if operation == "lock" || strings.HasPrefix(operation, "migration:") ||
			strings.HasPrefix(operation, "record:") {
			t.Fatalf("Status() performed mutation or migration lock: %v", connection.operations)
		}
	}
}

func TestMigrationRunnerRollsBackMigrationFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("migration execution failed")
	connection := newFakeMigrationConnection(migrationDatabaseState{})
	connection.migrationErr = wantErr
	runner := newTestMigrationRunner(t, connection)

	if _, err := runner.Up(t.Context()); !errors.Is(err, wantErr) {
		t.Fatalf("Up() error = %v, want migration execution error", err)
	}
	if connection.committed || !connection.rolledBack {
		t.Fatalf("transaction outcome = committed %t, rolled back %t", connection.committed, connection.rolledBack)
	}
	if connection.state.initialized || len(connection.state.applied) != 0 {
		t.Fatalf("failed migration changed durable fake state: %+v", connection.state)
	}
}

func TestMigrationRunnerRejectsDriftBeforeDDL(t *testing.T) {
	t.Parallel()

	state := currentMigrationDatabaseState()
	state.applied[0].checksum = "drifted"
	connection := newFakeMigrationConnection(state)
	runner := newTestMigrationRunner(t, connection)

	if _, err := runner.Up(t.Context()); !errors.Is(err, ErrMigrationState) {
		t.Fatalf("Up() error = %v, want ErrMigrationState", err)
	}
	if connection.committed || !connection.rolledBack {
		t.Fatalf("transaction outcome = committed %t, rolled back %t", connection.committed, connection.rolledBack)
	}
	for _, operation := range connection.operations {
		if strings.HasPrefix(operation, "migration:") || strings.HasPrefix(operation, "record:") {
			t.Fatalf("drifted migration state executed DDL: %v", connection.operations)
		}
	}
}

func TestMigrationRunnerPropagatesCancellationAndClosesOnce(t *testing.T) {
	t.Parallel()

	connection := newFakeMigrationConnection(migrationDatabaseState{})
	runner := newTestMigrationRunner(t, connection)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := runner.Status(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Status() error = %v, want context.Canceled", err)
	}
	if err := runner.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := runner.Close(t.Context()); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if connection.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", connection.closeCalls)
	}
}

func TestMigrationRunnerBoundsBegin(t *testing.T) {
	t.Parallel()

	connection := newFakeMigrationConnection(currentMigrationDatabaseState())
	connection.requireBeginDeadline = true
	runner := newTestMigrationRunner(t, connection)

	if _, err := runner.Status(t.Context()); err != nil {
		t.Fatalf("Status() error = %v, want bounded begin", err)
	}
}

func TestMigrationRunnerBoundsCommit(t *testing.T) {
	t.Parallel()

	connection := newFakeMigrationConnection(currentMigrationDatabaseState())
	connection.requireCommitDeadline = true
	runner := newTestMigrationRunner(t, connection)

	if _, err := runner.Status(t.Context()); err != nil {
		t.Fatalf("Status() error = %v, want bounded commit", err)
	}
}

func TestMigrationRunnerClassifiesCommitOutcomeAsUncertain(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("connection lost during commit")
	connection := newFakeMigrationConnection(currentMigrationDatabaseState())
	connection.commitErr = wantErr
	runner := newTestMigrationRunner(t, connection)

	_, err := runner.Status(t.Context())
	if !errors.Is(err, ErrMigrationCommitUncertain) || !errors.Is(err, wantErr) {
		t.Fatalf("Status() error = %v, want uncertain commit wrapping connection error", err)
	}
}
