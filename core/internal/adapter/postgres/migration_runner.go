package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/migrations"
)

var (
	// ErrMigrationOpen indicates that the direct migration connection could not
	// be constructed or established.
	ErrMigrationOpen = errors.New("open postgres migration connection")
	// ErrMigrationRun indicates that a bounded status or apply transaction
	// failed. More specific errors remain available through errors.Is.
	ErrMigrationRun = errors.New("run postgres migration")
	// ErrMigrationCommitUncertain indicates that PostgreSQL did not confirm
	// whether a migration transaction committed. Operators must inspect status
	// before retrying the command.
	ErrMigrationCommitUncertain = errors.New("postgres migration commit outcome uncertain")
)

// MigrationResult reports the bounded effect of one idempotent apply command.
type MigrationResult struct {
	Applied int
	Status  MigrationStatus
}

// MigrationRunner owns one direct PostgreSQL connection used only by an
// explicit one-shot migration command. Status and Up are single-owner
// operations and must not run concurrently on the same runner.
type MigrationRunner struct {
	connection migrationConnection
	options    MigrationOptions
	catalog    []migrations.Migration
	closeOnce  sync.Once
	closeErr   error
}

type migrationConnection interface {
	Begin(context.Context, bool) (migrationTransaction, error)
	Close(context.Context) error
}

type migrationTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) migrationRow
	Query(context.Context, string, ...any) (migrationRows, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type migrationRow interface {
	Scan(...any) error
}

type migrationRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

func newMigrationRunner(
	connection migrationConnection,
	options MigrationOptions,
	catalog []migrations.Migration,
) (*MigrationRunner, error) {
	if connection == nil || options.ConnectTimeout <= 0 || options.LockTimeout <= 0 ||
		options.StatementTimeout <= 0 || options.LockTimeout >= options.StatementTimeout ||
		options.User == "" || !validMigrationMetadata(options.Actor) ||
		!validMigrationMetadata(options.CodeRelease) || !validMigrationCatalog(catalog) {
		return nil, ErrInvalidMigrationOptions
	}
	return &MigrationRunner{
		connection: connection,
		options:    options,
		catalog:    append([]migrations.Migration(nil), catalog...),
	}, nil
}

// Status validates PostgreSQL, extension, role, catalog checksums, and binary
// compatibility in one bounded read-only transaction.
func (runner *MigrationRunner) Status(ctx context.Context) (MigrationStatus, error) {
	if ctx == nil || runner == nil || runner.connection == nil {
		return MigrationStatus{}, ErrInvalidMigrationOptions
	}
	var status MigrationStatus
	err := runner.withTransaction(ctx, true, func(transaction migrationTransaction) error {
		if err := runner.configureTransaction(ctx, transaction, false); err != nil {
			return err
		}
		if err := runner.validatePreflight(ctx, transaction); err != nil {
			return err
		}
		state, err := readMigrationDatabaseState(ctx, transaction)
		if err != nil {
			return err
		}
		status, err = validateMigrationState(runner.catalog, migrations.ApplicationGeneration, state)
		return err
	})
	return status, err
}

// Up applies every pending catalog entry atomically under the deployment
// migration lock. Calling Up on a current schema is a safe no-op.
func (runner *MigrationRunner) Up(ctx context.Context) (MigrationResult, error) {
	if ctx == nil || runner == nil || runner.connection == nil {
		return MigrationResult{}, ErrInvalidMigrationOptions
	}
	var result MigrationResult
	err := runner.withTransaction(ctx, false, func(transaction migrationTransaction) error {
		if err := runner.configureTransaction(ctx, transaction, true); err != nil {
			return err
		}
		if err := runner.validatePreflight(ctx, transaction); err != nil {
			return err
		}
		state, err := readMigrationDatabaseState(ctx, transaction)
		if err != nil {
			return err
		}
		status, err := validateMigrationState(runner.catalog, migrations.ApplicationGeneration, state)
		if err != nil {
			return err
		}
		pending := runner.catalog[int(status.CurrentVersion):]
		if len(pending) == 0 {
			result.Status = status
			return nil
		}
		if state.initialized {
			if err := transaction.Exec(ctx, markCompatibilityDirtySQL); err != nil {
				return fmt.Errorf("mark migration state dirty: %w", err)
			}
		}
		for _, migration := range pending {
			if err := transaction.Exec(ctx, migration.SQL); err != nil {
				return fmt.Errorf("apply migration version %d: %w", migration.Version, err)
			}
			if err := transaction.Exec(
				ctx,
				recordMigrationSQL,
				migration.Version,
				migration.Checksum,
				migration.Description,
				runner.options.CodeRelease,
				runner.options.Actor,
			); err != nil {
				return fmt.Errorf("record migration version %d: %w", migration.Version, err)
			}
		}
		latest := pending[len(pending)-1]
		if err := transaction.Exec(
			ctx,
			upsertCompatibilitySQL,
			latest.Version,
			latest.MinimumReaderGeneration,
			latest.MaximumReaderGeneration,
			latest.MinimumWriterGeneration,
			latest.MaximumWriterGeneration,
		); err != nil {
			return fmt.Errorf("record schema compatibility: %w", err)
		}
		result = MigrationResult{
			Applied: len(pending),
			Status: MigrationStatus{
				CurrentVersion: latest.Version,
				LatestVersion:  runner.catalog[len(runner.catalog)-1].Version,
				State:          MigrationStateClean,
			},
		}
		return nil
	})
	return result, err
}

// Close releases the direct migration connection once.
func (runner *MigrationRunner) Close(ctx context.Context) error {
	if ctx == nil || runner == nil || runner.connection == nil {
		return ErrInvalidMigrationOptions
	}
	runner.closeOnce.Do(func() {
		runner.closeErr = runner.connection.Close(ctx)
	})
	return runner.closeErr
}

func (runner *MigrationRunner) configureTransaction(
	ctx context.Context,
	transaction migrationTransaction,
	lock bool,
) error {
	if err := transaction.Exec(
		ctx,
		migrationTimeoutsSQL,
		postgresTimeoutValue(runner.options.StatementTimeout),
		postgresTimeoutValue(runner.options.LockTimeout),
	); err != nil {
		return fmt.Errorf("configure migration transaction: %w", err)
	}
	if lock {
		if err := transaction.Exec(ctx, migrationLockSQL, migrationLockKey); err != nil {
			return fmt.Errorf("acquire migration lock: %w", err)
		}
	}
	return nil
}

func (runner *MigrationRunner) validatePreflight(
	ctx context.Context,
	transaction migrationTransaction,
) error {
	var preflight migrationPreflight
	if err := transaction.QueryRow(ctx, migrationPreflightSQL, migrationSupportRoles()).Scan(
		&preflight.serverVersion,
		&preflight.extensionVersion,
		&preflight.currentUser,
		&preflight.superuser,
		&preflight.createDatabase,
		&preflight.createRole,
		&preflight.replication,
		&preflight.bypassRLS,
		&preflight.databaseOwner,
		&preflight.supportRolesSafe,
		&preflight.roleMembershipsSafe,
	); err != nil {
		return errors.Join(ErrMigrationPreflight, err)
	}
	return validateMigrationPreflight(runner.options.User, preflight)
}

func (runner *MigrationRunner) withTransaction(
	ctx context.Context,
	readOnly bool,
	operation func(migrationTransaction) error,
) (returnErr error) {
	beginContext, cancelBegin := context.WithTimeout(ctx, runner.options.ConnectTimeout)
	transaction, err := runner.connection.Begin(beginContext, readOnly)
	cancelBegin()
	if err != nil {
		return fmt.Errorf("%w: begin transaction: %w", ErrMigrationRun, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackContext, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			runner.options.ConnectTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackContext); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			returnErr = errors.Join(returnErr, fmt.Errorf("rollback migration transaction: %w", err))
		}
	}()

	if err := operation(transaction); err != nil {
		return fmt.Errorf("%w: %w", ErrMigrationRun, err)
	}
	commitContext, cancelCommit := context.WithTimeout(ctx, runner.options.ConnectTimeout)
	commitErr := transaction.Commit(commitContext)
	cancelCommit()
	if commitErr != nil {
		return errors.Join(
			ErrMigrationRun,
			ErrMigrationCommitUncertain,
			fmt.Errorf("commit transaction: %w", commitErr),
		)
	}
	committed = true
	return nil
}
