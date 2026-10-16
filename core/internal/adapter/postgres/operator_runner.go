package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/migrations"
)

var (
	// ErrOperatorPreflight indicates that the operator connection is not a
	// privileged role separate from every MeshTransit role.
	ErrOperatorPreflight = errors.New("postgres operator preflight failed")
	// ErrInvalidOperatorOptions indicates missing or unsafe operator settings.
	ErrInvalidOperatorOptions = errors.New("invalid postgres operator options")

	errOperatorDryRun = errors.New("operator dry run rolled back")
)

// OperatorStepFailedError names the step PostgreSQL refused and its
// SQLSTATE; nothing of the apply is committed.
type OperatorStepFailedError struct {
	Step     string
	SQLState string
	Err      error
}

func (err *OperatorStepFailedError) Error() string {
	return fmt.Sprintf("run operator step %s: %v", err.Step, err.Err)
}

func (err *OperatorStepFailedError) Unwrap() error { return err.Err }

// OperatorOptions contains the privileged operator connection: a superuser,
// or a role with CREATEROLE that may hand functions to their owner roles. It
// is never the migrator, runtime, worker or any role the steps manage.
type OperatorOptions struct {
	Address          string
	Database         string
	User             string
	PasswordFile     config.SecretFile
	CAFile           config.TrustFile
	ConnectTimeout   time.Duration
	LockTimeout      time.Duration
	StatementTimeout time.Duration
}

// OperatorRunner owns one direct connection used only by the explicit
// operator command. Status and Apply must not run concurrently on it.
type OperatorRunner struct {
	connection migrationConnection
	options    OperatorOptions
	closeOnce  sync.Once
	closeErr   error
}

// MigrationVerification is the schema state with the operator steps it needs.
type MigrationVerification struct {
	Status   MigrationStatus
	Operator OperatorReport
}

// operatorSessionSQL bounds the transaction and pins search_path, so no
// object of another schema can shadow what the steps name.
const operatorSessionSQL = `SELECT
    pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true),
    pg_catalog.set_config('statement_timeout', $1, true),
    pg_catalog.set_config('lock_timeout', $2, true),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $1, true)`

// operatorPreflightSQL also reports whether the operator is, directly or
// through other roles, a member of a MeshTransit role ($1). Only grants that
// let a role act as another count (INHERIT or SET, PostgreSQL 16): the
// ADMIN-only grant a CREATEROLE role keeps on every role it creates does not.
const operatorPreflightSQL = `WITH RECURSIVE granted(role_oid) AS (
    SELECT membership.roleid FROM pg_catalog.pg_auth_members AS membership
    WHERE membership.member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = CURRENT_USER)
      AND (membership.inherit_option OR membership.set_option)
    UNION
    SELECT membership.roleid FROM pg_catalog.pg_auth_members AS membership
    JOIN granted ON membership.member = granted.role_oid
    WHERE membership.inherit_option OR membership.set_option
)
SELECT
    pg_catalog.current_setting('server_version_num')::integer,
    CURRENT_USER::text,
    SESSION_USER::text,
    role.rolsuper,
    role.rolcreaterole,
    EXISTS (
        SELECT 1 FROM granted JOIN pg_catalog.pg_roles AS managed ON managed.oid = granted.role_oid
        WHERE managed.rolname = ANY($1::TEXT[]))
FROM pg_catalog.pg_roles AS role
WHERE role.rolname = CURRENT_USER`

// OpenOperatorRunner opens one direct, authenticated TLS connection. It runs
// nothing until Status or Apply is called.
func OpenOperatorRunner(ctx context.Context, options OperatorOptions) (*OperatorRunner, error) {
	if ctx == nil || options.ConnectTimeout <= 0 || options.LockTimeout <= 0 ||
		options.StatementTimeout <= 0 || options.LockTimeout >= options.StatementTimeout || options.User == "" {
		return nil, ErrInvalidOperatorOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(MigrationOptions{
		Address: options.Address, Database: options.Database, User: options.User,
		ConnectTimeout: options.ConnectTimeout, LockTimeout: options.LockTimeout,
		StatementTimeout: options.StatementTimeout, Actor: "operator", CodeRelease: "operator",
	}, password, caPEM)
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, ErrInvalidOperatorOptions)
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-operator"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationOpen, err)
	}
	return &OperatorRunner{connection: &pgxMigrationConnection{connection: connection}, options: options}, nil
}

// Status reports every catalog step in one read-only transaction.
func (runner *OperatorRunner) Status(ctx context.Context) (OperatorReport, error) {
	if ctx == nil || runner == nil || runner.connection == nil {
		return OperatorReport{}, ErrInvalidOperatorOptions
	}
	var report OperatorReport
	err := runner.withTransaction(ctx, true, false, func(transaction migrationTransaction) error {
		queryRow := transactionQueryRow(transaction)
		version, err := readOperatorSchemaVersion(ctx, queryRow)
		if err != nil {
			return err
		}
		report, err = readOperatorReport(ctx, queryRow, version)
		return err
	})
	return report, err
}

// Apply runs the planned steps in catalog order in one transaction under the
// migration lock, then requires each to hold and none applied before to have
// stopped holding. Any failure rolls everything back; a dry run always does.
func (runner *OperatorRunner) Apply(ctx context.Context, options OperatorApplyOptions) (OperatorApplyResult, error) {
	if ctx == nil || runner == nil || runner.connection == nil || options.Through < 0 {
		return OperatorApplyResult{}, ErrInvalidOperatorOptions
	}
	steps, err := migrations.OperatorSteps()
	if err != nil {
		return OperatorApplyResult{}, errors.Join(ErrOperatorCatalog, err)
	}
	byName := make(map[string]migrations.OperatorStep, len(steps))
	for _, step := range steps {
		byName[step.Name] = step
	}
	result := OperatorApplyResult{DryRun: options.DryRun}
	err = runner.withTransaction(ctx, false, true, func(transaction migrationTransaction) error {
		queryRow := transactionQueryRow(transaction)
		version, err := readOperatorSchemaVersion(ctx, queryRow)
		if err != nil {
			return err
		}
		before, err := readOperatorReport(ctx, queryRow, version)
		if err != nil {
			return err
		}
		plan, err := planOperatorSteps(steps, before, options)
		if err != nil {
			return err
		}
		for _, name := range plan.Run {
			if err := transaction.Exec(ctx, byName[name].Body()); err != nil {
				failed := &OperatorStepFailedError{Step: name, Err: err}
				if pgError := (*pgconn.PgError)(nil); errors.As(err, &pgError) {
					failed.SQLState = pgError.Code
				}
				return failed
			}
			if before.state(name) == OperatorStepApplied {
				result.Replayed = append(result.Replayed, name)
			} else {
				result.Applied = append(result.Applied, name)
			}
		}
		after, err := readOperatorReport(ctx, queryRow, version)
		if err != nil {
			return err
		}
		if err := verifyOperatorApply(before, after, plan.Run); err != nil {
			return err
		}
		result.Waiting = slices.Clone(plan.Waiting)
		result.Report = after
		if options.DryRun {
			return errOperatorDryRun
		}
		return nil
	})
	if options.DryRun && errors.Is(err, errOperatorDryRun) {
		return result, nil
	}
	if err != nil {
		return OperatorApplyResult{}, err
	}
	return result, nil
}

// Close releases the operator connection once.
func (runner *OperatorRunner) Close(ctx context.Context) error {
	if ctx == nil || runner == nil || runner.connection == nil {
		return ErrInvalidOperatorOptions
	}
	runner.closeOnce.Do(func() {
		runner.closeErr = runner.connection.Close(ctx)
	})
	return runner.closeErr
}

func (runner *OperatorRunner) withTransaction(
	ctx context.Context,
	readOnly bool,
	lock bool,
	operation func(migrationTransaction) error,
) error {
	return runMigrationTransaction(ctx, runner.connection, runner.options.ConnectTimeout, readOnly,
		func(transaction migrationTransaction) error {
			if err := transaction.Exec(ctx, operatorSessionSQL,
				postgresTimeoutValue(runner.options.StatementTimeout),
				postgresTimeoutValue(runner.options.LockTimeout)); err != nil {
				return fmt.Errorf("configure operator transaction: %w", err)
			}
			if err := runner.validatePreflight(ctx, transaction); err != nil {
				return err
			}
			// The migration lock: a step never runs while migrate up does.
			if lock {
				if err := transaction.Exec(ctx, migrationLockSQL, migrationLockKey); err != nil {
					return fmt.Errorf("acquire migration lock: %w", err)
				}
			}
			return operation(transaction)
		})
}

func (runner *OperatorRunner) validatePreflight(ctx context.Context, transaction migrationTransaction) error {
	managed, err := migrations.OperatorManagedRoles()
	if err != nil {
		return errors.Join(ErrOperatorPreflight, ErrOperatorCatalog)
	}
	var serverVersion int
	var currentUser, sessionUser string
	var superuser, createRole, managedMember bool
	if err := transaction.QueryRow(ctx, operatorPreflightSQL, managed).Scan(
		&serverVersion, &currentUser, &sessionUser, &superuser, &createRole, &managedMember,
	); err != nil {
		return errors.Join(ErrOperatorPreflight, err)
	}
	if serverVersion < minimumPostgreSQLVersion || currentUser != runner.options.User || sessionUser != currentUser ||
		!superuser && !createRole || managedMember || slices.Contains(managed, currentUser) {
		return ErrOperatorPreflight
	}
	return nil
}

func transactionQueryRow(transaction migrationTransaction) operatorQueryRow {
	return func(ctx context.Context, query string, arguments ...any) migrationRow {
		return transaction.QueryRow(ctx, query, arguments...)
	}
}

// Verify reports the schema state and the operator steps of its applied
// migrations in one read-only transaction as the migrator.
func (runner *MigrationRunner) Verify(ctx context.Context) (MigrationVerification, error) {
	if ctx == nil || runner == nil || runner.connection == nil {
		return MigrationVerification{}, ErrInvalidMigrationOptions
	}
	var verification MigrationVerification
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
		status, err := validateMigrationState(runner.catalog, migrations.ApplicationGeneration, state)
		if err != nil {
			return err
		}
		report, err := readOperatorReport(ctx, transactionQueryRow(transaction), status.CurrentVersion)
		if err != nil {
			return err
		}
		verification = MigrationVerification{Status: status, Operator: report}
		return nil
	})
	return verification, err
}
