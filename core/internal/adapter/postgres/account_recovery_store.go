package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/publicid"
)

const accountRecoveryPermission = "system.account_recovery"

const changeAccountRecoverySQL = `SELECT deployment_public_id::TEXT, account_public_id::TEXT, account_version,
 session_generation, recovery_state, sessions_ended, changed_at
FROM mesh_ops.change_account_recovery_v1($1::UUID, $2::TEXT, $3::UUID)`

// AccountRecoveryAction is one operator change to an Account.
type AccountRecoveryAction string

// Operator Account recovery actions.
const (
	// AccountRevokeSessions ends every Console session of the Account.
	AccountRevokeSessions AccountRecoveryAction = "revoke_sessions"
	// AccountQuarantine ends every session and refuses login until release.
	AccountQuarantine AccountRecoveryAction = "quarantine"
	// AccountRelease lets a quarantined Account sign in again.
	AccountRelease AccountRecoveryAction = "release"
)

var accountRecoveryAudit = map[AccountRecoveryAction]string{
	AccountRevokeSessions: "account.sessions_revoked",
	AccountQuarantine:     "account.quarantined",
	AccountRelease:        "account.released",
}

var (
	// ErrAccountNotFound reports no Account for the principal.
	ErrAccountNotFound = errors.New("postgres: account not found")
	// ErrAccountNotQuarantined reports a release of an Account that is not
	// quarantined.
	ErrAccountNotQuarantined = errors.New("postgres: account is not quarantined")
	// ErrAccountRecoveryUnavailable reports an unavailable or uncertain change.
	ErrAccountRecoveryUnavailable = errors.New("postgres: account recovery unavailable")
)

// AccountRecoveryReport is the Account after one operator change.
type AccountRecoveryReport struct {
	AccountID         publicid.ID
	Version           int64
	SessionGeneration int64
	RecoveryState     string
	SessionsEnded     int
	ChangedAt         time.Time
}

// ChangeAccountRecovery applies one operator change to the Account of a
// principal as the migration role, with one audit/outbox record on the
// Deployment stream, in one transaction.
func ChangeAccountRecovery(ctx context.Context, options MigrationOptions, principalID publicid.ID,
	action AccountRecoveryAction) (_ AccountRecoveryReport, resultErr error) {
	audited, known := accountRecoveryAudit[action]
	if ctx == nil || !principalID.IsValid() || !known || !validMigrationMetadata(options.Actor) ||
		!validMigrationMetadata(options.CodeRelease) {
		return AccountRecoveryReport{}, ErrInvalidMigrationOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(options, password, caPEM)
	if err != nil {
		return AccountRecoveryReport{}, err
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-account-recovery"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, err)
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(closeContext))
	}()
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, err)
	}
	defer func() {
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(rollbackContext); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('lock_timeout', $1, TRUE),
 pg_catalog.set_config('statement_timeout', $2, TRUE)`,
		postgresTimeoutValue(options.LockTimeout), postgresTimeoutValue(options.StatementTimeout)); err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, err)
	}
	ids, err := newAccountEvidenceIDs()
	if err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, err)
	}
	var deploymentID, accountID string
	var result accountRecoveryResult
	if err := tx.QueryRow(ctx, changeAccountRecoverySQL, principalID.String(), string(action),
		ids.change.String()).Scan(&deploymentID, &accountID, &result.version, &result.generation,
		&result.recoveryState, &result.sessionsEnded, &result.changedAt); err != nil {
		return AccountRecoveryReport{}, accountRecoveryError(err)
	}
	if result.account, err = publicid.Parse(accountID); err != nil || !result.valid() {
		return AccountRecoveryReport{}, ErrAccountRecoveryUnavailable
	}
	if err := appendAccountEvidence(ctx, tx.QueryRow, accountEvidence{
		deploymentID: deploymentID, ids: ids, result: result, action: audited,
		permission: accountRecoveryPermission, correlationID: ids.change, outboxClass: audited,
		payload: map[string]any{
			"account_public_id": result.account.String(), "principal_public_id": principalID.String(),
			"session_generation": result.generation, "recovery_state": result.recoveryState,
			"sessions_ended": result.sessionsEnded, "changed_at": result.changedAt.UTC().Format(time.RFC3339Nano),
			"operator_actor": options.Actor, "code_release": options.CodeRelease,
		},
	}); err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AccountRecoveryReport{}, errors.Join(ErrAccountRecoveryUnavailable, ErrMigrationCommitUncertain, err)
	}
	return AccountRecoveryReport{
		AccountID: result.account, Version: result.version, SessionGeneration: result.generation,
		RecoveryState: result.recoveryState, SessionsEnded: result.sessionsEnded, ChangedAt: result.changedAt.UTC(),
	}, nil
}

func accountRecoveryError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P0002":
			return ErrAccountNotFound
		case "MTA01":
			return ErrAccountNotQuarantined
		case "22023", "22P02":
			return ErrInvalidMigrationOptions
		}
	}
	return errors.Join(ErrAccountRecoveryUnavailable, err)
}
