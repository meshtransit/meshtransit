package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

var accountCommandActions = map[string]postgresadapter.AccountRecoveryAction{
	"revoke-sessions": postgresadapter.AccountRevokeSessions,
	"quarantine":      postgresadapter.AccountQuarantine,
	"release":         postgresadapter.AccountRelease,
}

type accountCommandOutput struct {
	Operation         string `json:"operation"`
	PrincipalID       string `json:"principal_id"`
	AccountID         string `json:"account_id"`
	RecoveryState     string `json:"recovery_state"`
	SessionGeneration int64  `json:"session_generation"`
	SessionsEnded     int    `json:"sessions_ended"`
	ChangedAt         string `json:"changed_at"`
}

// runAccount ends every Console session of the Account of one principal, or
// quarantines or releases it, as the migration role with the migration
// database credentials. It commits one change with its audit record.
func runAccount(ctx context.Context, operation, principal string, lookup config.LookupFunc,
	output, errorOutput io.Writer) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	fail := func(code string) int {
		logger.ErrorContext(ctx, "account change failed", "error_code", code)
		return 1
	}
	action, known := accountCommandActions[operation]
	principalID, err := publicid.Parse(principal)
	if !known || err != nil {
		return fail("invalid_account_operation")
	}
	migrationConfig, err := config.LoadMigration(lookup)
	if err != nil {
		return fail("invalid_migration_configuration")
	}
	report, err := postgresadapter.ChangeAccountRecovery(ctx, postgresadapter.MigrationOptions{
		Address: migrationConfig.PostgreSQL.Address, Database: migrationConfig.PostgreSQL.Database,
		User: migrationConfig.PostgreSQL.User, PasswordFile: migrationConfig.PostgreSQL.PasswordFile,
		CAFile: migrationConfig.PostgreSQL.CAFile, ConnectTimeout: migrationConfig.ConnectTimeout,
		LockTimeout: migrationConfig.LockTimeout, StatementTimeout: migrationConfig.StatementTimeout,
		Actor: migrationConfig.Actor, CodeRelease: buildinfo.Release(),
	}, principalID, action)
	switch {
	case errors.Is(err, postgresadapter.ErrAccountNotFound):
		return fail("account_not_found")
	case errors.Is(err, postgresadapter.ErrAccountNotQuarantined):
		return fail("account_not_quarantined")
	case err != nil:
		logger.ErrorContext(ctx, "account change failed", "error_code", "account_change_failure", "error", err)
		return 1
	}
	if err := json.NewEncoder(output).Encode(accountCommandOutput{
		Operation: operation, PrincipalID: principalID.String(), AccountID: report.AccountID.String(),
		RecoveryState: report.RecoveryState, SessionGeneration: report.SessionGeneration,
		SessionsEnded: report.SessionsEnded, ChangedAt: report.ChangedAt.Format(time.RFC3339),
	}); err != nil {
		return fail("account_output_failure")
	}
	return 0
}
