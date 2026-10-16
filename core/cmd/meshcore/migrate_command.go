package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

type migrationService interface {
	Status(context.Context) (postgresadapter.MigrationStatus, error)
	Up(context.Context) (postgresadapter.MigrationResult, error)
	Verify(context.Context) (postgresadapter.MigrationVerification, error)
	Close(context.Context) error
}

type migrationServiceFactory func(context.Context, config.MigrationConfig) (migrationService, error)

type migrationCommandOutput struct {
	Operation            string `json:"operation"`
	Applied              *int   `json:"applied,omitempty"`
	CurrentSchemaVersion int64  `json:"current_schema_version"`
	LatestSchemaVersion  int64  `json:"latest_schema_version"`
	State                string `json:"state"`
	// Verify only: every operator step of the applied migrations, and the
	// ones that do not hold.
	OperatorSteps        []operatorStepOutput `json:"operator_steps,omitempty"`
	PendingOperatorSteps []string             `json:"pending_operator_steps,omitempty"`
}

// verifyIncompleteExitCode reports a schema that is readable but not ready
// for this binary: migrations or operator steps pending.
const verifyIncompleteExitCode = 3

func runMigrate(
	ctx context.Context,
	operation string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
	factory migrationServiceFactory,
) (exitCode int) {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	migrationConfig, err := config.LoadMigration(lookup)
	if err != nil || factory == nil {
		logger.ErrorContext(
			ctx,
			"migration failed",
			"error_code", "invalid_migration_configuration",
			"error", err,
		)
		return 1
	}
	service, err := factory(ctx, migrationConfig)
	if err != nil {
		logger.ErrorContext(ctx, "migration failed", "error_code", "migration_open_failure", "error", err)
		return 1
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			migrationConfig.ConnectTimeout,
		)
		defer cancel()
		if err := service.Close(closeContext); err != nil {
			logger.ErrorContext(
				closeContext,
				"migration cleanup failed",
				"error_code", "migration_cleanup_failure",
				"error", err,
			)
			exitCode = 1
		}
	}()

	result := migrationCommandOutput{Operation: operation}
	switch operation {
	case "status":
		status, statusErr := service.Status(ctx)
		if statusErr != nil {
			logger.ErrorContext(ctx, "migration failed", "error_code", "migration_status_failure", "error", statusErr)
			return 1
		}
		result.CurrentSchemaVersion = status.CurrentVersion
		result.LatestSchemaVersion = status.LatestVersion
		result.State = string(status.State)
	case "up":
		migrationResult, upErr := service.Up(ctx)
		if upErr != nil {
			logger.ErrorContext(ctx, "migration failed", "error_code", "migration_apply_failure", "error", upErr)
			return 1
		}
		applied := migrationResult.Applied
		result.Applied = &applied
		result.CurrentSchemaVersion = migrationResult.Status.CurrentVersion
		result.LatestSchemaVersion = migrationResult.Status.LatestVersion
		result.State = string(migrationResult.Status.State)
	case "verify":
		verification, verifyErr := service.Verify(ctx)
		if verifyErr != nil {
			logger.ErrorContext(ctx, "migration failed", "error_code", "migration_verify_failure", "error", verifyErr)
			return 1
		}
		result.CurrentSchemaVersion = verification.Status.CurrentVersion
		result.LatestSchemaVersion = verification.Status.LatestVersion
		result.State = string(verification.Status.State)
		result.OperatorSteps = operatorStepsOutput(verification.Operator)
		result.PendingOperatorSteps = operatorPendingOutput(verification.Operator)
	default:
		logger.ErrorContext(ctx, "migration failed", "error_code", "invalid_migration_operation")
		return 2
	}

	if err := json.NewEncoder(output).Encode(result); err != nil {
		logger.ErrorContext(ctx, "migration failed", "error_code", "migration_output_failure")
		return 1
	}
	if operation == "verify" && (result.State != string(postgresadapter.MigrationStateClean) ||
		len(result.PendingOperatorSteps) != 0) {
		logger.WarnContext(ctx, "migration verification incomplete", "error_code", "migration_verify_incomplete",
			"schema_state", result.State, "pending_operator_steps", result.PendingOperatorSteps)
		return verifyIncompleteExitCode
	}
	return 0
}

func openMigrationService(
	ctx context.Context,
	migrationConfig config.MigrationConfig,
) (migrationService, error) {
	return postgresadapter.OpenMigrationRunner(ctx, postgresadapter.MigrationOptions{
		Address:          migrationConfig.PostgreSQL.Address,
		Database:         migrationConfig.PostgreSQL.Database,
		User:             migrationConfig.PostgreSQL.User,
		PasswordFile:     migrationConfig.PostgreSQL.PasswordFile,
		CAFile:           migrationConfig.PostgreSQL.CAFile,
		ConnectTimeout:   migrationConfig.ConnectTimeout,
		LockTimeout:      migrationConfig.LockTimeout,
		StatementTimeout: migrationConfig.StatementTimeout,
		Actor:            migrationConfig.Actor,
		CodeRelease:      buildinfo.Release(),
	})
}
