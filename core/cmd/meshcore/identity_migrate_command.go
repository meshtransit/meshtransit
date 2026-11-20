package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
	"meshtransit.net/core/internal/platform/selfhost"
)

// runIdentityMigrate is "meshcore identity migrate" (the chart's identity
// migration Job, V1-11): with the identity broker's migration login (the
// owner of its database, MESHTRANSIT_MIGRATION_* settings), bring the
// broker's schema to the pinned broker's and give its runtime login the
// data access it needs. It runs in the identity image (dexbroker build).
func runIdentityMigrate(ctx context.Context, lookup config.LookupFunc, output, errorOutput io.Writer) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	migration, err := config.LoadMigration(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "identity migrate failed", "error_code", "invalid_migration_configuration", "error", err)
		return 1
	}
	if err := migrateIdentityDatabase(ctx, migration, logger); err != nil {
		logger.ErrorContext(ctx, "identity migrate failed", "error_code", "identity_migration_failure", "error", err)
		return 1
	}
	return writeInstallReport(output, map[string]any{"operation": "identity migrate", "migrated": true})
}

// migrateIdentityDatabase migrates the broker's schema, then grants its
// runtime login (meshcore setup migrate and the chart's Job).
func migrateIdentityDatabase(ctx context.Context, migration config.MigrationConfig, logger *slog.Logger) error {
	if err := migrateIdentityStorage(ctx, migration, logger); err != nil {
		return fmt.Errorf("identity broker schema: %w", err)
	}
	if err := postgresadapter.GrantIdentityRuntime(ctx, postgresadapter.MigrationOptions{
		Address: migration.PostgreSQL.Address, Database: migration.PostgreSQL.Database,
		User: migration.PostgreSQL.User, PasswordFile: migration.PostgreSQL.PasswordFile,
		CAFile: migration.PostgreSQL.CAFile, ConnectTimeout: migration.ConnectTimeout,
		LockTimeout: migration.LockTimeout, StatementTimeout: migration.StatementTimeout,
		Actor: migration.Actor, CodeRelease: buildinfo.Release(),
	}, selfhost.IdentityRuntimeRole); err != nil {
		return fmt.Errorf("identity broker grants: %w", err)
	}
	return nil
}
