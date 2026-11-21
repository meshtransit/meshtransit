package main

import (
	"context"
	"io"
	"log/slog"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
)

// runInstallBootstrapDeployment is "meshcore install bootstrap deployment"
// (V1-11 S2h, the chart's Job after the migration): the first deployment,
// its login provider and first admins from the bootstrap plan, only when
// the Core database has no deployment yet. Afterwards it changes nothing,
// so a first admin removed in the Console does not come back and a changed
// plan has no effect. Settings: the migration's (MESHTRANSIT_MIGRATION_*),
// the api role's with the login profile, and MESHTRANSIT_BOOTSTRAP_PLAN_FILE.
func runInstallBootstrapDeployment(ctx context.Context, lookup config.LookupFunc, output, errorOutput io.Writer,
	logger *slog.Logger, dependencies installDependencies,
) int {
	migration, err := config.LoadMigration(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", "invalid_migration_configuration", "error", err)
		return 1
	}
	installed, err := dependencies.deploymentInstalled(ctx, postgresadapter.MigrationOptions{
		Address: migration.PostgreSQL.Address, Database: migration.PostgreSQL.Database,
		User: migration.PostgreSQL.User, PasswordFile: migration.PostgreSQL.PasswordFile,
		CAFile: migration.PostgreSQL.CAFile, ConnectTimeout: migration.ConnectTimeout,
		LockTimeout: migration.LockTimeout, StatementTimeout: migration.StatementTimeout,
		Actor: migration.Actor, CodeRelease: buildinfo.Release(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", "bootstrap_unavailable", "error", err)
		return 1
	}
	if installed {
		return writeInstallReport(output, map[string]any{
			"operation": "install bootstrap deployment", "skipped": "already installed",
		})
	}
	if dependencies.bootstrapDeployment == nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", "install_setup_invalid")
		return 1
	}
	return dependencies.bootstrapDeployment(ctx, lookup, output, errorOutput)
}
