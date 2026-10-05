package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/bootstrap"
	"github.com/meshtransit/meshtransit/internal/buildinfo"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/observability"
)

type bootstrapCommandOutput struct {
	Operation         string `json:"operation"`
	Committed         bool   `json:"committed"`
	DeploymentCreated bool   `json:"deployment_created"`
	ProviderCreated   bool   `json:"provider_created"`
	AccountsCreated   int    `json:"accounts_created"`
	AccountsExisting  int    `json:"accounts_existing"`
	WorkspacesCreated int    `json:"workspaces_created"`
}

// runBootstrap applies the installation plan. It loads the same api-role
// configuration and private login file meshcore serves, so the provider and
// client rows always equal what login checks, plus the migration database
// credentials and MESHTRANSIT_BOOTSTRAP_PLAN_FILE. "check" runs the whole
// transaction and rolls back; "apply" commits. Re-running is a no-op.
func runBootstrap(ctx context.Context, operation string, lookup config.LookupFunc, output, errorOutput io.Writer) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	fail := func(code string) int {
		logger.ErrorContext(ctx, "bootstrap failed", "error_code", code)
		return 1
	}
	if operation != "check" && operation != "apply" {
		return fail("invalid_bootstrap_operation")
	}
	processConfig, err := config.Load(lookup)
	if err != nil || processConfig.PrivateLogin == nil {
		return fail("invalid_bootstrap_configuration")
	}
	profile, err := processConfig.PrivateLogin.Load(ctx, processConfig)
	if err != nil {
		return fail("private_login_configuration_failure")
	}
	material, err := profile.Keys().Load(ctx)
	if err != nil {
		return fail("private_identity_key_failure")
	}
	subjectKey, err := bootstrapSubjectKey(material.SubjectActive)
	material.Clear()
	if err != nil {
		return fail("private_identity_key_failure")
	}
	contents, err := config.LoadBootstrapPlan(lookup)
	if err != nil {
		return fail("bootstrap_plan_unavailable")
	}
	plan, err := bootstrap.NewPlan(contents, profile.Route(), subjectKey)
	clear(contents)
	if err != nil {
		return fail("bootstrap_plan_invalid")
	}
	migrationConfig, err := config.LoadMigration(lookup)
	if err != nil {
		return fail("invalid_migration_configuration")
	}
	report, err := postgresadapter.ApplyBootstrap(ctx, postgresadapter.MigrationOptions{
		Address: migrationConfig.PostgreSQL.Address, Database: migrationConfig.PostgreSQL.Database,
		User: migrationConfig.PostgreSQL.User, PasswordFile: migrationConfig.PostgreSQL.PasswordFile,
		CAFile: migrationConfig.PostgreSQL.CAFile, ConnectTimeout: migrationConfig.ConnectTimeout,
		LockTimeout: migrationConfig.LockTimeout, StatementTimeout: migrationConfig.StatementTimeout,
		Actor: migrationConfig.Actor, CodeRelease: buildinfo.Release(),
	}, plan, operation == "apply")
	if err != nil {
		logger.ErrorContext(ctx, "bootstrap failed", "error_code", "bootstrap_apply_failure", "error", err)
		return 1
	}
	if err := json.NewEncoder(output).Encode(bootstrapCommandOutput{
		Operation: operation, Committed: operation == "apply",
		DeploymentCreated: report.DeploymentCreated, ProviderCreated: report.ProviderCreated,
		AccountsCreated: report.AccountsCreated, AccountsExisting: report.AccountsExisting,
		WorkspacesCreated: report.WorkspacesCreated,
	}); err != nil {
		return fail("bootstrap_output_failure")
	}
	return 0
}

func bootstrapSubjectKey(material config.ResidentKeyMaterial) (oidcauth.SubjectKey, error) {
	id, err := oidcauth.NewDigestKeyID(material.ID)
	if err != nil {
		return oidcauth.SubjectKey{}, err
	}
	return oidcauth.NewSubjectKey(id, material.Bytes[:])
}
