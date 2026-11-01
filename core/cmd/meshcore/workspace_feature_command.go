package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

type workspaceFeatureOutput struct {
	Operation   string                    `json:"operation"`
	WorkspaceID string                    `json:"workspace_id"`
	Changed     bool                      `json:"changed"`
	Features    []workspaceFeatureListing `json:"features"`
	// EnabledNetworks have logging on; after a revoke they stop at their
	// next ticket renewal.
	EnabledNetworks int64 `json:"enabled_networks"`
}

type workspaceFeatureListing struct {
	Feature   string `json:"feature"`
	Note      string `json:"note"`
	GrantedAt string `json:"granted_at"`
}

// runWorkspaceFeature grants, revokes or lists the paid features of one
// Workspace as the migration role, with the migration database
// credentials (connection logs design §16b C22):
//
//	meshcore workspace feature grant <workspace-id> connection_logs <note>
//	meshcore workspace feature revoke <workspace-id> connection_logs
//	meshcore workspace feature list <workspace-id>
func runWorkspaceFeature(ctx context.Context, args []string, lookup config.LookupFunc,
	output, errorOutput io.Writer,
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	fail := func(code string) int {
		logger.ErrorContext(ctx, "workspace feature change failed", "error_code", code)
		return 1
	}
	if len(args) < 2 {
		return fail("invalid_workspace_feature_operation")
	}
	operation := args[0]
	workspaceID, err := publicid.Parse(args[1])
	if err != nil || workspaceID.String() != args[1] {
		return fail("invalid_workspace_feature_operation")
	}
	switch {
	case operation == "list" && len(args) == 2:
	case operation == "grant" && len(args) >= 4, operation == "revoke" && len(args) == 3:
	default:
		return fail("invalid_workspace_feature_operation")
	}
	migrationConfig, err := config.LoadMigration(lookup)
	if err != nil {
		return fail("invalid_migration_configuration")
	}
	options := postgresadapter.MigrationOptions{
		Address: migrationConfig.PostgreSQL.Address, Database: migrationConfig.PostgreSQL.Database,
		User: migrationConfig.PostgreSQL.User, PasswordFile: migrationConfig.PostgreSQL.PasswordFile,
		CAFile: migrationConfig.PostgreSQL.CAFile, ConnectTimeout: migrationConfig.ConnectTimeout,
		LockTimeout: migrationConfig.LockTimeout, StatementTimeout: migrationConfig.StatementTimeout,
		Actor: migrationConfig.Actor, CodeRelease: buildinfo.Release(),
	}
	var report postgresadapter.WorkspaceFeatureReport
	switch operation {
	case "list":
		report, err = postgresadapter.ListWorkspaceFeatures(ctx, options, workspaceID)
	case "grant":
		report, err = postgresadapter.ChangeWorkspaceFeature(ctx, options, workspaceID, args[2], true,
			strings.Join(args[3:], " "))
	case "revoke":
		report, err = postgresadapter.ChangeWorkspaceFeature(ctx, options, workspaceID, args[2], false, "")
	}
	switch {
	case errors.Is(err, postgresadapter.ErrWorkspaceFeatureInvalid):
		return fail("invalid_workspace_feature_operation")
	case errors.Is(err, postgresadapter.ErrWorkspaceNotFound):
		return fail("workspace_not_found")
	case err != nil:
		logger.ErrorContext(ctx, "workspace feature change failed", "error_code", "workspace_feature_failure",
			"error", err)
		return 1
	}
	listing := make([]workspaceFeatureListing, 0, len(report.Features))
	for _, feature := range report.Features {
		listing = append(listing, workspaceFeatureListing{
			Feature: feature.Feature, Note: feature.Note,
			GrantedAt: feature.GrantedAt.Format(time.RFC3339),
		})
	}
	if err := json.NewEncoder(output).Encode(workspaceFeatureOutput{
		Operation: operation, WorkspaceID: workspaceID.String(), Changed: report.Changed, Features: listing,
		EnabledNetworks: report.EnabledNetworks,
	}); err != nil {
		return fail("workspace_feature_output_failure")
	}
	return 0
}
