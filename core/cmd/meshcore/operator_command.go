package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

type operatorService interface {
	Status(context.Context) (postgresadapter.OperatorReport, error)
	Apply(context.Context, postgresadapter.OperatorApplyOptions) (postgresadapter.OperatorApplyResult, error)
	Close(context.Context) error
}

type operatorServiceFactory func(context.Context, config.OperatorMigrationConfig) (operatorService, error)

type operatorStepOutput struct {
	Step         string   `json:"step"`
	Version      int64    `json:"version"`
	Kind         string   `json:"kind"`
	AfterRollout bool     `json:"after_rollout"`
	Status       string   `json:"status"`
	Missing      []string `json:"missing,omitempty"`
}

type operatorWaitingOutput struct {
	Step   string `json:"step"`
	Reason string `json:"reason"`
}

type operatorCommandOutput struct {
	Operation            string                  `json:"operation"`
	DryRun               bool                    `json:"dry_run,omitempty"`
	CurrentSchemaVersion int64                   `json:"current_schema_version"`
	Applied              []string                `json:"applied,omitempty"`
	Replayed             []string                `json:"replayed,omitempty"`
	Waiting              []operatorWaitingOutput `json:"waiting,omitempty"`
	Pending              []string                `json:"pending"`
	RoleMemberships      []string                `json:"role_memberships,omitempty"`
	Steps                []operatorStepOutput    `json:"steps,omitempty"`
}

// runMigrateOperator runs "meshcore migrate operator status|apply" with the
// operator's own settings only.
func runMigrateOperator(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
	factory operatorServiceFactory,
) (exitCode int) {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	operation, options, ok := parseOperatorArguments(args)
	if !ok {
		logger.ErrorContext(ctx, "operator migration failed", "error_code", "invalid_operator_arguments")
		if _, err := io.WriteString(errorOutput, usage); err != nil {
			return 1
		}
		return 2
	}
	operatorConfig, err := config.LoadOperatorMigration(lookup)
	if err != nil || factory == nil {
		logger.ErrorContext(ctx, "operator migration failed",
			"error_code", "invalid_operator_configuration", "error", err)
		return 1
	}
	service, err := factory(ctx, operatorConfig)
	if err != nil {
		logger.ErrorContext(ctx, "operator migration failed", "error_code", "operator_open_failure", "error", err)
		return 1
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), operatorConfig.ConnectTimeout)
		defer cancel()
		if err := service.Close(closeContext); err != nil {
			logger.ErrorContext(closeContext, "operator migration cleanup failed",
				"error_code", "operator_cleanup_failure", "error", err)
			exitCode = 1
		}
	}()

	result := operatorCommandOutput{Operation: "operator " + operation}
	if operation == "status" {
		report, statusErr := service.Status(ctx)
		if statusErr != nil {
			logOperatorFailure(ctx, logger, "operator_status_failure", statusErr)
			return 1
		}
		result.CurrentSchemaVersion = report.CurrentSchemaVersion
		result.Steps = operatorStepsOutput(report)
		result.Pending = operatorPendingOutput(report)
		result.RoleMemberships = report.Memberships
	} else {
		applied, applyErr := service.Apply(ctx, options)
		if applyErr != nil {
			logOperatorFailure(ctx, logger, "operator_apply_failure", applyErr)
			return 1
		}
		result.DryRun = applied.DryRun
		result.CurrentSchemaVersion = applied.Report.CurrentSchemaVersion
		result.Applied = applied.Applied
		result.Replayed = applied.Replayed
		for _, waiting := range applied.Waiting {
			result.Waiting = append(result.Waiting, operatorWaitingOutput{Step: waiting.Step, Reason: string(waiting.Reason)})
		}
		result.Pending = operatorPendingOutput(applied.Report)
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		logger.ErrorContext(ctx, "operator migration failed", "error_code", "operator_output_failure")
		return 1
	}
	return 0
}

func parseOperatorArguments(args []string) (string, postgresadapter.OperatorApplyOptions, bool) {
	options := postgresadapter.OperatorApplyOptions{}
	if len(args) == 0 || args[0] != "status" && args[0] != "apply" {
		return "", options, false
	}
	flags := flag.NewFlagSet("meshcore migrate operator "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if args[0] == "apply" {
		flags.BoolVar(&options.DryRun, "dry-run", false, "run and verify the steps, then roll back")
		flags.BoolVar(&options.AfterRollout, "after-rollout", false,
			"no replica of the previous release is left; run the steps that wait for it")
		flags.Int64Var(&options.Through, "through", 0, "newest migration whose steps may run")
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return "", options, false
	}
	through := false
	flags.Visit(func(set *flag.Flag) { through = through || set.Name == "through" })
	if through && options.Through <= 0 {
		return "", options, false
	}
	return args[0], options, true
}

// logOperatorFailure logs codes only (error_code, step, reason, SQLSTATE),
// never the error text: PostgreSQL errors may echo connection or object
// details.
func logOperatorFailure(ctx context.Context, logger *slog.Logger, code string, err error) {
	attributes := []any{"error_code", code}
	var refused *postgresadapter.OperatorStepRefusedError
	var failed *postgresadapter.OperatorStepFailedError
	switch {
	case errors.As(err, &refused):
		attributes = []any{"error_code", "operator_step_refused", "step", refused.Step, "reason", string(refused.Reason)}
	case errors.As(err, &failed):
		attributes = []any{"error_code", "operator_step_failure", "step", failed.Step, "sqlstate", failed.SQLState}
	case errors.Is(err, postgresadapter.ErrOperatorPreflight):
		attributes = []any{"error_code", "operator_preflight_failure"}
	case errors.Is(err, postgresadapter.ErrOperatorStepUnverified):
		attributes = []any{"error_code", "operator_step_unverified"}
	case errors.Is(err, postgresadapter.ErrMigrationState):
		attributes = []any{"error_code", "operator_schema_not_clean"}
	}
	logger.ErrorContext(ctx, "operator migration failed", attributes...)
}

func operatorStepsOutput(report postgresadapter.OperatorReport) []operatorStepOutput {
	steps := make([]operatorStepOutput, 0, len(report.Steps))
	for _, step := range report.Steps {
		steps = append(steps, operatorStepOutput{Step: step.Name, Version: step.Version, Kind: step.Kind,
			AfterRollout: step.AfterRollout, Status: string(step.State), Missing: step.Missing})
	}
	return steps
}

func operatorPendingOutput(report postgresadapter.OperatorReport) []string {
	pending := []string{}
	for _, step := range report.Pending() {
		pending = append(pending, step.Name)
	}
	return pending
}

func openOperatorService(ctx context.Context, operatorConfig config.OperatorMigrationConfig) (operatorService, error) {
	return postgresadapter.OpenOperatorRunner(ctx, postgresadapter.OperatorOptions{
		Address:          operatorConfig.PostgreSQL.Address,
		Database:         operatorConfig.PostgreSQL.Database,
		User:             operatorConfig.PostgreSQL.User,
		PasswordFile:     operatorConfig.PostgreSQL.PasswordFile,
		CAFile:           operatorConfig.PostgreSQL.CAFile,
		ConnectTimeout:   operatorConfig.ConnectTimeout,
		LockTimeout:      operatorConfig.LockTimeout,
		StatementTimeout: operatorConfig.StatementTimeout,
	})
}
