package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

func TestRunMigrateOperatorApplyPassesOptionsAndReportsSteps(t *testing.T) {
	t.Parallel()
	service := &fakeOperatorService{result: postgresadapter.OperatorApplyResult{
		DryRun:   true,
		Applied:  []string{"000170_device_alias_consumer_readmission_ownership"},
		Replayed: []string{"000171_device_alias_provider_readmission_ownership"},
		Waiting: []postgresadapter.OperatorWaiting{
			{Step: "000172_example_ownership", Reason: postgresadapter.OperatorWaitMigration},
		},
		Report: postgresadapter.OperatorReport{CurrentSchemaVersion: 171},
	}}
	var output, errorOutput bytes.Buffer
	exitCode := runMigrateOperator(t.Context(), []string{"apply", "--dry-run", "--after-rollout", "--through", "171"},
		operatorLookup(nil), &output, &errorOutput, fakeOperatorFactory(service))
	if exitCode != 0 {
		t.Fatalf("exit %d: %s", exitCode, errorOutput.String())
	}
	if service.options != (postgresadapter.OperatorApplyOptions{DryRun: true, AfterRollout: true, Through: 171}) ||
		service.applyCalls != 1 || service.closeCalls != 1 {
		t.Fatalf("service = %+v", service)
	}
	var result operatorCommandOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("output %q: %v", output.String(), err)
	}
	if result.Operation != "operator apply" || !result.DryRun || result.CurrentSchemaVersion != 171 ||
		strings.Join(result.Applied, ",") != "000170_device_alias_consumer_readmission_ownership" ||
		len(result.Waiting) != 1 || result.Waiting[0].Reason != "awaiting_migration" {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunMigrateOperatorStatusListsEveryStep(t *testing.T) {
	t.Parallel()
	service := &fakeOperatorService{report: postgresadapter.OperatorReport{CurrentSchemaVersion: 171, Steps: []postgresadapter.OperatorStepStatus{
		{Name: "000080_direct_device_map_role", Version: 80, Kind: "role", State: postgresadapter.OperatorStepApplied},
		{Name: "000170_device_alias_consumer_readmission_ownership", Version: 170, Kind: "ownership", AfterRollout: true,
			State: postgresadapter.OperatorStepPending, Missing: []string{"mesh_worker lacks EXECUTE on mesh_ops.x(UUID)"}},
	}}}
	var output, errorOutput bytes.Buffer
	if exitCode := runMigrateOperator(t.Context(), []string{"status"}, operatorLookup(nil), &output, &errorOutput,
		fakeOperatorFactory(service)); exitCode != 0 {
		t.Fatalf("exit %d: %s", exitCode, errorOutput.String())
	}
	var result operatorCommandOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Steps) != 2 || result.Steps[1].Status != "pending" || !result.Steps[1].AfterRollout ||
		len(result.Steps[1].Missing) != 1 || strings.Join(result.Pending, ",") != "000170_device_alias_consumer_readmission_ownership" {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunMigrateOperatorRejectsUsageWithoutConnecting(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{}, {"run"}, {"apply", "--force"}, {"apply", "extra"}, {"apply", "--through", "0"},
		{"apply", "--through", "x"}, {"status", "--dry-run"},
	} {
		service := &fakeOperatorService{}
		called := false
		factory := func(context.Context, config.OperatorMigrationConfig) (operatorService, error) {
			called = true
			return service, nil
		}
		var output, errorOutput bytes.Buffer
		if exitCode := runMigrateOperator(t.Context(), args, operatorLookup(nil), &output, &errorOutput, factory); exitCode != 2 || called {
			t.Errorf("%v: exit %d, connected %t", args, exitCode, called)
		}
	}
}

// The operator command reads only its own settings: the migrator's or the
// runtime's never stand in for them, and a credential path is never printed.
func TestRunMigrateOperatorRequiresTheOperatorSettings(t *testing.T) {
	t.Parallel()
	lookup := func(key string) (string, bool) {
		values := map[string]string{
			"MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS":       "database.internal:5432",
			"MESHTRANSIT_MIGRATION_POSTGRES_DATABASE":      "meshtransit",
			"MESHTRANSIT_MIGRATION_POSTGRES_USER":          "mesh_migrator",
			"MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE": "/private/operator/credential",
			"MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE":       "/run/secrets/ca.pem",
			"MESHTRANSIT_POSTGRES_RUNTIME_USER":            "mesh_runtime",
			"MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE":  "/private/operator/credential",
		}
		value, ok := values[key]
		return value, ok
	}
	called := false
	factory := func(context.Context, config.OperatorMigrationConfig) (operatorService, error) {
		called = true
		return &fakeOperatorService{}, nil
	}
	var output, errorOutput bytes.Buffer
	if exitCode := runMigrateOperator(t.Context(), []string{"status"}, lookup, &output, &errorOutput, factory); exitCode != 1 || called {
		t.Fatalf("exit %d, connected %t", exitCode, called)
	}
	if strings.Contains(errorOutput.String(), "/private/operator/credential") || output.Len() != 0 {
		t.Fatalf("output %q error %q", output.String(), errorOutput.String())
	}
}

func TestRunMigrateOperatorNamesTheRefusedStep(t *testing.T) {
	t.Parallel()
	service := &fakeOperatorService{applyErr: fmt.Errorf("plan: %w", &postgresadapter.OperatorStepRefusedError{
		Step: "000172_example_ownership", Reason: postgresadapter.OperatorWaitMigration})}
	var output, errorOutput bytes.Buffer
	exitCode := runMigrateOperator(t.Context(), []string{"apply", "--through", "172"}, operatorLookup(nil), &output,
		&errorOutput, fakeOperatorFactory(service))
	if exitCode != 1 || output.Len() != 0 || service.closeCalls != 1 {
		t.Fatalf("exit %d output %q close %d", exitCode, output.String(), service.closeCalls)
	}
	for _, want := range []string{`"error_code":"operator_step_refused"`, `"step":"000172_example_ownership"`,
		`"reason":"awaiting_migration"`} {
		if !strings.Contains(errorOutput.String(), want) {
			t.Fatalf("error output lacks %s: %s", want, errorOutput.String())
		}
	}
}

func TestRunMigrateVerifyFailsWhileAnOperatorStepIsPending(t *testing.T) {
	t.Parallel()
	service := &fakeMigrationService{verification: postgresadapter.MigrationVerification{
		Status: postgresadapter.MigrationStatus{CurrentVersion: 171, LatestVersion: 171, State: postgresadapter.MigrationStateClean},
		Operator: postgresadapter.OperatorReport{CurrentSchemaVersion: 171, Steps: []postgresadapter.OperatorStepStatus{
			{Name: "000171_device_alias_provider_readmission_ownership", Version: 171, Kind: "ownership",
				State: postgresadapter.OperatorStepPending, Missing: []string{"owner of mesh_ops.x(UUID) is not mesh_y"}},
		}},
	}}
	var output, errorOutput bytes.Buffer
	exitCode := runMigrate(t.Context(), "verify", migrationLookup(nil), &output, &errorOutput, fakeMigrationFactory(service, nil))
	if exitCode != 3 || service.verifyCalls != 1 || service.closeCalls != 1 {
		t.Fatalf("exit %d verify %d close %d: %s", exitCode, service.verifyCalls, service.closeCalls, errorOutput.String())
	}
	var result migrationCommandOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Operation != "verify" || strings.Join(result.PendingOperatorSteps, ",") !=
		"000171_device_alias_provider_readmission_ownership" || len(result.OperatorSteps) != 1 ||
		result.OperatorSteps[0].Missing[0] != "owner of mesh_ops.x(UUID) is not mesh_y" {
		t.Fatalf("result = %+v", result)
	}
	service.verification.Operator.Steps[0].State = postgresadapter.OperatorStepApplied
	service.verification.Operator.Steps[0].Missing = nil
	output.Reset()
	if exitCode := runMigrate(t.Context(), "verify", migrationLookup(nil), &output, &errorOutput,
		fakeMigrationFactory(service, nil)); exitCode != 0 {
		t.Fatalf("clean verify exit %d", exitCode)
	}
	service.verification.Status.State = postgresadapter.MigrationStatePending
	if exitCode := runMigrate(t.Context(), "verify", migrationLookup(nil), &output, &errorOutput,
		fakeMigrationFactory(service, nil)); exitCode != 3 {
		t.Fatalf("pending migration verify exit %d", exitCode)
	}
}

type fakeOperatorService struct {
	report     postgresadapter.OperatorReport
	result     postgresadapter.OperatorApplyResult
	applyErr   error
	options    postgresadapter.OperatorApplyOptions
	applyCalls int
	closeCalls int
}

func (service *fakeOperatorService) Status(context.Context) (postgresadapter.OperatorReport, error) {
	return service.report, nil
}

func (service *fakeOperatorService) Apply(
	_ context.Context,
	options postgresadapter.OperatorApplyOptions,
) (postgresadapter.OperatorApplyResult, error) {
	service.applyCalls++
	service.options = options
	return service.result, service.applyErr
}

func (service *fakeOperatorService) Close(context.Context) error {
	service.closeCalls++
	return nil
}

func fakeOperatorFactory(service operatorService) operatorServiceFactory {
	return func(context.Context, config.OperatorMigrationConfig) (operatorService, error) {
		return service, nil
	}
}

func operatorLookup(overrides map[string]string) config.LookupFunc {
	values := map[string]string{ //nolint:gosec // G101: fixtures contain file paths, not credentials.
		"MESHTRANSIT_OPERATOR_POSTGRES_ADDRESS":       "database.internal:5432",
		"MESHTRANSIT_OPERATOR_POSTGRES_DATABASE":      "meshtransit",
		"MESHTRANSIT_OPERATOR_POSTGRES_USER":          "postgres",
		"MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE": "/run/secrets/operator-postgres-password",
		"MESHTRANSIT_OPERATOR_POSTGRES_CA_FILE":       "/run/secrets/operator-postgres-ca.pem",
	}
	for key, value := range overrides {
		values[key] = value
	}
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
