package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

func TestRunMigrateStatusWritesMachineReadableState(t *testing.T) {
	t.Parallel()

	service := &fakeMigrationService{
		status: postgresadapter.MigrationStatus{
			CurrentVersion: 0,
			LatestVersion:  1,
			State:          postgresadapter.MigrationStateUninitialized,
		},
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	exitCode := runMigrate(
		context.Background(),
		"status",
		migrationLookup(nil),
		&output,
		&errorOutput,
		fakeMigrationFactory(service, nil),
	)
	if exitCode != 0 {
		t.Fatalf("runMigrate() = %d, want 0; error output = %s", exitCode, errorOutput.String())
	}
	var result migrationCommandOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %q", err, output.String())
	}
	if result.Operation != "status" || result.Applied != nil ||
		result.CurrentSchemaVersion != 0 || result.LatestSchemaVersion != 1 || result.State != "uninitialized" {
		t.Fatalf("migration status output = %+v", result)
	}
	if service.statusCalls != 1 || service.upCalls != 0 || service.closeCalls != 1 {
		t.Fatalf("service calls = status %d, up %d, close %d", service.statusCalls, service.upCalls, service.closeCalls)
	}
}

func TestRunMigrateUpReportsAppliedCount(t *testing.T) {
	t.Parallel()

	service := &fakeMigrationService{
		result: postgresadapter.MigrationResult{
			Applied: 1,
			Status: postgresadapter.MigrationStatus{
				CurrentVersion: 1,
				LatestVersion:  1,
				State:          postgresadapter.MigrationStateClean,
			},
		},
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	exitCode := runMigrate(
		context.Background(),
		"up",
		migrationLookup(nil),
		&output,
		&errorOutput,
		fakeMigrationFactory(service, nil),
	)
	if exitCode != 0 {
		t.Fatalf("runMigrate() = %d, want 0; error output = %s", exitCode, errorOutput.String())
	}
	var result migrationCommandOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %q", err, output.String())
	}
	if result.Operation != "up" || result.Applied == nil || *result.Applied != 1 ||
		result.CurrentSchemaVersion != 1 || result.State != "clean" {
		t.Fatalf("migration up output = %+v", result)
	}
	if service.statusCalls != 0 || service.upCalls != 1 || service.closeCalls != 1 {
		t.Fatalf("service calls = status %d, up %d, close %d", service.statusCalls, service.upCalls, service.closeCalls)
	}
}

func TestRunMigrateRejectsConfigurationWithoutOpeningConnection(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	factoryCalled := false
	factory := func(context.Context, config.MigrationConfig) (migrationService, error) {
		factoryCalled = true
		return nil, nil
	}

	exitCode := runMigrate(
		context.Background(),
		"status",
		func(key string) (string, bool) {
			if key == "MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE" {
				return "/private/operator/credential", true
			}
			return "", false
		},
		&output,
		&errorOutput,
		factory,
	)
	if exitCode != 1 || factoryCalled || output.Len() != 0 {
		t.Fatalf("result = exit %d, factory %t, output %q", exitCode, factoryCalled, output.String())
	}
	if strings.Contains(errorOutput.String(), "/private/operator/credential") {
		t.Fatalf("error output exposed credential path: %s", errorOutput.String())
	}
}

func TestRunMigrateRedactsOperationFailureAndStillCloses(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("database.internal secret migration detail")
	service := &fakeMigrationService{statusErr: wantErr}
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	exitCode := runMigrate(
		context.Background(),
		"status",
		migrationLookup(nil),
		&output,
		&errorOutput,
		fakeMigrationFactory(service, nil),
	)
	if exitCode != 1 || service.closeCalls != 1 || output.Len() != 0 {
		t.Fatalf("result = exit %d, close %d, output %q", exitCode, service.closeCalls, output.String())
	}
	if strings.Contains(errorOutput.String(), "database.internal") || strings.Contains(errorOutput.String(), "secret") {
		t.Fatalf("error output exposed migration detail: %s", errorOutput.String())
	}
}

type fakeMigrationService struct {
	status       postgresadapter.MigrationStatus
	result       postgresadapter.MigrationResult
	verification postgresadapter.MigrationVerification
	statusErr    error
	upErr        error
	closeErr     error
	statusCalls  int
	upCalls      int
	verifyCalls  int
	closeCalls   int
}

func (service *fakeMigrationService) Verify(context.Context) (postgresadapter.MigrationVerification, error) {
	service.verifyCalls++
	return service.verification, nil
}

func (service *fakeMigrationService) Status(context.Context) (postgresadapter.MigrationStatus, error) {
	service.statusCalls++
	return service.status, service.statusErr
}

func (service *fakeMigrationService) Up(context.Context) (postgresadapter.MigrationResult, error) {
	service.upCalls++
	return service.result, service.upErr
}

func (service *fakeMigrationService) Close(context.Context) error {
	service.closeCalls++
	return service.closeErr
}

func fakeMigrationFactory(
	service migrationService,
	err error,
) migrationServiceFactory {
	return func(context.Context, config.MigrationConfig) (migrationService, error) {
		return service, err
	}
}

func migrationLookup(overrides map[string]string) config.LookupFunc {
	values := map[string]string{ //nolint:gosec // G101: fixtures contain file paths, not credentials.
		"MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS":       "database.internal:5432",
		"MESHTRANSIT_MIGRATION_POSTGRES_DATABASE":      "meshtransit",
		"MESHTRANSIT_MIGRATION_POSTGRES_USER":          "mesh_migrator",
		"MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE": "/run/secrets/migration-postgres-password",
		"MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE":       "/run/secrets/migration-postgres-ca.pem",
		"MESHTRANSIT_MIGRATION_ACTOR":                  "deployment-controller",
	}
	for key, value := range overrides {
		values[key] = value
	}
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
