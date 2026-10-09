package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

const (
	testDeploymentID = "01890f00-0000-7000-8000-000000000001"
	testProviderID   = "01890f00-0000-7000-8000-000000000002"
	testClientID     = "01890f00-0000-7000-8000-000000000003"
	testActorID      = "01890f00-0000-7000-8000-000000000004"
)

func TestParseTransitionSpec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		args        []string
		environment map[string]string
		wantMode    transitionMode
		wantError   bool
	}{
		{name: "dry run", args: validArgs("dry-run"), environment: validEnvironment(false), wantMode: transitionModeDryRun},
		{name: "apply", args: validArgs("apply"), environment: validEnvironment(true), wantMode: transitionModeApply},
		{name: "apply disabled", args: validArgs("apply"), environment: validEnvironment(false), wantError: true},
		{name: "wrong confirmation", args: validArgs("dry-run"), environment: withValue(validEnvironment(false), envConfirmation, testProviderID), wantError: true},
		{name: "zero generation", args: replaceArgument(validArgs("dry-run"), "--expected-generation", "0"), environment: validEnvironment(false), wantError: true},
		{name: "overflow version", args: replaceArgument(validArgs("dry-run"), "--expected-client-version", "9223372036854775807"), environment: validEnvironment(false), wantError: true},
		{name: "control in reason", args: replaceArgument(validArgs("dry-run"), "--audit-reason", "invalid\nreason"), environment: validEnvironment(false), wantError: true},
		{name: "positional argument", args: append(validArgs("dry-run"), "unexpected"), environment: validEnvironment(false), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			spec, err := parseTransitionSpec(test.args, lookupFromMap(test.environment))
			if test.wantError {
				if !errors.Is(err, errInvalidInput) {
					t.Fatalf("parseTransitionSpec() error = %v, want errInvalidInput", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTransitionSpec() error = %v", err)
			}
			if spec.mode != test.wantMode || spec.expectedGeneration != 1 ||
				spec.expectedGenerationVersion != 1 || !spec.isValid() {
				t.Fatalf("parseTransitionSpec() = %+v", spec)
			}
		})
	}
}

func TestRunWritesOnlySafeStructuredResult(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := run(
		t.Context(),
		validArgs("dry-run"),
		lookupFromMap(validEnvironment(false)),
		&output,
		&errorOutput,
		func(_ context.Context, spec transitionSpec, database databaseSettings) (transitionOutput, error) {
			if spec.mode != transitionModeDryRun || database.address != "database.example:5432" {
				t.Fatal("executor received unvalidated input")
			}
			return transitionOutput{
				Operation: "validated", ProviderID: testProviderID, ClientID: testClientID,
				PreviousGeneration: 1, CurrentGeneration: 2,
				PreviousScopes: []string{"openid"},
				CurrentScopes:  []string{"openid", "federated:id"},
			}, nil
		},
	)
	if exitCode != exitSuccess || errorOutput.Len() != 0 {
		t.Fatalf("run() exit/stderr = %d/%q", exitCode, errorOutput.String())
	}
	var result transitionOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if result.Operation != "validated" || result.CurrentGeneration != 2 ||
		len(result.CurrentScopes) != 2 {
		t.Fatalf("run() output = %+v", result)
	}
}

func TestRunRedactsExecutionFailure(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := run(
		t.Context(),
		validArgs("dry-run"),
		lookupFromMap(validEnvironment(false)),
		&output,
		&errorOutput,
		func(context.Context, transitionSpec, databaseSettings) (transitionOutput, error) {
			return transitionOutput{}, errors.New("database.example:5432 /run/secrets/admin")
		},
	)
	if exitCode != exitFailure || output.Len() != 0 ||
		errorOutput.String() != "providertransition: transition failed\n" {
		t.Fatalf("run() exit/stdout/stderr = %d/%q/%q", exitCode, output.String(), errorOutput.String())
	}
}

func TestValidExpectedVersionRejectsBoundaries(t *testing.T) {
	t.Parallel()
	if validExpectedVersion(0) || validExpectedVersion(math.MaxInt64) || !validExpectedVersion(1) {
		t.Fatal("validExpectedVersion() accepted an unsafe boundary")
	}
}

func validArgs(mode string) []string {
	return []string{
		"--deployment-id", testDeploymentID,
		"--provider-id", testProviderID,
		"--client-id", testClientID,
		"--actor-principal-id", testActorID,
		"--expected-generation", "1",
		"--expected-generation-version", "1",
		"--expected-provider-version", "1",
		"--expected-client-version", "1",
		"--mode", mode,
		"--audit-reason", "enable broker connector evidence scope",
	}
}

func validEnvironment(enable bool) map[string]string {
	// #nosec G101 -- these are synthetic file references, not credentials.
	values := map[string]string{
		envConfirmation:           stringsJoin(testDeploymentID, testProviderID, testClientID),
		envPostgreSQLAddress:      "database.example:5432",
		envPostgreSQLDatabase:     "meshtransit",
		envPostgreSQLAdminUser:    "mesh_admin",
		envPostgreSQLPasswordFile: "/run/secrets/postgres-admin-password",
		envPostgreSQLTrustFile:    "/run/trust/postgres-ca.pem",
	}
	if enable {
		values[envEnable] = enableConfirmation
	}
	return values
}

func stringsJoin(values ...string) string {
	var result string
	for index, value := range values {
		if index > 0 {
			result += "/"
		}
		result += value
	}
	return result
}

func lookupFromMap(values map[string]string) config.LookupFunc {
	return func(key string) (string, bool) {
		value, found := values[key]
		return value, found
	}
}

func withValue(values map[string]string, key, value string) map[string]string {
	cloned := make(map[string]string, len(values))
	for currentKey, currentValue := range values {
		cloned[currentKey] = currentValue
	}
	cloned[key] = value
	return cloned
}

func replaceArgument(args []string, name, value string) []string {
	replaced := append([]string(nil), args...)
	for index := range replaced {
		if replaced[index] == name && index+1 < len(replaced) {
			replaced[index+1] = value
			return replaced
		}
	}
	return replaced
}
