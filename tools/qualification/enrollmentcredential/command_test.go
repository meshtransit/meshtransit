package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/config"
)

const (
	testDeploymentID = "01995d00-0000-7000-8000-000000000001"
	testWorkspaceID  = "01995d00-0000-7000-8000-000000000101"
	testNetworkID    = "01995d00-0000-7000-8000-000000000201"
	testProfileID    = "01995d00-0000-7000-8000-000000000601"
	testPrincipalID  = "01995d00-0000-7000-8000-000000000011"
)

func TestParseIssueSpecRequiresExactConfirmation(t *testing.T) {
	t.Parallel()
	environment := testEnvironment()
	spec, err := parseIssueSpec(testArguments("/tmp/meshtransit-enrollment"), mapLookup(environment))
	if err != nil {
		t.Fatalf("parseIssueSpec() error = %v", err)
	}
	if !spec.isValid() || spec.expiresIn != 10*time.Minute {
		t.Fatalf("parseIssueSpec() = %#v, want valid ten-minute issue", spec)
	}

	environment[envConfirmation] = testDeploymentID + "/wrong"
	if _, err := parseIssueSpec(
		testArguments("/tmp/meshtransit-enrollment"),
		mapLookup(environment),
	); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseIssueSpec() confirmation error = %v, want invalid input", err)
	}
}

func TestParseIssueSpecRejectsUnsafeTTLAndExistingArguments(t *testing.T) {
	t.Parallel()
	environment := testEnvironment()
	arguments := testArguments("/tmp/meshtransit-enrollment")
	arguments[13] = "1m500ms"
	if _, err := parseIssueSpec(arguments, mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseIssueSpec() fractional expiry error = %v, want invalid input", err)
	}
	arguments = testArguments("/tmp/meshtransit-enrollment")
	arguments[13] = "16m"
	if _, err := parseIssueSpec(arguments, mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseIssueSpec() long expiry error = %v, want invalid input", err)
	}
	arguments = append(testArguments("/tmp/meshtransit-enrollment"), "unexpected")
	if _, err := parseIssueSpec(arguments, mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseIssueSpec() positional argument error = %v, want invalid input", err)
	}
}

func TestLoadDatabaseSettingsRejectsRuntimeRoles(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"mesh_runtime", "mesh_worker", "mesh_migrator"} {
		environment := testEnvironment()
		environment[envPostgreSQLAdminUser] = role
		if _, err := loadDatabaseSettings(mapLookup(environment)); !errors.Is(err, errInvalidInput) {
			t.Fatalf("loadDatabaseSettings(%q) error = %v, want invalid input", role, err)
		}
	}
}

func TestLoadDatabaseSettingsAllowsExplicitContainerLocalSocket(t *testing.T) {
	t.Parallel()
	environment := testEnvironment()
	delete(environment, envPostgreSQLAddress)
	delete(environment, envPostgreSQLPasswordFile)
	delete(environment, envPostgreSQLTrustFile)
	environment[envPostgreSQLUnixSocket] = postgresContainerSocket
	environment[envPostgreSQLLocalConfirm] = localPostgresConfirmation

	database, err := loadDatabaseSettings(mapLookup(environment))
	if err != nil {
		t.Fatalf("loadDatabaseSettings() error = %v", err)
	}
	if database.unixSocket != postgresContainerSocket || database.address != "" {
		t.Fatalf("loadDatabaseSettings() = %#v, want local socket only", database)
	}

	environment[envPostgreSQLLocalConfirm] = "wrong"
	if _, err := loadDatabaseSettings(mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("loadDatabaseSettings() local confirmation error = %v, want invalid input", err)
	}
}

func TestRunRedactsExecutorFailure(t *testing.T) {
	t.Parallel()
	var standardOutput bytes.Buffer
	var errorOutput bytes.Buffer
	secret := "mtc1.secret-bearing-value"
	exitCode := run(
		context.Background(),
		testArguments("/tmp/meshtransit-enrollment"),
		mapLookup(testEnvironment()),
		&standardOutput,
		&errorOutput,
		rand.Reader,
		func(
			context.Context,
			issueSpec,
			databaseSettings,
			io.Reader,
		) (issueOutput, error) {
			return issueOutput{}, errors.New(secret)
		},
	)
	if exitCode != exitFailure || standardOutput.Len() != 0 {
		t.Fatalf("run() exit/output = %d/%q, want failure and empty stdout", exitCode, standardOutput.String())
	}
	if strings.Contains(errorOutput.String(), secret) ||
		errorOutput.String() != "enrollmentcredential: issue failed\n" {
		t.Fatalf("run() stderr = %q, want generic redacted failure", errorOutput.String())
	}
}

func testArguments(tokenOutput string) []string {
	return []string{
		"-deployment-id", testDeploymentID,
		"-workspace-id", testWorkspaceID,
		"-network-id", testNetworkID,
		"-profile-id", testProfileID,
		"-issuer-principal-id", testPrincipalID,
		"-token-output-file", tokenOutput,
		"-expires-in", "10m",
		"-audit-reason", "phase-1-two-node-qualification",
	}
}

func testEnvironment() map[string]string {
	// #nosec G101 -- these synthetic values are file references, not credentials.
	return map[string]string{
		envConfirmation: testDeploymentID + "/" + testWorkspaceID + "/" +
			testNetworkID + "/" + testProfileID + "/" + testPrincipalID,
		envEnable:                  enableConfirmation,
		envPostgreSQLAddress:       "postgres.example:5432",
		envPostgreSQLDatabase:      "meshtransit",
		envPostgreSQLAdminUser:     "meshcore",
		envPostgreSQLPasswordFile:  "/tmp/meshtransit-postgres-password",
		envPostgreSQLTrustFile:     "/tmp/meshtransit-postgres-ca",
		envEnrollmentDigestKeyID:   "enrollment-v1",
		envEnrollmentDigestKeyFile: "/tmp/meshtransit-enrollment-key",
	}
}

func mapLookup(values map[string]string) config.LookupFunc {
	return func(key string) (string, bool) {
		value, found := values[key]
		return value, found
	}
}
