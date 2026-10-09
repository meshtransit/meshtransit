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

	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

const (
	testDeploymentID = "01995d00-0000-7000-8000-000000000001"
	testWorkspaceID  = "01995d00-0000-7000-8000-000000000101"
	testNetworkID    = "01995d00-0000-7000-8000-000000000201"
	testPrincipalID  = "01995d00-0000-7000-8000-000000000011"
)

func TestParseSeedSpecRequiresExactConfirmation(t *testing.T) {
	t.Parallel()
	environment := testEnvironment()
	spec, err := parseSeedSpec(testArguments("/tmp/meshtransit-token"), mapLookup(environment))
	if err != nil {
		t.Fatalf("parseSeedSpec() error = %v", err)
	}
	if !spec.isValid() || spec.expiresIn != 10*time.Minute {
		t.Fatalf("parseSeedSpec() = %#v, want valid ten-minute seed", spec)
	}

	environment[envConfirmation] = testDeploymentID + "/wrong"
	if _, err := parseSeedSpec(
		testArguments("/tmp/meshtransit-token"),
		mapLookup(environment),
	); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseSeedSpec() confirmation error = %v, want invalid input", err)
	}
}

func TestParseSeedSpecRejectsFractionalExpiryAndExistingArguments(t *testing.T) {
	t.Parallel()
	environment := testEnvironment()
	arguments := testArguments("/tmp/meshtransit-token")
	arguments[11] = "1m500ms"
	if _, err := parseSeedSpec(arguments, mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseSeedSpec() fractional expiry error = %v, want invalid input", err)
	}
	arguments = append(testArguments("/tmp/meshtransit-token"), "unexpected")
	if _, err := parseSeedSpec(arguments, mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseSeedSpec() positional argument error = %v, want invalid input", err)
	}
}

func TestParseSeedSpecRequiresExplicitRenewalConfirmation(t *testing.T) {
	t.Parallel()
	environment := testEnvironment()
	arguments := append(testArguments("/tmp/meshtransit-token"), "-renew-expired-fixture")
	if _, err := parseSeedSpec(arguments, mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseSeedSpec() renewal without confirmation error = %v, want invalid input", err)
	}

	environment[envRenewalConfirmation] = "wrong"
	if _, err := parseSeedSpec(arguments, mapLookup(environment)); !errors.Is(err, errInvalidInput) {
		t.Fatalf("parseSeedSpec() wrong renewal confirmation error = %v, want invalid input", err)
	}

	environment[envRenewalConfirmation] = renewalConfirmation
	spec, err := parseSeedSpec(arguments, mapLookup(environment))
	if err != nil {
		t.Fatalf("parseSeedSpec() renewal error = %v", err)
	}
	if !spec.isValid() || !spec.renewExpiredFixture {
		t.Fatalf("parseSeedSpec() = %#v, want explicit renewal", spec)
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

func TestRunRedactsExecutorFailure(t *testing.T) {
	t.Parallel()
	var standardOutput bytes.Buffer
	var errorOutput bytes.Buffer
	secret := "mtas1.secret-bearing-value"
	exitCode := run(
		context.Background(),
		testArguments("/tmp/meshtransit-token"),
		mapLookup(testEnvironment()),
		&standardOutput,
		&errorOutput,
		rand.Reader,
		func(
			context.Context,
			seedSpec,
			databaseSettings,
			io.Reader,
		) (seedOutput, error) {
			return seedOutput{}, errors.New(secret)
		},
	)
	if exitCode != exitFailure || standardOutput.Len() != 0 {
		t.Fatalf("run() exit/output = %d/%q, want failure and empty stdout", exitCode, standardOutput.String())
	}
	if strings.Contains(errorOutput.String(), secret) ||
		errorOutput.String() != "managementsession: seed failed\n" {
		t.Fatalf("run() stderr = %q, want generic redacted failure", errorOutput.String())
	}
}

func testArguments(tokenOutput string) []string {
	return []string{
		"-deployment-id", testDeploymentID,
		"-workspace-id", testWorkspaceID,
		"-network-id", testNetworkID,
		"-principal-id", testPrincipalID,
		"-token-output-file", tokenOutput,
		"-expires-in", "10m",
		"-audit-reason", "phase-1-management-qualification",
	}
}

func testEnvironment() map[string]string {
	// #nosec G101 -- these synthetic values are file references, not credentials.
	return map[string]string{
		envConfirmation: testDeploymentID + "/" + testWorkspaceID + "/" +
			testNetworkID + "/" + testPrincipalID,
		envEnable:                 enableConfirmation,
		envPostgreSQLAddress:      "postgres.example:5432",
		envPostgreSQLDatabase:     "meshtransit",
		envPostgreSQLAdminUser:    "meshcore",
		envPostgreSQLPasswordFile: "/tmp/meshtransit-postgres-password",
		envPostgreSQLTrustFile:    "/tmp/meshtransit-postgres-ca",
		envSessionDigestKeyID:     "session-v1",
		envSessionDigestKeyFile:   "/tmp/meshtransit-session-key",
	}
}

func mapLookup(values map[string]string) config.LookupFunc {
	return func(key string) (string, bool) {
		value, found := values[key]
		return value, found
	}
}
