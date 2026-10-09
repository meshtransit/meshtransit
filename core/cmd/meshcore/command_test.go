package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/platform/buildinfo"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

func TestExecuteVersionIsMachineReadableAndDoesNotLoadConfiguration(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	lookup := func(string) (string, bool) {
		t.Fatal("version command loaded process configuration")
		return "", false
	}

	exitCode := execute(context.Background(), []string{"version"}, lookup, &output, &errorOutput)
	if exitCode != 0 {
		t.Fatalf("execute() = %d, want 0; error output = %s", exitCode, errorOutput.String())
	}
	var result versionOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %q", err, output.String())
	}
	build := buildinfo.Current()
	if result.Version != build.Version || result.Revision != build.Revision || result.GoVersion != build.GoVersion {
		t.Fatalf("version output = %+v, want build defaults and Go version", result)
	}
	if result.ConfigSchemaVersion != config.SchemaVersion {
		t.Fatalf("config schema version = %d, want %d", result.ConfigSchemaVersion, config.SchemaVersion)
	}
}

func TestExecuteConfigValidateRelayDoesNotRequireDependencies(t *testing.T) {
	t.Parallel()

	lookup := func(key string) (string, bool) {
		if key == "MESHTRANSIT_ROLE" {
			return "relay", true
		}
		return "", false
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	exitCode := execute(
		context.Background(),
		[]string{"config", "validate"},
		lookup,
		&output,
		&errorOutput,
	)
	if exitCode != 0 {
		t.Fatalf("execute() = %d, want 0; error output = %s", exitCode, errorOutput.String())
	}
	var result configValidationOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %q", err, output.String())
	}
	if result.Status != "valid" || result.Role != "relay" || result.SchemaVersion != config.SchemaVersion {
		t.Fatalf("validation output = %+v, want valid relay schema %d", result, config.SchemaVersion)
	}
}

func TestExecuteConfigValidateRejectsInvalidCABundleWithoutExposingInputs(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	passwordPath := filepath.Join(directory, "credential")
	caPath := filepath.Join(directory, "private-ca")
	if err := os.WriteFile(passwordPath, []byte("do-not-log-this-value\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(password) error = %v", err)
	}
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(CA) error = %v", err)
	}
	values := map[string]string{
		"MESHTRANSIT_ROLE":                           "api",
		"MESHTRANSIT_POSTGRES_ADDRESS":               "database.internal:5432",
		"MESHTRANSIT_POSTGRES_DATABASE":              "meshtransit",
		"MESHTRANSIT_POSTGRES_RUNTIME_USER":          "mesh_runtime",
		"MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE": passwordPath,
		"MESHTRANSIT_POSTGRES_CA_FILE":               caPath,
		"MESHTRANSIT_REDIS_ADDRESS":                  "cache.internal:6379",
		"MESHTRANSIT_REDIS_USERNAME":                 "meshcore",
		"MESHTRANSIT_REDIS_PASSWORD_FILE":            passwordPath,
		"MESHTRANSIT_REDIS_CA_FILE":                  caPath,
	}
	lookup := func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer

	exitCode := execute(
		context.Background(),
		[]string{"config", "validate"},
		lookup,
		&output,
		&errorOutput,
	)
	if exitCode != 1 {
		t.Fatalf("execute() = %d, want 1", exitCode)
	}
	if output.Len() != 0 {
		t.Fatalf("standard output = %q, want empty", output.String())
	}
	for _, sensitive := range []string{directory, passwordPath, caPath, "do-not-log-this-value"} {
		if strings.Contains(errorOutput.String(), sensitive) {
			t.Fatalf("error output exposed sensitive input %q: %s", sensitive, errorOutput.String())
		}
	}
}

func TestExecuteUsesUnixStyleUsageExitCode(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := execute(context.Background(), []string{"unknown"}, nil, &output, &errorOutput)
	if exitCode != 2 {
		t.Fatalf("execute() = %d, want 2", exitCode)
	}
	if output.Len() != 0 || errorOutput.String() != usage {
		t.Fatalf("output = %q, error output = %q", output.String(), errorOutput.String())
	}
}

func TestExecuteRecognizesMigrationCommandsBeforeProcessConfiguration(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := execute(context.Background(), []string{"migrate", "unknown"}, nil, &output, &errorOutput)
	if exitCode != 2 {
		t.Fatalf("execute() = %d, want usage exit code 2", exitCode)
	}
	if output.Len() != 0 || errorOutput.String() != usage {
		t.Fatalf("output = %q, error output = %q", output.String(), errorOutput.String())
	}
}
