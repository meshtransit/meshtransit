//go:build integration

package integration

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRoleAllProcessRejectsInvalidConfigurationBeforeListening(t *testing.T) {
	if os.Getenv("MESHTRANSIT_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_INTEGRATION=1 with file-backed test credentials")
	}
	binary := validateTestBinary(t, os.Getenv(testMeshcoreBinaryEnvironment))

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold operator address: %v", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Errorf("release operator address: %v", closeErr)
		}
	}()

	runtimeUser := os.Getenv("MESHTRANSIT_POSTGRES_RUNTIME_USER")
	if runtimeUser == "" {
		t.Fatal("MESHTRANSIT_POSTGRES_RUNTIME_USER is required")
	}
	environment := integrationProcessEnvironment(
		listener.Addr().String(),
		reserveLoopbackAddress(t),
	)
	environment = setEnvironmentValue(
		environment,
		"MESHTRANSIT_POSTGRES_WORKER_USER",
		runtimeUser,
	)
	process := startIntegrationProcess(t, binary, environment)
	t.Cleanup(func() { process.forceStop(t) })

	waitCtx, cancelWait := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelWait()
	waitErr := process.wait(waitCtx)
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("invalid process exit = %v, want exit code 1", waitErr)
	}

	output := process.stderr.String()
	if !strings.Contains(output, `"error_code":"invalid_configuration"`) {
		t.Fatalf("stderr = %q, want redacted invalid_configuration event", output)
	}
	for _, sensitive := range []string{
		runtimeUser,
		os.Getenv("MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE"),
		os.Getenv("MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE"),
	} {
		if sensitive != "" && strings.Contains(output, sensitive) {
			t.Fatal("startup failure exposed a sensitive configuration value")
		}
	}
	if strings.Contains(output, `"msg":"runtime ready"`) {
		t.Fatalf("invalid process reached readiness: %s", output)
	}
}

func setEnvironmentValue(environment []string, name string, value string) []string {
	prefix := name + "="
	for index := range environment {
		if strings.HasPrefix(environment[index], prefix) {
			environment[index] = prefix + value
			return environment
		}
	}
	return append(environment, prefix+value)
}
