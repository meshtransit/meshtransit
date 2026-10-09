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

func TestRoleControlProcessRejectsInvalidConfigurationBeforeListening(t *testing.T) {
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

	privateKeyFile := os.Getenv("MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE")
	if privateKeyFile == "" {
		t.Fatal("MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE is required")
	}
	environment := integrationProcessEnvironment(
		listener.Addr().String(),
		reserveLoopbackAddress(t),
	)
	environment = setEnvironmentValue(
		environment,
		"MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE",
		privateKeyFile,
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
		privateKeyFile,
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
