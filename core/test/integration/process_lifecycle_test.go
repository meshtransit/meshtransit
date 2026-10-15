//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	testMeshcoreBinaryEnvironment = "MESHTRANSIT_TEST_MESHCORE_BINARY"
	integrationResponseLimit      = 1 << 20
)

func TestRoleControlProcessRestartsAfterGracefulShutdown(t *testing.T) {
	if os.Getenv("MESHTRANSIT_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_INTEGRATION=1 with file-backed test credentials")
	}
	binary := validateTestBinary(t, os.Getenv(testMeshcoreBinaryEnvironment))

	for cycle := 1; cycle <= 2; cycle++ {
		t.Run(fmt.Sprintf("cycle-%d", cycle), func(t *testing.T) {
			assertRoleControlProcessCycle(t, binary)
		})
	}
}

func assertRoleControlProcessCycle(t *testing.T, binary string) {
	t.Helper()

	healthAddress := reserveLoopbackAddress(t)
	controlAddress := reserveLoopbackAddress(t)
	process := startIntegrationProcess(
		t,
		binary,
		integrationProcessEnvironment(healthAddress, controlAddress),
	)
	t.Cleanup(func() { process.forceStop(t) })

	startCtx, cancelStart := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelStart()
	if err := waitForReady(startCtx, process, healthAddress); err != nil {
		process.forceStop(t)
		t.Fatalf("wait for control readiness: %v; stderr: %s", err, process.stderr.String())
	}

	metricsCtx, cancelMetrics := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancelMetrics()
	if err := assertRoleControlMetrics(metricsCtx, healthAddress); err != nil {
		process.forceStop(t)
		t.Fatalf("verify control metrics: %v; stderr: %s", err, process.stderr.String())
	}

	stopCtx, cancelStop := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelStop()
	if err := process.stop(stopCtx); err != nil {
		t.Fatalf("gracefully stop control process: %v; stderr: %s", err, process.stderr.String())
	}
}

type integrationProcess struct {
	command *exec.Cmd
	done    <-chan error
	stderr  bytes.Buffer
	exited  bool
	waitErr error
}

func startIntegrationProcess(t *testing.T, binary string, environment []string) *integrationProcess {
	t.Helper()

	process := &integrationProcess{}
	processCtx, cancelProcess := context.WithCancel(context.Background())
	// The integration script builds this validated local executable immediately
	// before the test; it is not derived from a product request.
	process.command = exec.CommandContext(processCtx, binary, "serve") //nolint:gosec
	process.command.Env = environment
	process.command.Stdout = io.Discard
	process.command.Stderr = &process.stderr
	if err := process.command.Start(); err != nil {
		cancelProcess()
		t.Fatalf("start meshcore process: %v", err)
	}

	done := make(chan error, 1)
	process.done = done
	go func() {
		waitErr := process.command.Wait()
		cancelProcess()
		done <- waitErr
		close(done)
	}()
	return process
}

func (process *integrationProcess) stop(ctx context.Context) error {
	if exited, err := process.poll(); exited {
		if err == nil {
			return errors.New("process exited before shutdown signal")
		}
		return fmt.Errorf("process exited before shutdown signal: %w", err)
	}
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("signal process: %w", err)
	}
	if err := process.wait(ctx); err != nil {
		return fmt.Errorf("wait for process: %w", err)
	}
	return nil
}

func (process *integrationProcess) forceStop(t *testing.T) {
	t.Helper()
	if exited, _ := process.poll(); exited {
		return
	}
	if err := process.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("kill integration process: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := process.wait(ctx); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return
		}
		t.Errorf("join killed integration process: %v", err)
	}
}

func (process *integrationProcess) poll() (bool, error) {
	if process.exited {
		return true, process.waitErr
	}
	select {
	case process.waitErr = <-process.done:
		process.exited = true
		return true, process.waitErr
	default:
		return false, nil
	}
}

func (process *integrationProcess) wait(ctx context.Context) error {
	if exited, err := process.poll(); exited {
		return err
	}
	select {
	case process.waitErr = <-process.done:
		process.exited = true
		return process.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitForReady(ctx context.Context, process *integrationProcess, address string) error {
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if exited, err := process.poll(); exited {
			if err == nil {
				return errors.New("process exited before readiness")
			}
			return fmt.Errorf("process exited before readiness: %w", err)
		}
		status, body, err := integrationGET(ctx, client, address, "/ready")
		if err == nil && status == http.StatusOK && strings.Contains(body, `"status":"ready"`) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func assertRoleControlMetrics(ctx context.Context, address string) error {
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	status, body, err := integrationGET(ctx, client, address, "/metrics")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("metrics status = %d, want %d", status, http.StatusOK)
	}
	metric := `meshtransit_runtime_role{role="control"} 1`
	if !strings.Contains(body, metric) {
		return fmt.Errorf("metrics missing %q", metric)
	}
	for _, metric := range []string{
		"meshtransit_control_connections_limit 8",
		"meshtransit_control_connections_active 0",
		`meshtransit_mtcp_handshakes_total{result="established"} 0`,
		"meshtransit_mtcp_sessions_active 0",
	} {
		if !strings.Contains(body, metric) {
			return fmt.Errorf("metrics missing %q", metric)
		}
	}
	return nil
}

func integrationGET(
	ctx context.Context,
	client *http.Client,
	address string,
	path string,
) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil) //nolint:gosec // Test process on loopback.
	if err != nil {
		return 0, "", err
	}
	response, err := client.Do(request) //nolint:gosec // Test process on loopback.
	if err != nil {
		return 0, "", err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, integrationResponseLimit+1))
	closeErr := response.Body.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return 0, "", err
	}
	if len(body) > integrationResponseLimit {
		return 0, "", fmt.Errorf("response body exceeds %d bytes", integrationResponseLimit)
	}
	return response.StatusCode, string(body), nil
}

func integrationHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   time.Second,
	}
}

func reserveLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback address: %v", err)
	}
	return address
}

func validateTestBinary(t *testing.T, value string) string {
	t.Helper()
	if value == "" {
		t.Fatalf("%s is required", testMeshcoreBinaryEnvironment)
	}
	binary, err := filepath.Abs(value)
	if err != nil {
		t.Fatalf("resolve %s: %v", testMeshcoreBinaryEnvironment, err)
	}
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatalf("stat %s: %v", testMeshcoreBinaryEnvironment, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s must reference an executable regular file", testMeshcoreBinaryEnvironment)
	}
	return binary
}

func integrationProcessEnvironment(healthAddress, controlAddress string) []string {
	overrides := map[string]string{
		"MESHTRANSIT_ROLE":                               "control",
		"MESHTRANSIT_HEALTH_ADDRESS":                     healthAddress,
		"MESHTRANSIT_CONTROL_ADDRESS":                    controlAddress,
		"MESHTRANSIT_SHUTDOWN_TIMEOUT":                   "3s",
		"MESHTRANSIT_DEPENDENCY_CHECK_TIMEOUT":           "1s",
		"MESHTRANSIT_DEPENDENCY_CHECK_INTERVAL":          "2s",
		"MESHTRANSIT_NETWORK_REVISION_BATCH_SIZE":        "1",
		"MESHTRANSIT_NETWORK_REVISION_LEASE":             "5s",
		"MESHTRANSIT_NETWORK_REVISION_POLL_INTERVAL":     "100ms",
		"MESHTRANSIT_NETWORK_REVISION_RETRY_DELAY":       "1s",
		"MESHTRANSIT_NETWORK_REVISION_OPERATION_TIMEOUT": "1s",
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, value := range os.Environ() {
		name, _, found := strings.Cut(value, "=")
		if _, overridden := overrides[name]; found && overridden {
			continue
		}
		environment = append(environment, value)
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		environment = append(environment, name+"="+overrides[name])
	}
	// MTCP requires an advertised control key expiry. The platform script
	// exports one so the test's own config.Load sees the same value; a
	// caller that did not gets a near-term default.
	if _, present := os.LookupEnv(integrationMTCPKeyNotAfterEnvironment); !present {
		environment = append(environment, integrationMTCPKeyNotAfterEnvironment+"="+
			time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	}
	return environment
}

const integrationMTCPKeyNotAfterEnvironment = "MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER"
