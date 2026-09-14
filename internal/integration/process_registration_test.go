//go:build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/config"
)

func TestRoleAllProcessRegistrationConvergesAcrossRestart(t *testing.T) {
	if os.Getenv("MESHTRANSIT_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_INTEGRATION=1 with disposable TLS dependencies")
	}
	binary := validateTestBinary(t, os.Getenv(testMeshcoreBinaryEnvironment))
	processConfig, err := config.Load(os.LookupEnv)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	adminConfig := loadIntegrationAdminConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	adminConnection := openIntegrationPostgreSQLConnection(
		ctx,
		t,
		adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database,
		adminConfig.PostgreSQL.User,
		adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile,
		adminConfig.ConnectTimeout,
	)
	fixture := seedProcessRegistrationCredential(ctx, t, adminConnection, processConfig)
	controlAddress := reserveLoopbackAddress(t)
	client := newProcessRegistrationClient(t, processConfig, controlAddress)

	first := startReadyRoleAllProcess(t, binary, controlAddress)
	registerCtx, cancelRegister := context.WithTimeout(ctx, 10*time.Second)
	if err := client.Register(registerCtx, fixture.credential.Reveal()); err != nil {
		cancelRegister()
		first.process.forceStop(t)
		t.Fatalf("first process registration: %v; stderr: %s", err, first.process.stderr.String())
	}
	cancelRegister()
	assertControlRegistrationMetrics(t, first)
	stopIntegrationProcess(t, first.process)
	firstEvidence := readProcessRegistrationEvidence(ctx, t, adminConnection, client.Identity())
	assertProcessRegistrationEvidence(t, firstEvidence)

	second := startReadyRoleAllProcess(t, binary, controlAddress)
	replayCtx, cancelReplay := context.WithTimeout(ctx, 10*time.Second)
	if err := client.Register(replayCtx, fixture.credential.Reveal()); err != nil {
		cancelReplay()
		second.process.forceStop(t)
		t.Fatalf("restarted process registration replay: %v; stderr: %s", err, second.process.stderr.String())
	}
	cancelReplay()
	assertControlRegistrationMetrics(t, second)
	stopIntegrationProcess(t, second.process)
	secondEvidence := readProcessRegistrationEvidence(ctx, t, adminConnection, client.Identity())
	if secondEvidence != firstEvidence {
		t.Fatalf("registration replay changed authority: before=%+v after=%+v", firstEvidence, secondEvidence)
	}
}

func startReadyRoleAllProcess(
	t *testing.T,
	binary string,
	controlAddress string,
) readyRoleAllProcess {
	t.Helper()
	healthAddress := reserveLoopbackAddress(t)
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
		t.Fatalf("wait for role=all readiness: %v; stderr: %s", err, process.stderr.String())
	}
	return readyRoleAllProcess{process: process, healthAddress: healthAddress}
}

func stopIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	stopCtx, cancelStop := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelStop()
	if err := process.stop(stopCtx); err != nil {
		t.Fatalf("gracefully stop role=all process: %v; stderr: %s", err, process.stderr.String())
	}
}

type readyRoleAllProcess struct {
	process       *integrationProcess
	healthAddress string
}

func assertControlRegistrationMetrics(t *testing.T, running readyRoleAllProcess) {
	t.Helper()
	if running.process == nil || running.healthAddress == "" {
		t.Fatal("integration process is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	status, body, err := integrationGET(ctx, client, running.healthAddress, "/metrics")
	if err != nil {
		t.Fatalf("read process registration metrics: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("process registration metrics status = %d, want %d", status, http.StatusOK)
	}
	for _, metric := range []string{
		`meshtransit_control_session_attempts_total{result="established"} 1`,
		`meshtransit_control_registration_requests_total{result="authorized"} 1`,
		"meshtransit_control_registrations_active 0",
		"meshtransit_control_authenticated_sessions_active 0",
	} {
		if !strings.Contains(body, metric) {
			t.Fatalf("process registration metrics missing %q", metric)
		}
	}
}
