//go:build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/legacyts2021/protocoltest"
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
	firstMap := fetchProcessFullMap(ctx, t, first, client)
	firstStreamMap := fetchProcessInitialStreamMap(ctx, t, first, client)
	if !reflect.DeepEqual(firstStreamMap, firstMap) {
		first.process.forceStop(t)
		t.Fatalf("first stream map differs from one-shot map: one-shot=%+v stream=%+v", firstMap, firstStreamMap)
	}
	assertControlClientMetrics(t, first)
	stopIntegrationProcess(t, first.process)
	firstEvidence := readProcessRegistrationEvidence(ctx, t, adminConnection, client.Identity())
	assertProcessRegistrationEvidence(t, firstEvidence)
	assertProcessFullMap(t, firstMap, firstEvidence, client.Identity())

	second := startReadyRoleAllProcess(t, binary, controlAddress)
	replayCtx, cancelReplay := context.WithTimeout(ctx, 10*time.Second)
	if err := client.Register(replayCtx, fixture.credential.Reveal()); err != nil {
		cancelReplay()
		second.process.forceStop(t)
		t.Fatalf("restarted process registration replay: %v; stderr: %s", err, second.process.stderr.String())
	}
	cancelReplay()
	secondMap := fetchProcessFullMap(ctx, t, second, client)
	secondStreamMap := fetchProcessInitialStreamMap(ctx, t, second, client)
	if !reflect.DeepEqual(secondStreamMap, secondMap) {
		second.process.forceStop(t)
		t.Fatalf("restarted stream map differs from one-shot map: one-shot=%+v stream=%+v", secondMap, secondStreamMap)
	}
	assertControlClientMetrics(t, second)
	stopIntegrationProcess(t, second.process)
	secondEvidence := readProcessRegistrationEvidence(ctx, t, adminConnection, client.Identity())
	if secondEvidence != firstEvidence {
		t.Fatalf("registration replay changed authority: before=%+v after=%+v", firstEvidence, secondEvidence)
	}
	if !reflect.DeepEqual(secondMap, firstMap) {
		t.Fatalf("map changed across restart: before=%+v after=%+v", firstMap, secondMap)
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

func fetchProcessFullMap(
	ctx context.Context,
	t *testing.T,
	running readyRoleAllProcess,
	client *protocoltest.Client,
) protocoltest.FullMap {
	t.Helper()
	mapCtx, cancelMap := context.WithTimeout(ctx, 10*time.Second)
	defer cancelMap()
	result, err := client.FetchFullMap(mapCtx)
	if err != nil {
		running.process.forceStop(t)
		t.Fatalf("fetch process full map: %v; stderr: %s", err, running.process.stderr.String())
	}
	return result
}

func fetchProcessInitialStreamMap(
	ctx context.Context,
	t *testing.T,
	running readyRoleAllProcess,
	client *protocoltest.Client,
) protocoltest.FullMap {
	t.Helper()
	mapCtx, cancelMap := context.WithTimeout(ctx, 10*time.Second)
	defer cancelMap()
	result, err := client.FetchInitialStreamMap(mapCtx)
	if err != nil {
		running.process.forceStop(t)
		t.Fatalf("fetch process initial stream map: %v; stderr: %s", err, running.process.stderr.String())
	}
	return result
}

func assertProcessFullMap(
	t *testing.T,
	result protocoltest.FullMap,
	evidence processRegistrationEvidence,
	identity protocoltest.Identity,
) {
	t.Helper()
	if result.NodeID <= 0 || result.OwnerID <= 0 ||
		result.StableNodeID != evidence.nodePublicID ||
		result.Name != evidence.hostname+"." || result.ComputedName != evidence.hostname ||
		result.MachineKey != identity.MachineKey || result.NodeKey != identity.NodeKey ||
		len(result.Addresses) != 1 || result.Addresses[0].String() != evidence.primaryAddress ||
		len(result.AllowedIPs) != 1 || result.AllowedIPs[0] != result.Addresses[0] ||
		result.CapabilityVersion != 142 || !result.MachineAuthorized ||
		result.PeerCount != 0 || !result.DenyAll {
		t.Fatalf("process full map is incomplete or unsafe: %+v", result)
	}
}

func assertControlClientMetrics(t *testing.T, running readyRoleAllProcess) {
	t.Helper()
	if running.process == nil || running.healthAddress == "" {
		t.Fatal("integration process is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	want := []string{
		`meshtransit_control_session_attempts_total{result="established"} 3`,
		`meshtransit_control_registration_requests_total{result="authorized"} 1`,
		`meshtransit_control_map_requests_total{result="authorized"} 1`,
		`meshtransit_control_map_requests_total{result="stream_closed"} 1`,
		`meshtransit_redis_commands_total{operation="presence_claim",result="success"} 1`,
		`meshtransit_redis_commands_total{operation="presence_release",result="success"} 1`,
		"meshtransit_control_registrations_active 0",
		"meshtransit_control_authenticated_sessions_active 0",
		"meshtransit_control_map_streams_active 0",
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, body, err := integrationGET(ctx, client, running.healthAddress, "/metrics")
		if err == nil && status == http.StatusOK && containsEveryMetric(body, want) {
			return
		}
		select {
		case <-ctx.Done():
			if err != nil {
				t.Fatalf("read process control metrics: %v", err)
			}
			if status != http.StatusOK {
				t.Fatalf("process control metrics status = %d, want %d", status, http.StatusOK)
			}
			for _, metric := range want {
				if !strings.Contains(body, metric) {
					t.Fatalf("process control metrics missing %q", metric)
				}
			}
		case <-ticker.C:
		}
	}
}

func containsEveryMetric(body string, metrics []string) bool {
	for _, metric := range metrics {
		if !strings.Contains(body, metric) {
			return false
		}
	}
	return true
}
