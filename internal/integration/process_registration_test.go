//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/adapter/legacyts2021/protocoltest"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/node"
)

func TestRoleControlProcessRegistrationConvergesAcrossRestart(t *testing.T) {
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

	first := startReadyControlProcess(t, binary, controlAddress)
	registerCtx, cancelRegister := context.WithTimeout(ctx, 10*time.Second)
	if err := client.Register(registerCtx, fixture.credential.Reveal()); err != nil {
		cancelRegister()
		first.process.forceStop(t)
		t.Fatalf("first process registration: %v; stderr: %s", err, first.process.stderr.String())
	}
	cancelRegister()
	firstMap := fetchProcessFullMap(ctx, t, first, client)
	assertProcessEndpointObservation(ctx, t, firstMap.StableNodeID, client.Connectivity())
	firstStreamMap := fetchProcessInitialStreamMap(ctx, t, first, client)
	if !reflect.DeepEqual(firstStreamMap, firstMap) {
		first.process.forceStop(t)
		t.Fatalf("first stream map differs from one-shot map: one-shot=%+v stream=%+v", firstMap, firstStreamMap)
	}
	firstEvidence := readProcessRegistrationEvidence(ctx, t, adminConnection, client.Identity())
	assertProcessRegistrationEvidence(t, firstEvidence)
	assertProcessFullMap(
		t,
		firstMap,
		firstEvidence,
		client.Identity(),
		client.Connectivity(),
	)
	assertControlClientMetrics(t, first)
	waitForProcessRevisionDelivery(ctx, t, first, adminConnection, firstEvidence.nodePublicID)
	stopReadyControlProcess(t, first)

	second := startReadyControlProcess(t, binary, controlAddress)
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
	stopReadyControlProcess(t, second)
	secondEvidence := readProcessRegistrationEvidence(ctx, t, adminConnection, client.Identity())
	if secondEvidence != firstEvidence {
		t.Fatalf("registration replay changed authority: before=%+v after=%+v", firstEvidence, secondEvidence)
	}
	if !reflect.DeepEqual(secondMap, firstMap) {
		t.Fatalf("map changed across restart: before=%+v after=%+v", firstMap, secondMap)
	}

	third := startReadyControlProcess(t, binary, controlAddress)
	assertProcessConnectivityWakeup(ctx, t, third, client)
	assertProcessRevisionWakeup(ctx, t, third, client, adminConnection)
	stopReadyControlProcess(t, third)
}

func assertProcessEndpointObservation(
	ctx context.Context,
	t *testing.T,
	stableNodeID string,
	want protocoltest.Connectivity,
) {
	t.Helper()
	nodeID, err := node.ParseID(stableNodeID)
	if err != nil {
		t.Fatalf("parse process endpoint Node ID: %v", err)
	}
	client := openIntegrationRedisClient(ctx, t)
	set, found, err := client.LoadEndpoints(ctx, nodeID, 1)
	if err != nil || !found {
		t.Fatalf("load process endpoint observation = (%+v, %t, %v), want found", set, found, err)
	}
	if set.DiscoveryKey().Bytes() != want.DiscoveryKey {
		t.Fatal("process endpoint observation discovery key differs from client report")
	}
	gotEndpoints := set.Endpoints()
	gotAddresses := make([]netip.AddrPort, len(gotEndpoints))
	for index, endpoint := range gotEndpoints {
		gotAddresses[index] = endpoint.Address()
		if endpoint.Source() != node.EndpointSourceSTUN {
			t.Fatalf("process endpoint source = %v, want STUN", endpoint.Source())
		}
	}
	if !slices.Equal(gotAddresses, want.Endpoints) {
		t.Fatalf("process endpoint addresses = %v, want %v", gotAddresses, want.Endpoints)
	}
}

func assertProcessRevisionWakeup(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *protocoltest.Client,
	adminConnection *pgx.Conn,
) {
	t.Helper()
	baseline := fetchProcessFullMap(ctx, t, running, client)
	streamCtx, cancelStream := context.WithTimeout(ctx, 10*time.Second)
	stream, initial, err := client.OpenMapStream(streamCtx)
	if err != nil {
		cancelStream()
		running.process.forceStop(t)
		t.Fatalf("open process map stream: %v; stderr: %s", err, running.process.stderr.String())
	}
	if !reflect.DeepEqual(initial, baseline) {
		_ = stream.Close()
		cancelStream()
		running.process.forceStop(t)
		t.Fatalf("initial revision stream map differs from baseline: baseline=%+v stream=%+v", baseline, initial)
	}
	feedBefore := waitForProcessRevisionFeedMetrics(t, running, func(metrics processRevisionFeedMetrics) bool {
		return metrics.connected && metrics.activeWatchers == 1
	})
	commitIntegrationNetworkRevision(streamCtx, t, adminConnection, "994")
	advanced, err := stream.NextFullMap()
	closeErr := stream.Close()
	cancelStream()
	if err != nil || closeErr != nil {
		running.process.forceStop(t)
		t.Fatalf("receive process revision wakeup: read=%v close=%v; stderr: %s", err, closeErr, running.process.stderr.String())
	}
	if !reflect.DeepEqual(advanced, baseline) {
		running.process.forceStop(t)
		t.Fatalf("revision-only change altered map projection: baseline=%+v advanced=%+v", baseline, advanced)
	}
	waitForProcessRevisionFeedMetrics(t, running, func(metrics processRevisionFeedMetrics) bool {
		return metrics.connected && metrics.activeWatchers == 0 &&
			metrics.wakeups >= feedBefore.wakeups+1 &&
			metrics.delivered >= feedBefore.delivered+1
	})
}

func assertProcessConnectivityWakeup(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *protocoltest.Client,
) {
	t.Helper()
	baseline := fetchProcessFullMap(ctx, t, running, client)
	streamCtx, cancelStream := context.WithTimeout(ctx, 10*time.Second)
	stream, initial, err := client.OpenMapStream(streamCtx)
	if err != nil {
		cancelStream()
		running.process.forceStop(t)
		t.Fatalf("open connectivity map stream: %v; stderr: %s", err, running.process.stderr.String())
	}
	if !reflect.DeepEqual(initial, baseline) {
		_ = stream.Close()
		cancelStream()
		running.process.forceStop(t)
		t.Fatalf("initial connectivity stream differs from baseline: baseline=%+v stream=%+v", baseline, initial)
	}

	endpoint := netip.MustParseAddrPort("198.51.100.20:41641")
	if err := client.UpdateEndpoint(endpoint); err != nil {
		_ = stream.Close()
		cancelStream()
		t.Fatalf("update protocol-test endpoint: %v", err)
	}
	expected := baseline
	expected.Endpoints = []netip.AddrPort{endpoint}
	updated := fetchProcessFullMap(ctx, t, running, client)
	advanced, readErr := stream.NextConnectivityDelta()
	closeErr := stream.Close()
	cancelStream()
	if readErr != nil || closeErr != nil {
		running.process.forceStop(t)
		t.Fatalf("receive connectivity wakeup: read=%v close=%v; stderr: %s", readErr, closeErr, running.process.stderr.String())
	}
	if !reflect.DeepEqual(updated, expected) || !advanced.SelfChanged ||
		advanced.SelfNodeID != baseline.NodeID ||
		advanced.DiscoveryKey != baseline.DiscoveryKey ||
		!slices.Equal(advanced.Endpoints, []netip.AddrPort{endpoint}) ||
		len(advanced.PeersChanged) != 0 {
		running.process.forceStop(t)
		t.Fatalf("connectivity projection did not converge: baseline=%+v one-shot=%+v stream=%+v", baseline, updated, advanced)
	}
}

func startReadyControlProcess(
	t *testing.T,
	binary string,
	controlAddress string,
) readyControlProcess {
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
		t.Fatalf("wait for control readiness: %v; stderr: %s", err, process.stderr.String())
	}
	workerHealthAddress := reserveLoopbackAddress(t)
	workerEnvironment := integrationProcessEnvironment(workerHealthAddress, reserveLoopbackAddress(t))
	workerEnvironment = setEnvironmentValue(workerEnvironment, "MESHTRANSIT_ROLE", "worker")
	worker := startIntegrationProcess(t, binary, workerEnvironment)
	t.Cleanup(func() { worker.forceStop(t) })
	workerStartCtx, cancelWorkerStart := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelWorkerStart()
	if err := waitForReady(workerStartCtx, worker, workerHealthAddress); err != nil {
		worker.forceStop(t)
		process.forceStop(t)
		t.Fatalf("wait for worker readiness: %v; stderr: %s", err, worker.stderr.String())
	}
	return readyControlProcess{process: process, worker: worker, healthAddress: healthAddress}
}

func stopReadyControlProcess(t *testing.T, running readyControlProcess) {
	t.Helper()
	stopIntegrationProcess(t, running.worker)
	stopIntegrationProcess(t, running.process)
}

func stopIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	stopCtx, cancelStop := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelStop()
	if err := process.stop(stopCtx); err != nil {
		t.Fatalf("gracefully stop control process: %v; stderr: %s", err, process.stderr.String())
	}
}

type readyControlProcess struct {
	process       *integrationProcess
	worker        *integrationProcess
	healthAddress string
}

func fetchProcessFullMap(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
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
	running readyControlProcess,
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
	connectivity protocoltest.Connectivity,
) {
	t.Helper()
	if result.NodeID <= 0 || result.OwnerID <= 0 ||
		result.StableNodeID != evidence.nodePublicID ||
		result.Name != evidence.hostname+"." || result.ComputedName != evidence.hostname ||
		result.MachineKey != identity.MachineKey || result.NodeKey != identity.NodeKey ||
		len(result.Addresses) != 1 || result.Addresses[0].String() != evidence.primaryAddress ||
		len(result.AllowedIPs) != 1 || result.AllowedIPs[0] != result.Addresses[0] ||
		result.CapabilityVersion != 142 || !result.MachineAuthorized ||
		result.DiscoveryKey != connectivity.DiscoveryKey ||
		!slices.Equal(result.Endpoints, connectivity.Endpoints) ||
		result.PeerCount != 0 || !result.DenyAll {
		t.Fatalf("process full map is incomplete or unsafe: %+v", result)
	}
}

func assertControlClientMetrics(t *testing.T, running readyControlProcess) {
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
		`meshtransit_redis_commands_total{operation="presence_acquire",result="success"} 1`,
		`meshtransit_redis_commands_total{operation="endpoints_observe",result="success"} 1`,
		"meshtransit_control_registrations_active 0",
		"meshtransit_control_authenticated_sessions_active 0",
		"meshtransit_control_map_streams_active 0",
		"meshtransit_revision_feed_subscriber_connected 1",
		"meshtransit_revision_feed_watchers_active 0",
		"meshtransit_connectivity_feed_subscriber_connected 1",
		"meshtransit_connectivity_feed_watchers_active 0",
		`meshtransit_redis_commands_total{operation="connectivity_load",result="success"}`,
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	lastStatus := 0
	lastBody := ""
	for {
		status, body, err := integrationGET(ctx, client, running.healthAddress, "/metrics")
		if err == nil {
			lastStatus = status
			lastBody = body
		}
		if err == nil && status == http.StatusOK && containsEveryMetric(body, want) {
			return
		}
		select {
		case <-ctx.Done():
			if lastBody == "" && err != nil {
				t.Fatalf("read process control metrics: %v", err)
			}
			if lastStatus != http.StatusOK {
				t.Fatalf("process control metrics status = %d, want %d", lastStatus, http.StatusOK)
			}
			for _, metric := range want {
				if !strings.Contains(lastBody, metric) {
					t.Fatalf("process control metrics missing %q", metric)
				}
			}
		case <-ticker.C:
		}
	}
}

type processRevisionFeedMetrics struct {
	connected      bool
	activeWatchers uint64
	wakeups        uint64
	delivered      uint64
	coalesced      uint64
}

func waitForProcessRevisionFeedMetrics(
	t *testing.T,
	running readyControlProcess,
	ready func(processRevisionFeedMetrics) bool,
) processRevisionFeedMetrics {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var latest processRevisionFeedMetrics
	var body string
	for {
		status, responseBody, err := integrationGET(ctx, client, running.healthAddress, "/metrics")
		body = responseBody
		if err == nil && status == http.StatusOK {
			if parsed, ok := parseProcessRevisionFeedMetrics(body); ok {
				latest = parsed
				if ready(parsed) {
					return parsed
				}
			}
		}
		select {
		case <-ctx.Done():
			if err != nil {
				t.Fatalf("read process revision-feed metrics: %v", err)
			}
			t.Fatalf("process revision-feed metrics did not converge: latest=%+v body=%s", latest, body)
		case <-ticker.C:
		}
	}
}

func parseProcessRevisionFeedMetrics(body string) (processRevisionFeedMetrics, bool) {
	connected, connectedOK := parseProcessMetric(body, "meshtransit_revision_feed_subscriber_connected")
	watchers, watchersOK := parseProcessMetric(body, "meshtransit_revision_feed_watchers_active")
	wakeups, wakeupsOK := parseProcessMetric(body, "meshtransit_revision_feed_wakeups_received_total")
	delivered, deliveredOK := parseProcessMetric(
		body,
		`meshtransit_revision_feed_fanout_total{result="delivered"}`,
	)
	coalesced, coalescedOK := parseProcessMetric(
		body,
		`meshtransit_revision_feed_fanout_total{result="coalesced"}`,
	)
	return processRevisionFeedMetrics{
		connected:      connected == 1,
		activeWatchers: watchers,
		wakeups:        wakeups,
		delivered:      delivered,
		coalesced:      coalesced,
	}, connectedOK && connected <= 1 && watchersOK && wakeupsOK && deliveredOK && coalescedOK
}

func parseProcessMetric(body, name string) (uint64, bool) {
	for line := range strings.SplitSeq(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != name {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		return value, err == nil
	}
	return 0, false
}

func waitForProcessRevisionDelivery(
	parent context.Context,
	t *testing.T,
	running readyControlProcess,
	adminConnection *pgx.Conn,
	nodePublicID string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		var pending int64
		err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event
WHERE workspace_id = 101
  AND network_id = 201
  AND aggregate_kind = 'device'
  AND aggregate_public_id = $1::UUID
  AND network_revision IS NOT NULL
  AND completed_at IS NULL`, nodePublicID).Scan(&pending)
		if err == nil && pending == 0 {
			return
		}
		select {
		case <-ctx.Done():
			running.process.forceStop(t)
			if err != nil {
				t.Fatalf("read process revision delivery state: %v", err)
			}
			t.Fatalf("process left %d Network revision events undelivered", pending)
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
