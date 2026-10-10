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
	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	"meshtransit.net/core/internal/adapter/mtcp/mtcptest"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/platform/config"
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
	// The overall budget covers process start-up plus the largest revision
	// backlog wait.
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second+processRevisionMaxWait)
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
	firstRegistration := registerProcessClient(ctx, t, first, client, fixture.credential.Reveal())
	assertProcessControlKey(t, client, processConfig)
	firstMap := fetchProcessFullMap(ctx, t, first, client)
	assertProcessEndpointObservation(ctx, t, firstMap.DeviceID, client.Connectivity())
	// A new session's snapshot already carries the endpoints Core stored
	// from the previous session's report.
	firstStreamMap := fetchProcessInitialStreamMap(ctx, t, first, client)
	if !reflect.DeepEqual(firstStreamMap, firstMap) {
		first.process.forceStop(t)
		t.Fatalf("first stream snapshot differs from converged map: converged=%+v snapshot=%+v", firstMap, firstStreamMap)
	}
	firstEvidence := readProcessRegistrationEvidence(ctx, t, adminConnection, client.Identity())
	assertProcessRegistrationEvidence(t, firstEvidence)
	assertProcessRegistration(t, firstRegistration, firstEvidence)
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
	secondRegistration := registerProcessClient(ctx, t, second, client, fixture.credential.Reveal())
	if !reflect.DeepEqual(secondRegistration, firstRegistration) {
		second.process.forceStop(t)
		t.Fatalf("registration replay answered another authorization: before=%+v after=%+v",
			firstRegistration, secondRegistration)
	}
	secondMap := fetchProcessFullMap(ctx, t, second, client)
	secondStreamMap := fetchProcessInitialStreamMap(ctx, t, second, client)
	if !reflect.DeepEqual(secondStreamMap, secondMap) {
		second.process.forceStop(t)
		t.Fatalf("restarted stream snapshot differs from converged map: converged=%+v snapshot=%+v",
			secondMap, secondStreamMap)
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

func registerProcessClient(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *mtcptest.Client,
	credential string,
) mtcptest.Registration {
	t.Helper()
	registerCtx, cancelRegister := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRegister()
	registration, err := client.Register(registerCtx, credential)
	if err != nil {
		running.process.forceStop(t)
		t.Fatalf("process registration: %v; stderr: %s", err, running.process.stderr.String())
	}
	return registration
}

// assertProcessControlKey checks that the key document advertised the
// configured control key and expiry, and that the client pinned it.
func assertProcessControlKey(t *testing.T, client *mtcptest.Client, processConfig config.Config) {
	t.Helper()
	if processConfig.Control == nil {
		t.Fatal("process integration configuration did not load control")
	}
	text, err := processConfig.Control.NoisePrivateKeyFile.Read()
	if err != nil {
		t.Fatalf("read process control key: %v", err)
	}
	private, err := mtcpadapter.ParseControlKey(text)
	if err != nil {
		t.Fatalf("parse process control key: %v", err)
	}
	pinned := client.PinnedControlKey()
	if pinned.Public != private.Public() ||
		!pinned.NotAfter.Equal(processConfig.Control.MTCP.KeyNotAfter.Truncate(time.Second)) {
		t.Fatalf("pinned control key = %x until %v, want the configured key until %v",
			pinned.Public, pinned.NotAfter, processConfig.Control.MTCP.KeyNotAfter)
	}
}

func assertProcessRegistration(
	t *testing.T,
	registration mtcptest.Registration,
	evidence processRegistrationEvidence,
) {
	t.Helper()
	if registration.DeviceID != evidence.nodePublicID || registration.NetworkID != integrationNetworkPublicID ||
		len(registration.Addresses) != 1 ||
		netip.PrefixFrom(registration.Addresses[0], registration.Addresses[0].BitLen()).String() != evidence.primaryAddress ||
		!registration.KeyExpiry.After(time.Now()) {
		t.Fatalf("process registration response disagrees with its evidence: %+v", registration)
	}
}

func assertProcessEndpointObservation(
	ctx context.Context,
	t *testing.T,
	deviceID string,
	want mtcptest.Connectivity,
) {
	t.Helper()
	nodeID, err := node.ParseID(deviceID)
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

// assertProcessRevisionWakeup commits a revision that changes nothing the
// node sees. Core cannot express a revision-only change as a delta, so the
// open stream must receive a new-epoch snapshot carrying the new revision
// (mtcp-v1 §7.1) with the map as it was.
func assertProcessRevisionWakeup(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *mtcptest.Client,
	adminConnection *pgx.Conn,
) {
	t.Helper()
	baseline := fetchProcessFullMap(ctx, t, running, client)
	streamCtx, cancelStream := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStream()
	stream, initial := openProcessMapStream(streamCtx, t, running, client)
	if !reflect.DeepEqual(initial.Map, baseline) {
		_ = stream.Close()
		running.process.forceStop(t)
		t.Fatalf("initial revision stream map differs from baseline: baseline=%+v stream=%+v", baseline, initial.Map)
	}
	feedBefore := waitForProcessRevisionFeedMetrics(t, running, func(metrics processRevisionFeedMetrics) bool {
		return metrics.connected && metrics.activeWatchers == 1
	})
	_, committed := commitIntegrationNetworkRevision(streamCtx, t, adminConnection, "994")
	advanced := nextProcessMapUpdate(streamCtx, t, running, stream, initial, func(update mtcptest.MapUpdate) bool {
		return update.NetworkRevisions[integrationNetworkPublicID] >= uint64(committed) //nolint:gosec // positive
	})
	if err := stream.Close(); err != nil {
		running.process.forceStop(t)
		t.Fatalf("close process revision stream: %v", err)
	}
	if initial.NetworkRevisions[integrationNetworkPublicID] >= uint64(committed) || //nolint:gosec // positive
		!advanced.Snapshot ||
		advanced.NetworkRevisions[integrationNetworkPublicID] != uint64(committed) || //nolint:gosec // positive
		!reflect.DeepEqual(advanced.Map, baseline) {
		running.process.forceStop(t)
		t.Fatalf("revision-only change altered map projection: baseline=%+v initial=%v advanced=%+v committed=%d",
			baseline, initial.NetworkRevisions, advanced, committed)
	}
	waitForProcessRevisionFeedMetrics(t, running, func(metrics processRevisionFeedMetrics) bool {
		return metrics.connected && metrics.activeWatchers == 0 &&
			metrics.wakeups >= feedBefore.wakeups+1 &&
			metrics.delivered >= feedBefore.delivered+1
	})
}

// assertProcessConnectivityWakeup reports a new endpoint on an open stream:
// the stream must receive it as a delta replacing self, and the next
// session must converge on the same map.
func assertProcessConnectivityWakeup(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *mtcptest.Client,
) {
	t.Helper()
	baseline := fetchProcessFullMap(ctx, t, running, client)
	streamCtx, cancelStream := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStream()
	stream, initial := openProcessMapStream(streamCtx, t, running, client)
	if !reflect.DeepEqual(initial.Map, baseline) {
		_ = stream.Close()
		running.process.forceStop(t)
		t.Fatalf("initial connectivity stream differs from baseline: baseline=%+v stream=%+v", baseline, initial.Map)
	}

	endpoint := netip.MustParseAddrPort("198.51.100.20:41641")
	if err := client.UpdateEndpoint(endpoint); err != nil {
		_ = stream.Close()
		running.process.forceStop(t)
		t.Fatalf("update protocol-test endpoint: %v", err)
	}
	expected := baseline
	expected.Endpoints = []netip.AddrPort{endpoint}
	if err := stream.ReportEndpoints(streamCtx); err != nil {
		_ = stream.Close()
		running.process.forceStop(t)
		t.Fatalf("report protocol-test endpoint: %v; stderr: %s", err, running.process.stderr.String())
	}
	advanced := nextProcessMapUpdate(streamCtx, t, running, stream, initial, func(update mtcptest.MapUpdate) bool {
		return slices.Equal(update.Map.Endpoints, expected.Endpoints)
	})
	if err := stream.Close(); err != nil {
		running.process.forceStop(t)
		t.Fatalf("close process connectivity stream: %v", err)
	}
	updated := fetchProcessFullMap(ctx, t, running, client)
	if !reflect.DeepEqual(advanced.Map, expected) || advanced.Snapshot || !advanced.SelfChanged ||
		!reflect.DeepEqual(updated, expected) {
		running.process.forceStop(t)
		t.Fatalf("connectivity projection did not converge: baseline=%+v stream=%+v reconnect=%+v",
			baseline, advanced, updated)
	}
	assertProcessEndpointObservation(ctx, t, baseline.DeviceID, client.Connectivity())
}

func openProcessMapStream(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *mtcptest.Client,
) (*mtcptest.MapStream, mtcptest.MapUpdate) {
	t.Helper()
	stream, initial, err := client.OpenMapStream(ctx)
	if err != nil {
		running.process.forceStop(t)
		t.Fatalf("open process map stream: %v; stderr: %s", err, running.process.stderr.String())
	}
	return stream, initial
}

// nextProcessMapUpdate reads the stream until done accepts an update. Every
// update on the way must leave the peers alone: the node is alone in its
// Network.
func nextProcessMapUpdate(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	stream *mtcptest.MapStream,
	initial mtcptest.MapUpdate,
	done func(mtcptest.MapUpdate) bool,
) mtcptest.MapUpdate {
	t.Helper()
	for {
		update, err := stream.Next(ctx)
		if err != nil {
			_ = stream.Close()
			running.process.forceStop(t)
			t.Fatalf("read process map stream: %v; stderr: %s", err, running.process.stderr.String())
		}
		if len(update.PeersUpserted) != 0 || len(update.PeersRemoved) != 0 ||
			len(update.PeersPatched) != 0 {
			_ = stream.Close()
			running.process.forceStop(t)
			t.Fatalf("process map stream sent an unexpected update after revisions %v: %+v",
				initial.NetworkRevisions, update)
		}
		if done(update) {
			return update
		}
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

// fetchProcessFullMap is MTCP's one-shot map: a session that reports the
// client's connectivity, waits for the map converged on it and closes.
func fetchProcessFullMap(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *mtcptest.Client,
) mtcptest.FullMap {
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

// fetchProcessInitialStreamMap returns the snapshot a new session starts
// with, before it reports anything.
func fetchProcessInitialStreamMap(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	client *mtcptest.Client,
) mtcptest.FullMap {
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
	result mtcptest.FullMap,
	evidence processRegistrationEvidence,
	identity mtcptest.Identity,
	connectivity mtcptest.Connectivity,
) {
	t.Helper()
	if result.DeviceID != evidence.nodePublicID ||
		result.Name != evidence.hostname+"." || result.DisplayName != evidence.hostname ||
		result.NodeKey != identity.NodeKey ||
		len(result.Addresses) != 1 || result.Addresses[0].String() != evidence.primaryAddress ||
		len(result.AllowedPrefixes) != 1 || result.AllowedPrefixes[0] != result.Addresses[0] ||
		!result.KeyExpiry.After(time.Now()) ||
		result.DiscoveryKey != connectivity.DiscoveryKey ||
		!slices.Equal(result.Endpoints, connectivity.Endpoints) ||
		result.PeerCount != 0 || !result.DenyAll {
		t.Fatalf("process full map is incomplete or unsafe: %+v", result)
	}
}

// processMetricWant is one expected metric value; atLeast tolerates
// sessions retried after a Lifecycle RECONNECT.
type processMetricWant struct {
	name    string
	value   uint64
	atLeast bool
}

// assertControlClientMetrics checks one process after one registration
// session and two map sessions (one reporting endpoints), all closed.
func assertControlClientMetrics(t *testing.T, running readyControlProcess) {
	t.Helper()
	if running.process == nil || running.healthAddress == "" {
		t.Fatal("integration process is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	want := []processMetricWant{
		{name: `meshtransit_mtcp_handshakes_total{result="established"}`, value: 3, atLeast: true},
		{name: `meshtransit_mtcp_messages_total{direction="received",type="0x10"}`, value: 1}, // RegisterRequest
		{name: `meshtransit_mtcp_messages_total{direction="sent",type="0x11"}`, value: 1},     // RegisterResponse
		{name: `meshtransit_mtcp_messages_total{direction="sent",type="0x51"}`, value: 3},     // KeyUpdate
		{name: `meshtransit_mtcp_messages_total{direction="sent",type="0x20"}`, value: 3},     // MapSnapshot
		{name: `meshtransit_mtcp_messages_total{direction="received",type="0x30"}`, value: 1}, // EndpointReport
		{name: `meshtransit_redis_commands_total{operation="presence_acquire",result="success"}`, value: 3, atLeast: true},
		{name: `meshtransit_redis_commands_total{operation="endpoints_observe",result="success"}`, value: 1},
		{name: `meshtransit_redis_commands_total{operation="connectivity_load",result="success"}`, value: 1, atLeast: true},
		{name: "meshtransit_mtcp_sessions_active", value: 0},
		{name: "meshtransit_control_connections_active", value: 0},
		{name: "meshtransit_revision_feed_subscriber_connected", value: 1},
		{name: "meshtransit_revision_feed_watchers_active", value: 0},
		{name: "meshtransit_connectivity_feed_subscriber_connected", value: 1},
		{name: "meshtransit_connectivity_feed_watchers_active", value: 0},
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
		if err == nil && status == http.StatusOK && unmetProcessMetric(body, want) == "" {
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
			t.Fatalf("process control metrics: %s", unmetProcessMetric(lastBody, want))
		case <-ticker.C:
		}
	}
}

// unmetProcessMetric describes the first expectation body does not meet,
// or returns "".
func unmetProcessMetric(body string, want []processMetricWant) string {
	for _, metric := range want {
		value, found := parseProcessMetric(body, metric.name)
		switch {
		case !found:
			return metric.name + " is missing"
		case metric.atLeast && value < metric.value:
			return metric.name + " = " + strconv.FormatUint(value, 10) + ", want at least " +
				strconv.FormatUint(metric.value, 10)
		case !metric.atLeast && value != metric.value:
			return metric.name + " = " + strconv.FormatUint(value, 10) + ", want " + strconv.FormatUint(metric.value, 10)
		}
	}
	return ""
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

// Revision delivery budget: the worker claims one event per poll in
// available_at order, so earlier tests' backlog in the shared database is
// delivered first. The deadline grows with the backlog ahead of the Device
// event, up to processRevisionMaxWait.
const (
	processRevisionBaseWait = 10 * time.Second
	processRevisionPerEvent = 250 * time.Millisecond
	processRevisionMaxWait  = 90 * time.Second
)

func processRevisionDeliveryWait(ahead int64) time.Duration {
	if ahead <= 0 {
		return processRevisionBaseWait
	}
	return min(processRevisionBaseWait+time.Duration(ahead)*processRevisionPerEvent, processRevisionMaxWait)
}

func waitForProcessRevisionDelivery(
	parent context.Context,
	t *testing.T,
	running readyControlProcess,
	adminConnection *pgx.Conn,
	nodePublicID string,
) {
	t.Helper()
	var ahead int64
	if err := adminConnection.QueryRow(parent, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event AS event
WHERE event.completed_at IS NULL
  AND event.network_revision IS NOT NULL
  AND event.id <= (
      SELECT pg_catalog.max(device.id) FROM mesh_ops.outbox_event AS device
      WHERE device.aggregate_kind = 'device' AND device.aggregate_public_id = $1::UUID
  )`, nodePublicID).Scan(&ahead); err != nil {
		running.process.forceStop(t)
		t.Fatalf("read process revision backlog: %v", err)
	}
	ctx, cancel := context.WithTimeout(parent, processRevisionDeliveryWait(ahead))
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	pending := int64(-1)
	var readErr error
	for {
		var current int64
		readErr = adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event
WHERE workspace_id = 101
  AND network_id = 201
  AND aggregate_kind = 'device'
  AND aggregate_public_id = $1::UUID
  AND network_revision IS NOT NULL
  AND completed_at IS NULL`, nodePublicID).Scan(&current)
		if readErr == nil {
			pending = current
			if pending == 0 {
				return
			}
		}
		select {
		case <-ctx.Done():
			running.process.forceStop(t)
			t.Fatalf("process left %d Network revision events undelivered behind a backlog of %d (last read error: %v); worker stderr: %s",
				pending, ahead, readErr, running.worker.stderr.String())
		case <-ticker.C:
		}
	}
}
