//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/adapter/mtcp/mtcptest"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/platform/config"
)

// The scale test is opt-in: MESHTRANSIT_SCALE_SESSIONS=N registers N Devices
// in the fixture Network, holds N map streams on one control process and
// measures how revision and connectivity changes fan out to them.
const (
	scaleSessionsEnvironment = "MESHTRANSIT_SCALE_SESSIONS"
	// MESHTRANSIT_SCALE_POLICY=none keeps the fixture's deny-all policy;
	// otherwise every Device may reach Device 0, so Device 0 sees N-1 peers
	// and each other Device sees Device 0.
	scalePolicyEnvironment = "MESHTRANSIT_SCALE_POLICY"
	// Pool sizes for the control process; the platform script's 2 and 1
	// are far below the production defaults (10 and 10).
	scalePostgresPoolEnvironment = "MESHTRANSIT_SCALE_POSTGRES_RUNTIME_MAX_CONNECTIONS"
	scaleRedisPoolEnvironment    = "MESHTRANSIT_SCALE_REDIS_POOL_SIZE"
	// MESHTRANSIT_SCALE_REBALANCE=1 adds a phase: a second control process
	// starts, reconnecting nodes go to it, and the first sheds to its share.
	scaleRebalanceEnvironment = "MESHTRANSIT_SCALE_REBALANCE"
	scaleRebalanceInterval    = "1s"
	// MESHTRANSIT_SCALE_CONTROL_PROCESSES=K spreads the sessions over K
	// control processes sharing the database and Redis (clients are
	// assigned round robin, as a load balancer would).
	scaleProcessesEnvironment = "MESHTRANSIT_SCALE_CONTROL_PROCESSES"
	// MESHTRANSIT_SCALE_PARALLELISM bounds concurrent registrations and
	// stream opens (default 32).
	scaleParallelismEnvironment = "MESHTRANSIT_SCALE_PARALLELISM"
	// MESHTRANSIT_SCALE_PROFILE_ADDRESS=127.0.0.1:port serves pprof from the
	// first control process; with MESHTRANSIT_SCALE_PROFILE_FILE the test
	// saves its heap profile there once every phase ran.
	scaleProfileEnvironment     = "MESHTRANSIT_SCALE_PROFILE_ADDRESS"
	scaleProfileFileEnvironment = "MESHTRANSIT_SCALE_PROFILE_FILE"
	scaleDefaultPoolSize        = "10"

	scaleSessionHeadway        = 128 // sessions above N for registrations and reconnects in flight
	scaleMaxSessions           = 200_000
	scaleMaxSessionsPerProcess = 16_384
	scaleMaxProcesses          = 16
	scalePhaseTimeout          = 2 * time.Minute
	scaleQuietPeriod           = 2 * time.Second
	scaleExtraPrefix           = "100.80.0.0/14"
	scaleHubEndpoint           = "198.51.100.77:41641"
)

func TestRoleControlProcessScalesMapStreams(t *testing.T) {
	sessions := scaleSessionCount(t)
	binary := validateTestBinary(t, os.Getenv(testMeshcoreBinaryEnvironment))
	processConfig, err := config.Load(os.LookupEnv)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	adminConfig := loadIntegrationAdminConfig(t)
	perSession := time.Duration(sessions) * 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 6*scalePhaseTimeout+3*perSession)
	defer cancel()
	admin := openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database, adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile, adminConfig.ConnectTimeout)
	credential := seedScaleEnrollment(ctx, t, admin, processConfig)
	seeded := scaleSeedCount(t)
	if seeded > 0 {
		t.Logf("seed: %d Devices in %v", seeded, seedScaleNetworkDevices(ctx, t, admin, seeded).Round(time.Millisecond))
	}
	processes := scaleProcessCount(t, sessions)
	perProcess := (sessions + processes - 1) / processes
	controlAddresses := []string{reserveLoopbackAddress(t)}
	running := startScaleControlProcess(t, binary, controlAddresses[0], perProcess)
	healthAddresses := []string{running.healthAddress}
	for range processes - 1 {
		health, control := reserveLoopbackAddress(t), reserveLoopbackAddress(t)
		startScaleControlOnly(t, binary, health, control, perProcess)
		controlAddresses, healthAddresses = append(controlAddresses, control), append(healthAddresses, health)
	}
	clients := newScaleClients(t, processConfig, controlAddresses, sessions)

	registered := registerScaleClients(ctx, t, running, clients, credential, scalePhaseTimeout+perSession)
	peersVisible := os.Getenv(scalePolicyEnvironment) != "none"
	if peersVisible {
		seedScaleStarPolicy(ctx, t, admin, registered.deviceIDs)
	}
	backlog := waitForScaleRevisionBacklog(ctx, t, running, admin, scalePhaseTimeout+perSession)

	collector := newScaleCollector(len(clients))
	defer collector.closeAll()
	streams := openScaleStreams(ctx, t, running, clients, collector, scalePhaseTimeout+perSession)
	collector.quiesce(ctx, scalePhaseTimeout)
	collector.failOnUnexpected(t, running)

	revision := measureScaleRevisionFanout(ctx, t, running, admin, collector, len(clients))
	connectivity := measureScaleConnectivityFanout(ctx, t, running, clients[0], collector,
		registered.deviceIDs[0], peersVisible)
	collector.failOnUnexpected(t, running)
	rebalanced := "not measured (set " + scaleRebalanceEnvironment + "=1 with one process)"
	if os.Getenv(scaleRebalanceEnvironment) == "1" && processes == 1 {
		rebalanced = measureScaleRebalance(ctx, t, binary, running, clients, collector, sessions)
	}
	metrics := readScaleMetrics(t, running)
	saveScaleHeapProfile(ctx, t)

	t.Logf("scale summary: sessions=%d processes=%d peers_visible=%t seeded=%d", sessions, processes, peersVisible,
		seeded)
	for index, health := range healthAddresses {
		t.Logf("control process %d: %s", index, scaleProcessSummary(ctx, t, health))
	}
	t.Logf("registration: %s", registered.stats)
	t.Logf("revision backlog drained in %v (%d events at start)", backlog.elapsed.Round(time.Millisecond), backlog.start)
	t.Logf("stream open: %s; initial peers on Device 0=%d, on Device 1=%d",
		streams.stats, streams.initial[0].Map.PeerCount, streams.initial[min(1, len(streams.initial)-1)].Map.PeerCount)
	t.Logf("revision fan-out: %s", revision)
	t.Logf("connectivity fan-out: %s", connectivity)
	t.Logf("rebalance: %s", rebalanced)
	t.Logf("streams Core ended with Lifecycle RECONNECT and the test reopened: %d", collector.reconnectCount())
	for _, line := range metrics {
		t.Logf("metric %s", line)
	}
	for _, line := range scaleProcessWarnings(running.process.stderr.String()) {
		t.Logf("control log %s", line)
	}
	for _, line := range scaleProcessWarnings(running.worker.stderr.String()) {
		t.Logf("worker log %s", line)
	}
	collector.closeAll()
	stopReadyControlProcess(t, running)
}

func scaleSessionCount(t *testing.T) int {
	t.Helper()
	raw := os.Getenv(scaleSessionsEnvironment)
	if raw == "" {
		t.Skip("set " + scaleSessionsEnvironment + "=N with MESHTRANSIT_INTEGRATION=1 to run the MTCP scale test")
	}
	if os.Getenv("MESHTRANSIT_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_INTEGRATION=1 with disposable TLS dependencies")
	}
	sessions, err := strconv.Atoi(raw)
	if err != nil || sessions < 2 || sessions > scaleMaxSessions {
		t.Fatalf("%s=%q must be an integer in [2, %d]", scaleSessionsEnvironment, raw, scaleMaxSessions)
	}
	return sessions
}

// startScaleControlProcess is startReadyControlProcess with the session
// bound raised to hold every stream and production-sized pools.
func startScaleControlProcess(t *testing.T, binary, controlAddress string, sessions int) readyControlProcess {
	t.Helper()
	healthAddress := reserveLoopbackAddress(t)
	process := startScaleControlOnly(t, binary, healthAddress, controlAddress, sessions)
	workerHealthAddress := reserveLoopbackAddress(t)
	workerEnvironment := integrationProcessEnvironment(workerHealthAddress, reserveLoopbackAddress(t))
	workerEnvironment = setEnvironmentValue(workerEnvironment, "MESHTRANSIT_ROLE", "worker")
	// The product's outbox defaults, not the fixture's one-event batches.
	for _, name := range []string{"MESHTRANSIT_NETWORK_REVISION_BATCH_SIZE", "MESHTRANSIT_NETWORK_REVISION_LEASE",
		"MESHTRANSIT_NETWORK_REVISION_POLL_INTERVAL", "MESHTRANSIT_NETWORK_REVISION_OPERATION_TIMEOUT"} {
		workerEnvironment = withoutEnvironmentValue(workerEnvironment, name)
	}
	worker := startIntegrationProcess(t, binary, workerEnvironment)
	t.Cleanup(func() { worker.forceStop(t) })
	workerCtx, cancelWorker := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelWorker()
	if err := waitForReady(workerCtx, worker, workerHealthAddress); err != nil {
		worker.forceStop(t)
		process.forceStop(t)
		t.Fatalf("wait for worker readiness: %v; stderr: %s", err, worker.stderr.String())
	}
	return readyControlProcess{process: process, worker: worker, healthAddress: healthAddress}
}

// startScaleControlOnly starts one control process sized for the scale test
// and waits until it is ready.
func startScaleControlOnly(t *testing.T, binary, healthAddress, controlAddress string, sessions int) *integrationProcess {
	t.Helper()
	environment := integrationProcessEnvironment(healthAddress, controlAddress)
	environment = setEnvironmentValue(environment, "MESHTRANSIT_CONTROL_MAX_SESSIONS",
		strconv.Itoa(min(scaleMaxSessionsPerProcess, sessions+scaleSessionHeadway)))
	// Every test client connects from one loopback address; per-source
	// handshake admission would measure the limiter, not Core.
	environment = setEnvironmentValue(environment, "MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_RATE",
		scaleEnvironmentOr("MESHTRANSIT_SCALE_HANDSHAKE_RATE", "2000"))
	environment = setEnvironmentValue(environment, "MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_BURST",
		scaleEnvironmentOr("MESHTRANSIT_SCALE_HANDSHAKE_BURST", "20000"))
	environment = setEnvironmentValue(environment, "MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS",
		scaleEnvironmentOr(scalePostgresPoolEnvironment, scaleDefaultPoolSize))
	environment = setEnvironmentValue(environment, "MESHTRANSIT_REDIS_POOL_SIZE",
		scaleEnvironmentOr(scaleRedisPoolEnvironment, scaleDefaultPoolSize))
	if os.Getenv(scaleRebalanceEnvironment) == "1" {
		environment = setEnvironmentValue(environment, "MESHTRANSIT_CONTROL_REBALANCE_INTERVAL", scaleRebalanceInterval)
	}
	if address := os.Getenv(scaleProfileEnvironment); address != "" && !scaleProfileClaimed.Swap(true) {
		// The first control process serves profiles for the run.
		environment = setEnvironmentValue(environment, "MESHTRANSIT_PROFILE_ADDRESS", address)
	}
	process := startIntegrationProcess(t, binary, environment)
	t.Cleanup(func() { process.forceStop(t) })
	startCtx, cancelStart := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelStart()
	if err := waitForReady(startCtx, process, healthAddress); err != nil {
		process.forceStop(t)
		t.Fatalf("wait for control readiness: %v; stderr: %s", err, process.stderr.String())
	}
	return process
}

// scaleProcessCount reads how many control processes share the sessions;
// each must hold its share within the per-process session cap.
func scaleProcessCount(t *testing.T, sessions int) int {
	t.Helper()
	processes, err := strconv.Atoi(scaleEnvironmentOr(scaleProcessesEnvironment, "1"))
	if err != nil || processes < 1 || processes > scaleMaxProcesses {
		t.Fatalf("%s must be an integer in [1, %d]", scaleProcessesEnvironment, scaleMaxProcesses)
	}
	if share := (sessions + processes - 1) / processes; share+scaleSessionHeadway > scaleMaxSessionsPerProcess {
		t.Fatalf("%d sessions on %d processes exceed %d per process; add processes", sessions, processes,
			scaleMaxSessionsPerProcess-scaleSessionHeadway)
	}
	return processes
}

func scaleParallelism() int {
	parallelism, err := strconv.Atoi(scaleEnvironmentOr(scaleParallelismEnvironment, "32"))
	if err != nil || parallelism < 1 || parallelism > 1024 {
		return 32
	}
	return parallelism
}

func scaleEnvironmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// newScaleID returns a random UUIDv7 for fixture rows the test may write
// again on a reused database.
func newScaleID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("generate scale fixture ID: %v", err)
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().UnixMilli()))
	copy(raw[:6], stamp[2:])
	raw[6] = 0x70 | raw[6]&0x0f
	raw[8] = 0x80 | raw[8]&0x3f
	text := hex.EncodeToString(raw[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

func readScaleNetworkRevisions(ctx context.Context, t *testing.T, admin *pgx.Conn) (int64, int64) {
	t.Helper()
	var networkRevision, policyRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision, policy_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&networkRevision, &policyRevision); err != nil {
		t.Fatalf("read scale Network revisions: %v", err)
	}
	return networkRevision, policyRevision
}

// seedScaleEnrollment adds an unlimited enrollment profile and credential to
// the fixture Network and, for more than one /24 of Devices, another prefix.
func seedScaleEnrollment(ctx context.Context, t *testing.T, admin *pgx.Conn, processConfig config.Config) string {
	t.Helper()
	if processConfig.Enrollment == nil {
		t.Fatal("process integration configuration did not load enrollment")
	}
	token, err := enrollment.GenerateCredentialToken()
	if err != nil {
		t.Fatalf("generate scale credential token: %v", err)
	}
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse scale Deployment ID: %v", err)
	}
	digest, err := processCredentialKeyring(t, processConfig.Enrollment.CredentialDigest.Active).
		Digest(deploymentID, 1, token)
	if err != nil {
		t.Fatalf("digest scale credential: %v", err)
	}
	digestBytes, fingerprint := digest.Bytes(), digest.Fingerprint()
	credentialPublicID, profilePublicID := newScaleID(t), newScaleID(t)
	networkRevision, _ := readScaleNetworkRevisions(ctx, t, admin)
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: newScaleID(t), eventPublicID: newScaleID(t), outboxPublicID: newScaleID(t),
		streamID: 201, aggregateKind: "enrollment_credential", aggregatePublicID: credentialPublicID,
		aggregateVersion: 1, networkRevision: networkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "enrollment.credential.created", permission: "device.register",
		outboxEventClass: "enrollment.credential.created",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)
		var profileID int64
		if err := transaction.QueryRow(ctx, `INSERT INTO mesh.enrollment_profile (
    public_id, workspace_id, network_id, created_by_principal_id, display_name, name_key,
    node_lifetime_seconds, ephemeral_mode, credential_use_policy, credential_max_uses, state
) VALUES ($1::UUID, 101, 201, 11, 'Scale enrollment', $2, 86400, 'persistent', 'unlimited', NULL, 'active')
RETURNING id`, profilePublicID, "scale-"+profilePublicID).Scan(&profileID); err != nil {
			t.Fatalf("insert scale enrollment profile: %v", err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.enrollment_credential (
    public_id, workspace_id, network_id, enrollment_profile_id, issuer_principal_id,
    digest_algorithm, digest_key_id, token_digest, token_fingerprint, issued_recovery_epoch,
    use_limit_kind, max_uses, used_count, valid_from, expires_at, state
) VALUES (
    $1::UUID, 101, 201, $2, 11, $3, $4, $5::BYTEA, $6::BYTEA, 1, 'unlimited', NULL, 0,
    pg_catalog.now() - INTERVAL '1 minute', pg_catalog.now() + INTERVAL '2 hours', 'active'
)`, credentialPublicID, profileID, digest.Algorithm(), digest.KeyID().String(), digestBytes[:],
			fingerprint[:]); err != nil {
			t.Fatalf("insert scale enrollment credential: %v", err)
		}
		// The fixture's pool is a /16; a pool and Network prefix of their own
		// hold up to 262,144 Devices.
		if _, err := transaction.Exec(ctx, `WITH pool AS (
    INSERT INTO mesh.address_pool (public_id, deployment_id, workspace_id, address_realm_id, purpose, prefix, family, state)
    SELECT $1::UUID, 1, 101, 301, 'node_overlay', $3::CIDR, 4, 'active'
    WHERE NOT EXISTS (SELECT 1 FROM mesh.address_pool WHERE address_realm_id = 301 AND prefix = $3::CIDR)
    RETURNING id
)
INSERT INTO mesh.network_prefix (
    public_id, workspace_id, network_id, address_realm_id, address_pool_id, prefix, family, state
)
SELECT $2::UUID, 101, 201, 301, pool.id, $3::CIDR, 4, 'active' FROM pool`,
			newScaleID(t), newScaleID(t), scaleExtraPrefix); err != nil {
			t.Fatalf("insert scale address pool and network prefix: %v", err)
		}
	})
	credentialID, err := enrollment.ParseCredentialID(credentialPublicID)
	if err != nil {
		t.Fatalf("parse scale Credential ID: %v", err)
	}
	presentation, err := enrollment.NewCredentialPresentation(credentialID, token)
	if err != nil {
		t.Fatalf("construct scale credential: %v", err)
	}
	return presentation.Reveal()
}

// seedScaleStarPolicy publishes a release in which every Device may reach
// the first one over TCP/443, so the first Device sees every other Device
// as a peer and each other Device sees the first.
func seedScaleStarPolicy(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceIDs []string) {
	t.Helper()
	networkRevision, policyRevision := readScaleNetworkRevisions(ctx, t, admin)
	releasePublicID := newScaleID(t)
	ruleIDs := make([]string, len(deviceIDs)-1)
	for index := range ruleIDs {
		ruleIDs[index] = newScaleID(t)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: newScaleID(t), eventPublicID: newScaleID(t), outboxPublicID: newScaleID(t),
		streamID: 201, aggregateKind: "policy_release", aggregatePublicID: releasePublicID,
		aggregateVersion: 1, networkRevision: networkRevision + 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "policy.published", permission: "policy.publish",
		outboxEventClass: "network.revision.advanced",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)
		var advancedNetwork, advancedPolicy int64
		if err := transaction.QueryRow(ctx, `SELECT network_revision, policy_revision
FROM mesh_ops.advance_network_policy_revision()`).Scan(&advancedNetwork, &advancedPolicy); err != nil {
			t.Fatalf("advance scale policy revision: %v", err)
		}
		if advancedNetwork != networkRevision+1 || advancedPolicy != policyRevision+1 {
			t.Fatalf("scale policy revisions = (%d, %d), want (%d, %d)",
				advancedNetwork, advancedPolicy, networkRevision+1, policyRevision+1)
		}
		if _, err := transaction.Exec(ctx, `UPDATE mesh.policy_release
SET state = 'superseded', superseded_at = pg_catalog.now(), version = version + 1
WHERE workspace_id = 101 AND network_id = 201 AND state = 'active'`); err != nil {
			t.Fatalf("supersede scale policy release: %v", err)
		}
		var releaseID int64
		if err := transaction.QueryRow(ctx, `INSERT INTO mesh.policy_release (
    public_id, workspace_id, network_id, policy_revision, semantic_hash, compiler_format_version, state
) VALUES ($1::UUID, 101, 201, $2, pg_catalog.decode(pg_catalog.repeat('5c', 32), 'hex'), 1, 'active')
RETURNING id`, releasePublicID, advancedPolicy).Scan(&releaseID); err != nil {
			t.Fatalf("insert scale policy release: %v", err)
		}
		tag, err := transaction.Exec(ctx, `INSERT INTO mesh.compiled_policy_rule (
    public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
    source_device_id, destination_device_id, protocol, destination_ports
)
SELECT rule.public_id::UUID, $2::UUID, 101, 201, $3, $4, source.id, hub.id, 'tcp', '{[443,444)}'::INT4MULTIRANGE
FROM ROWS FROM (pg_catalog.unnest($1::TEXT[]), pg_catalog.unnest($6::TEXT[])) AS rule(public_id, source_public_id)
JOIN mesh.device AS source
  ON source.workspace_id = 101 AND source.network_id = 201 AND source.public_id = rule.source_public_id::UUID
JOIN mesh.device AS hub
  ON hub.workspace_id = 101 AND hub.network_id = 201 AND hub.public_id = $5::UUID`,
			ruleIDs, newScaleID(t), releaseID, advancedPolicy, deviceIDs[0], deviceIDs[1:])
		if err != nil || tag.RowsAffected() != int64(len(ruleIDs)) {
			t.Fatalf("insert scale policy rules = (%v, %v), want %d rows", tag, err, len(ruleIDs))
		}
	})
}

// commitScaleNetworkRevision is commitIntegrationNetworkRevision with fresh
// evidence IDs, so the test can run again on the same database.
func commitScaleNetworkRevision(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	current, _ := readScaleNetworkRevisions(ctx, t, admin)
	committed := current + 1
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: newScaleID(t), eventPublicID: newScaleID(t), outboxPublicID: newScaleID(t),
		streamID: 201, aggregateKind: "network", aggregatePublicID: integrationNetworkPublicID,
		aggregateVersion: committed, networkRevision: committed,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "network.updated", permission: "network.update", outboxEventClass: "network.updated",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)
		if _, err := transaction.Exec(ctx, `UPDATE mesh.network
SET display_name = 'Network scale integration', version = version + 1
WHERE workspace_id = 101 AND id = 201`); err != nil {
			t.Fatalf("update scale Network: %v", err)
		}
		tag, err := transaction.Exec(ctx, `UPDATE mesh_ops.network_revision
SET network_revision = $1, updated_at = pg_catalog.clock_timestamp()
WHERE workspace_id = 101 AND network_id = 201 AND network_revision = $2`, committed, current)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("advance scale Network revision = (%v, %v), want 1 row", tag, err)
		}
	})
	return committed
}

func newScaleClients(t *testing.T, processConfig config.Config, controlAddresses []string, count int) []*mtcptest.Client {
	t.Helper()
	caPEM, err := processConfig.Storage.PostgreSQL.CAFile.Read()
	if err != nil {
		t.Fatalf("read scale client CA: %v", err)
	}
	defer clear(caPEM)
	clients := make([]*mtcptest.Client, count)
	for index := range clients {
		clients[index], err = mtcptest.NewClient(mtcptest.Options{
			ControlAddress: controlAddresses[index%len(controlAddresses)], TLSServerName: processControlTLSServerName,
			RootCAPEM: caPEM, Hostname: fmt.Sprintf("scale-%04d.example", index),
		})
		if err != nil {
			t.Fatalf("mtcptest.NewClient(%d) error = %v", index, err)
		}
	}
	return clients
}

// scaleRetries counts the attempts Core turned away: shed handshakes
// (MTCP admits ten per second per source with a burst of 50, mtcp-v1 §14,
// and every test client shares the loopback source) and Errors Core marked
// non-fatal, which a node retries after the delay Core names.
type scaleRetries struct {
	shed      int
	retryable int
	timeouts  int
}

func (retries scaleRetries) String() string {
	return fmt.Sprintf("shed retries=%d, retryable-error retries=%d, timeout retries=%d", retries.shed,
		retries.retryable, retries.timeouts)
}

// retryScaleShed repeats op while Core sheds the handshake or answers with
// a non-fatal Error.
func retryScaleShed(ctx context.Context, op func() error) (scaleRetries, error) {
	var retries scaleRetries
	for {
		err := op()
		if err == nil {
			return retries, nil
		}
		delay := 100*time.Millisecond + mathrand.N(300*time.Millisecond) //nolint:gosec // jitter only
		switch {
		case strings.Contains(err.Error(), "status 503"):
			retries.shed++
		case strings.Contains(err.Error(), "fatal=false"):
			retries.retryable++
			delay = scaleRetryAfter(err.Error(), delay)
		case ctx.Err() == nil && (strings.Contains(err.Error(), "i/o timeout") ||
			strings.Contains(err.Error(), "lifecycle RECONNECT")):
			// A node retries a registration that timed out or that Core
			// asked to reconnect; the same keys get the same answer.
			retries.timeouts++
		default:
			return retries, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return retries, errors.Join(err, ctx.Err())
		case <-timer.C:
		}
	}
}

// scaleRetryAfter reads "retry after N ms" from a non-fatal Error.
func scaleRetryAfter(text string, fallback time.Duration) time.Duration {
	_, after, found := strings.Cut(text, "retry after ")
	if !found {
		return fallback
	}
	milliseconds, _, _ := strings.Cut(after, " ms")
	value, err := strconv.Atoi(milliseconds)
	if err != nil || value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

// runScaleBounded runs work for every index with scaleParallelism workers
// and returns each index's latency, the summed retries and the first error.
func runScaleBounded(count int, work func(index int) (scaleRetries, error)) ([]time.Duration, scaleRetries, error) {
	latencies := make([]time.Duration, count)
	var (
		mu       sync.Mutex
		retries  scaleRetries
		firstErr error
		group    sync.WaitGroup
	)
	slots := make(chan struct{}, scaleParallelism())
	for index := range count {
		slots <- struct{}{}
		group.Go(func() {
			defer func() { <-slots }()
			started := time.Now()
			attempts, err := work(index)
			mu.Lock()
			defer mu.Unlock()
			latencies[index] = time.Since(started)
			retries.shed += attempts.shed
			retries.retryable += attempts.retryable
			retries.timeouts += attempts.timeouts
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("session %d: %w", index, err)
			}
		})
	}
	group.Wait()
	return latencies, retries, firstErr
}

type scaleRegistrations struct {
	deviceIDs []string
	stats     string
}

func registerScaleClients(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	clients []*mtcptest.Client,
	credential string,
	budget time.Duration,
) scaleRegistrations {
	t.Helper()
	phaseCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	deviceIDs := make([]string, len(clients))
	started := time.Now()
	latencies, retries, err := runScaleBounded(len(clients), func(index int) (scaleRetries, error) {
		return retryScaleShed(phaseCtx, func() error {
			registration, err := clients[index].Register(phaseCtx, credential)
			deviceIDs[index] = registration.DeviceID
			return err
		})
	})
	elapsed := time.Since(started)
	if err != nil {
		running.process.forceStop(t)
		t.Fatalf("register scale clients: %v; stderr: %s", err, scaleTail(running.process.stderr.String()))
	}
	return scaleRegistrations{deviceIDs: deviceIDs, stats: fmt.Sprintf(
		"%d Devices in %v (%.1f/s), %v, latency %s",
		len(clients), elapsed.Round(time.Millisecond), float64(len(clients))/elapsed.Seconds(), retries,
		scaleQuantiles(latencies))}
}

type scaleBacklog struct {
	start   int64
	elapsed time.Duration
}

// waitForScaleRevisionBacklog waits until the worker delivered every
// revision event of the fixture Network, so the streams open on a quiet
// feed.
func waitForScaleRevisionBacklog(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	admin *pgx.Conn,
	budget time.Duration,
) scaleBacklog {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	started := time.Now()
	first := int64(-1)
	for {
		var pending int64
		err := admin.QueryRow(waitCtx, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event
WHERE workspace_id = 101 AND network_id = 201
  AND network_revision IS NOT NULL AND completed_at IS NULL`).Scan(&pending)
		if err == nil && first < 0 {
			first = pending
		}
		if err == nil && pending == 0 {
			return scaleBacklog{start: first, elapsed: time.Since(started)}
		}
		select {
		case <-waitCtx.Done():
			running.process.forceStop(t)
			t.Fatalf("revision backlog of %d events left %d undelivered (last error: %v); worker stderr: %s",
				first, pending, err, scaleTail(running.worker.stderr.String()))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type scaleStreams struct {
	initial []mtcptest.MapUpdate
	stats   string
}

func openScaleStreams(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	clients []*mtcptest.Client,
	collector *scaleCollector,
	budget time.Duration,
) scaleStreams {
	t.Helper()
	phaseCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	opened := scaleStreams{initial: make([]mtcptest.MapUpdate, len(clients))}
	started := time.Now()
	latencies, retries, err := runScaleBounded(len(clients), func(index int) (scaleRetries, error) {
		return retryScaleShed(phaseCtx, func() error {
			stream, initial, err := clients[index].OpenMapStream(phaseCtx)
			if err == nil {
				opened.initial[index] = initial
				collector.read(ctx, index, stream, clients[index])
			}
			return err
		})
	})
	elapsed := time.Since(started)
	if err != nil {
		collector.closeAll()
		running.process.forceStop(t)
		t.Fatalf("open scale streams: %v; stderr: %s", err, scaleTail(running.process.stderr.String()))
	}
	opened.stats = fmt.Sprintf("%d streams in %v (%.1f/s), %v, latency %s",
		len(clients), elapsed.Round(time.Millisecond), float64(len(clients))/elapsed.Seconds(), retries,
		scaleQuantiles(latencies))
	return opened
}

func measureScaleRevisionFanout(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	admin *pgx.Conn,
	collector *scaleCollector,
	count int,
) string {
	t.Helper()
	targets := make([]int, count)
	for index := range targets {
		targets[index] = index
	}
	// Set the watch before the commit; nothing can satisfy it earlier.
	var committed uint64
	var committedMu sync.Mutex
	watch := collector.watch(targets, func(_ int, update mtcptest.MapUpdate) bool {
		committedMu.Lock()
		defer committedMu.Unlock()
		return committed != 0 && update.NetworkRevisions[integrationNetworkPublicID] >= committed
	})
	revision := commitScaleNetworkRevision(ctx, t, admin)
	committedMu.Lock()
	committed = uint64(revision) //nolint:gosec // positive
	committedMu.Unlock()
	latencies := collector.await(ctx, t, running, watch, scalePhaseTimeout, "revision")
	return fmt.Sprintf("revision %d reached %d streams: %s", revision, len(latencies), scaleQuantiles(latencies))
}

// measureScaleConnectivityFanout reconnects Device 0 and reports a new
// endpoint on its new stream. The stream is driven by this goroutine until
// the report is sent, because MapStream allows one caller at a time.
func measureScaleConnectivityFanout(
	ctx context.Context,
	t *testing.T,
	running readyControlProcess,
	hub *mtcptest.Client,
	collector *scaleCollector,
	hubID string,
	peersVisible bool,
) string {
	t.Helper()
	collector.expectEnd(0)
	_ = collector.stream(0).Close()
	var stream *mtcptest.MapStream
	if _, err := retryScaleShed(ctx, func() error {
		var err error
		stream, _, err = hub.OpenMapStream(ctx)
		return err
	}); err != nil {
		running.process.forceStop(t)
		t.Fatalf("reopen scale hub stream: %v; stderr: %s", err, scaleTail(running.process.stderr.String()))
	}
	// Read and acknowledge the hub's stream from the start: with N-1 peers
	// it receives more than the unacknowledged-map window while traffic
	// settles, and Core closes a stream that stops acknowledging. Sends are
	// serialized by the session, so the report below may share the stream.
	collector.read(ctx, 0, stream, hub)
	collector.quiesce(ctx, scalePhaseTimeout)
	// The client spaces its reports; wait that out so the latency below
	// starts when the report leaves, not while the client holds it.
	if err := stream.AwaitReportSpacing(ctx); err != nil {
		t.Fatalf("await scale hub report spacing: %v", err)
	}
	endpoint := netip.MustParseAddrPort(scaleHubEndpoint)
	if err := hub.UpdateEndpoint(endpoint); err != nil {
		t.Fatalf("update scale hub endpoint: %v", err)
	}
	targets := []int{0}
	if peersVisible {
		targets = make([]int, collector.size())
		for index := range targets {
			targets[index] = index
		}
	}
	watch := collector.watch(targets, func(index int, update mtcptest.MapUpdate) bool {
		if index == 0 {
			return slices.Equal(update.Map.Endpoints, []netip.AddrPort{endpoint})
		}
		return update.Snapshot || slices.Contains(update.PeersPatched, hubID) ||
			slices.Contains(update.PeersUpserted, hubID)
	})
	if err := stream.ReportEndpoints(ctx); err != nil {
		running.process.forceStop(t)
		t.Fatalf("report scale hub endpoint: %v; stderr: %s", err, scaleTail(running.process.stderr.String()))
	}
	latencies := collector.await(ctx, t, running, watch, scalePhaseTimeout, "connectivity")
	self := latencies[0]
	peers := slices.Delete(slices.Clone(latencies), 0, 1)
	if len(peers) == 0 {
		return fmt.Sprintf("self delta after %v; peers invisible under the fixture's deny-all policy",
			self.Round(time.Millisecond))
	}
	return fmt.Sprintf("self delta after %v; %d peers (snapshots=%d): %s", self.Round(time.Millisecond),
		len(peers), watch.snapshots(), scaleQuantiles(peers))
}

// readScaleMetrics returns the control process's runtime, session and
// pressure metrics with non-zero values, plus its RSS from ps.
func readScaleMetrics(t *testing.T, running readyControlProcess) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	status, body, err := integrationGET(ctx, client, running.healthAddress, "/metrics")
	if err != nil || status != http.StatusOK {
		t.Fatalf("read scale metrics = (%d, %v), want %d", status, err, http.StatusOK)
	}
	prefixes := []string{
		"go_goroutines", "go_threads", "go_memstats_heap_alloc_bytes", "go_memstats_heap_inuse_bytes",
		"go_memstats_sys_bytes", "go_memstats_stack_inuse_bytes", "go_memstats_next_gc_bytes", "process_resident_memory_bytes", "process_open_fds", "process_cpu_seconds_total",
		"meshtransit_mtcp_handshakes_total", "meshtransit_mtcp_sessions_active", "meshtransit_control_connections",
		"meshtransit_revision_feed", "meshtransit_connectivity_feed", "meshtransit_postgres_pool",
		"meshtransit_map_connectivity", "meshtransit_map_snapshots_total", "meshtransit_redis_command",
	}
	pressure := []string{"reject", "shed", "limit", "drop", "overflow", "timeout", "failure", "error"}
	var lines []string
	for line := range strings.SplitSeq(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.HasPrefix(line, "#") || fields[1] == "0" ||
			strings.Contains(fields[0], "_bucket{") || strings.HasPrefix(fields[0], "go_gc_gomemlimit") {
			continue
		}
		matched := slices.ContainsFunc(prefixes, func(prefix string) bool { return strings.HasPrefix(line, prefix) }) ||
			slices.ContainsFunc(pressure, func(word string) bool { return strings.Contains(fields[0], word) })
		if matched {
			lines = append(lines, line)
		}
	}
	pid := strconv.Itoa(running.process.command.Process.Pid)
	// ps is a fixed local tool; the PID is our own child process.
	if output, err := exec.CommandContext(ctx, "ps", "-o", "rss=", "-p", pid).Output(); err == nil { //nolint:gosec
		lines = append(lines, "ps_rss_kib "+strings.TrimSpace(string(output)))
	}
	return lines
}

// scaleProcessWarnings counts a process's WARN and ERROR log records by
// message and error, so pressure the metrics do not name shows up.
func scaleProcessWarnings(stderr string) []string {
	counts := make(map[string]int)
	for line := range strings.SplitSeq(stderr, "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			continue
		}
		level, _ := record["level"].(string)
		if level != "WARN" && level != "ERROR" {
			continue
		}
		key := fmt.Sprintf("%s %v", level, record["msg"])
		if cause, found := record["error"]; found {
			key += fmt.Sprintf(" error=%v", cause)
		}
		counts[key]++
	}
	lines := make([]string, 0, len(counts))
	for key, count := range counts {
		lines = append(lines, fmt.Sprintf("%dx %s", count, key))
	}
	slices.Sort(lines)
	return lines
}

func scaleQuantiles(latencies []time.Duration) string {
	if len(latencies) == 0 {
		return "no samples"
	}
	sorted := slices.Clone(latencies)
	slices.Sort(sorted)
	at := func(percent int) time.Duration {
		return sorted[(len(sorted)-1)*percent/100].Round(time.Millisecond)
	}
	return fmt.Sprintf("p50=%v p95=%v max=%v", at(50), at(95), sorted[len(sorted)-1].Round(time.Millisecond))
}

// scaleTail bounds a process log quoted in a failure.
func scaleTail(text string) string {
	const limit = 4096
	if len(text) <= limit {
		return text
	}
	return "..." + text[len(text)-limit:]
}

// withoutEnvironmentValue drops name from environment.
func withoutEnvironmentValue(environment []string, name string) []string {
	kept := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, name+"=") {
			kept = append(kept, entry)
		}
	}
	return kept
}

// scaleProcessSummary reads one control process's sessions, CPU, memory and
// goroutines.
func scaleProcessSummary(ctx context.Context, t *testing.T, healthAddress string) string {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	status, body, err := integrationGET(readCtx, client, healthAddress, "/metrics")
	if err != nil || status != http.StatusOK {
		return fmt.Sprintf("metrics unavailable (%d, %v)", status, err)
	}
	values := map[string]string{}
	for line := range strings.SplitSeq(body, "\n") {
		for _, name := range []string{"meshtransit_mtcp_sessions_active", "process_cpu_seconds_total",
			"process_resident_memory_bytes", "go_goroutines", "meshtransit_mtcp_sessions_shed_total"} {
			if value, found := strings.CutPrefix(line, name+" "); found {
				values[name] = value
			}
		}
	}
	rss, _ := strconv.ParseFloat(values["process_resident_memory_bytes"], 64)
	return fmt.Sprintf("sessions=%s shed=%s cpu=%ss rss=%.0fMB goroutines=%s", values["meshtransit_mtcp_sessions_active"],
		values["meshtransit_mtcp_sessions_shed_total"], values["process_cpu_seconds_total"], rss/1e6, values["go_goroutines"])
}

// scaleProfileClaimed gives the profile address to one process only.
var scaleProfileClaimed atomic.Bool

// saveScaleHeapProfile writes the first control process's heap profile.
func saveScaleHeapProfile(ctx context.Context, t *testing.T) {
	t.Helper()
	address, path := os.Getenv(scaleProfileEnvironment), os.Getenv(scaleProfileFileEnvironment)
	if address == "" || path == "" {
		return
	}
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	status, body, err := integrationGET(readCtx, client, address, "/debug/pprof/heap?gc=1")
	if err != nil || status != http.StatusOK {
		t.Logf("heap profile unavailable: %d, %v", status, err)
		return
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Logf("save heap profile: %v", err)
		return
	}
	t.Logf("heap profile saved to %s", path)
	// Goroutines grouped by stack, next to it, to see what holds stacks.
	if status, body, err := integrationGET(readCtx, client, address, "/debug/pprof/goroutine?debug=1"); err == nil &&
		status == http.StatusOK {
		_ = os.WriteFile(path+".goroutines.txt", []byte(body), 0o600)
	}
}
