//go:build integration

package integration

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
)

func assertPostgreSQLBrowserRegistrationApproval(
	ctx context.Context, t *testing.T, admin, runtimeConnection *pgx.Conn,
	runtime *postgresadapter.Pool,
) {
	t.Helper()
	const deploymentPublicID = "01890f00-0000-7000-8000-000000000001"
	const networkPublicID = "01890f00-0000-7000-8000-000000000203"
	const intentPublicID = "01890f00-0000-7000-8000-000000001690"
	var networkRevision, recoveryEpoch int64
	var sessionKeyID string
	var sessionDigestBytes []byte
	if err := admin.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id=103 AND network_id=203`).Scan(&networkRevision); err != nil {
		t.Fatalf("read browser approval fixture Network revision: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT deployment.recovery_epoch,
    session.token_digest_key_id, session.token_digest
FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id=session.deployment_id
WHERE session.public_id=$1::UUID`, integrationManagementSessionPublicID).Scan(
		&recoveryEpoch, &sessionKeyID, &sessionDigestBytes,
	); err != nil {
		t.Fatalf("read browser approval fixture Session: %v", err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000001680",
		eventPublicID:          "01890f02-0000-7000-8000-000000001680",
		outboxPublicID:         "01890f03-0000-7000-8000-000000001680",
		streamID:               203,
		aggregateKind:          "network_membership",
		aggregatePublicID:      "01890f00-0000-7000-8000-000000001682",
		aggregateVersion:       1,
		networkRevision:        networkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "browser.registration.fixture.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "browser.registration.fixture.created",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.enrollment_profile (
    id, public_id, workspace_id, network_id, created_by_principal_id,
    display_name, name_key, node_lifetime_seconds, ephemeral_mode,
    credential_use_policy, state, interactive_authorization_enabled
) OVERRIDING SYSTEM VALUE VALUES (
    1681, '01890f00-0000-7000-8000-000000001681', 103, 203, 11,
    'Committed browser login profile', 'committed-browser-login-profile',
    3600, 'persistent', 'unlimited', 'active', TRUE
)`); err != nil {
			t.Fatalf("seed committed interactive Enrollment Profile: %v", err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.network_membership (
    id, public_id, deployment_id, workspace_id, network_id,
    principal_id, workspace_membership_id, state, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    1682, '01890f00-0000-7000-8000-000000001682', 1, 103, 203,
    11, 841, 'active', pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`); err != nil {
			t.Fatalf("seed committed Network membership: %v", err)
		}
	})

	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		t.Fatal(err)
	}
	selectedNetwork, err := network.ParseID(networkPublicID)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := enrollment.NewBrowserIntentKeyID("integration-browser-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := enrollment.NewBrowserIntentKey(keyID, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.NewBrowserIntentKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	options := postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second,
	}
	intentStore, err := postgresadapter.NewBrowserIntentStore(runtime, options, keys)
	if err != nil {
		t.Fatal(err)
	}
	approvalStore, err := postgresadapter.NewBrowserApprovalStore(
		runtime, options, deploymentID, recoveryEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	var machineBytes, nodeBytes [32]byte
	copy(machineBytes[:], bytes.Repeat([]byte{0xf1}, 32))
	copy(nodeBytes[:], bytes.Repeat([]byte{0xf2}, 32))
	machineKey, err := node.NewMachineKey(machineBytes)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey(nodeBytes)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := node.ParseHostname("committed-browser-device")
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := enrollment.ParseBrowserIntentID(intentPublicID)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := enrollment.NewBrowserIntentNonce()
	if err != nil {
		t.Fatal(err)
	}
	token, err := intentStore.Issue(ctx, deploymentID, recoveryEpoch, identity,
		hostname, intentID, nonce, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("commit browser URL issuance with audit/outbox: %v", err)
	}
	var digestValue [32]byte
	copy(digestValue[:], sessionDigestBytes)
	sessionDigestID, err := accountsession.NewDigestKeyID(sessionKeyID)
	if err != nil {
		t.Fatal(err)
	}
	sessionDigest, err := accountsession.NewDigest(sessionDigestID, digestValue)
	if err != nil {
		t.Fatal(err)
	}
	landing, found, err := intentStore.ReadLanding(ctx, deploymentID, recoveryEpoch,
		sessionDigest, token.Encoded())
	if err != nil || !found || landing.State != "pending" {
		t.Fatalf("committed browser landing = (%+v, %v, %v)", landing, found, err)
	}
	wrongNetwork, err := network.ParseID("01890f00-0000-7000-8000-000000000204")
	if err != nil {
		t.Fatal(err)
	}
	approved, err := approvalStore.Approve(ctx, sessionDigest, token.Encoded(), wrongNetwork)
	if err != nil || approved {
		t.Fatalf("ineligible Network approval = (%v, %v)", approved, err)
	}
	approved, err = approvalStore.Approve(ctx, sessionDigest, token.Encoded(), selectedNetwork)
	if err != nil || !approved {
		t.Fatalf("commit browser Network approval with audit/outbox = (%v, %v)", approved, err)
	}
	approved, err = approvalStore.Approve(ctx, sessionDigest, token.Encoded(), selectedNetwork)
	if err != nil || approved {
		t.Fatalf("duplicate browser approval = (%v, %v)", approved, err)
	}
	var registrationPublicID, pendingState, intentState, approvalSession string
	if err := admin.QueryRow(ctx, `SELECT
    registration.public_id::TEXT, registration.state, intent.state,
    intent.approved_session_public_id::TEXT
FROM mesh.browser_registration_intent AS intent
JOIN mesh.pending_registration AS registration
  ON registration.public_id=intent.pending_registration_public_id
WHERE intent.public_id=$1::UUID
  AND registration.authorization_kind='interactive'`, intentPublicID).Scan(
		&registrationPublicID, &pendingState, &intentState, &approvalSession,
	); err != nil || pendingState != "authorized" || intentState != "approved" ||
		approvalSession != integrationManagementSessionPublicID {
		t.Fatalf("committed approval state = (%s, %s, %s, %s, %v)",
			registrationPublicID, pendingState, intentState, approvalSession, err)
	}
	followup, found, err := intentStore.ReadFollowup(ctx, deploymentID,
		recoveryEpoch, identity, hostname, token.Encoded())
	if err != nil || !found || followup.State != "approved" ||
		followup.PendingRegistrationID.String() != registrationPublicID {
		t.Fatalf("approved machine-bound Followup = (%+v, %v, %v)",
			followup, found, err)
	}
	intentDigest, err := enrollment.DigestPresentedBrowserIntentToken(token.Encoded())
	if err != nil {
		t.Fatal(err)
	}
	intentDigestBytes := intentDigest.Bytes()
	machineFingerprint := machineKey.Fingerprint()
	var recheckedApprovalCount int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.lock_browser_registration_approval_authority_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA,
    $6::UUID, 'approved'::TEXT
)`, deploymentPublicID, recoveryEpoch, sessionKeyID, sessionDigestBytes,
		intentDigestBytes[:], networkPublicID,
	).Scan(&recheckedApprovalCount); err != nil || recheckedApprovalCount != 1 {
		t.Fatalf("approved intent reauthorization = %d: %v", recheckedApprovalCount, err)
	}
	completionCount := func(machineMaterial []byte) int {
		t.Helper()
		var count int
		if err := runtimeConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.lock_browser_registration_completion_authority_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA,
    $5::BYTEA, $6::BYTEA, $7::TEXT
) AS authority
WHERE authority.registration_public_id=$8::UUID
  AND authority.session_public_id=$9::UUID
  AND authority.network_public_id=$10::UUID`,
			deploymentPublicID, recoveryEpoch, intentDigestBytes[:], machineMaterial,
			machineFingerprint[:], nodeBytes[:], hostname.String(),
			registrationPublicID, integrationManagementSessionPublicID, networkPublicID,
		).Scan(&count); err != nil {
			t.Fatalf("read committed browser completion authority: %v", err)
		}
		return count
	}
	if got := completionCount(machineBytes[:]); got != 1 {
		t.Fatalf("approved machine completion authority count = %d, want 1", got)
	}
	if got := completionCount(bytes.Repeat([]byte{0x93}, 32)); got != 0 {
		t.Fatalf("wrong Noise machine reached completion authority: %d", got)
	}
	suspended, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = suspended.Rollback(ctx) }()
	setIntegrationChange(ctx, t, suspended, "01890f00-0000-7000-8000-000000001691")
	if _, err := suspended.Exec(ctx, `UPDATE mesh.network_membership
SET state='suspended', authority_generation=authority_generation+1,
    version=version+1, updated_at=pg_catalog.clock_timestamp()
WHERE id=1682`); err != nil {
		t.Fatalf("suspend browser fixture membership: %v", err)
	}
	var suspendedCount int
	if err := suspended.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.lock_browser_registration_completion_authority_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA,
    $5::BYTEA, $6::BYTEA, $7::TEXT
)`, deploymentPublicID, recoveryEpoch, intentDigestBytes[:], machineBytes[:],
		machineFingerprint[:], nodeBytes[:], hostname.String(),
	).Scan(&suspendedCount); err != nil || suspendedCount != 0 {
		t.Fatalf("suspended membership completion authority = %d: %v", suspendedCount, err)
	}
	if err := suspended.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, evidence := range []struct {
		kind, id, class string
	}{
		{"browser_registration_intent", intentPublicID, "registration.browser.requested"},
		{"pending_registration", registrationPublicID, "registration.browser.approved"},
	} {
		var outboxCount int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event
WHERE aggregate_kind=$1 AND aggregate_public_id=$2::UUID AND event_class=$3`,
			evidence.kind, evidence.id, evidence.class,
		).Scan(&outboxCount); err != nil || outboxCount != 1 {
			t.Fatalf("committed %s outbox count = %d: %v", evidence.class, outboxCount, err)
		}
	}
	completionStore, err := postgresadapter.NewBrowserCompletionStore(
		runtime, postgresadapter.RegistrationTransactionOptions{
			StatementTimeout: 5 * time.Second, LockTimeout: time.Second,
			IdleTimeout: 10 * time.Second, AddressCandidateLimit: 256,
		}, deploymentID, recoveryEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, found, err := completionStore.Complete(ctx, identity,
		hostname, token.Encoded())
	if err != nil || !found || !completed.IsValid() ||
		completed.RegistrationID().String() != registrationPublicID ||
		completed.Scope().NetworkID() != selectedNetwork {
		t.Fatalf("commit interactive Device = (%+v, %v, %v)", completed, found, err)
	}
	var deviceCount, leaseCount, completionOutboxCount int
	var completedPendingState, completedIntentState string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*),
    pg_catalog.min(registration.state), pg_catalog.min(intent.state)
FROM mesh.device AS device
JOIN mesh.pending_registration AS registration ON registration.device_id=device.id
JOIN mesh.browser_registration_intent AS intent
  ON intent.pending_registration_public_id=registration.public_id
WHERE device.public_id=$1::UUID
  AND registration.public_id=$2::UUID
  AND device.registered_by_kind='principal'
  AND device.owner_principal_id=11
  AND device.workspace_id=103 AND device.network_id=203`,
		completed.NodeID().String(), registrationPublicID,
	).Scan(&deviceCount, &completedPendingState, &completedIntentState); err != nil ||
		deviceCount != 1 || completedPendingState != "completed" ||
		completedIntentState != "completed" {
		t.Fatalf("committed Device/registration/intent = %d/%s/%s: %v",
			deviceCount, completedPendingState, completedIntentState, err)
	}
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id=lease.device_id
WHERE device.public_id=$1::UUID AND lease.state='active'`,
		completed.NodeID().String(),
	).Scan(&leaseCount); err != nil || leaseCount < 1 {
		t.Fatalf("interactive Device leases = %d: %v", leaseCount, err)
	}
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event
WHERE aggregate_kind='device' AND aggregate_public_id=$1::UUID
  AND event_class='network.revision.advanced'`,
		completed.NodeID().String(),
	).Scan(&completionOutboxCount); err != nil || completionOutboxCount != 1 {
		t.Fatalf("interactive Device outbox = %d: %v", completionOutboxCount, err)
	}
	replayed, found, err := completionStore.Complete(ctx, identity,
		hostname, token.Encoded())
	if err != nil || !found || !replayed.IsValid() ||
		replayed.NodeID() != completed.NodeID() ||
		replayed.RegistrationID() != completed.RegistrationID() ||
		replayed.NetworkRevision() != completed.NetworkRevision() {
		t.Fatalf("lost-response browser completion replay = (%+v, %v, %v)",
			replayed, found, err)
	}
	wrongMachineKey, err := node.NewMachineKey([32]byte{0x93})
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity, err := node.NewRegistrationIdentity(wrongMachineKey, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err = completionStore.Complete(ctx, wrongIdentity,
		hostname, token.Encoded())
	if err != nil || found {
		t.Fatalf("wrong Noise machine replay = (%v, %v)", found, err)
	}
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event
WHERE aggregate_kind='device' AND aggregate_public_id=$1::UUID
  AND event_class='network.revision.advanced'`,
		completed.NodeID().String(),
	).Scan(&completionOutboxCount); err != nil || completionOutboxCount != 1 {
		t.Fatalf("replay duplicated Device outbox = %d: %v", completionOutboxCount, err)
	}
}
