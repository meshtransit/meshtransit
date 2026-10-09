//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/adapter/postgres/registrationintake"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	registrationapp "github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration"
	appintake "github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const (
	intakeCredentialInternalID = 642
	intakeCredentialPublicID   = "01890f60-0000-7000-8000-000000000642"
	intakeRegistrationPublicID = "01890f60-0000-7000-8000-000000000646"
	intakeChangePublicID       = "01890f61-0000-7000-8000-000000000641"
	intakeAuditPublicID        = "01890f62-0000-7000-8000-000000000641"
	intakeOutboxPublicID       = "01890f63-0000-7000-8000-000000000641"
)

type registrationIntakeFixture struct {
	request appintake.Request
	keyring *enrollment.CredentialKeyring
}

func assertPostgreSQLRegistrationIntake(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	fixture := seedRegistrationIntakeAuthority(ctx, t, adminConnection)
	transactions, err := postgresadapter.NewRegistrationIntakeTransactions(
		runtimePool,
		registrationintake.Options{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationIntakeTransactions() error = %v", err)
	}
	evidenceIDs := &integrationIntakeEvidenceIDs{ids: intakeEvidenceIDs(t)}
	service, err := appintake.NewService(
		appintake.Options{
			MaxAttempts:     3,
			RollbackTimeout: time.Second,
			PendingTTL:      10 * time.Minute,
		},
		appintake.Dependencies{
			Transactions:     transactions,
			PreparedIntents:  transactions,
			CredentialProofs: fixture.keyring,
			EvidenceIDs:      evidenceIDs,
			Clock:            integrationIntakeClock{},
			Retry:            integrationIntakeRetry{},
		},
	)
	if err != nil {
		t.Fatalf("intake.NewService() error = %v", err)
	}
	assertRegistrationIntakeAuthority(
		ctx,
		t,
		transactions,
		fixture,
	)

	wrongRequest := fixture.request
	wrongRequest.Token, err = enrollment.GenerateCredentialToken()
	if err != nil {
		t.Fatalf("generate incorrect integration credential token: %v", err)
	}
	if _, err := service.Prepare(ctx, wrongRequest); !errors.Is(err, appintake.ErrAuthenticationFailed) {
		t.Fatalf("Prepare(wrong proof) error = %v, want generic authentication failure", err)
	}
	assertPendingIntentCount(ctx, t, adminConnection, 0)

	command, err := service.Prepare(ctx, fixture.request)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if command.Scope.WorkspaceID().String() != firstWorkspacePublicID ||
		command.Scope.NetworkID().String() != firstNetworkPublicID || command.RecoveryEpoch != 1 {
		t.Fatalf("Prepare() returned non-server-derived authority: %+v", command)
	}
	replayed, err := service.Prepare(ctx, fixture.request)
	if err != nil {
		t.Fatalf("Prepare(replay) error = %v", err)
	}
	if replayed != command || evidenceIDs.calls != 1 {
		t.Fatalf("Prepare(replay) = %+v, evidence calls = %d, want exact replay/1", replayed, evidenceIDs.calls)
	}
	assertRegistrationIntakeEvidence(ctx, t, adminConnection, command)
}

func assertWorkerCannotResolveRegistrationIntakeScope(
	ctx context.Context,
	t *testing.T,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	var canResolve bool
	if err := workerConnection.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege(
    CURRENT_USER,
    'mesh_ops.resolve_registration_intake_scope(uuid)',
    'EXECUTE'
)`).Scan(&canResolve); err != nil {
		t.Fatalf("query worker registration-intake resolver privilege: %v", err)
	}
	if canResolve {
		t.Fatal("worker can execute registration-intake scope resolver")
	}
	err := workerConnection.QueryRow(ctx, `SELECT deployment_public_id
FROM mesh_ops.resolve_registration_intake_scope(
    '01890f20-0000-7000-8000-000000000612'::UUID
)`).Scan(new(string))
	assertPostgreSQLCode(t, err, "42501")
}

func assertRegistrationIntakeAuthority(
	ctx context.Context,
	t *testing.T,
	transactions *registrationintake.Transactions,
	fixture registrationIntakeFixture,
) {
	t.Helper()
	lookup := appintake.Lookup{
		RegistrationID:     fixture.request.RegistrationID,
		CredentialID:       fixture.request.CredentialID,
		MachineFingerprint: fixture.request.Identity.MachineKey().Fingerprint(),
		RequestedNodeKey:   fixture.request.Identity.NodeKey().Bytes(),
	}
	transaction, err := transactions.Begin(ctx, lookup)
	if err != nil {
		t.Fatalf("RegistrationIntakeTransactions.Begin() error = %v", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), integrationCleanupTimeout)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			t.Errorf("RegistrationIntakeTransaction.Rollback() error = %v", err)
		}
	}()
	resolution, err := transaction.Resolve(ctx, lookup)
	if err != nil {
		t.Fatalf("RegistrationIntakeTransaction.Resolve() error = %v", err)
	}
	authority := resolution.Authority()
	if !fixture.keyring.Verify(
		authority.DeploymentID(),
		authority.Credential().IssuedRecoveryEpoch(),
		fixture.request.Token,
		authority.Digest(),
	) {
		t.Fatal("resolved registration-intake authority rejected the matching proof")
	}
	if err := authority.Profile().ValidateCredential(authority.Credential()); err != nil {
		t.Fatalf("resolved registration-intake profile rejected credential: %v", err)
	}
	if _, err := authority.Credential().Consume(time.Now().UTC(), authority.RecoveryEpoch()); err != nil {
		t.Fatalf("resolved registration-intake credential is unusable: %v", err)
	}
}

func seedRegistrationIntakeAuthority(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) registrationIntakeFixture {
	t.Helper()
	token, err := enrollment.GenerateCredentialToken()
	if err != nil {
		t.Fatalf("generate integration credential token: %v", err)
	}
	keyID, err := enrollment.NewDigestKeyID("integration-intake-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("generate integration credential digest key: %v", err)
	}
	key, err := enrollment.NewDigestKey(keyID, keyMaterial)
	if err != nil {
		t.Fatalf("NewDigestKey() error = %v", err)
	}
	keyring, err := enrollment.NewCredentialKeyring(key)
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	digest, err := keyring.Digest(deploymentID, 1, token)
	if err != nil {
		t.Fatalf("CredentialKeyring.Digest() error = %v", err)
	}
	digestBytes := digest.Bytes()
	fingerprint := digest.Fingerprint()

	var currentNetworkRevision int64
	if err := connection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&currentNetworkRevision); err != nil {
		t.Fatalf("read Network revision before intake credential seed: %v", err)
	}
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f61-0000-7000-8000-000000000640",
		eventPublicID:          "01890f62-0000-7000-8000-000000000640",
		outboxPublicID:         "01890f63-0000-7000-8000-000000000640",
		streamID:               201,
		aggregateKind:          "enrollment_credential",
		aggregatePublicID:      intakeCredentialPublicID,
		aggregateVersion:       1,
		networkRevision:        currentNetworkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "enrollment.credential.created",
		permission:             "device.register",
		outboxEventClass:       "enrollment.credential.created",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.enrollment_credential (
    id, public_id, workspace_id, network_id, enrollment_profile_id,
    issuer_principal_id, digest_algorithm, digest_key_id, token_digest,
    token_fingerprint, issued_recovery_epoch, use_limit_kind, max_uses,
    used_count, valid_from, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, 101, 201, 601, 11, $3, $4, $5::BYTEA, $6::BYTEA,
    1, 'bounded', 1, 0, pg_catalog.now() - INTERVAL '1 minute',
    pg_catalog.now() + INTERVAL '1 hour', 'active'
)`,
			intakeCredentialInternalID,
			intakeCredentialPublicID,
			digest.Algorithm(),
			digest.KeyID().String(),
			digestBytes[:],
			fingerprint[:],
		); err != nil {
			t.Fatalf("insert registration-intake credential: %v", err)
		}
	})
	var deploymentState, recoveryState, workspaceState, networkState string
	var deploymentDeleted, workspaceDeleted, networkDeleted bool
	if err := connection.QueryRow(ctx, `SELECT
    deployment.state,
    deployment.recovery_state,
    workspace.state,
    network.state,
    deployment.deleted_at IS NOT NULL,
    workspace.deleted_at IS NOT NULL,
    network.deleted_at IS NOT NULL
FROM mesh.enrollment_credential AS credential
JOIN mesh.network AS network
  ON network.workspace_id = credential.workspace_id
 AND network.id = credential.network_id
JOIN mesh.workspace AS workspace
  ON workspace.id = network.workspace_id
JOIN mesh.deployment AS deployment
  ON deployment.id = workspace.deployment_id
WHERE credential.public_id = $1::UUID`, intakeCredentialPublicID).Scan(
		&deploymentState,
		&recoveryState,
		&workspaceState,
		&networkState,
		&deploymentDeleted,
		&workspaceDeleted,
		&networkDeleted,
	); err != nil {
		t.Fatalf("read seeded registration-intake hierarchy: %v", err)
	}
	if deploymentState != "active" || recoveryState != "verified" ||
		workspaceState != "active" || networkState != "active" || deploymentDeleted ||
		workspaceDeleted || networkDeleted {
		t.Fatalf(
			"seeded registration-intake hierarchy = %s/%s/%s/%s deleted=%t/%t/%t",
			deploymentState,
			recoveryState,
			workspaceState,
			networkState,
			deploymentDeleted,
			workspaceDeleted,
			networkDeleted,
		)
	}
	var resolvedDeployment, resolvedWorkspace, resolvedNetwork string
	var resolvedRecoveryEpoch int64
	if err := connection.QueryRow(ctx, `SELECT
    deployment_public_id::TEXT,
    workspace_public_id::TEXT,
    network_public_id::TEXT,
    recovery_epoch
FROM mesh_ops.resolve_registration_intake_scope($1::UUID)`, intakeCredentialPublicID).Scan(
		&resolvedDeployment,
		&resolvedWorkspace,
		&resolvedNetwork,
		&resolvedRecoveryEpoch,
	); err != nil {
		t.Fatalf("resolve seeded registration-intake scope as migrator: %v", err)
	}
	if resolvedDeployment != "01890f00-0000-7000-8000-000000000001" ||
		resolvedWorkspace != firstWorkspacePublicID || resolvedNetwork != firstNetworkPublicID ||
		resolvedRecoveryEpoch != 1 {
		t.Fatalf(
			"resolved seeded registration-intake scope = (%s, %s, %s, %d)",
			resolvedDeployment,
			resolvedWorkspace,
			resolvedNetwork,
			resolvedRecoveryEpoch,
		)
	}

	registrationID, err := enrollment.ParseRegistrationID(intakeRegistrationPublicID)
	if err != nil {
		t.Fatalf("ParseRegistrationID() error = %v", err)
	}
	credentialID, err := enrollment.ParseCredentialID(intakeCredentialPublicID)
	if err != nil {
		t.Fatalf("ParseCredentialID() error = %v", err)
	}
	machineKey, err := node.NewMachineKey(filledIntegrationKey(0x71))
	if err != nil {
		t.Fatalf("NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey(filledIntegrationKey(0x72))
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatalf("NewRegistrationIdentity() error = %v", err)
	}
	hostname, err := node.ParseHostname("intake-node.example")
	if err != nil {
		t.Fatalf("ParseHostname() error = %v", err)
	}
	return registrationIntakeFixture{
		request: appintake.Request{
			RegistrationID: registrationID,
			CredentialID:   credentialID,
			Token:          token,
			Identity:       identity,
			Hostname:       hostname,
		},
		keyring: keyring,
	}
}

func assertRegistrationIntakeEvidence(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command registrationapp.Command,
) {
	t.Helper()
	if !command.IsValid() {
		t.Fatal("registration intake returned invalid command")
	}
	var pendingCount, auditCount, outboxCount int
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.pending_registration
WHERE public_id = $1::UUID
  AND authorization_kind = 'credential'
  AND state = 'pending'
  AND intent_format_version = 2`, intakeRegistrationPublicID).Scan(&pendingCount); err != nil {
		t.Fatalf("count prepared registration intent: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_audit.audit_event
WHERE target_kind = 'pending_registration'
  AND target_public_id = $1::UUID
  AND action = 'registration.requested'
  AND permission = 'device.register'`, intakeRegistrationPublicID).Scan(&auditCount); err != nil {
		t.Fatalf("count registration-intake audit evidence: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.outbox_event
WHERE aggregate_kind = 'pending_registration'
  AND aggregate_public_id = $1::UUID
  AND event_class = 'registration.pending.created'`, intakeRegistrationPublicID).Scan(&outboxCount); err != nil {
		t.Fatalf("count registration-intake outbox evidence: %v", err)
	}
	if pendingCount != 1 || auditCount != 1 || outboxCount != 1 {
		t.Fatalf(
			"registration-intake evidence counts = pending %d audit %d outbox %d, want 1/1/1",
			pendingCount,
			auditCount,
			outboxCount,
		)
	}
}

func assertPendingIntentCount(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	want int,
) {
	t.Helper()
	var count int
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.pending_registration
WHERE public_id = $1::UUID`, intakeRegistrationPublicID).Scan(&count); err != nil {
		t.Fatalf("count registration-intake pending rows: %v", err)
	}
	if count != want {
		t.Fatalf("registration-intake pending rows = %d, want %d", count, want)
	}
}

type integrationIntakeEvidenceIDs struct {
	ids   appintake.EvidenceIDs
	calls int
}

func (generator *integrationIntakeEvidenceIDs) NewEvidenceIDs() (appintake.EvidenceIDs, error) {
	generator.calls++
	return generator.ids, nil
}

type integrationIntakeClock struct{}

func (integrationIntakeClock) Now() time.Time { return time.Now().UTC() }

type integrationIntakeRetry struct{}

func (integrationIntakeRetry) Wait(context.Context, int) error { return nil }

func intakeEvidenceIDs(t *testing.T) appintake.EvidenceIDs {
	t.Helper()
	changeID, err := publicid.Parse(intakeChangePublicID)
	if err != nil {
		t.Fatalf("parse intake change ID: %v", err)
	}
	auditID, err := publicid.Parse(intakeAuditPublicID)
	if err != nil {
		t.Fatalf("parse intake audit ID: %v", err)
	}
	outboxID, err := publicid.Parse(intakeOutboxPublicID)
	if err != nil {
		t.Fatalf("parse intake outbox ID: %v", err)
	}
	ids, err := appintake.NewEvidenceIDs(changeID, auditID, outboxID)
	if err != nil {
		t.Fatalf("NewEvidenceIDs() error = %v", err)
	}
	return ids
}
