//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/adapter/legacyts2021/protocoltest"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/platform/config"
)

const (
	processCredentialInternalID = 652
	processCredentialPublicID   = "01890f70-0000-7000-8000-000000000652"
	processChangePublicID       = "01890f71-0000-7000-8000-000000000651"
	processAuditPublicID        = "01890f72-0000-7000-8000-000000000651"
	processOutboxPublicID       = "01890f73-0000-7000-8000-000000000651"
	processRegistrationHostname = "process-node.example"
	processControlTLSServerName = "example.com"
)

type processRegistrationFixture struct {
	credential enrollment.CredentialPresentation
}

type processRegistrationEvidence struct {
	registrationPublicID string
	registrationState    string
	registrationResult   string
	nodePublicID         string
	hostname             string
	primaryAddress       string
	credentialUsedCount  int64
	registrationRecords  int64
	credentialUseRecords int64
	machineKeyEpochs     int64
	nodeKeyEpochs        int64
	primaryLeases        int64
	intakeAuditEvents    int64
	intakeOutboxEvents   int64
	deviceAuditEvents    int64
	deviceOutboxEvents   int64
	networkRevision      int64
	inventoryRevision    int64
	completedRevision    int64
}

func seedProcessRegistrationCredential(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	processConfig config.Config,
) processRegistrationFixture {
	t.Helper()
	if processConfig.Enrollment == nil {
		t.Fatal("process integration configuration did not load enrollment")
	}
	token, err := enrollment.GenerateCredentialToken()
	if err != nil {
		t.Fatalf("generate process registration credential token: %v", err)
	}
	keyring := processCredentialKeyring(t, processConfig.Enrollment.CredentialDigest.Active)
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse process registration Deployment ID: %v", err)
	}
	digest, err := keyring.Digest(deploymentID, 1, token)
	if err != nil {
		t.Fatalf("digest process registration credential: %v", err)
	}
	digestBytes := digest.Bytes()
	fingerprint := digest.Fingerprint()

	var currentNetworkRevision int64
	if err := connection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&currentNetworkRevision); err != nil {
		t.Fatalf("read Network revision before process credential seed: %v", err)
	}
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         processChangePublicID,
		eventPublicID:          processAuditPublicID,
		outboxPublicID:         processOutboxPublicID,
		streamID:               201,
		aggregateKind:          "enrollment_credential",
		aggregatePublicID:      processCredentialPublicID,
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
			processCredentialInternalID,
			processCredentialPublicID,
			digest.Algorithm(),
			digest.KeyID().String(),
			digestBytes[:],
			fingerprint[:],
		); err != nil {
			t.Fatalf("insert process registration credential: %v", err)
		}
	})
	credentialID, err := enrollment.ParseCredentialID(processCredentialPublicID)
	if err != nil {
		t.Fatalf("parse process registration Credential ID: %v", err)
	}
	presentation, err := enrollment.NewCredentialPresentation(credentialID, token)
	if err != nil {
		t.Fatalf("construct process registration credential: %v", err)
	}
	return processRegistrationFixture{credential: presentation}
}

func processCredentialKeyring(
	t *testing.T,
	keyConfig config.CredentialDigestKeyConfig,
) *enrollment.CredentialKeyring {
	t.Helper()
	encoded, err := keyConfig.MaterialFile.Read()
	if err != nil {
		t.Fatalf("read process registration digest key: %v", err)
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(material)
	if err != nil || base64.RawURLEncoding.EncodeToString(material) != encoded {
		t.Fatal("decode process registration digest key")
	}
	key, err := enrollment.NewDigestKey(keyConfig.ID, material)
	if err != nil {
		t.Fatalf("construct process registration digest key: %v", err)
	}
	keyring, err := enrollment.NewCredentialKeyring(key)
	if err != nil {
		t.Fatalf("construct process registration keyring: %v", err)
	}
	return keyring
}

func newProcessRegistrationClient(
	t *testing.T,
	processConfig config.Config,
	controlAddress string,
) *protocoltest.Client {
	t.Helper()
	if processConfig.Storage == nil {
		t.Fatal("process integration configuration did not load storage")
	}
	caPEM, err := processConfig.Storage.PostgreSQL.CAFile.Read()
	if err != nil {
		t.Fatalf("read process registration CA: %v", err)
	}
	defer clear(caPEM)
	client, err := protocoltest.NewClient(protocoltest.Options{
		ControlAddress: controlAddress,
		TLSServerName:  processControlTLSServerName,
		RootCAPEM:      caPEM,
		Hostname:       processRegistrationHostname,
	})
	if err != nil {
		t.Fatalf("protocoltest.NewClient() error = %v", err)
	}
	return client
}

func readProcessRegistrationEvidence(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	identity protocoltest.Identity,
) processRegistrationEvidence {
	t.Helper()
	machineKey, err := node.NewMachineKey(identity.MachineKey)
	if err != nil {
		t.Fatalf("construct process registration machine key: %v", err)
	}
	machineFingerprint := machineKey.Fingerprint()
	var evidence processRegistrationEvidence
	if err := connection.QueryRow(ctx, `SELECT
    registration.public_id::TEXT,
    registration.state,
    registration.completed_disposition,
    device.public_id::TEXT,
    device.hostname,
    lease.address::TEXT,
    credential.used_count,
    (SELECT pg_catalog.count(*) FROM mesh.pending_registration AS credential_registration
     WHERE credential_registration.enrollment_credential_id = credential.id),
    (SELECT pg_catalog.count(*) FROM mesh.enrollment_credential_use AS credential_use
     WHERE credential_use.pending_registration_id = registration.id),
    (SELECT pg_catalog.count(*) FROM mesh.device_machine_key_epoch AS machine_epoch
     WHERE machine_epoch.device_id = device.id
       AND machine_epoch.public_key = $3::BYTEA),
    (SELECT pg_catalog.count(*) FROM mesh.device_node_key_epoch AS node_epoch
     WHERE node_epoch.device_id = device.id
       AND node_epoch.public_key = $4::BYTEA),
    (SELECT pg_catalog.count(*) FROM mesh.node_address_lease AS active_lease
     WHERE active_lease.device_id = device.id
       AND active_lease.lease_role = 'primary'
       AND active_lease.state = 'active'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS intake_audit
     WHERE intake_audit.target_kind = 'pending_registration'
       AND intake_audit.target_public_id = registration.public_id
       AND intake_audit.action = 'registration.requested'),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS intake_outbox
     WHERE intake_outbox.aggregate_kind = 'pending_registration'
       AND intake_outbox.aggregate_public_id = registration.public_id
       AND intake_outbox.event_class = 'registration.pending.created'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS device_audit
     WHERE device_audit.target_kind = 'device'
       AND device_audit.target_public_id = device.public_id
       AND device_audit.action = 'device.registered'),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS device_outbox
     WHERE device_outbox.aggregate_kind = 'device'
       AND device_outbox.aggregate_public_id = device.public_id
       AND device_outbox.event_class = 'network.revision.advanced'),
    revision.network_revision,
    revision.inventory_revision,
    registration.completed_network_revision
FROM mesh.enrollment_credential AS credential
JOIN mesh.pending_registration AS registration
  ON registration.enrollment_credential_id = credential.id
JOIN mesh.device AS device ON device.id = registration.device_id
JOIN mesh.node_address_lease AS lease
  ON lease.device_id = device.id
 AND lease.lease_role = 'primary'
 AND lease.state = 'active'
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = registration.workspace_id
 AND revision.network_id = registration.network_id
WHERE credential.public_id = $1::UUID
  AND registration.machine_key_fingerprint = $2::BYTEA
  AND registration.requested_node_key = $4::BYTEA`,
		processCredentialPublicID,
		machineFingerprint[:],
		identity.MachineKey[:],
		identity.NodeKey[:],
	).Scan(
		&evidence.registrationPublicID,
		&evidence.registrationState,
		&evidence.registrationResult,
		&evidence.nodePublicID,
		&evidence.hostname,
		&evidence.primaryAddress,
		&evidence.credentialUsedCount,
		&evidence.registrationRecords,
		&evidence.credentialUseRecords,
		&evidence.machineKeyEpochs,
		&evidence.nodeKeyEpochs,
		&evidence.primaryLeases,
		&evidence.intakeAuditEvents,
		&evidence.intakeOutboxEvents,
		&evidence.deviceAuditEvents,
		&evidence.deviceOutboxEvents,
		&evidence.networkRevision,
		&evidence.inventoryRevision,
		&evidence.completedRevision,
	); err != nil {
		t.Fatalf("read process registration evidence: %v", err)
	}
	return evidence
}

func assertProcessRegistrationEvidence(t *testing.T, evidence processRegistrationEvidence) {
	t.Helper()
	if evidence.registrationPublicID == "" || evidence.nodePublicID == "" ||
		evidence.registrationState != "completed" || evidence.registrationResult != "created" ||
		evidence.hostname != processRegistrationHostname || evidence.primaryAddress == "" ||
		evidence.credentialUsedCount != 1 || evidence.registrationRecords != 1 ||
		evidence.credentialUseRecords != 1 ||
		evidence.machineKeyEpochs != 1 ||
		evidence.nodeKeyEpochs != 1 || evidence.primaryLeases != 1 ||
		evidence.intakeAuditEvents != 1 || evidence.intakeOutboxEvents != 1 ||
		evidence.deviceAuditEvents != 1 || evidence.deviceOutboxEvents != 1 ||
		evidence.networkRevision != evidence.completedRevision || evidence.inventoryRevision <= 0 {
		t.Fatalf("process registration evidence is incomplete: %+v", evidence)
	}
}
