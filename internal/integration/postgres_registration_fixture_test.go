//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	registrationapp "github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

type registrationAuthorityFixture struct {
	authorityInternalID    int64
	registrationInternalID int64
	authorityPublicID      string
	registrationPublicID   string
	changePublicID         string
	eventPublicID          string
	outboxPublicID         string
	digestLabel            string
	hostname               string
	authorityMaterial      byte
	machineMaterial        byte
	nodeMaterial           byte
}

func seedOpenRegistrationAuthority(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) registrationapp.Command {
	t.Helper()
	return seedOpenRegistrationFixture(ctx, t, connection, registrationAuthorityFixture{
		authorityInternalID:    612,
		registrationInternalID: 616,
		authorityPublicID:      "01890f20-0000-7000-8000-000000000612",
		registrationPublicID:   "01890f20-0000-7000-8000-000000000616",
		changePublicID:         "01890f21-0000-7000-8000-000000000611",
		eventPublicID:          "01890f22-0000-7000-8000-000000000611",
		outboxPublicID:         "01890f23-0000-7000-8000-000000000611",
		digestLabel:            "integration-registration-transaction-v1",
		hostname:               "node-two.example",
		authorityMaterial:      0x31,
		machineMaterial:        0x31,
		nodeMaterial:           0x32,
	})
}

func seedConcurrentRegistrationAuthority(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) registrationapp.Command {
	t.Helper()
	return seedOpenRegistrationFixture(ctx, t, connection, registrationAuthorityFixture{
		authorityInternalID:    622,
		registrationInternalID: 626,
		authorityPublicID:      "01890f20-0000-7000-8000-000000000622",
		registrationPublicID:   "01890f20-0000-7000-8000-000000000626",
		changePublicID:         "01890f21-0000-7000-8000-000000000621",
		eventPublicID:          "01890f22-0000-7000-8000-000000000621",
		outboxPublicID:         "01890f23-0000-7000-8000-000000000621",
		digestLabel:            "integration-registration-service-v1",
		hostname:               "node-three.example",
		authorityMaterial:      0x41,
		machineMaterial:        0x41,
		nodeMaterial:           0x42,
	})
}

func seedOpenRegistrationFixture(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	fixture registrationAuthorityFixture,
) registrationapp.Command {
	t.Helper()
	command := registrationCommand(t, fixture)
	var currentNetworkRevision int64
	if err := connection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&currentNetworkRevision); err != nil {
		t.Fatalf("read Network revision before open registration seed: %v", err)
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("build open registration request hash: %v", err)
	}
	requestHashBytes := requestHash.Bytes()
	machineFingerprint := command.Identity.MachineKey().Fingerprint()
	requestedNodeKey := command.Identity.NodeKey().Bytes()
	authorityMaterial := filledIntegrationKey(fixture.authorityMaterial)

	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         fixture.changePublicID,
		eventPublicID:          fixture.eventPublicID,
		outboxPublicID:         fixture.outboxPublicID,
		streamID:               201,
		aggregateKind:          "pending_registration",
		aggregatePublicID:      command.RegistrationID.String(),
		aggregateVersion:       1,
		networkRevision:        currentNetworkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "registration.created",
		permission:             "device.register",
		outboxEventClass:       "registration.created",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.enrollment_credential (
    id,
    public_id,
    workspace_id,
    network_id,
    enrollment_profile_id,
    issuer_principal_id,
    digest_algorithm,
    digest_key_id,
    token_digest,
    token_fingerprint,
    issued_recovery_epoch,
    use_limit_kind,
    max_uses,
    used_count,
    valid_from,
    expires_at,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    $1,
    $2::UUID,
    101,
    201,
    601,
    11,
    'hmac-sha256-v1',
    $3,
    $4::BYTEA,
    $5::BYTEA,
    1,
    'bounded',
    1,
    0,
    pg_catalog.now() - INTERVAL '1 minute',
    pg_catalog.now() + INTERVAL '1 hour',
    'active'
)`,
			fixture.authorityInternalID,
			fixture.authorityPublicID,
			fixture.digestLabel,
			authorityMaterial[:],
			authorityMaterial[:16],
		); err != nil {
			t.Fatalf("insert open registration credential: %v", err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.pending_registration (
    id,
    public_id,
    workspace_id,
    network_id,
    enrollment_profile_id,
    authorization_kind,
    enrollment_credential_id,
    request_hash,
    machine_key_fingerprint,
    requested_node_key,
    expires_at,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    $1,
    $2::UUID,
    101,
    201,
    601,
    'credential',
    $3,
    $4::BYTEA,
    $5::BYTEA,
    $6::BYTEA,
    pg_catalog.now() + INTERVAL '10 minutes',
    'pending'
)`,
			fixture.registrationInternalID,
			fixture.registrationPublicID,
			fixture.authorityInternalID,
			requestHashBytes[:],
			machineFingerprint[:],
			requestedNodeKey[:],
		); err != nil {
			t.Fatalf("insert open pending registration: %v", err)
		}
	})
	return command
}

func registrationCommand(
	t *testing.T,
	fixture registrationAuthorityFixture,
) registrationapp.Command {
	t.Helper()
	workspaceID, err := workspace.ParseID(firstWorkspacePublicID)
	if err != nil {
		t.Fatalf("parse integration Workspace ID: %v", err)
	}
	networkID, err := network.ParseID(firstNetworkPublicID)
	if err != nil {
		t.Fatalf("parse integration Network ID: %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("construct integration Network scope: %v", err)
	}
	registrationID, err := enrollment.ParseRegistrationID(fixture.registrationPublicID)
	if err != nil {
		t.Fatalf("parse integration Registration ID: %v", err)
	}
	credentialID, err := enrollment.ParseCredentialID(fixture.authorityPublicID)
	if err != nil {
		t.Fatalf("parse integration Credential ID: %v", err)
	}
	machineKey, err := node.NewMachineKey(filledIntegrationKey(fixture.machineMaterial))
	if err != nil {
		t.Fatalf("construct integration machine key: %v", err)
	}
	nodeKey, err := node.NewKey(filledIntegrationKey(fixture.nodeMaterial))
	if err != nil {
		t.Fatalf("construct integration Node key: %v", err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatalf("construct integration registration identity: %v", err)
	}
	hostname, err := node.ParseHostname(fixture.hostname)
	if err != nil {
		t.Fatalf("parse integration hostname: %v", err)
	}
	return registrationapp.Command{
		RegistrationID: registrationID,
		Scope:          scope,
		CredentialID:   credentialID,
		Identity:       identity,
		Hostname:       hostname,
		RecoveryEpoch:  1,
	}
}
