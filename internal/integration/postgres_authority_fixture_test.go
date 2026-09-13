//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
)

type authorityFixture struct {
	workspaceID     int64
	networkID       int64
	addressRealmID  int64
	addressPoolID   int64
	networkPrefixID int64
	publicIDSuffix  string
	nameSuffix      string
}

type authorityEvidenceFixture struct {
	changePublicID         string
	eventPublicID          string
	outboxPublicID         string
	streamID               int64
	aggregateKind          string
	aggregatePublicID      string
	aggregateVersion       int64
	networkRevision        any
	actorPrincipalPublicID any
	action                 string
	permission             string
	outboxEventClass       string
}

func seedAuthorityFixture(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()

	commitAuditedAuthorityFixture(t, ctx, connection, authorityEvidenceFixture{
		changePublicID:    "01890f01-0000-7000-8000-000000000001",
		eventPublicID:     "01890f02-0000-7000-8000-000000000001",
		outboxPublicID:    "01890f03-0000-7000-8000-000000000001",
		streamID:          1,
		aggregateKind:     "deployment",
		aggregatePublicID: "01890f00-0000-7000-8000-000000000001",
		aggregateVersion:  1,
		action:            "deployment.created",
		permission:        "system.bootstrap",
		outboxEventClass:  "deployment.created",
	}, func(transaction pgx.Tx) {
		_, err := transaction.Exec(ctx, `INSERT INTO mesh.deployment (
    id,
    installation_public_id,
    profile,
    state,
    schema_epoch,
    authority_generation,
    recovery_epoch,
    recovery_state
) OVERRIDING SYSTEM VALUE VALUES (
    1,
    '01890f00-0000-7000-8000-000000000001',
    'cloud',
    'active',
    1,
    1,
    1,
    'verified'
)`)
		if err != nil {
			t.Fatalf("insert integration deployment: %v", err)
		}
		_, err = transaction.Exec(ctx, `INSERT INTO mesh_audit.audit_stream (
    id, deployment_id, scope_kind
) OVERRIDING SYSTEM VALUE VALUES (1, 1, 'deployment')`)
		if err != nil {
			t.Fatalf("insert integration deployment audit stream: %v", err)
		}
	})

	commitAuditedAuthorityFixture(t, ctx, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000011",
		eventPublicID:          "01890f02-0000-7000-8000-000000000011",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000011",
		streamID:               1,
		aggregateKind:          "principal",
		aggregatePublicID:      "01890f00-0000-7000-8000-000000000011",
		aggregateVersion:       1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "principal.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "principal.created",
	}, func(transaction pgx.Tx) {
		_, err := transaction.Exec(ctx, `INSERT INTO mesh.principal (
    id,
    public_id,
    deployment_id,
    kind,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    11,
    '01890f00-0000-7000-8000-000000000011',
    1,
    'account',
    'active'
)`)
		if err != nil {
			t.Fatalf("insert integration principal: %v", err)
		}
	})

	seedWorkspaceAuthority(t, ctx, connection, authorityFixture{
		workspaceID:     101,
		networkID:       201,
		addressRealmID:  301,
		addressPoolID:   401,
		networkPrefixID: 501,
		publicIDSuffix:  "101",
		nameSuffix:      "one",
	})
	seedWorkspaceAuthority(t, ctx, connection, authorityFixture{
		workspaceID:     102,
		networkID:       202,
		addressRealmID:  302,
		addressPoolID:   402,
		networkPrefixID: 502,
		publicIDSuffix:  "102",
		nameSuffix:      "two",
	})
}

func seedWorkspaceAuthority(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	fixture authorityFixture,
) {
	t.Helper()

	publicID := "01890f00-0000-7000-8000-000000000" + strconv.FormatInt(fixture.networkID, 10)
	commitAuditedAuthorityFixture(t, ctx, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000" + fixture.publicIDSuffix,
		eventPublicID:          "01890f02-0000-7000-8000-000000000" + fixture.publicIDSuffix,
		outboxPublicID:         "01890f03-0000-7000-8000-000000000" + fixture.publicIDSuffix,
		streamID:               fixture.networkID,
		aggregateKind:          "network",
		aggregatePublicID:      publicID,
		aggregateVersion:       1,
		networkRevision:        int64(1),
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "network.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "network.created",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(t, ctx, transaction, fixture.workspaceID, fixture.networkID)

		statements := []struct {
			name      string
			query     string
			arguments []any
		}{
			{
				name: "workspace",
				query: `INSERT INTO mesh.workspace (
    id, public_id, deployment_id, owner_principal_id, display_name, name_key, state
) OVERRIDING SYSTEM VALUE VALUES ($1, $2, 1, 11, $3, $4, 'active')`,
				arguments: []any{
					fixture.workspaceID,
					"01890f00-0000-7000-8000-000000000" + fixture.publicIDSuffix,
					"Workspace " + fixture.nameSuffix,
					"workspace-" + fixture.nameSuffix,
				},
			},
			{
				name: "network",
				query: `INSERT INTO mesh.network (
    id, public_id, workspace_id, display_name, name_key, node_limit, state
) OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3, $4, $5, 1000, 'active')`,
				arguments: []any{
					fixture.networkID,
					"01890f00-0000-7000-8000-000000000" + strconv.FormatInt(fixture.networkID, 10),
					fixture.workspaceID,
					"Network " + fixture.nameSuffix,
					"network-" + fixture.nameSuffix,
				},
			},
			{
				name: "address realm",
				query: `INSERT INTO mesh.address_realm (
    id, public_id, deployment_id, workspace_id, kind, ipv4_enabled, ipv6_enabled, state
) OVERRIDING SYSTEM VALUE VALUES ($1, $2, 1, $3, 'workspace_overlay', TRUE, TRUE, 'active')`,
				arguments: []any{
					fixture.addressRealmID,
					"01890f00-0000-7000-8000-000000000" + strconv.FormatInt(fixture.addressRealmID, 10),
					fixture.workspaceID,
				},
			},
			{
				name: "address pool",
				query: `INSERT INTO mesh.address_pool (
    id, public_id, deployment_id, workspace_id, address_realm_id, purpose, prefix, family, state
) OVERRIDING SYSTEM VALUE VALUES ($1, $2, 1, $3, $4, 'node_overlay', '100.64.0.0/16', 4, 'active')`,
				arguments: []any{
					fixture.addressPoolID,
					"01890f00-0000-7000-8000-000000000" + strconv.FormatInt(fixture.addressPoolID, 10),
					fixture.workspaceID,
					fixture.addressRealmID,
				},
			},
			{
				name: "network prefix",
				query: `INSERT INTO mesh.network_prefix (
    id, public_id, workspace_id, network_id, address_realm_id, address_pool_id, prefix, family, state
) OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3, $4, $5, $6, '100.64.1.0/24', 4, 'active')`,
				arguments: []any{
					fixture.networkPrefixID,
					"01890f00-0000-7000-8000-000000000" + strconv.FormatInt(fixture.networkPrefixID, 10),
					fixture.workspaceID,
					fixture.networkID,
					fixture.addressRealmID,
					fixture.addressPoolID,
				},
			},
			{
				name: "network revision",
				query: `INSERT INTO mesh_ops.network_revision (workspace_id, network_id)
VALUES ($1, $2)`,
				arguments: []any{fixture.workspaceID, fixture.networkID},
			},
			{
				name: "audit stream",
				query: `INSERT INTO mesh_audit.audit_stream (
    id, deployment_id, workspace_id, network_id, scope_kind
) OVERRIDING SYSTEM VALUE VALUES ($1, 1, $2, $3, 'network')`,
				arguments: []any{fixture.networkID, fixture.workspaceID, fixture.networkID},
			},
		}
		for _, statement := range statements {
			if _, err := transaction.Exec(ctx, statement.query, statement.arguments...); err != nil {
				t.Fatalf("insert integration %s: %v", statement.name, err)
			}
		}
	})
}

func commitAuditedAuthorityFixture(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	evidence authorityEvidenceFixture,
	mutate func(pgx.Tx),
) {
	t.Helper()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin audited authority fixture transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(t, ctx, transaction)
	setIntegrationChange(t, ctx, transaction, evidence.changePublicID)
	mutate(transaction)

	var expectedSequence int64
	var previousHash []byte
	if err := transaction.QueryRow(ctx, `SELECT next_sequence, latest_event_hash
FROM mesh_audit.audit_stream
WHERE id = $1`, evidence.streamID).Scan(&expectedSequence, &previousHash); err != nil {
		t.Fatalf("read integration audit stream head: %v", err)
	}
	hashInput := append([]byte{}, previousHash...)
	hashInput = append(hashInput, evidence.changePublicID...)
	hashInput = append(hashInput, evidence.eventPublicID...)
	eventHash := sha256.Sum256(hashInput)

	var appendedSequence int64
	if err := transaction.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT,
    $2::UUID,
    $3::UUID,
    $4::BIGINT,
    $5::BYTEA,
    $6::BYTEA,
    $7::TEXT,
    $8::UUID,
    $9::BIGINT,
    $10::BIGINT,
    $11::UUID,
    $12::TEXT,
    $13::TEXT,
    NULL::UUID,
    NULL::BYTEA,
    NULL::BYTEA,
    '{}'::JSONB,
    $14::TEXT,
    '{}'::JSONB
)`,
		evidence.streamID,
		evidence.eventPublicID,
		evidence.outboxPublicID,
		expectedSequence,
		previousHash,
		eventHash[:],
		evidence.aggregateKind,
		evidence.aggregatePublicID,
		evidence.aggregateVersion,
		evidence.networkRevision,
		evidence.actorPrincipalPublicID,
		evidence.action,
		evidence.permission,
		evidence.outboxEventClass,
	).Scan(&appendedSequence); err != nil {
		t.Fatalf("append integration authority evidence: %v", err)
	}
	if appendedSequence != expectedSequence {
		t.Fatalf(
			"appended integration audit sequence = %d, want %d",
			appendedSequence,
			expectedSequence,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit audited authority fixture transaction: %v", err)
	}
}

func setIntegrationChange(
	t *testing.T,
	ctx context.Context,
	transaction pgx.Tx,
	changePublicID string,
) {
	t.Helper()

	if _, err := transaction.Exec(
		ctx,
		"SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)",
		changePublicID,
	); err != nil {
		t.Fatalf("set integration authority change: %v", err)
	}
}
