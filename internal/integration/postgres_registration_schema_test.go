//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func seedRegistrationAuthority(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f11-0000-7000-8000-000000000601",
		eventPublicID:          "01890f12-0000-7000-8000-000000000601",
		outboxPublicID:         "01890f13-0000-7000-8000-000000000601",
		streamID:               201,
		aggregateKind:          "device",
		aggregatePublicID:      "01890f10-0000-7000-8000-000000000603",
		aggregateVersion:       1,
		networkRevision:        int64(3),
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "device.registered",
		permission:             "device.register",
		outboxEventClass:       "network.revision.advanced",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)

		statements := []struct {
			name  string
			query string
		}{
			{
				name: "enrollment profile",
				query: `INSERT INTO mesh.enrollment_profile (
    id,
    public_id,
    workspace_id,
    network_id,
    created_by_principal_id,
    display_name,
    name_key,
    node_lifetime_seconds,
    ephemeral_mode,
    credential_use_policy,
    credential_max_uses,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    601,
    '01890f10-0000-7000-8000-000000000601',
    101,
    201,
    11,
    'Integration enrollment',
    'integration-enrollment',
    3600,
    'persistent',
    'bounded',
    1,
    'active'
)`,
			},
			{
				name: "enrollment credential",
				query: `INSERT INTO mesh.enrollment_credential (
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
    602,
    '01890f10-0000-7000-8000-000000000602',
    101,
    201,
    601,
    11,
    'hmac-sha256-v1',
    'integration-key-v1',
    pg_catalog.decode(pg_catalog.repeat('11', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('12', 16), 'hex'),
    1,
    'bounded',
    1,
    1,
    pg_catalog.now() - INTERVAL '1 minute',
    pg_catalog.now() + INTERVAL '1 hour',
    'active'
)`,
			},
			{
				name: "device",
				query: `INSERT INTO mesh.device (
    id,
    public_id,
    workspace_id,
    network_id,
    enrollment_profile_id,
    owner_principal_id,
    custodian_principal_id,
    registered_by_kind,
    registered_by_credential_id,
    hostname,
    hostname_key,
    is_ephemeral,
    expires_at,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    603,
    '01890f10-0000-7000-8000-000000000603',
    101,
    201,
    601,
    11,
    11,
    'credential',
    602,
    'node-one.example',
    'node-one.example',
    FALSE,
    pg_catalog.now() + INTERVAL '1 hour',
    'active'
)`,
			},
			{
				name: "machine key epoch",
				query: `INSERT INTO mesh.device_machine_key_epoch (
    id,
    public_id,
    workspace_id,
    network_id,
    device_id,
    epoch,
    public_key,
    fingerprint,
    valid_from,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    604,
    '01890f10-0000-7000-8000-000000000604',
    101,
    201,
    603,
    1,
    pg_catalog.decode(pg_catalog.repeat('21', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('31', 32), 'hex'),
    pg_catalog.now(),
    'active'
)`,
			},
			{
				name: "node key epoch",
				query: `INSERT INTO mesh.device_node_key_epoch (
    id,
    public_id,
    workspace_id,
    network_id,
    device_id,
    epoch,
    public_key,
    fingerprint,
    valid_from,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    605,
    '01890f10-0000-7000-8000-000000000605',
    101,
    201,
    603,
    1,
    pg_catalog.decode(pg_catalog.repeat('22', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('32', 32), 'hex'),
    pg_catalog.now(),
    'active'
)`,
			},
			{
				name: "completed registration",
				query: `INSERT INTO mesh.pending_registration (
    id,
    public_id,
    workspace_id,
    network_id,
    enrollment_profile_id,
    authorization_kind,
    enrollment_credential_id,
    request_hash,
    machine_key_fingerprint,
    device_id,
    expires_at,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    606,
    '01890f10-0000-7000-8000-000000000606',
    101,
    201,
    601,
    'credential',
    602,
    pg_catalog.decode(pg_catalog.repeat('61', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('31', 32), 'hex'),
    603,
    pg_catalog.now() + INTERVAL '10 minutes',
    'completed'
)`,
			},
			{
				name: "credential use",
				query: `INSERT INTO mesh.enrollment_credential_use (
    id,
    public_id,
    workspace_id,
    network_id,
    enrollment_credential_id,
    pending_registration_id,
    device_id,
    machine_key_fingerprint,
    result,
    used_at
) OVERRIDING SYSTEM VALUE VALUES (
    607,
    '01890f10-0000-7000-8000-000000000607',
    101,
    201,
    602,
    606,
    603,
    pg_catalog.decode(pg_catalog.repeat('31', 32), 'hex'),
    'created',
    pg_catalog.now()
)`,
			},
			{
				name: "node address lease",
				query: `INSERT INTO mesh.node_address_lease (
    id,
    public_id,
    workspace_id,
    network_id,
    address_realm_id,
    address_pool_id,
    network_prefix_id,
    device_id,
    address,
    family,
    generation,
    lease_role,
    state
) OVERRIDING SYSTEM VALUE VALUES (
    608,
    '01890f10-0000-7000-8000-000000000608',
    101,
    201,
    301,
    401,
    501,
    603,
    '100.64.1.1',
    4,
    1,
    'primary',
    'active'
)`,
			},
			{
				name: "network revision",
				query: `UPDATE mesh_ops.network_revision
SET network_revision = network_revision + 1,
    inventory_revision = inventory_revision + 1,
    updated_at = pg_catalog.clock_timestamp()
WHERE workspace_id = 101 AND network_id = 201`,
			},
		}

		for _, statement := range statements {
			if _, err := transaction.Exec(ctx, statement.query); err != nil {
				t.Fatalf("insert integration %s: %v", statement.name, err)
			}
		}
	})
}

func assertRegistrationSchemaConstraints(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	tests := []struct {
		name     string
		query    string
		wantCode string
	}{
		{
			name: "credential usage cannot exceed quota",
			query: `INSERT INTO mesh.enrollment_credential (
    public_id, workspace_id, network_id, enrollment_profile_id, issuer_principal_id,
    digest_algorithm, digest_key_id, token_digest, token_fingerprint,
    issued_recovery_epoch, use_limit_kind, max_uses, used_count,
    valid_from, expires_at, state
) VALUES (
    '01890f10-0000-7000-8000-000000000701', 101, 201, 601, 11,
    'hmac-sha256-v1', 'invalid-quota',
    pg_catalog.decode(pg_catalog.repeat('41', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('42', 16), 'hex'),
    1, 'bounded', 1, 2, pg_catalog.now(), pg_catalog.now() + INTERVAL '1 hour', 'active'
)`,
			wantCode: "23514",
		},
		{
			name: "cross-network profile substitution",
			query: `INSERT INTO mesh.device (
    public_id, workspace_id, network_id, enrollment_profile_id,
    owner_principal_id, custodian_principal_id, registered_by_kind,
    registered_by_credential_id, hostname, hostname_key, is_ephemeral, expires_at, state
) VALUES (
    '01890f10-0000-7000-8000-000000000702', 101, 202, 601,
    11, 11, 'credential', 602, 'wrong-scope', 'wrong-scope', FALSE,
    pg_catalog.now() + INTERVAL '1 hour', 'active'
)`,
			wantCode: "23503",
		},
		{
			name: "registration request hash has fixed width",
			query: `INSERT INTO mesh.pending_registration (
    public_id, workspace_id, network_id, enrollment_profile_id,
    authorization_kind, enrollment_credential_id, request_hash, machine_key_fingerprint,
    expires_at, state
) VALUES (
    '01890f10-0000-7000-8000-000000000706', 101, 201, 601,
    'credential', 602, pg_catalog.decode('01', 'hex'),
    pg_catalog.decode(pg_catalog.repeat('46', 32), 'hex'),
    pg_catalog.now() + INTERVAL '10 minutes', 'pending'
)`,
			wantCode: "23514",
		},
		{
			name: "completed registration requires device",
			query: `INSERT INTO mesh.pending_registration (
    public_id, workspace_id, network_id, enrollment_profile_id,
    authorization_kind, enrollment_credential_id, request_hash, machine_key_fingerprint,
    expires_at, state
) VALUES (
    '01890f10-0000-7000-8000-000000000703', 101, 201, 601,
    'credential', 602, pg_catalog.decode(pg_catalog.repeat('47', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('43', 32), 'hex'),
    pg_catalog.now() + INTERVAL '10 minutes', 'completed'
)`,
			wantCode: "23514",
		},
		{
			name: "live address cannot be reused",
			query: `INSERT INTO mesh.node_address_lease (
    public_id, workspace_id, network_id, address_realm_id, address_pool_id,
    network_prefix_id, device_id, address, family, generation, lease_role, state
) VALUES (
    '01890f10-0000-7000-8000-000000000704', 101, 201, 301, 401,
    501, 603, '100.64.1.1', 4, 2, 'secondary', 'active'
)`,
			wantCode: "23505",
		},
		{
			name: "one active primary per address family",
			query: `INSERT INTO mesh.node_address_lease (
    public_id, workspace_id, network_id, address_realm_id, address_pool_id,
    network_prefix_id, device_id, address, family, generation, lease_role, state
) VALUES (
    '01890f10-0000-7000-8000-000000000705', 101, 201, 301, 401,
    501, 603, '100.64.1.2', 4, 2, 'primary', 'active'
)`,
			wantCode: "23505",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction, err := connection.Begin(ctx)
			if err != nil {
				t.Fatalf("begin registration constraint transaction: %v", err)
			}
			defer rollbackIntegrationTransaction(ctx, t, transaction)
			_, err = transaction.Exec(ctx, test.query)
			assertPostgreSQLCode(t, err, test.wantCode)
		})
	}
}

func assertRegistrationRuntimeIsolation(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	tests := []struct {
		name           string
		workspaceScope string
		networkScope   string
		wantCount      int64
	}{
		{name: "missing scope"},
		{name: "invalid scope", workspaceScope: "invalid", networkScope: "invalid"},
		{name: "exact scope", workspaceScope: "101", networkScope: "201", wantCount: 1},
		{name: "mismatched scope", workspaceScope: "101", networkScope: "202"},
		{name: "other workspace", workspaceScope: "102", networkScope: "202"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction, err := connection.Begin(ctx)
			if err != nil {
				t.Fatalf("begin registration scope transaction: %v", err)
			}
			defer rollbackIntegrationTransaction(ctx, t, transaction)
			if test.workspaceScope != "" || test.networkScope != "" {
				if _, err := transaction.Exec(ctx, `SELECT
    pg_catalog.set_config('mesh.workspace_id', $1, TRUE),
    pg_catalog.set_config('mesh.network_id', $2, TRUE)`,
					test.workspaceScope,
					test.networkScope,
				); err != nil {
					t.Fatalf("set registration scope: %v", err)
				}
			}

			for _, table := range []string{
				"enrollment_profile",
				"enrollment_credential",
				"device",
				"device_machine_key_epoch",
				"device_node_key_epoch",
				"pending_registration",
				"enrollment_credential_use",
				"node_address_lease",
			} {
				var count int64
				if err := transaction.QueryRow(
					ctx,
					"SELECT pg_catalog.count(*) FROM mesh."+table,
				).Scan(&count); err != nil {
					t.Fatalf("query scoped %s: %v", table, err)
				}
				if count != test.wantCount {
					t.Fatalf("scoped %s count = %d, want %d", table, count, test.wantCount)
				}
			}
		})
	}

	var canInsertDevice, canUpdateHostname, canUpdateDevicePublicID bool
	var canUpdateCredentialDigest, canUpdateCredentialUse, canDeleteDevice bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh.device', 'INSERT'),
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh.device', 'hostname', 'UPDATE'),
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh.device', 'public_id', 'UPDATE'),
    pg_catalog.has_column_privilege(
        CURRENT_USER,
        'mesh.enrollment_credential',
        'token_digest',
        'UPDATE'
    ),
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh.enrollment_credential_use', 'UPDATE'),
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh.device', 'DELETE')`).Scan(
		&canInsertDevice,
		&canUpdateHostname,
		&canUpdateDevicePublicID,
		&canUpdateCredentialDigest,
		&canUpdateCredentialUse,
		&canDeleteDevice,
	); err != nil {
		t.Fatalf("query registration privilege contract: %v", err)
	}
	if !canInsertDevice || !canUpdateHostname || canUpdateDevicePublicID ||
		canUpdateCredentialDigest || canUpdateCredentialUse || canDeleteDevice {
		t.Fatalf(
			"registration privileges: insert device=%t update hostname=%t "+
				"update device public id=%t update credential digest=%t "+
				"update credential use=%t delete device=%t",
			canInsertDevice,
			canUpdateHostname,
			canUpdateDevicePublicID,
			canUpdateCredentialDigest,
			canUpdateCredentialUse,
			canDeleteDevice,
		)
	}

	t.Run("mutation requires audit change context", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin unaudited registration transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationScope(ctx, t, transaction, 101, 201)
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.enrollment_profile (
    public_id, workspace_id, network_id, created_by_principal_id,
    display_name, name_key, node_lifetime_seconds, ephemeral_mode,
    credential_use_policy, credential_max_uses, state
) VALUES (
    '01890f10-0000-7000-8000-000000000706', 101, 201, 11,
    'Unaudited', 'unaudited', 3600, 'persistent', 'bounded', 1, 'active'
)`)
		assertPostgreSQLCode(t, err, "23514")
	})

	t.Run("RLS rejects cross-scope insert", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin cross-scope registration transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationScope(ctx, t, transaction, 101, 201)
		setIntegrationChange(ctx, t, transaction, "01890f11-0000-7000-8000-000000000707")
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.enrollment_profile (
    public_id, workspace_id, network_id, created_by_principal_id,
    display_name, name_key, node_lifetime_seconds, ephemeral_mode,
    credential_use_policy, credential_max_uses, state
) VALUES (
    '01890f10-0000-7000-8000-000000000707', 102, 202, 11,
    'Wrong scope', 'wrong-scope', 3600, 'persistent', 'bounded', 1, 'active'
)`)
		assertPostgreSQLCode(t, err, "42501")
	})
}
