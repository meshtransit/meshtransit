//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/authorization"
)

const (
	integrationAccountPublicID         = "01890f00-0000-7000-8000-000000000701"
	integrationIdentitySubjectPublicID = "01890f00-0000-7000-8000-000000000711"
)

func assertAccountIdentityPermissionFoundation(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()

	seedAccountIdentityFoundation(ctx, t, adminConnection)
	assertAccountIdentityRows(ctx, t, adminConnection)
	assertAccountIdentityConstraints(ctx, t, adminConnection)
	assertPermissionCatalog(ctx, t, adminConnection)
	assertAccountIdentityPrivilegeContract(ctx, t, adminConnection, runtimeConnection)
}

func seedAccountIdentityFoundation(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000701",
		eventPublicID:          "01890f02-0000-7000-8000-000000000701",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000701",
		streamID:               1,
		aggregateKind:          "account",
		aggregatePublicID:      integrationAccountPublicID,
		aggregateVersion:       1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "account.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "account.created",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.account (
    id, public_id, deployment_id, principal_id, display_name,
    login_identifier_digest_algorithm, login_identifier_digest_key_id,
    login_identifier_digest, session_generation, recovery_state
) OVERRIDING SYSTEM VALUE VALUES (
    701, '01890f00-0000-7000-8000-000000000701', 1, 11, 'Integration Owner',
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('77', 32), 'hex'), 1, 'verified'
)`); err != nil {
			t.Fatalf("insert integration account: %v", err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.identity_subject (
    id, public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest,
    claims_revision, last_seen_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    711, '01890f00-0000-7000-8000-000000000711', 1, 601, 11,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('88', 32), 'hex'),
    1, pg_catalog.transaction_timestamp(), 'active'
)`); err != nil {
			t.Fatalf("insert integration identity subject: %v", err)
		}
	})

	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000712",
		eventPublicID:          "01890f02-0000-7000-8000-000000000712",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000712",
		streamID:               1,
		aggregateKind:          "identity_subject",
		aggregatePublicID:      "01890f00-0000-7000-8000-000000000712",
		aggregateVersion:       1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "identity_subject.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "identity_subject.created",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.identity_provider (
    id, public_id, deployment_id, issuer, issuer_digest_algorithm, issuer_digest_key_id,
    issuer_digest, protocol, authority_kind, discovery_uri, jwks_uri,
    current_generation, recovery_state, state
) OVERRIDING SYSTEM VALUE VALUES (
    602, '01890f00-0000-7000-8000-000000000602', 1,
    'https://idp-two.example.test/realms/main', 'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('33', 32), 'hex'), 'oidc', 'external_oidc',
    'https://idp-two.example.test/.well-known/openid-configuration',
    'https://idp-two.example.test/jwks', 1, 'verified', 'active'
)`); err != nil {
			t.Fatalf("insert second integration identity provider: %v", err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.identity_provider_generation (
    id, public_id, deployment_id, identity_provider_id, generation,
    trust_configuration_semantic_hash, recovery_mode, recovery_evidence_reference,
    valid_from, state
) OVERRIDING SYSTEM VALUE VALUES (
    612, '01890f00-0000-7000-8000-000000000612', 1, 602, 1,
    pg_catalog.decode(pg_catalog.repeat('34', 32), 'hex'), 'initial', NULL,
    pg_catalog.transaction_timestamp(), 'current'
)`); err != nil {
			t.Fatalf("insert second integration identity provider generation: %v", err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.identity_subject (
    id, public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest,
    claims_revision, last_seen_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    712, '01890f00-0000-7000-8000-000000000712', 1, 602, 11,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('88', 32), 'hex'),
    1, pg_catalog.transaction_timestamp(), 'active'
)`); err != nil {
			t.Fatalf("insert same subject digest under second provider: %v", err)
		}
	})
}

func assertAccountIdentityRows(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	var displayName, recoveryState, subjectState string
	var sessionGeneration, claimsRevision, matchingSubjects, mutationCount int64
	if err := connection.QueryRow(ctx, `SELECT
    account.display_name,
    account.session_generation,
    account.recovery_state,
    subject.claims_revision,
    subject.state,
    (
        SELECT pg_catalog.count(*)
        FROM mesh.identity_subject AS candidate
        WHERE candidate.subject_digest_key_id = subject.subject_digest_key_id
          AND candidate.subject_digest = subject.subject_digest
    ),
    (
        SELECT pg_catalog.count(*)
        FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = '01890f01-0000-7000-8000-000000000701'
    )
FROM mesh.account AS account
JOIN mesh.identity_subject AS subject
  ON subject.deployment_id = account.deployment_id
 AND subject.principal_id = account.principal_id
WHERE account.public_id = $1
  AND subject.public_id = $2`,
		integrationAccountPublicID,
		integrationIdentitySubjectPublicID,
	).Scan(
		&displayName,
		&sessionGeneration,
		&recoveryState,
		&claimsRevision,
		&subjectState,
		&matchingSubjects,
		&mutationCount,
	); err != nil {
		t.Fatalf("query account identity foundation: %v", err)
	}
	if displayName != "Integration Owner" || sessionGeneration != 1 ||
		recoveryState != "verified" || claimsRevision != 1 || subjectState != "active" ||
		matchingSubjects != 2 || mutationCount != 2 {
		t.Fatalf(
			"account identity display=%q generation=%d recovery=%s claims=%d state=%s subjects=%d mutations=%d",
			displayName,
			sessionGeneration,
			recoveryState,
			claimsRevision,
			subjectState,
			matchingSubjects,
			mutationCount,
		)
	}
}

func assertAccountIdentityConstraints(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	t.Run("account requires account principal", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin service principal account transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000702")
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.principal (
    id, public_id, deployment_id, kind, state
) OVERRIDING SYSTEM VALUE VALUES (
    901, '01890f00-0000-7000-8000-000000000901', 1, 'service', 'active'
)`); err != nil {
			t.Fatalf("insert service principal: %v", err)
		}
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.account (
    id, public_id, deployment_id, principal_id, display_name, recovery_state
) OVERRIDING SYSTEM VALUE VALUES (
    702, '01890f00-0000-7000-8000-000000000702', 1, 901,
    'Invalid Service Account', 'verified'
)`)
		assertPostgreSQLCode(t, err, "23503")
	})

	t.Run("subject binding is exact within provider", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.identity_subject (
    id, public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest,
    claims_revision, last_seen_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    713, '01890f00-0000-7000-8000-000000000713', 1, 601, 11,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('88', 32), 'hex'),
    1, pg_catalog.transaction_timestamp(), 'active'
)`)
		assertPostgreSQLCode(t, err, "23505")
	})

	t.Run("account requires complete login digest", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin incomplete login digest transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000703")
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.principal (
    id, public_id, deployment_id, kind, state
) OVERRIDING SYSTEM VALUE VALUES (
    902, '01890f00-0000-7000-8000-000000000902', 1, 'account', 'active'
)`); err != nil {
			t.Fatalf("insert incomplete digest account principal: %v", err)
		}
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.account (
    id, public_id, deployment_id, principal_id, display_name,
    login_identifier_digest_algorithm, recovery_state
) OVERRIDING SYSTEM VALUE VALUES (
    703, '01890f00-0000-7000-8000-000000000703', 1, 902,
    'Incomplete Digest', 'hmac-sha256-v1', 'verified'
)`)
		assertPostgreSQLCode(t, err, "23514")
	})

	t.Run("account session generation is positive", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin invalid session generation transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000704")
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.principal (
    id, public_id, deployment_id, kind, state
) OVERRIDING SYSTEM VALUE VALUES (
    903, '01890f00-0000-7000-8000-000000000903', 1, 'account', 'active'
)`); err != nil {
			t.Fatalf("insert invalid generation account principal: %v", err)
		}
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.account (
    id, public_id, deployment_id, principal_id, display_name,
    session_generation, recovery_state
) OVERRIDING SYSTEM VALUE VALUES (
    704, '01890f00-0000-7000-8000-000000000704', 1, 903,
    'Invalid Generation', 0, 'verified'
)`)
		assertPostgreSQLCode(t, err, "23514")
	})

	var forbiddenRawColumns int64
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM pg_catalog.pg_attribute AS attribute
JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN ('account', 'identity_subject')
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
  AND attribute.attname IN (
      'email', 'login_identifier', 'preferred_username', 'raw_subject', 'subject',
      'provider_token', 'refresh_token'
  )`).Scan(&forbiddenRawColumns); err != nil {
		t.Fatalf("query raw identity columns: %v", err)
	}
	if forbiddenRawColumns != 0 {
		t.Fatalf("raw identity columns = %d, want 0", forbiddenRawColumns)
	}
}

func assertPermissionCatalog(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	rows, err := connection.Query(ctx, `SELECT permission_key
FROM mesh.permission
ORDER BY id`)
	if err != nil {
		t.Fatalf("query permission catalog: %v", err)
	}
	defer rows.Close()

	actual := make([]string, 0, len(authorization.Permissions()))
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			t.Fatalf("scan permission catalog: %v", err)
		}
		actual = append(actual, permission)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate permission catalog: %v", err)
	}
	expected := authorization.Permissions()
	if len(actual) != len(expected) {
		t.Fatalf("permission catalog rows = %d, want %d", len(actual), len(expected))
	}
	for index, permission := range expected {
		if actual[index] != string(permission) {
			t.Fatalf(
				"permission catalog row %d = %q, want %q",
				index,
				actual[index],
				permission,
			)
		}
	}

	_, err = connection.Exec(ctx, `UPDATE mesh.permission
SET description = 'mutated'
WHERE permission_key = 'network.read'`)
	assertPostgreSQLCode(t, err, "55000")

	_, err = connection.Exec(ctx, `DELETE FROM mesh.permission
WHERE permission_key = 'network.read'`)
	assertPostgreSQLCode(t, err, "55000")

	_, err = connection.Exec(ctx, `INSERT INTO mesh.permission (
    permission_key, description, risk_class, allowed_scope_kinds, catalog_version
) VALUES ('network.*', 'Invalid wildcard', 'read', ARRAY['network'], 1)`)
	assertPostgreSQLCode(t, err, "23514")
}

func assertAccountIdentityPrivilegeContract(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()

	var runtimeHasAccess, workerHasAccess, observerHasAccess, anyRLS bool
	if err := adminConnection.QueryRow(ctx, `SELECT
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'DELETE')
    ), FALSE),
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'DELETE')
    ), FALSE),
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'DELETE')
    ), FALSE),
    COALESCE(pg_catalog.bool_or(relation.relrowsecurity), FALSE)
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN ('account', 'identity_subject', 'permission')`).Scan(
		&runtimeHasAccess,
		&workerHasAccess,
		&observerHasAccess,
		&anyRLS,
	); err != nil {
		t.Fatalf("query account identity privilege contract: %v", err)
	}
	if runtimeHasAccess || workerHasAccess || observerHasAccess || anyRLS {
		t.Fatalf(
			"account identity privileges runtime=%t worker=%t observer=%t RLS=%t",
			runtimeHasAccess,
			workerHasAccess,
			observerHasAccess,
			anyRLS,
		)
	}

	_, err := runtimeConnection.Exec(ctx, "SELECT public_id FROM mesh.account")
	assertPostgreSQLCode(t, err, "42501")
}
