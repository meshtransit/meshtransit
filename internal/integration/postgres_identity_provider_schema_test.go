//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

const integrationIdentityProviderPublicID = "01890f00-0000-7000-8000-000000000601"

func assertIdentityProviderSchemaFoundation(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()

	seedIdentityProviderFoundation(ctx, t, adminConnection)
	assertIdentityProviderFoundationRows(ctx, t, adminConnection)
	assertIdentityProviderConstraints(ctx, t, adminConnection)
	assertIdentityProviderPrivilegeContract(ctx, t, adminConnection, runtimeConnection)
}

func seedIdentityProviderFoundation(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000601",
		eventPublicID:          "01890f02-0000-7000-8000-000000000601",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000601",
		streamID:               1,
		aggregateKind:          "identity_provider",
		aggregatePublicID:      integrationIdentityProviderPublicID,
		aggregateVersion:       1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "identity_provider.created",
		permission:             "identity_provider.manage",
		outboxEventClass:       "identity_provider.created",
	}, func(transaction pgx.Tx) {
		statements := []struct {
			name  string
			query string
		}{
			{
				name: "identity provider",
				query: `INSERT INTO mesh.identity_provider (
    id, public_id, deployment_id, issuer, issuer_digest_algorithm, issuer_digest_key_id,
    issuer_digest, protocol, authority_kind, discovery_uri,
    authorization_endpoint, token_endpoint, jwks_uri,
    current_generation, recovery_state, state
) OVERRIDING SYSTEM VALUE VALUES (
    601, '01890f00-0000-7000-8000-000000000601', 1,
    'https://idp.example.test/realms/main', 'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('11', 32), 'hex'), 'oidc', 'managed_oidc',
    'https://idp.example.test/realms/main/.well-known/openid-configuration',
    'https://idp.example.test/realms/main/protocol/openid-connect/auth',
    'https://idp.example.test/realms/main/protocol/openid-connect/token',
    'https://idp.example.test/realms/main/protocol/openid-connect/certs',
    1, 'verified', 'active'
)`,
			},
			{
				name: "identity provider generation",
				query: `INSERT INTO mesh.identity_provider_generation (
    id, public_id, deployment_id, identity_provider_id, generation,
    trust_configuration_semantic_hash, recovery_mode, recovery_evidence_reference,
    valid_from, state
) OVERRIDING SYSTEM VALUE VALUES (
    611, '01890f00-0000-7000-8000-000000000611', 1, 601, 1,
    pg_catalog.decode(pg_catalog.repeat('22', 32), 'hex'), 'initial', NULL,
    pg_catalog.transaction_timestamp(), 'current'
)`,
			},
			{
				name: "identity provider client",
				query: `INSERT INTO mesh.identity_provider_client (
    id, public_id, deployment_id, identity_provider_id, client_kind, client_id,
    allowed_flows, allowed_scopes, allowed_algorithms, redirect_uris,
    post_logout_redirect_uris, pkce_s256_required, client_auth_method,
    credential_reference, state
) OVERRIDING SYSTEM VALUE VALUES (
    621, '01890f00-0000-7000-8000-000000000621', 1, 601, 'confidential',
    'meshtransit-console', ARRAY['authorization_code'], ARRAY['openid', 'profile'],
    ARRAY['RS256'], ARRAY['https://console.example.test/auth/callback'],
    ARRAY['https://console.example.test/logout/complete'], TRUE,
    'client_secret_basic', 'secret://oidc/console', 'active'
)`,
			},
			{
				name: "workspace identity provider",
				query: `INSERT INTO mesh.workspace_identity_provider (
    id, public_id, deployment_id, workspace_id, identity_provider_id,
    identity_provider_client_id, admission_mode, minimum_assurance,
    routing_priority, state
) OVERRIDING SYSTEM VALUE VALUES (
    631, '01890f00-0000-7000-8000-000000000631', 1, 101, 601, 621,
    'invitation_only', 'urn:meshtransit:assurance:mfa', 10, 'active'
)`,
			},
		}
		for _, statement := range statements {
			if _, err := transaction.Exec(ctx, statement.query); err != nil {
				t.Fatalf("insert integration %s: %v", statement.name, err)
			}
		}
	})
}

func assertIdentityProviderFoundationRows(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	var providerGeneration, generationCount, clientCount, bindingCount int64
	var generationState, recoveryState string
	if err := connection.QueryRow(ctx, `SELECT
    provider.current_generation,
    provider.recovery_state,
    generation.state,
    (SELECT pg_catalog.count(*) FROM mesh.identity_provider_generation WHERE identity_provider_id = provider.id),
    (SELECT pg_catalog.count(*) FROM mesh.identity_provider_client WHERE identity_provider_id = provider.id),
    (SELECT pg_catalog.count(*) FROM mesh.workspace_identity_provider WHERE identity_provider_id = provider.id)
FROM mesh.identity_provider AS provider
JOIN mesh.identity_provider_generation AS generation
  ON generation.deployment_id = provider.deployment_id
 AND generation.identity_provider_id = provider.id
 AND generation.generation = provider.current_generation
WHERE provider.public_id = $1`, integrationIdentityProviderPublicID).Scan(
		&providerGeneration,
		&recoveryState,
		&generationState,
		&generationCount,
		&clientCount,
		&bindingCount,
	); err != nil {
		t.Fatalf("query identity provider foundation: %v", err)
	}
	if providerGeneration != 1 || recoveryState != "verified" || generationState != "current" ||
		generationCount != 1 || clientCount != 1 || bindingCount != 1 {
		t.Fatalf(
			"identity provider foundation generation=%d recovery=%s state=%s generations=%d clients=%d bindings=%d",
			providerGeneration,
			recoveryState,
			generationState,
			generationCount,
			clientCount,
			bindingCount,
		)
	}
}

func assertIdentityProviderConstraints(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	t.Run("provider requires current generation", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin missing provider generation transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000602")
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.identity_provider (
    id, public_id, deployment_id, issuer, issuer_digest_algorithm, issuer_digest_key_id,
    issuer_digest, protocol, authority_kind, discovery_uri, jwks_uri,
    current_generation, recovery_state, state
) OVERRIDING SYSTEM VALUE VALUES (
    602, '01890f00-0000-7000-8000-000000000602', 1,
    'https://idp-two.example.test/realms/main', 'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('33', 32), 'hex'), 'oidc', 'external_oidc',
    'https://idp-two.example.test/.well-known/openid-configuration',
    'https://idp-two.example.test/jwks', 1, 'verified', 'active'
)`)
		if err != nil {
			t.Fatalf("insert provider without generation: %v", err)
		}
		_, err = transaction.Exec(
			ctx,
			"SET CONSTRAINTS mesh.identity_provider_current_generation_state_check IMMEDIATE",
		)
		assertPostgreSQLCode(t, err, "23514")
	})

	t.Run("exact issuer is unique", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.identity_provider (
    id, public_id, deployment_id, issuer, issuer_digest_algorithm, issuer_digest_key_id,
    issuer_digest, protocol, authority_kind, discovery_uri, jwks_uri,
    current_generation, recovery_state, state
) OVERRIDING SYSTEM VALUE VALUES (
    603, '01890f00-0000-7000-8000-000000000603', 1,
    'https://idp.example.test/realms/main', 'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('44', 32), 'hex'), 'oidc', 'managed_oidc',
    'https://idp.example.test/realms/main/.well-known/openid-configuration',
    'https://idp.example.test/realms/main/protocol/openid-connect/certs',
    1, 'verified', 'active'
)`)
		assertPostgreSQLCode(t, err, "23505")
	})

	t.Run("provider has one current generation", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.identity_provider_generation (
    id, public_id, deployment_id, identity_provider_id, generation,
    trust_configuration_semantic_hash, recovery_mode, recovery_evidence_reference,
    valid_from, state
) OVERRIDING SYSTEM VALUE VALUES (
    612, '01890f00-0000-7000-8000-000000000612', 1, 601, 2,
    pg_catalog.decode(pg_catalog.repeat('55', 32), 'hex'), 'initial', NULL,
    pg_catalog.transaction_timestamp(), 'current'
)`)
		assertPostgreSQLCode(t, err, "23505")
	})

	t.Run("recovery generation requires evidence", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin missing recovery evidence transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000613")
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.identity_provider_generation (
    id, public_id, deployment_id, identity_provider_id, generation,
    trust_configuration_semantic_hash, recovery_mode, recovery_evidence_reference,
    valid_from, valid_until, state
) OVERRIDING SYSTEM VALUE VALUES (
    613, '01890f00-0000-7000-8000-000000000613', 1, 601, 3,
    pg_catalog.decode(pg_catalog.repeat('56', 32), 'hex'), 'lossy', NULL,
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    pg_catalog.transaction_timestamp(), 'superseded'
)`)
		assertPostgreSQLConstraint(
			t,
			err,
			"identity_provider_generation_recovery_evidence_check",
		)
	})

	t.Run("public client cannot reference credential", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.identity_provider_client (
    id, public_id, deployment_id, identity_provider_id, client_kind, client_id,
    allowed_flows, allowed_scopes, allowed_algorithms, redirect_uris,
    post_logout_redirect_uris, pkce_s256_required, client_auth_method,
    credential_reference, state
) OVERRIDING SYSTEM VALUE VALUES (
    623, '01890f00-0000-7000-8000-000000000623', 1, 601, 'public',
    'invalid-public-client', ARRAY['authorization_code'], ARRAY['openid'],
    ARRAY['RS256'], ARRAY['http://127.0.0.1/callback'], ARRAY[]::TEXT[], TRUE,
    'client_secret_basic', 'secret://invalid', 'active'
)`)
		assertPostgreSQLCode(t, err, "23514")
	})

	t.Run("confidential client requires credential", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin missing client credential transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000624")
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.identity_provider_client (
    id, public_id, deployment_id, identity_provider_id, client_kind, client_id,
    allowed_flows, allowed_scopes, allowed_algorithms, redirect_uris,
    post_logout_redirect_uris, pkce_s256_required, client_auth_method,
    credential_reference, state
) OVERRIDING SYSTEM VALUE VALUES (
    624, '01890f00-0000-7000-8000-000000000624', 1, 601, 'confidential',
    'missing-credential-client', ARRAY['authorization_code'], ARRAY['openid'],
    ARRAY['RS256'], ARRAY['https://console.example.test/auth/callback'],
    ARRAY[]::TEXT[], TRUE, 'client_secret_basic', NULL, 'active'
)`)
		assertPostgreSQLConstraint(t, err, "identity_provider_client_auth_method_check")
	})

	t.Run("workspace binding requires complete organization digest", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin incomplete organization digest transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000632")
		_, err = transaction.Exec(ctx, `INSERT INTO mesh.workspace_identity_provider (
    id, public_id, deployment_id, workspace_id, identity_provider_id,
    identity_provider_client_id, organization_digest_algorithm,
    admission_mode, minimum_assurance, routing_priority, state
) OVERRIDING SYSTEM VALUE VALUES (
    632, '01890f00-0000-7000-8000-000000000632', 1, 102, 601, 621,
    'hmac-sha256-v1', 'invitation_only', NULL, 20, 'active'
)`)
		assertPostgreSQLConstraint(
			t,
			err,
			"workspace_identity_provider_organization_digest_check",
		)
	})
}

func assertIdentityProviderPrivilegeContract(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()

	var runtimeHasAccess, workerHasAccess, bindingRLS, bindingForceRLS bool
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
    pg_catalog.bool_and(
        CASE WHEN relation.relname = 'workspace_identity_provider' THEN relation.relrowsecurity ELSE TRUE END
    ),
    pg_catalog.bool_and(
        CASE WHEN relation.relname = 'workspace_identity_provider' THEN relation.relforcerowsecurity ELSE TRUE END
    )
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN (
      'identity_provider',
      'identity_provider_generation',
      'identity_provider_client',
      'workspace_identity_provider'
  )`).Scan(&runtimeHasAccess, &workerHasAccess, &bindingRLS, &bindingForceRLS); err != nil {
		t.Fatalf("query identity provider privilege contract: %v", err)
	}
	if runtimeHasAccess || workerHasAccess || !bindingRLS || !bindingForceRLS {
		t.Fatalf(
			"identity provider privileges runtime=%t worker=%t binding RLS=%t force=%t",
			runtimeHasAccess,
			workerHasAccess,
			bindingRLS,
			bindingForceRLS,
		)
	}

	_, err := runtimeConnection.Exec(ctx, "SELECT public_id FROM mesh.identity_provider")
	assertPostgreSQLCode(t, err, "42501")
}
