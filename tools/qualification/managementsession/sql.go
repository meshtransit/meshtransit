package main

const configureSeedTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', '5s', TRUE),
    pg_catalog.set_config('lock_timeout', '2s', TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', '10s', TRUE)`

const loadSeedScopeSQL = `SELECT
    deployment.id,
    deployment.profile,
    deployment.recovery_epoch,
    deployment.state,
    deployment.recovery_state,
    principal.id,
    principal.kind,
    principal.state,
    principal.authority_generation,
    workspace.id,
    workspace.state,
    workspace.authority_generation,
    network.id,
    network.state,
    network.authority_generation,
    revision.network_revision
FROM mesh.deployment AS deployment
JOIN mesh.principal AS principal
  ON principal.deployment_id = deployment.id
JOIN mesh.workspace AS workspace
  ON workspace.deployment_id = deployment.id
JOIN mesh.network AS network
  ON network.workspace_id = workspace.id
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = workspace.id
 AND revision.network_id = network.id
WHERE deployment.installation_public_id = $1::UUID
  AND workspace.public_id = $2::UUID
  AND network.public_id = $3::UUID
  AND principal.public_id = $4::UUID`

const lockSeedScopeSQL = loadSeedScopeSQL + `
FOR UPDATE OF deployment, principal, workspace, network, revision`

const countSeedAuthoritySQL = `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.account
     WHERE deployment_id = $1::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.identity_provider
     WHERE deployment_id = $1::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.identity_provider_generation
     WHERE deployment_id = $1::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.identity_provider_client
     WHERE deployment_id = $1::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.identity_subject
     WHERE deployment_id = $1::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.account_session
     WHERE deployment_id = $1::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.workspace_membership
     WHERE deployment_id = $1::BIGINT AND workspace_id = $2::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.role_definition
     WHERE deployment_id = $1::BIGINT AND workspace_id = $2::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.role_permission
     WHERE deployment_id = $1::BIGINT AND workspace_id = $2::BIGINT),
    (SELECT pg_catalog.count(*) FROM mesh.role_binding
     WHERE deployment_id = $1::BIGINT AND workspace_id = $2::BIGINT)`

const setSeedChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const insertSeedAccountSQL = `INSERT INTO mesh.account (
    public_id, deployment_id, principal_id, display_name,
    session_generation, recovery_state
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, 'Qualification Account', 1, 'verified'
)
RETURNING id`

const insertSeedProviderSQL = `INSERT INTO mesh.identity_provider (
    public_id, deployment_id, issuer, issuer_digest_algorithm,
    issuer_digest_key_id, issuer_digest, protocol, authority_kind,
    discovery_uri, jwks_uri, current_generation, recovery_state, state
) VALUES (
    $1::UUID, $2::BIGINT, $3::TEXT, 'hmac-sha256-v1',
    'qualification-unrecoverable-v1', $4::BYTEA, 'oidc', 'external_oidc',
    $5::TEXT, $6::TEXT, 1, 'verified', 'active'
)
RETURNING id`

const insertSeedProviderGenerationSQL = `INSERT INTO mesh.identity_provider_generation (
    public_id, deployment_id, identity_provider_id, generation,
    trust_configuration_semantic_hash, recovery_mode, valid_from, state
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, 1,
    $4::BYTEA, 'initial', pg_catalog.transaction_timestamp(), 'current'
)
RETURNING id`

const insertSeedProviderClientSQL = `INSERT INTO mesh.identity_provider_client (
    public_id, deployment_id, identity_provider_id, client_kind, client_id,
    allowed_flows, allowed_scopes, allowed_algorithms, redirect_uris,
    post_logout_redirect_uris, pkce_s256_required, client_auth_method, state
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, 'public', 'meshtransit-qualification',
    ARRAY['device_authorization'], ARRAY['openid'], ARRAY['RS256'],
    ARRAY[]::TEXT[], ARRAY[]::TEXT[], TRUE, 'none', 'active'
)
RETURNING id`

const insertSeedSubjectSQL = `INSERT INTO mesh.identity_subject (
    public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest,
    claims_revision, last_seen_at, state
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    'hmac-sha256-v1', 'qualification-unrecoverable-v1', $5::BYTEA,
    1, pg_catalog.transaction_timestamp(), 'active'
)
RETURNING id`

const insertSeedSessionSQL = `INSERT INTO mesh.account_session (
    public_id, deployment_id, principal_id, identity_provider_id,
    identity_subject_id, identity_provider_client_id, login_workspace_id,
    token_digest_algorithm, token_digest_key_id, token_digest,
    provider_generation, authentication_time, acr, amr,
    principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at,
    idle_expires_at, absolute_expires_at, state
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    $5::BIGINT, $6::BIGINT, $7::BIGINT,
    'hmac-sha256-v1', $8::TEXT, $9::BYTEA,
    1, pg_catalog.transaction_timestamp(),
    'urn:meshtransit:assurance:qualification', ARRAY['qualification'],
    $10::BIGINT, 1, $11::BIGINT,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + ($12::BIGINT * INTERVAL '1 second'),
    pg_catalog.transaction_timestamp() + ($12::BIGINT * INTERVAL '1 second'),
    'active'
)
RETURNING id, absolute_expires_at`

const insertSeedMembershipSQL = `INSERT INTO mesh.workspace_membership (
    public_id, deployment_id, workspace_id, principal_id,
    state, authority_generation, valid_from, expires_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    'active', 1, pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + ($5::BIGINT * INTERVAL '1 second')
)
RETURNING id`

const insertSeedRoleDefinitionSQL = `INSERT INTO mesh.role_definition (
    public_id, deployment_id, workspace_id, role_key, display_name,
    kind, state, authority_generation
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT,
    'qualification_device_admin', 'Qualification Device Administrator',
    'custom', 'active', 1
)
RETURNING id`

const insertSeedRolePermissionSQL = `INSERT INTO mesh.role_permission (
    public_id, deployment_id, workspace_id, role_definition_id, permission_id
)
SELECT $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'device.manage'
RETURNING id`

const insertSeedRoleBindingSQL = `INSERT INTO mesh.role_binding (
    public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, role_definition_id, state,
    authority_generation, valid_from, expires_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, $5::BIGINT,
    $6::BIGINT, $7::BIGINT, 'active', 1,
    pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + ($8::BIGINT * INTERVAL '1 second')
)
RETURNING id`

const lockSeedAuditStreamSQL = `SELECT id, next_sequence, latest_event_hash
FROM mesh_audit.audit_stream
WHERE deployment_id = $1::BIGINT
  AND workspace_id = $2::BIGINT
  AND network_id = $3::BIGINT
  AND scope_kind = 'network'
FOR UPDATE`

const appendSeedEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'role_binding', $7::UUID, 1, $8::BIGINT, $9::UUID,
    'qualification.management_session.seeded', 'system.bootstrap',
    $10::UUID, NULL::BYTEA, $11::BYTEA, $12::JSONB,
    'qualification.management_session.seeded', $13::JSONB
)`
