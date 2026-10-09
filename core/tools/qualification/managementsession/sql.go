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

const loadRenewalFixtureSQL = `WITH seeded_session AS (
    SELECT
        session.public_id,
        session.authentication_time,
        mutation.change_public_id,
        mutation.transaction_id,
        event.target_public_id
    FROM mesh.account_session AS session
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.aggregate_kind = 'account_session'
     AND mutation.row_public_id = session.public_id
     AND mutation.operation = 'insert'
     AND mutation.before_version IS NULL
     AND mutation.after_version = 1
    JOIN mesh_audit.audit_event_identity AS identity
      ON identity.change_public_id = mutation.change_public_id
     AND identity.transaction_id = mutation.transaction_id
    JOIN mesh_audit.audit_event AS event
      ON event.event_identity_id = identity.id
     AND event.occurred_at = identity.occurred_at
    WHERE session.deployment_id = $1::BIGINT
      AND session.principal_id = $4::BIGINT
      AND event.action = 'qualification.management_session.seeded'
      AND event.permission = 'system.bootstrap'
      AND event.target_kind = 'role_binding'
      AND event.correlation_public_id = session.public_id
      AND event.result = 'succeeded'
      AND event.payload ->> 'qualification_only' = 'true'
)
SELECT
    account.id,
    account.principal_id,
    account.session_generation,
    provider.id,
    provider.current_generation,
    client.id,
    subject.id,
    subject.public_id::TEXT,
    membership.id,
    membership.public_id::TEXT,
    membership.version,
    membership.authority_generation,
    membership.expires_at,
    role_definition.id,
    role_definition.public_id::TEXT,
    role_definition.version,
    role_definition.authority_generation,
    role_permission.id,
    binding.id,
    binding.public_id::TEXT,
    binding.version,
    binding.authority_generation,
    binding.expires_at,
    seeded_session.authentication_time,
    pg_catalog.transaction_timestamp()
FROM mesh.account AS account
JOIN mesh.identity_provider AS provider
  ON provider.deployment_id = account.deployment_id
JOIN mesh.identity_provider_generation AS generation
  ON generation.deployment_id = provider.deployment_id
 AND generation.identity_provider_id = provider.id
 AND generation.generation = provider.current_generation
JOIN mesh.identity_provider_client AS client
  ON client.deployment_id = provider.deployment_id
 AND client.identity_provider_id = provider.id
JOIN mesh.identity_subject AS subject
  ON subject.deployment_id = provider.deployment_id
 AND subject.identity_provider_id = provider.id
 AND subject.principal_id = account.principal_id
JOIN mesh.workspace_membership AS membership
  ON membership.deployment_id = account.deployment_id
 AND membership.workspace_id = $2::BIGINT
 AND membership.principal_id = account.principal_id
JOIN mesh.role_definition AS role_definition
  ON role_definition.deployment_id = account.deployment_id
 AND role_definition.workspace_id = membership.workspace_id
JOIN mesh.role_permission AS role_permission
  ON role_permission.deployment_id = role_definition.deployment_id
 AND role_permission.workspace_id = role_definition.workspace_id
 AND role_permission.role_definition_id = role_definition.id
JOIN mesh.permission AS permission
  ON permission.id = role_permission.permission_id
JOIN mesh.role_binding AS binding
  ON binding.deployment_id = membership.deployment_id
 AND binding.workspace_id = membership.workspace_id
 AND binding.network_id = $3::BIGINT
 AND binding.principal_id = membership.principal_id
 AND binding.workspace_membership_id = membership.id
 AND binding.role_definition_id = role_definition.id
JOIN seeded_session
  ON seeded_session.target_public_id = binding.public_id
WHERE account.deployment_id = $1::BIGINT
  AND account.principal_id = $4::BIGINT
  AND account.principal_kind = 'account'
  AND account.display_name = 'Qualification Account'
  AND account.login_identifier_digest_algorithm IS NULL
  AND account.login_identifier_digest_key_id IS NULL
  AND account.login_identifier_digest IS NULL
  AND account.profile_encryption_algorithm IS NULL
  AND account.profile_encryption_key_id IS NULL
  AND account.profile_ciphertext IS NULL
  AND account.session_generation = 1
  AND account.recovery_state = 'verified'
  AND account.version = 1
  AND provider.issuer = 'https://idp.qualification.example'
  AND provider.issuer_digest_algorithm = 'hmac-sha256-v1'
  AND provider.issuer_digest_key_id = 'qualification-unrecoverable-v1'
  AND pg_catalog.octet_length(provider.issuer_digest) = 32
  AND provider.protocol = 'oidc'
  AND provider.authority_kind = 'external_oidc'
  AND provider.discovery_uri = 'https://idp.qualification.example/.well-known/openid-configuration'
  AND provider.jwks_uri = 'https://idp.qualification.example/jwks'
  AND provider.current_generation = 1
  AND provider.recovery_state = 'verified'
  AND provider.state = 'active'
  AND provider.version = 1
  AND generation.generation = 1
  AND generation.trust_configuration_semantic_hash = $6::BYTEA
  AND generation.recovery_mode = 'initial'
  AND generation.recovery_evidence_reference IS NULL
  AND generation.valid_until IS NULL
  AND generation.state = 'current'
  AND generation.version = 1
  AND client.client_kind = 'public'
  AND client.client_id = 'meshtransit-qualification'
  AND client.allowed_flows = ARRAY['device_authorization']::TEXT[]
  AND client.allowed_scopes = ARRAY['openid']::TEXT[]
  AND client.allowed_algorithms = ARRAY['RS256']::TEXT[]
  AND client.redirect_uris = ARRAY[]::TEXT[]
  AND client.post_logout_redirect_uris = ARRAY[]::TEXT[]
  AND client.pkce_s256_required
  AND client.client_auth_method = 'none'
  AND client.credential_reference IS NULL
  AND client.state = 'active'
  AND client.version = 1
  AND client.deleted_at IS NULL
  AND subject.subject_digest_algorithm = 'hmac-sha256-v1'
  AND subject.subject_digest_key_id = 'qualification-unrecoverable-v1'
  AND pg_catalog.octet_length(subject.subject_digest) = 32
  AND subject.claims_revision = 1
  AND subject.state = 'active'
  AND subject.version = 1
  AND subject.deleted_at IS NULL
  AND membership.state = 'active'
  AND membership.authority_generation = membership.version
  AND membership.expires_at IS NOT NULL
  AND membership.expires_at <= pg_catalog.transaction_timestamp()
  AND role_definition.role_key = 'qualification_device_admin'
  AND role_definition.display_name = 'Qualification Device Administrator'
  AND role_definition.kind = 'custom'
  AND role_definition.state = 'active'
  AND role_definition.authority_generation = 1
  AND role_definition.version = 1
  AND role_permission.state = 'active'
  AND role_permission.version = 1
  AND permission.permission_key = 'device.manage'
  AND binding.state = 'active'
  AND binding.authority_generation = binding.version
  AND binding.expires_at = membership.expires_at
  AND binding.expires_at <= pg_catalog.transaction_timestamp()
  AND (SELECT pg_catalog.count(*) FROM seeded_session) = 1
  AND (
      SELECT pg_catalog.count(*)
      FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
  ) = 10
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'account'
        AND mutation.row_public_id = account.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'identity_provider'
        AND mutation.row_public_id = provider.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'identity_provider_generation'
        AND mutation.row_public_id = generation.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'identity_provider_client'
        AND mutation.row_public_id = client.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'identity_subject'
        AND mutation.row_public_id = subject.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'workspace_membership'
        AND mutation.row_public_id = membership.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'role_definition'
        AND mutation.row_public_id = role_definition.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'role_permission'
        AND mutation.row_public_id = role_permission.public_id
        AND mutation.operation = 'insert'
  )
  AND EXISTS (
      SELECT 1 FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.change_public_id = seeded_session.change_public_id
        AND mutation.transaction_id = seeded_session.transaction_id
        AND mutation.aggregate_kind = 'role_binding'
        AND mutation.row_public_id = binding.public_id
        AND mutation.operation = 'insert'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM mesh.account_session AS session
      WHERE session.deployment_id = account.deployment_id
        AND (
            session.principal_id IS DISTINCT FROM account.principal_id
            OR session.identity_provider_id IS DISTINCT FROM provider.id
            OR session.identity_subject_id IS DISTINCT FROM subject.id
            OR session.identity_provider_client_id IS DISTINCT FROM client.id
            OR session.login_workspace_id IS DISTINCT FROM membership.workspace_id
            OR session.token_digest_algorithm IS DISTINCT FROM 'hmac-sha256-v1'
            OR session.token_digest_key_id IS DISTINCT FROM $5::TEXT
            OR pg_catalog.octet_length(session.token_digest) IS DISTINCT FROM 32
            OR session.provider_generation IS DISTINCT FROM provider.current_generation
            OR session.authentication_time IS DISTINCT FROM seeded_session.authentication_time
            OR session.acr IS DISTINCT FROM 'urn:meshtransit:assurance:qualification'
            OR session.amr IS DISTINCT FROM ARRAY['qualification']::TEXT[]
            OR session.principal_authority_generation IS DISTINCT FROM (
                SELECT principal.authority_generation
                FROM mesh.principal AS principal
                WHERE principal.id = account.principal_id
                  AND principal.deployment_id = account.deployment_id
            )
            OR session.account_session_generation IS DISTINCT FROM account.session_generation
            OR session.deployment_recovery_epoch IS DISTINCT FROM (
                SELECT deployment.recovery_epoch
                FROM mesh.deployment AS deployment
                WHERE deployment.id = account.deployment_id
            )
            OR session.issued_at IS DISTINCT FROM session.last_used_at
            OR session.idle_expires_at IS DISTINCT FROM session.absolute_expires_at
            OR session.absolute_expires_at > pg_catalog.transaction_timestamp()
            OR session.ended_at IS NOT NULL
            OR session.end_reason IS NOT NULL
            OR session.state IS DISTINCT FROM 'active'
            OR session.version IS DISTINCT FROM 1
            OR NOT EXISTS (
                SELECT 1
                FROM mesh_audit.authority_mutation AS mutation
                JOIN mesh_audit.audit_event_identity AS identity
                  ON identity.change_public_id = mutation.change_public_id
                 AND identity.transaction_id = mutation.transaction_id
                JOIN mesh_audit.audit_event AS event
                  ON event.event_identity_id = identity.id
                 AND event.occurred_at = identity.occurred_at
                WHERE mutation.aggregate_kind = 'account_session'
                  AND mutation.row_public_id = session.public_id
                  AND mutation.operation = 'insert'
                  AND mutation.before_version IS NULL
                  AND mutation.after_version = 1
                  AND event.action IN (
                      'qualification.management_session.seeded',
                      'qualification.management_session.renewed'
                  )
                  AND event.permission = 'system.bootstrap'
                  AND event.target_kind = 'role_binding'
                  AND event.target_public_id = binding.public_id
                  AND event.correlation_public_id = session.public_id
                  AND event.result = 'succeeded'
                  AND event.payload ->> 'qualification_only' = 'true'
            )
        )
  )
  AND (
      SELECT pg_catalog.count(*)
      FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.aggregate_kind = 'workspace_membership'
        AND mutation.row_public_id = membership.public_id
        AND mutation.operation = 'update'
  ) = membership.version - 1
  AND (
      SELECT pg_catalog.count(*)
      FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.aggregate_kind = 'role_binding'
        AND mutation.row_public_id = binding.public_id
        AND mutation.operation = 'update'
  ) = binding.version - 1
  AND NOT EXISTS (
      SELECT 1
      FROM mesh_audit.authority_mutation AS mutation
      WHERE mutation.operation = 'update'
        AND (
            (mutation.aggregate_kind = 'workspace_membership' AND mutation.row_public_id = membership.public_id)
            OR (mutation.aggregate_kind = 'role_binding' AND mutation.row_public_id = binding.public_id)
        )
        AND NOT EXISTS (
            SELECT 1
            FROM mesh_audit.audit_event_identity AS identity
            JOIN mesh_audit.audit_event AS event
              ON event.event_identity_id = identity.id
             AND event.occurred_at = identity.occurred_at
            WHERE identity.change_public_id = mutation.change_public_id
              AND identity.transaction_id = mutation.transaction_id
              AND event.action = 'qualification.management_session.renewed'
              AND event.permission = 'system.bootstrap'
              AND event.target_kind = 'role_binding'
              AND event.target_public_id = binding.public_id
              AND event.result = 'succeeded'
              AND event.payload ->> 'qualification_only' = 'true'
        )
  )
FOR UPDATE OF account, provider, generation, client, subject,
    membership, role_definition, role_permission, binding`

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

const insertRenewalSessionSQL = `INSERT INTO mesh.account_session (
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
    $10::BIGINT, $11::TIMESTAMPTZ,
    'urn:meshtransit:assurance:qualification', ARRAY['qualification'],
    $12::BIGINT, $13::BIGINT, $14::BIGINT,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + ($15::BIGINT * INTERVAL '1 second'),
    pg_catalog.transaction_timestamp() + ($15::BIGINT * INTERVAL '1 second'),
    'active'
)
RETURNING id, absolute_expires_at`

const renewMembershipSQL = `UPDATE mesh.workspace_membership
SET expires_at = pg_catalog.transaction_timestamp() + ($5::BIGINT * INTERVAL '1 second'),
    authority_generation = authority_generation + 1,
    version = version + 1,
    updated_at = pg_catalog.transaction_timestamp()
WHERE id = $1::BIGINT
  AND public_id = $2::UUID
  AND version = $3::BIGINT
  AND authority_generation = $4::BIGINT
  AND state = 'active'
  AND expires_at IS NOT NULL
  AND expires_at <= pg_catalog.transaction_timestamp()
RETURNING version, authority_generation, expires_at`

const renewRoleBindingSQL = `UPDATE mesh.role_binding
SET expires_at = pg_catalog.transaction_timestamp() + ($5::BIGINT * INTERVAL '1 second'),
    authority_generation = authority_generation + 1,
    version = version + 1,
    updated_at = pg_catalog.transaction_timestamp()
WHERE id = $1::BIGINT
  AND public_id = $2::UUID
  AND version = $3::BIGINT
  AND authority_generation = $4::BIGINT
  AND state = 'active'
  AND expires_at IS NOT NULL
  AND expires_at <= pg_catalog.transaction_timestamp()
RETURNING version, authority_generation, expires_at`

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

const appendRenewalEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'role_binding', $7::UUID, $8::BIGINT, $9::BIGINT, $10::UUID,
    'qualification.management_session.renewed', 'system.bootstrap',
    $11::UUID, $12::BYTEA, $13::BYTEA, $14::JSONB,
    'qualification.management_session.renewed', $15::JSONB
)`
