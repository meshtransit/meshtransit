package main

const configureTransitionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', '5s', TRUE),
    pg_catalog.set_config('lock_timeout', '2s', TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', '10s', TRUE)`

const loadTransitionStateSQL = `SELECT
    deployment.id,
    deployment.profile,
    deployment.recovery_state,
    deployment.state,
    provider.id,
    provider.current_generation,
    provider.recovery_state,
    provider.state,
    provider.protocol,
    provider.authority_kind,
    provider.version,
    generation.id,
    generation.public_id::TEXT,
    generation.generation,
    generation.trust_configuration_semantic_hash,
    generation.recovery_mode,
    generation.valid_until,
    generation.state,
    generation.version,
    client.id,
    client.client_kind,
    client.allowed_flows,
    client.allowed_scopes,
    client.state,
    client.version,
    actor.id,
    actor.kind,
    actor.state,
    (
        SELECT pg_catalog.count(*)
        FROM mesh.workspace_identity_provider AS route
        WHERE route.deployment_id = deployment.id
          AND route.identity_provider_id = provider.id
          AND route.identity_provider_client_id = client.id
          AND route.state = 'active'
          AND route.deleted_at IS NULL
    )
FROM mesh.deployment AS deployment
JOIN mesh.identity_provider AS provider
  ON provider.deployment_id = deployment.id
JOIN mesh.identity_provider_generation AS generation
  ON generation.deployment_id = deployment.id
 AND generation.identity_provider_id = provider.id
 AND generation.generation = provider.current_generation
JOIN mesh.identity_provider_client AS client
  ON client.deployment_id = deployment.id
 AND client.identity_provider_id = provider.id
JOIN mesh.principal AS actor
  ON actor.deployment_id = deployment.id
WHERE deployment.installation_public_id = $1::UUID
  AND provider.public_id = $2::UUID
  AND client.public_id = $3::UUID
  AND actor.public_id = $4::UUID`

const lockTransitionStateSQL = loadTransitionStateSQL + `
FOR UPDATE OF deployment, provider, generation, client, actor`

const setTransitionChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const supersedeProviderGenerationSQL = `UPDATE mesh.identity_provider_generation
SET state = 'superseded',
    valid_until = pg_catalog.transaction_timestamp(),
    version = version + 1,
    updated_at = GREATEST(updated_at, pg_catalog.transaction_timestamp())
WHERE id = $1::BIGINT
  AND public_id = $2::UUID
  AND generation = $3::BIGINT
  AND state = 'current'
  AND valid_until IS NULL
  AND version = $4::BIGINT
RETURNING version`

const insertProviderGenerationSQL = `INSERT INTO mesh.identity_provider_generation (
    public_id,
    deployment_id,
    identity_provider_id,
    generation,
    trust_configuration_semantic_hash,
    recovery_mode,
    recovery_evidence_reference,
    valid_from,
    state
) VALUES (
    $1::UUID,
    $2::BIGINT,
    $3::BIGINT,
    $4::BIGINT,
    $5::BYTEA,
    'continuous',
    $6::TEXT,
    pg_catalog.transaction_timestamp(),
    'current'
)
RETURNING version`

const advanceProviderGenerationSQL = `UPDATE mesh.identity_provider
SET current_generation = current_generation + 1,
    version = version + 1,
    updated_at = GREATEST(updated_at, pg_catalog.transaction_timestamp())
WHERE id = $1::BIGINT
  AND public_id = $2::UUID
  AND current_generation = $3::BIGINT
  AND recovery_state = 'verified'
  AND state = 'active'
  AND version = $4::BIGINT
RETURNING current_generation, version`

const updateProviderClientScopesSQL = `UPDATE mesh.identity_provider_client
SET allowed_scopes = ARRAY['openid', 'federated:id']::TEXT[],
    version = version + 1,
    updated_at = GREATEST(updated_at, pg_catalog.transaction_timestamp())
WHERE id = $1::BIGINT
  AND public_id = $2::UUID
  AND allowed_scopes = ARRAY['openid']::TEXT[]
  AND state = 'active'
  AND deleted_at IS NULL
  AND version = $3::BIGINT
RETURNING version`

const lockDeploymentAuditStreamSQL = `SELECT id, next_sequence, latest_event_hash
FROM mesh_audit.audit_stream
WHERE deployment_id = $1::BIGINT
  AND workspace_id IS NULL
  AND network_id IS NULL
  AND scope_kind = 'deployment'
FOR UPDATE`

const appendTransitionEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT,
    $2::UUID,
    $3::UUID,
    $4::BIGINT,
    $5::BYTEA,
    $6::BYTEA,
    'identity_provider',
    $7::UUID,
    $8::BIGINT,
    NULL::BIGINT,
    $9::UUID,
    'identity.provider_client.scopes_changed',
    'identity.provider.configure',
    $10::UUID,
    $11::BYTEA,
    $12::BYTEA,
    $13::JSONB,
    'identity.provider_client.scopes_changed',
    $14::JSONB
)`

const verifyTransitionEvidenceSQL = `SELECT
    (SELECT pg_catalog.count(*)
     FROM mesh_audit.authority_mutation AS mutation
     WHERE mutation.change_public_id = $1::UUID
       AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT),
    (SELECT pg_catalog.count(*)
     FROM mesh_audit.audit_event_identity AS identity
     WHERE identity.change_public_id = $1::UUID
       AND identity.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT),
    (SELECT pg_catalog.count(*)
     FROM mesh_ops.outbox_event AS event
     WHERE event.change_public_id = $1::UUID
       AND event.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT)`
