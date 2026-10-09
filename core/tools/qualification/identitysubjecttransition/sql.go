package main

const configurePlanSQL = `SELECT
    pg_catalog.set_config('statement_timeout', '5s', TRUE),
    pg_catalog.set_config('lock_timeout', '2s', TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', '10s', TRUE)`

const loadAuthorityStateSQL = `SELECT
    deployment.id,
    deployment.profile,
    deployment.recovery_state,
    deployment.state,
    actor.id,
    actor.kind,
    actor.state,
    source.id,
    source.issuer,
    source.protocol,
    source.authority_kind,
    source.current_generation,
    source.recovery_state,
    source.state,
    source.version,
    source_generation.generation,
    source_generation.trust_configuration_semantic_hash,
    source_generation.recovery_mode,
    source_generation.valid_until,
    source_generation.state,
    source_generation.version,
    target.id,
    target.issuer,
    target.protocol,
    target.authority_kind,
    target.current_generation,
    target.recovery_state,
    target.state,
    target.version,
    target_generation.generation,
    target_generation.trust_configuration_semantic_hash,
    target_generation.recovery_mode,
    target_generation.valid_until,
    target_generation.state,
    target_generation.version
FROM mesh.deployment AS deployment
JOIN mesh.principal AS actor
  ON actor.deployment_id = deployment.id
JOIN mesh.identity_provider AS source
  ON source.deployment_id = deployment.id
JOIN mesh.identity_provider_generation AS source_generation
  ON source_generation.deployment_id = deployment.id
 AND source_generation.identity_provider_id = source.id
 AND source_generation.generation = source.current_generation
JOIN mesh.identity_provider AS target
  ON target.deployment_id = deployment.id
JOIN mesh.identity_provider_generation AS target_generation
  ON target_generation.deployment_id = deployment.id
 AND target_generation.identity_provider_id = target.id
 AND target_generation.generation = target.current_generation
WHERE deployment.installation_public_id = $1::UUID
  AND actor.public_id = $2::UUID
  AND source.public_id = $3::UUID
  AND target.public_id = $4::UUID`

const lockAuthorityStateSQL = loadAuthorityStateSQL + `
FOR UPDATE OF deployment, actor, source, source_generation, target, target_generation`

const lockSourceProviderFenceSQL = `SELECT source.id
FROM mesh.deployment AS deployment
JOIN mesh.identity_provider AS source
  ON source.deployment_id = deployment.id
WHERE deployment.installation_public_id = $1::UUID
  AND source.public_id = $2::UUID
FOR UPDATE OF source`

const lockApplyTablesSQL = `LOCK TABLE
    mesh.identity_subject,
    mesh.account_session,
    mesh.auth_transaction
IN SHARE ROW EXCLUSIVE MODE`

const loadActiveSourceSubjectsSQL = `SELECT
    subject.id,
    subject.public_id::TEXT,
    principal.id,
    principal.public_id::TEXT,
    subject.subject_digest_algorithm,
    subject.subject_digest_key_id,
    subject.subject_digest,
    subject.claims_revision,
    subject.last_seen_at,
    subject.version
FROM mesh.identity_subject AS subject
JOIN mesh.principal AS principal
  ON principal.deployment_id = subject.deployment_id
 AND principal.id = subject.principal_id
WHERE subject.deployment_id = $1::BIGINT
  AND subject.identity_provider_id = $2::BIGINT
  AND subject.state = 'active'
ORDER BY subject.id
LIMIT $3::BIGINT`

const targetCollisionSQL = `WITH target(principal_public_id, digest, target_public_id) AS (
    SELECT
        ($3::UUID[])[ordinal],
        ($4::BYTEA[])[ordinal],
        ($6::UUID[])[ordinal]
    FROM pg_catalog.generate_subscripts($3::UUID[], 1) AS ordinal
)
SELECT EXISTS (
    SELECT 1
    FROM mesh.identity_subject AS subject
    JOIN mesh.principal AS principal
      ON principal.deployment_id = subject.deployment_id
     AND principal.id = subject.principal_id
    JOIN target
      ON target.principal_public_id = principal.public_id
      OR subject.public_id = target.target_public_id
      OR (
          subject.subject_digest_algorithm = 'hmac-sha256-v1'
          AND subject.subject_digest_key_id = $5::TEXT
          AND subject.subject_digest = target.digest
      )
    WHERE subject.deployment_id = $1::BIGINT
      AND subject.identity_provider_id = $2::BIGINT
)`

const loadActiveSessionIDsSQL = `SELECT id
FROM mesh.account_session
WHERE deployment_id = $1::BIGINT
  AND identity_provider_id = $2::BIGINT
  AND state = 'active'
ORDER BY id
LIMIT $3::BIGINT`

const setApplyChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const suspendSourceProviderSQL = `UPDATE mesh.identity_provider
SET state = 'suspended',
    version = version + 1,
    updated_at = GREATEST(updated_at, pg_catalog.transaction_timestamp())
WHERE id = $1::BIGINT
  AND public_id = $2::UUID
  AND current_generation = $3::BIGINT
  AND recovery_state = 'verified'
  AND state = 'active'
  AND version = $4::BIGINT
RETURNING version`

const unlinkSourceSubjectSQL = `UPDATE mesh.identity_subject
SET state = 'unlinked',
    version = version + 1,
    updated_at = GREATEST(updated_at, pg_catalog.transaction_timestamp())
WHERE id = $1::BIGINT
  AND public_id = $2::UUID
  AND deployment_id = $3::BIGINT
  AND identity_provider_id = $4::BIGINT
  AND principal_id = $5::BIGINT
  AND subject_digest_algorithm = $6::TEXT
  AND subject_digest_key_id = $7::TEXT
  AND subject_digest = $8::BYTEA
  AND claims_revision = $9::BIGINT
  AND state = 'active'
  AND version = $10::BIGINT
RETURNING version`

const insertTargetSubjectSQL = `INSERT INTO mesh.identity_subject (
    public_id,
    deployment_id,
    identity_provider_id,
    principal_id,
    subject_digest_algorithm,
    subject_digest_key_id,
    subject_digest,
    claims_revision,
    last_seen_at,
    state
) VALUES (
    $1::UUID,
    $2::BIGINT,
    $3::BIGINT,
    $4::BIGINT,
    $5::TEXT,
    $6::TEXT,
    $7::BYTEA,
    $8::BIGINT,
    pg_catalog.transaction_timestamp(),
    'active'
)
RETURNING version`

const revokeSourceSessionsSQL = `UPDATE mesh.account_session
SET state = 'revoked',
    ended_at = pg_catalog.transaction_timestamp(),
    end_reason = 'identity_unlinked',
    version = version + 1,
    updated_at = GREATEST(updated_at, pg_catalog.transaction_timestamp())
WHERE deployment_id = $1::BIGINT
  AND identity_provider_id = $2::BIGINT
  AND state = 'active'`

const failSourceAuthTransactionsSQL = `UPDATE mesh.auth_transaction
SET state = 'failed',
    consumed_at = COALESCE(consumed_at, pg_catalog.transaction_timestamp()),
    consumed_result_kind = NULL,
    consumed_result_public_id = NULL,
    failure_class = 'provider_migrated',
    pkce_verifier_encryption_algorithm = NULL,
    pkce_verifier_encryption_key_id = NULL,
    pkce_verifier_ciphertext = NULL,
    version = version + 1,
    updated_at = GREATEST(updated_at, pg_catalog.transaction_timestamp())
WHERE deployment_id = $1::BIGINT
  AND identity_provider_id = $2::BIGINT
  AND state IN ('pending', 'consuming')`

const lockDeploymentAuditStreamSQL = `SELECT id, next_sequence, latest_event_hash
FROM mesh_audit.audit_stream
WHERE deployment_id = $1::BIGINT
  AND workspace_id IS NULL
  AND network_id IS NULL
  AND scope_kind = 'deployment'
FOR UPDATE`

const appendApplyEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
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
    'identity.subject_transition.applied',
    'identity_provider.manage',
    $10::UUID,
    $11::BYTEA,
    $12::BYTEA,
    $13::JSONB,
    'identity.subject_transition.applied',
    $14::JSONB
)`

const verifyApplyEvidenceSQL = `SELECT
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

const loadOpenAuthTransactionIDsSQL = `SELECT id
FROM mesh.auth_transaction
WHERE deployment_id = $1::BIGINT
  AND identity_provider_id = $2::BIGINT
  AND state IN ('pending', 'consuming')
ORDER BY id
LIMIT $3::BIGINT`
