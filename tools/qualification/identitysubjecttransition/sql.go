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

const loadActiveSourceSubjectsSQL = `SELECT
    subject.id,
    subject.public_id::TEXT,
    principal.public_id::TEXT,
    subject.subject_digest_algorithm,
    subject.subject_digest_key_id,
    subject.subject_digest,
    subject.claims_revision,
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

const targetCollisionSQL = `WITH target(principal_public_id, digest) AS (
    SELECT
        ($3::UUID[])[ordinal],
        ($4::BYTEA[])[ordinal]
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

const loadOpenAuthTransactionIDsSQL = `SELECT id
FROM mesh.auth_transaction
WHERE deployment_id = $1::BIGINT
  AND identity_provider_id = $2::BIGINT
  AND state IN ('pending', 'consuming')
ORDER BY id
LIMIT $3::BIGINT`
