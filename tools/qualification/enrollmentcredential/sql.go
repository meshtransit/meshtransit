package main

const configureIssueTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', '5s', TRUE),
    pg_catalog.set_config('lock_timeout', '2s', TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', '10s', TRUE)`

const setIssueScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const loadIssueScopeSQL = `SELECT
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
    revision.network_revision,
    profile.id,
    profile.created_by_principal_id,
    profile.state,
    profile.node_lifetime_seconds,
    profile.ephemeral_mode,
    profile.credential_use_policy,
    COALESCE(profile.credential_max_uses, 0),
    profile.version,
    profile.deleted_at IS NOT NULL
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
JOIN mesh.enrollment_profile AS profile
  ON profile.workspace_id = workspace.id
 AND profile.network_id = network.id
WHERE deployment.installation_public_id = $1::UUID
  AND workspace.public_id = $2::UUID
  AND network.public_id = $3::UUID
  AND profile.public_id = $4::UUID
  AND principal.public_id = $5::UUID`

const lockIssueScopeSQL = loadIssueScopeSQL + `
FOR UPDATE OF deployment, principal, workspace, network, revision, profile`

const countUsableEnrollmentAuthoritiesSQL = `SELECT pg_catalog.count(*)
FROM mesh.enrollment_credential AS credential
WHERE credential.workspace_id = $1::BIGINT
  AND credential.network_id = $2::BIGINT
  AND credential.enrollment_profile_id = $3::BIGINT
  AND credential.state = 'active'
  AND credential.deleted_at IS NULL
  AND credential.valid_from <= pg_catalog.transaction_timestamp()
  AND credential.expires_at > pg_catalog.transaction_timestamp()
  AND (
      credential.use_limit_kind = 'unlimited'
      OR credential.used_count < credential.max_uses
  )`

const loadIssueTimeSQL = `SELECT pg_catalog.transaction_timestamp()`

const setIssueChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const insertCredentialSQL = `INSERT INTO mesh.enrollment_credential (
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
) VALUES (
    $1::UUID,
    $2::BIGINT,
    $3::BIGINT,
    $4::BIGINT,
    $5::BIGINT,
    'hmac-sha256-v1',
    $6::TEXT,
    $7::BYTEA,
    $8::BYTEA,
    $9::BIGINT,
    'bounded',
    1,
    0,
    $10::TIMESTAMPTZ,
    $11::TIMESTAMPTZ,
    'active'
)
RETURNING version`

const lockIssueAuditStreamSQL = `SELECT id, next_sequence, latest_event_hash
FROM mesh_audit.audit_stream
WHERE deployment_id = $1::BIGINT
  AND workspace_id = $2::BIGINT
  AND network_id = $3::BIGINT
  AND scope_kind = 'network'
FOR UPDATE`

const appendIssueEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'enrollment_credential', $7::UUID, 1, $8::BIGINT, $9::UUID,
    'qualification.enrollment_credential.issued', 'system.bootstrap',
    NULL::UUID, NULL::BYTEA, $10::BYTEA, $11::JSONB,
    'qualification.enrollment_credential.issued', $12::JSONB
)`
