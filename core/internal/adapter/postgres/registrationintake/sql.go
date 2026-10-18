package registrationintake

const configureTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const resolveScopeSQL = `SELECT
    deployment_public_id::TEXT,
    workspace_public_id::TEXT,
    network_public_id::TEXT,
    recovery_epoch
FROM mesh_ops.resolve_registration_intake_scope($1::UUID)`

const setScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const lockIntentsSQL = `SELECT
    registration.id,
    registration.public_id::TEXT,
    registration.enrollment_credential_id,
    registration.intent_format_version,
    registration.request_hash,
    registration.machine_key_fingerprint,
    registration.requested_node_key,
    registration.state,
    registration.version
FROM mesh.pending_registration AS registration
JOIN mesh.enrollment_credential AS credential
  ON credential.workspace_id = registration.workspace_id
 AND credential.network_id = registration.network_id
 AND credential.id = registration.enrollment_credential_id
WHERE registration.public_id = $1::UUID
   OR (
       registration.machine_key_fingerprint = $2::BYTEA
       AND (
           registration.state IN ('pending', 'authorized')
           OR (
               registration.state = 'completed'
               AND credential.public_id = $3::UUID
               AND registration.requested_node_key = $4::BYTEA
           )
       )
   )
ORDER BY
    CASE
        WHEN registration.public_id = $1::UUID THEN 0
        WHEN registration.state IN ('pending', 'authorized') THEN 1
        ELSE 2
    END,
    registration.id DESC
LIMIT 3
FOR UPDATE OF registration`

const lockRevisionSQL = `SELECT *
FROM mesh_ops.lock_network_revision()`

const lockEnrollmentAuthoritySQL = `SELECT *
FROM mesh_ops.lock_registration_credential($1::UUID)`

const loadDigestSQL = `SELECT
    credential.digest_algorithm,
    credential.digest_key_id,
    credential.token_digest,
    credential.token_fingerprint
FROM mesh.enrollment_credential AS credential
WHERE credential.public_id = $1::UUID`

// lockProfileSQL also reads the Device lifetime the Network chose (schema 179).
const lockProfileSQL = `SELECT
    profile.id,
    profile.public_id::TEXT,
    profile.node_lifetime_seconds,
    profile.ephemeral_mode,
    profile.credential_use_policy,
    profile.credential_max_uses,
    profile.state,
    profile.version,
    profile.name_key,
    profile.device_lifetime_seconds,
    profile.device_never_expires
FROM mesh.enrollment_profile AS profile
WHERE profile.id = $1::BIGINT
FOR UPDATE`

const lockAuditHeadSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const setChangeIDSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const insertIntentSQL = `INSERT INTO mesh.pending_registration (
    public_id,
    workspace_id,
    network_id,
    enrollment_profile_id,
    authorization_kind,
    enrollment_credential_id,
    machine_key_fingerprint,
    expires_at,
    state,
    intent_format_version,
    request_hash,
    requested_node_key,
    created_at,
    updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, $5::TEXT, $6::BIGINT,
    $7::BYTEA, $8::TIMESTAMPTZ, 'pending', 2, $9::BYTEA, $10::BYTEA,
    $11::TIMESTAMPTZ, $12::TIMESTAMPTZ
)
RETURNING id, version`

const appendEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    $7::TEXT, $8::UUID, $9::BIGINT, $10::BIGINT, $11::UUID,
    $12::TEXT, $13::TEXT, $14::UUID, NULL::BYTEA, $15::BYTEA,
    $16::JSONB, $17::TEXT, $18::JSONB
)`

const loadPreparedIntentSQL = `SELECT
    registration.request_hash,
    credential.public_id::TEXT,
    registration.machine_key_fingerprint,
    registration.requested_node_key,
    registration.intent_format_version,
    registration.state,
    registration.version
FROM mesh.pending_registration AS registration
JOIN mesh.enrollment_credential AS credential
  ON credential.workspace_id = registration.workspace_id
 AND credential.network_id = registration.network_id
 AND credential.id = registration.enrollment_credential_id
WHERE registration.public_id = $1::UUID`
