package postgres

const configurePolicyPublicationTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setPolicyPublicationScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const lockPolicyPublicationRevisionSQL = `SELECT *
FROM mesh_ops.lock_network_revision()`

const lockActivePolicyReleaseSQL = `SELECT *
FROM mesh_ops.lock_active_policy_release()`

const lockPolicyPublicationAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const setPolicyPublicationChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const publishCompiledPolicySQL = `SELECT network_revision, policy_revision, release_version
FROM mesh_ops.publish_compiled_policy(
    $1::UUID,
    $2::BIGINT,
    $3::BYTEA,
    $4::INTEGER,
    $5::TIMESTAMPTZ,
    $6::JSONB
)`

const appendPolicyPublicationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'policy_release', $7::UUID, $8::BIGINT, $9::BIGINT, $10::UUID,
    $11::TEXT, 'policy.publish', $12::UUID, $13::BYTEA, $14::BYTEA,
    $15::JSONB, 'network.revision.advanced', $16::JSONB
)`

const loadCommittedPolicyReleaseSQL = `SELECT
    release.activated_network_revision,
    release.policy_revision,
    release.semantic_hash
FROM mesh.policy_release AS release
WHERE release.workspace_id = $1::BIGINT
  AND release.network_id = $2::BIGINT
  AND release.public_id = $3::UUID`
