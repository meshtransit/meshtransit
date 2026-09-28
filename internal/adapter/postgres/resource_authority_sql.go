package postgres

const configureResourceAuthoritySQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setResourceAuthorityScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const authorizeResourceAuthoritySQL = `SELECT
    role_binding_public_id::TEXT,
    role_definition_public_id::TEXT,
    scope_authority_generation,
    membership_authority_generation,
    binding_authority_generation,
    role_authority_generation,
    binding_expires_at IS NOT NULL,
    COALESCE(binding_expires_at, $13::TIMESTAMPTZ)
FROM mesh_ops.resolve_network_permission_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TEXT, $13::TIMESTAMPTZ
)
LIMIT 1`

const claimResourceAuthorityIdempotencySQL = `SELECT
    record_public_id::TEXT,
    stored_request_semantic_hash,
    record_state,
    COALESCE(result_kind, ''),
    COALESCE(result_public_id::TEXT, ''),
    COALESCE(result_version, 0),
    COALESCE(result_network_revision, 0),
    COALESCE(result_payload, '{}'::JSONB)::TEXT,
    record_expires_at,
    created
FROM mesh_ops.claim_network_idempotency(
    $1::UUID, $2::UUID, $3::TEXT, $4::TEXT, $5::BYTEA, $6::BYTEA,
    $7::TIMESTAMPTZ, $8::TIMESTAMPTZ
)`

const loadResourceAuthorityIdempotencySQL = `SELECT
    record_public_id::TEXT,
    stored_request_semantic_hash,
    record_state,
    COALESCE(result_kind, ''),
    COALESCE(result_public_id::TEXT, ''),
    COALESCE(result_version, 0),
    COALESCE(result_network_revision, 0),
    COALESCE(result_payload, '{}'::JSONB)::TEXT,
    record_expires_at
FROM mesh_ops.load_network_idempotency($1::UUID, $2::TEXT, $3::TEXT, $4::BYTEA)`

const lockResourceAuthorityRevisionSQL = `SELECT * FROM mesh_ops.lock_network_revision()`

const lockResourceAuthorityAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const setResourceAuthorityChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id', $1::TEXT, TRUE
)`

const createDeviceResourceSQL = `SELECT
    network_revision, inventory_revision, resource_version, target_generation
FROM mesh_ops.create_device_resource_v1(
    $1::UUID, $2::UUID, $3::BIGINT, $4::UUID, $5::UUID,
    $6::TEXT, $7::BYTEA, $8::TIMESTAMPTZ
)`

const createResourceGroupSQL = `SELECT
    network_revision, group_revision, group_version, definition_version
FROM mesh_ops.create_resource_group_v1(
    $1::UUID, $2::UUID, $3::BIGINT, $4::UUID,
    $5::TEXT, $6::BYTEA, $7::TIMESTAMPTZ, $8::JSONB
)`

const appendResourceAuthorityEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    $7::TEXT, $8::UUID, $9::BIGINT, $10::BIGINT, $11::UUID,
    $12::TEXT, $13::TEXT, $14::UUID, $15::BYTEA, $16::BYTEA,
    $17::JSONB, $18::TEXT, $19::JSONB
)`

const completeResourceAuthorityIdempotencySQL = `SELECT
    mesh_ops.complete_network_idempotency(
        $1::UUID, $2::UUID, $3::TEXT, $4::TEXT, $5::BYTEA, $6::BYTEA,
        $7::TEXT, $8::UUID, $9::BIGINT, $10::BIGINT, $11::JSONB,
        $12::UUID, $13::TIMESTAMPTZ
    )::TEXT`

//nolint:unused // Retained for compatibility with the M1 stable-aggregate resolver.
const resolveCommittedDeviceResourceSQL = `SELECT *
FROM mesh_ops.resolve_resource_v1($1::UUID)`

//nolint:unused // Retained for compatibility with the M1 stable-aggregate resolver.
const resolveCommittedResourceGroupSQL = `SELECT *
FROM mesh_ops.resolve_resource_group_v1($1::UUID)`
