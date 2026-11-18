package postgres

const configureDeviceRevocationTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setDeviceRevocationScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const authorizeDeviceRevocationSQL = `SELECT
    COALESCE(role_binding_public_id::TEXT, ''),
    COALESCE(role_definition_public_id::TEXT, ''),
    scope_authority_generation,
    membership_authority_generation,
    binding_authority_generation,
    role_authority_generation,
    binding_expires_at IS NOT NULL,
    COALESCE(binding_expires_at, $13::TIMESTAMPTZ),
    workspace_owner_authority_generation
FROM mesh_ops.resolve_network_permission_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TEXT, $13::TIMESTAMPTZ
)
LIMIT 1`

const claimDeviceRevocationIdempotencySQL = `SELECT
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

const loadDeviceRevocationIdempotencySQL = `SELECT
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

const lockDeviceRevocationRevisionSQL = `SELECT *
FROM mesh_ops.lock_network_revision()`

// lockDeviceRevocationTargetSQL (schema 297, role isolation S2.2) locks the
// Device and its current key epochs through a definer, so the api needs no
// UPDATE on those tables to hold the lock.
const lockDeviceRevocationTargetSQL = `SELECT
    device_id, device_version, session_generation, device_state,
    machine_key_epoch, machine_key_id, machine_key_version, machine_key_state, machine_key_valid_from,
    node_key_epoch, node_key_id, node_key_version, node_key_state, node_key_valid_from
FROM mesh_ops.lock_device_revocation_target_v1($1::BIGINT, $2::BIGINT, $3::UUID)`

const lockDeviceRevocationAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const advanceDeviceRevocationRevisionSQL = `SELECT network_revision, inventory_revision
FROM mesh_ops.advance_network_inventory_revision()`

const appendDeviceRevocationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'device', $7::UUID, $8::BIGINT, $9::BIGINT, $10::UUID,
    'device.revoked', 'device.manage', $11::UUID, $12::BYTEA, $13::BYTEA,
    $14::JSONB, 'network.revision.advanced', $15::JSONB
)`

const completeDeviceRevocationIdempotencySQL = `SELECT
    mesh_ops.complete_network_idempotency(
        $1::UUID, $2::UUID, $3::TEXT, $4::TEXT, $5::BYTEA, $6::BYTEA,
        $7::TEXT, $8::UUID, $9::BIGINT, $10::BIGINT, $11::JSONB,
        $12::UUID, $13::TIMESTAMPTZ
    )::TEXT`

// deviceActorWithinCeilingSQL (schema 295, TD-SEC-87) reports whether the
// actor may act on the locked Device given who owns it: the Workspace owner's
// only the owner, another member's only within the ceiling over their roles.
const deviceActorWithinCeilingSQL = `SELECT mesh_ops.device_actor_within_ceiling_v1(
    $1::BIGINT, $2::BIGINT, $3::BIGINT, $4::UUID, $5::TIMESTAMPTZ)`

// revokeDeviceFunctionSQL (schema 296, role isolation S3) revokes the locked
// Device and its current key epochs and quarantines its leases, after
// checking device.manage and the owner's ceiling inside the database.
const revokeDeviceFunctionSQL = `SELECT device_version, session_generation, machine_key_version, node_key_version,
    quarantined_leases
FROM mesh_ops.revoke_device_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::UUID, $13::BIGINT, $14::BIGINT, $15::BIGINT, $16::BIGINT, $17::BIGINT, $18::BIGINT,
    $19::TEXT, $20::UUID, $21::TIMESTAMPTZ
)`
