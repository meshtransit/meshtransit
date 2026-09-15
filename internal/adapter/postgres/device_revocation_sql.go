package postgres

const configureDeviceRevocationTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setDeviceRevocationScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

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

const lockDeviceRevocationTargetSQL = `SELECT
    device.id,
    device.version,
    device.session_generation,
    device.state,
    device.current_machine_key_epoch,
    machine_key.id,
    machine_key.version,
    machine_key.state,
    machine_key.valid_from,
    device.current_node_key_epoch,
    node_key.id,
    node_key.version,
    node_key.state,
    node_key.valid_from
FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS machine_key
  ON machine_key.workspace_id = device.workspace_id
 AND machine_key.network_id = device.network_id
 AND machine_key.device_id = device.id
 AND machine_key.epoch = device.current_machine_key_epoch
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.workspace_id = device.workspace_id
 AND node_key.network_id = device.network_id
 AND node_key.device_id = device.id
 AND node_key.epoch = device.current_node_key_epoch
WHERE device.workspace_id = $1::BIGINT
  AND device.network_id = $2::BIGINT
  AND device.public_id = $3::UUID
FOR UPDATE OF device, machine_key, node_key`

const lockDeviceRevocationAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const setDeviceRevocationChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const revokeDeviceSQL = `UPDATE mesh.device AS device
SET state = 'revoked',
    session_generation = device.session_generation + 1,
    version = device.version + 1,
    updated_at = $7::TIMESTAMPTZ
WHERE device.id = $1::BIGINT
  AND device.workspace_id = $2::BIGINT
  AND device.network_id = $3::BIGINT
  AND device.public_id = $4::UUID
  AND device.version = $5::BIGINT
  AND device.session_generation = $6::BIGINT
  AND device.state = 'active'
RETURNING device.version, device.session_generation`

const revokeMachineKeyEpochSQL = `UPDATE mesh.device_machine_key_epoch AS key_epoch
SET valid_until = $8::TIMESTAMPTZ,
    revocation_reason = $9::TEXT,
    state = 'revoked',
    version = key_epoch.version + 1,
    updated_at = $8::TIMESTAMPTZ
WHERE key_epoch.id = $1::BIGINT
  AND key_epoch.workspace_id = $2::BIGINT
  AND key_epoch.network_id = $3::BIGINT
  AND key_epoch.device_id = $4::BIGINT
  AND key_epoch.epoch = $5::BIGINT
  AND key_epoch.version = $6::BIGINT
  AND key_epoch.state = 'active'
  AND key_epoch.valid_from <= $7::TIMESTAMPTZ
  AND key_epoch.valid_until IS NULL
RETURNING key_epoch.version`

const revokeNodeKeyEpochSQL = `UPDATE mesh.device_node_key_epoch AS key_epoch
SET valid_until = $8::TIMESTAMPTZ,
    revocation_reason = $9::TEXT,
    state = 'revoked',
    version = key_epoch.version + 1,
    updated_at = $8::TIMESTAMPTZ
WHERE key_epoch.id = $1::BIGINT
  AND key_epoch.workspace_id = $2::BIGINT
  AND key_epoch.network_id = $3::BIGINT
  AND key_epoch.device_id = $4::BIGINT
  AND key_epoch.epoch = $5::BIGINT
  AND key_epoch.version = $6::BIGINT
  AND key_epoch.state = 'active'
  AND key_epoch.valid_from <= $7::TIMESTAMPTZ
  AND key_epoch.valid_until IS NULL
RETURNING key_epoch.version`

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
