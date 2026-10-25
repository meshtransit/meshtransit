package postgres

const configureNodeKeyRotationTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const resolveNodeKeyRotationScopeSQL = `SELECT
    workspace_public_id::TEXT,
    network_public_id::TEXT
FROM mesh_ops.resolve_node_key_rotation_scope(
    $1::BYTEA, $2::BYTEA, $3::BYTEA, $4::BYTEA
)`

const setNodeKeyRotationScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const lockNodeKeyRotationRevisionSQL = `SELECT *
FROM mesh_ops.lock_network_revision()`

const lockNodeKeyRotationTargetSQL = `SELECT
    device.id,
    device.public_id::TEXT,
    device.hostname,
    device.version,
    device.session_generation,
    device.current_node_key_epoch,
    machine_key.public_key,
    node_key.id,
    node_key.version,
    node_key.public_key,
    node_key.valid_from,
    device.kind = 'kubernetes_gateway'
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
  AND machine_key.fingerprint = $3::BYTEA
  AND machine_key.public_key = $4::BYTEA
  AND machine_key.state = 'active'
  AND node_key.state = 'active'
  AND device.state = 'active'
  AND device.deleted_at IS NULL
  AND device.expires_at > pg_catalog.transaction_timestamp()
FOR UPDATE OF device, machine_key, node_key`

// readNodeKeyRotationBudgetSQL reads when an earlier key epoch began. It
// runs under the Device lock, which orders every key change of the Device,
// so the rotation budget holds across replicas.
const readNodeKeyRotationBudgetSQL = `SELECT valid_from
FROM mesh.device_node_key_epoch
WHERE workspace_id = $1::BIGINT
  AND network_id = $2::BIGINT
  AND device_id = $3::BIGINT
  AND epoch = $4::BIGINT`

const lockNodeKeyRotationReplaySQL = `SELECT
    previous.public_key,
    current.rotation_proof_hash,
    previous.state,
    previous.valid_until
FROM mesh.device_node_key_epoch AS previous
JOIN mesh.device_node_key_epoch AS current
  ON current.workspace_id = previous.workspace_id
 AND current.network_id = previous.network_id
 AND current.device_id = previous.device_id
 AND current.epoch = previous.epoch + 1
WHERE previous.workspace_id = $1::BIGINT
  AND previous.network_id = $2::BIGINT
  AND previous.device_id = $3::BIGINT
  AND previous.epoch = $4::BIGINT - 1
  AND current.epoch = $4::BIGINT
FOR UPDATE OF previous, current`

const lockNodeKeyRotationAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const setNodeKeyRotationChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const expireNodeKeyRotationEpochSQL = `UPDATE mesh.device_node_key_epoch AS key_epoch
SET valid_until = $8::TIMESTAMPTZ,
    state = 'expired',
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

const insertNodeKeyRotationEpochSQL = `INSERT INTO mesh.device_node_key_epoch (
    public_id, workspace_id, network_id, device_id, epoch,
    public_key, fingerprint, valid_from, rotation_proof_hash,
    state, created_at, updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, $5::BIGINT,
    $6::BYTEA, $7::BYTEA, $8::TIMESTAMPTZ, $9::BYTEA,
    'active', $8::TIMESTAMPTZ, $8::TIMESTAMPTZ
)
RETURNING version`

const rotateDeviceNodeKeySQL = `UPDATE mesh.device AS device
SET current_node_key_epoch = $7::BIGINT,
    session_generation = device.session_generation + 1,
    version = device.version + 1,
    updated_at = $8::TIMESTAMPTZ
WHERE device.id = $1::BIGINT
  AND device.workspace_id = $2::BIGINT
  AND device.network_id = $3::BIGINT
  AND device.public_id = $4::UUID
  AND device.version = $5::BIGINT
  AND device.session_generation = $6::BIGINT
  AND device.current_node_key_epoch = $7::BIGINT - 1
  AND device.state = 'active'
RETURNING device.version, device.session_generation, device.current_node_key_epoch`

const advanceNodeKeyRotationRevisionSQL = `SELECT network_revision, inventory_revision
FROM mesh_ops.advance_network_inventory_revision()`

const appendNodeKeyRotationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'device', $7::UUID, $8::BIGINT, $9::BIGINT, NULL::UUID,
    'device.node_key_rotated', 'device.node_key.rotate', $10::UUID,
    $11::BYTEA, $12::BYTEA, $13::JSONB,
    'network.revision.advanced', $14::JSONB
)`
