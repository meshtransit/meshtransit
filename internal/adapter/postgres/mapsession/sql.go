package mapsession

const configureTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $2, TRUE)`

const resolveScopeSQL = `SELECT
    workspace_public_id::TEXT,
    network_public_id::TEXT,
    recovery_epoch
FROM mesh_ops.resolve_map_session_scope($1::BYTEA, $2::BYTEA)`

const setScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const loadSnapshotSQL = `SELECT
    device.id,
    device.owner_principal_id,
    network.display_name,
    device.public_id::TEXT,
    device.hostname,
    machine.public_key,
    node_key.public_key,
    device.session_generation,
    device.created_at,
	device.expires_at,
	revision.network_revision,
	revision.policy_revision,
	ARRAY(
        SELECT lease.address::TEXT
        FROM mesh.node_address_lease AS lease
        WHERE lease.workspace_id = device.workspace_id
          AND lease.network_id = device.network_id
          AND lease.device_id = device.id
          AND lease.state = 'active'
          AND lease.lease_role = 'primary'
        ORDER BY lease.family, lease.address, lease.id
    )
FROM mesh.device AS device
JOIN mesh.network AS network
  ON network.workspace_id = device.workspace_id
 AND network.id = device.network_id
JOIN mesh.device_machine_key_epoch AS machine
  ON machine.workspace_id = device.workspace_id
 AND machine.network_id = device.network_id
 AND machine.device_id = device.id
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.workspace_id = device.workspace_id
 AND node_key.network_id = device.network_id
 AND node_key.device_id = device.id
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = device.workspace_id
 AND revision.network_id = device.network_id
WHERE machine.fingerprint = $1::BYTEA
  AND machine.state = 'active'
  AND machine.epoch = device.current_machine_key_epoch
  AND node_key.public_key = $2::BYTEA
  AND node_key.state = 'active'
  AND node_key.epoch = device.current_node_key_epoch
  AND network.state = 'active'
  AND network.deleted_at IS NULL
  AND device.state = 'active'
  AND device.deleted_at IS NULL
  AND device.expires_at > pg_catalog.transaction_timestamp()`

const loadPeerCandidatesSQL = `SELECT
    numeric_node_id,
    numeric_owner_id,
    node_public_id::TEXT,
    owner_public_id::TEXT,
    hostname,
    machine_key,
    node_key,
    session_generation,
    created_at,
    key_expiry,
    addresses
FROM mesh_ops.load_map_peer_candidates_v2($1::BYTEA, $2::BYTEA, $3::INTEGER)`

const loadPacketPolicySQL = `SELECT
    release.policy_revision,
    rule.access_rule_public_id::TEXT,
    source.public_id::TEXT,
    destination.public_id::TEXT,
    rule.protocol,
    ARRAY(
        SELECT pg_catalog.lower(port_range)::INTEGER
        FROM pg_catalog.unnest(rule.destination_ports) AS port_range
        ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
    ),
    ARRAY(
        SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
        FROM pg_catalog.unnest(rule.destination_ports) AS port_range
        ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
    )
FROM mesh.policy_release AS release
LEFT JOIN mesh.compiled_policy_rule AS rule
  ON rule.workspace_id = release.workspace_id
 AND rule.network_id = release.network_id
 AND rule.policy_release_id = release.id
 AND rule.policy_revision = release.policy_revision
 AND (rule.source_device_id = $1::BIGINT OR rule.destination_device_id = $1::BIGINT)
LEFT JOIN mesh.device AS source
  ON source.workspace_id = rule.workspace_id
 AND source.network_id = rule.network_id
 AND source.id = rule.source_device_id
LEFT JOIN mesh.device AS destination
  ON destination.workspace_id = rule.workspace_id
 AND destination.network_id = rule.network_id
 AND destination.id = rule.destination_device_id
WHERE release.workspace_id = mesh_ops.current_workspace_id()
  AND release.network_id = mesh_ops.current_network_id()
  AND release.policy_revision = $2::BIGINT
  AND release.state = 'active'
ORDER BY rule.access_rule_public_id, rule.source_device_id, rule.destination_device_id, rule.id
LIMIT $3::INTEGER`
