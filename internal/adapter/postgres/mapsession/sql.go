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

// loadPacketPolicySQL reads the Device's edges of the active release:
// Device-to-Device rules plus group rules resolved from current membership
// (schema 120), each only while both ends are live. One row with null rule
// columns means the release exists and gives this Device nothing.
const loadPacketPolicySQL = `WITH release AS (
    SELECT release.id, release.workspace_id, release.network_id, release.policy_revision
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = mesh_ops.current_workspace_id()
      AND release.network_id = mesh_ops.current_network_id()
      AND release.policy_revision = $2::BIGINT
      AND release.state = 'active'
),
edge AS (
    SELECT rule.id AS ordinal, rule.access_rule_public_id, rule.source_device_id,
           rule.destination_device_id, rule.protocol, rule.destination_ports
    FROM release
    JOIN mesh.compiled_policy_rule AS rule
      ON rule.workspace_id = release.workspace_id
     AND rule.network_id = release.network_id
     AND rule.policy_release_id = release.id
     AND rule.policy_revision = release.policy_revision
     AND (rule.source_device_id = $1::BIGINT OR rule.destination_device_id = $1::BIGINT)
    UNION ALL
    SELECT 0, grouped.access_rule_public_id, grouped.source_device_id,
           grouped.destination_device_id, grouped.protocol, grouped.destination_ports
    FROM release
    CROSS JOIN LATERAL mesh_ops.resolve_group_policy_edges_v1($1::BIGINT) AS grouped
),
live_edge AS (
    SELECT edge.*
    FROM edge
    JOIN release ON TRUE
    WHERE EXISTS (
        SELECT 1 FROM mesh.device AS live_source
        WHERE live_source.workspace_id = release.workspace_id
          AND live_source.network_id = release.network_id
          AND live_source.id = edge.source_device_id
          AND live_source.state = 'active'
          AND live_source.deleted_at IS NULL
          AND live_source.expires_at > pg_catalog.transaction_timestamp()
    ) AND EXISTS (
        SELECT 1 FROM mesh.device AS live_destination
        WHERE live_destination.workspace_id = release.workspace_id
          AND live_destination.network_id = release.network_id
          AND live_destination.id = edge.destination_device_id
          AND live_destination.state = 'active'
          AND live_destination.deleted_at IS NULL
          AND live_destination.expires_at > pg_catalog.transaction_timestamp()
    )
)
SELECT
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
FROM release
LEFT JOIN live_edge AS rule ON TRUE
LEFT JOIN mesh.device AS source
  ON source.workspace_id = release.workspace_id
 AND source.network_id = release.network_id
 AND source.id = rule.source_device_id
LEFT JOIN mesh.device AS destination
  ON destination.workspace_id = release.workspace_id
 AND destination.network_id = release.network_id
 AND destination.id = rule.destination_device_id
ORDER BY rule.access_rule_public_id, rule.source_device_id, rule.destination_device_id, rule.ordinal
LIMIT $3::INTEGER`
