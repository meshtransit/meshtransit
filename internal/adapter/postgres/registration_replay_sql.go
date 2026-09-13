package postgres

const setRegistrationReplayScopeSQL = `SELECT *
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const loadRegistrationReplaySQL = `SELECT
    registration.intent_format_version,
    registration.state,
    registration.request_hash,
    registration.machine_key_fingerprint,
    registration.requested_node_key,
    credential.public_id::TEXT,
    device.public_id::TEXT,
    registration.completed_hostname,
    registration.completed_disposition,
    registration.completed_network_revision
FROM mesh.pending_registration AS registration
JOIN mesh.enrollment_credential AS credential
  ON credential.workspace_id = registration.workspace_id
 AND credential.network_id = registration.network_id
 AND credential.id = registration.enrollment_credential_id
LEFT JOIN mesh.device AS device
  ON device.workspace_id = registration.workspace_id
 AND device.network_id = registration.network_id
 AND device.id = registration.device_id
WHERE registration.public_id = $1::UUID`
