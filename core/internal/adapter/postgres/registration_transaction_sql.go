package postgres

const configureRegistrationTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setRegistrationTransactionScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const lockRegistrationNetworkRevisionSQL = `SELECT *
FROM mesh_ops.lock_network_revision()`

const lockRegistrationEnrollmentAuthoritySQL = `SELECT *
FROM mesh_ops.lock_registration_credential($1::UUID)`

const lockRegistrationProfileSQL = `SELECT
    profile.id,
    profile.public_id::TEXT,
    profile.node_lifetime_seconds,
    profile.ephemeral_mode,
    profile.credential_use_policy,
    profile.credential_max_uses,
    profile.state,
    profile.version
FROM mesh.enrollment_profile AS profile
WHERE profile.id = $1::BIGINT
FOR UPDATE`

const lockPendingRegistrationSQL = `SELECT
    registration.id,
    registration.enrollment_profile_id,
    registration.enrollment_credential_id,
    registration.intent_format_version,
    registration.request_hash,
    registration.machine_key_fingerprint,
    registration.requested_node_key,
    registration.device_id,
    registration.completed_hostname,
    registration.completed_disposition,
    registration.completed_network_revision,
    registration.state,
    registration.version,
    registration.created_at,
    registration.expires_at
FROM mesh.pending_registration AS registration
WHERE registration.public_id = $1::UUID
FOR UPDATE`

const lockRegistrationDeviceSQL = `SELECT
    device.id,
    device.public_id::TEXT,
    device.enrollment_profile_id,
    device.hostname,
    device.version,
    machine.public_key,
    node_key.public_key,
    device.hostname_locked,
    device.ownership = 'workspace',
    device.expires_at
FROM mesh.device_machine_key_epoch AS machine
JOIN mesh.device AS device
  ON device.workspace_id = machine.workspace_id
 AND device.network_id = machine.network_id
 AND device.id = machine.device_id
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.workspace_id = device.workspace_id
 AND node_key.network_id = device.network_id
 AND node_key.device_id = device.id
 AND node_key.state = 'active'
WHERE machine.fingerprint = $1::BYTEA
  AND machine.state = 'active'
  AND device.state = 'active'
FOR UPDATE OF device, machine, node_key`

const lockCompletedRegistrationDeviceSQL = `SELECT device.public_id::TEXT
FROM mesh.device AS device
WHERE device.id = $1::BIGINT
FOR UPDATE`

const lockRegistrationAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const loadRegistrationHostnamesSQL = `SELECT device.hostname
FROM mesh.device AS device
WHERE device.deleted_at IS NULL
  AND ($1::BIGINT IS NULL OR device.id <> $1::BIGINT)
ORDER BY device.hostname_key, device.id
LIMIT $2::BIGINT`

const lockRegistrationPrefixesSQL = `SELECT *
FROM mesh_ops.lock_registration_prefixes($1::BIGINT)`

const loadRegistrationLeasesSQL = `SELECT
    lease.network_prefix_id,
    lease.device_id,
    pg_catalog.host(lease.address),
    lease.family,
    lease.lease_role,
    lease.state
FROM mesh.node_address_lease AS lease
WHERE lease.network_prefix_id = $1::BIGINT
  AND lease.state IN ('active', 'quarantined')
  AND lease.address >= $3::INET
ORDER BY lease.network_prefix_id, lease.address, lease.id
LIMIT $2::BIGINT`

// lowestFreeRegistrationAddressSQL finds the lowest address of a prefix that
// no live lease holds: the first host ($2) or the address after a live lease.
// Allocation searches from there, so a prefix may hold more Devices than one
// search window (the caller holds the allocator lock; the live-address unique
// index stays the final arbiter). The last address of each family is skipped
// because adding one to it overflows; it is never a host of a mesh prefix.
const lowestFreeRegistrationAddressSQL = `WITH live AS (
    SELECT lease.address
    FROM mesh.node_address_lease AS lease
    WHERE lease.network_prefix_id = $1::BIGINT
      AND lease.state IN ('active', 'quarantined')
)
SELECT pg_catalog.host(candidate.address)
FROM (
    SELECT $2::INET AS address
    UNION
    SELECT live.address + 1
    FROM live
    WHERE pg_catalog.host(live.address) NOT IN (
        '255.255.255.255', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    )
) AS candidate
WHERE NOT EXISTS (
    SELECT 1 FROM live WHERE live.address = candidate.address
)
ORDER BY candidate.address
LIMIT 1`

const lockRegistrationDeviceLeasesSQL = `SELECT lease.family
FROM mesh.node_address_lease AS lease
WHERE lease.device_id = $1::BIGINT
  AND lease.state = 'active'
  AND lease.lease_role = 'primary'
ORDER BY lease.family, lease.id
FOR UPDATE`

const setRegistrationChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const insertRegistrationDeviceSQL = `INSERT INTO mesh.device (
    public_id,
    workspace_id,
    network_id,
    enrollment_profile_id,
    owner_principal_id,
    custodian_principal_id,
    registered_by_kind,
    registered_by_credential_id,
    hostname,
    hostname_key,
    is_ephemeral,
    expires_at,
    state,
    created_at,
    updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, $5::BIGINT, $5::BIGINT,
    'credential', $6::BIGINT, $7::TEXT, $7::TEXT, $8::BOOLEAN,
    $9::TIMESTAMPTZ, 'active', $10::TIMESTAMPTZ, $10::TIMESTAMPTZ
)
RETURNING id, version`

const resumeRegistrationDeviceSQL = `UPDATE mesh.device
SET hostname = $2::TEXT,
    hostname_key = $2::TEXT,
    expires_at = $3::TIMESTAMPTZ,
    state = 'active',
    version = version + 1,
    updated_at = $4::TIMESTAMPTZ
WHERE id = $1::BIGINT
  AND version = $5::BIGINT
RETURNING version`

const insertRegistrationMachineKeySQL = `INSERT INTO mesh.device_machine_key_epoch (
    public_id, workspace_id, network_id, device_id, epoch,
    public_key, fingerprint, valid_from, state, created_at, updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, 1,
    $5::BYTEA, $6::BYTEA, $7::TIMESTAMPTZ, 'active', $7::TIMESTAMPTZ, $7::TIMESTAMPTZ
)`

const insertRegistrationNodeKeySQL = `INSERT INTO mesh.device_node_key_epoch (
    public_id, workspace_id, network_id, device_id, epoch,
    public_key, fingerprint, valid_from, state, created_at, updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, 1,
    $5::BYTEA, $6::BYTEA, $7::TIMESTAMPTZ, 'active', $7::TIMESTAMPTZ, $7::TIMESTAMPTZ
)`

const consumeRegistrationEnrollmentAuthoritySQL = `UPDATE mesh.enrollment_credential
SET used_count = $2::BIGINT,
    version = version + 1,
    updated_at = $3::TIMESTAMPTZ
WHERE id = $1::BIGINT
  AND used_count = $4::BIGINT
  AND version = $5::BIGINT`

const completePendingRegistrationSQL = `UPDATE mesh.pending_registration
SET device_id = $2::BIGINT,
    completed_hostname = $3::TEXT,
    completed_disposition = $4::TEXT,
    completed_network_revision = $5::BIGINT,
    state = 'completed',
    version = version + 1,
    updated_at = $6::TIMESTAMPTZ
WHERE id = $1::BIGINT
  AND state IN ('pending', 'authorized')
  AND version = $7::BIGINT`

const insertRegistrationCredentialUseSQL = `INSERT INTO mesh.enrollment_credential_use (
    public_id, workspace_id, network_id, enrollment_credential_id,
    pending_registration_id, device_id, machine_key_fingerprint, result,
    used_at, created_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    $5::BIGINT, $6::BIGINT, $7::BYTEA, $8::TEXT,
    $9::TIMESTAMPTZ, $9::TIMESTAMPTZ
)`

const insertRegistrationLeaseSQL = `INSERT INTO mesh.node_address_lease (
    public_id, workspace_id, network_id, address_realm_id, address_pool_id,
    network_prefix_id, device_id, address, family, generation, lease_role,
    state, created_at, updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, $5::BIGINT,
    $6::BIGINT, $7::BIGINT, $8::INET, $9::INTEGER, 1, 'primary',
    'active', $10::TIMESTAMPTZ, $10::TIMESTAMPTZ
)`

const advanceRegistrationRevisionSQL = `SELECT network_revision, inventory_revision
FROM mesh_ops.advance_network_inventory_revision()`

const appendRegistrationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'device', $7::UUID, $8::BIGINT, $9::BIGINT, $10::UUID,
    $11::TEXT, 'device.register', $12::UUID, NULL::BYTEA, $13::BYTEA,
    $14::JSONB, 'network.revision.advanced', $15::JSONB
)`
