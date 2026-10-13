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

// registrationHostnamesTakenSQL returns which of the candidate hostnames ($3)
// a live Device of the Network other than the registering one ($4) holds,
// one probe of the Network's hostname unique index per candidate. With
// current statistics the cost does not grow with the Network. A Workspace
// created after mesh.device was last analyzed is rated at about one row,
// and the planner may then probe another Workspace-led index and filter the
// Workspace's Devices until autovacuum analyzes the table again.
const registrationHostnamesTakenSQL = `SELECT probe.hostname_key
FROM pg_catalog.unnest($3::TEXT[]) AS candidate(hostname_key)
CROSS JOIN LATERAL (
    SELECT device.hostname_key
    FROM mesh.device AS device
    WHERE device.workspace_id = $1::BIGINT
      AND device.network_id = $2::BIGINT
      AND device.hostname_key = candidate.hostname_key
      AND device.deleted_at IS NULL
      AND ($4::BIGINT IS NULL OR device.id <> $4::BIGINT)
    LIMIT 1
) AS probe`

const lockRegistrationPrefixesSQL = `SELECT *
FROM mesh_ops.lock_registration_prefixes($1::BIGINT)`

// reclaimableLeasePredicate matches a lease (joined with its Device as
// device) whose address may be given to a new Device: its quarantine has
// ended, or it still belongs to a Device revoked before schema 143 at least
// one quarantine interval ago. Such a lease is not live for allocation and
// is released when its address is reused (releaseReclaimedRegistrationLeaseSQL).
// The allocator queries left-join only revoked Devices (revokedDeviceJoin),
// so device.id IS NOT NULL keeps the predicate false, never NULL, for the
// rest.
const reclaimableLeasePredicate = `(lease.state = 'quarantined'
        AND lease.quarantine_until <= pg_catalog.clock_timestamp())
    OR (lease.state = 'active' AND device.id IS NOT NULL AND device.state = 'revoked'
        AND device.updated_at + mesh_ops.node_address_quarantine_v1() <= pg_catalog.clock_timestamp())`

// revokedDeviceJoin joins a lease to its Device only when that Device is
// revoked, so a large prefix does not look up every live lease's Device.
const revokedDeviceJoin = `LEFT JOIN mesh.device AS device
  ON device.id = lease.device_id AND device.state = 'revoked'`

// releaseReclaimedRegistrationLeaseSQL releases the reclaimable lease, if any,
// that holds the address a new Device is about to take, so the live-address
// unique index admits the new lease. It runs in the registering transaction,
// whose evidence and Network revision cover the release.
const releaseReclaimedRegistrationLeaseSQL = `UPDATE mesh.node_address_lease AS lease
SET state = 'released',
    released_at = COALESCE(lease.released_at, GREATEST(device.updated_at, lease.updated_at)),
    quarantine_until = NULL,
    version = lease.version + 1,
    updated_at = GREATEST($3::TIMESTAMPTZ, lease.updated_at)
FROM mesh.device AS device
WHERE device.id = lease.device_id
  AND lease.network_prefix_id = $1::BIGINT
  AND lease.address = $2::INET
  AND (` + reclaimableLeasePredicate + `)`

// loadRegistrationLeasesSQL reads one window of a prefix's live leases in
// address order from $3, through the prefix's live-address index. A lease
// that is active for a revoked Device (before schema 143) is live until it is
// reclaimable but does not settle the address floor (schema 157).
const loadRegistrationLeasesSQL = `SELECT
    lease.network_prefix_id,
    lease.device_id,
    pg_catalog.host(lease.address),
    lease.family,
    lease.lease_role,
    lease.state,
    (lease.state = 'active' AND device.id IS NOT NULL)
FROM mesh.node_address_lease AS lease
` + revokedDeviceJoin + `
WHERE lease.network_prefix_id = $1::BIGINT
  AND lease.state IN ('active', 'quarantined')
  AND NOT (` + reclaimableLeasePredicate + `)
  AND lease.address >= $3::INET
ORDER BY lease.network_prefix_id, lease.address, lease.id
LIMIT $2::BIGINT`

// lockRegistrationAddressFloorSQL locks a prefix's address floor (schema
// 157): every address from the prefix's first host up to the floor is held
// by a settled lease, so the lowest free address below it is a lease whose
// quarantine ended. The caller holds the prefix's allocator lock.
const lockRegistrationAddressFloorSQL = `SELECT
    pg_catalog.host(address_floor.floor_address),
    address_floor.prefix::TEXT
FROM mesh_ops.registration_address_floor AS address_floor
WHERE address_floor.network_prefix_id = $1::BIGINT
FOR UPDATE`

// insertRegistrationAddressFloorSQL creates a prefix's floor at its first
// host ($5) when it has none; the caller then locks it.
const insertRegistrationAddressFloorSQL = `INSERT INTO mesh_ops.registration_address_floor (
    workspace_id,
    network_id,
    network_prefix_id,
    prefix,
    floor_address
) VALUES ($1::BIGINT, $2::BIGINT, $3::BIGINT, $4::CIDR, $5::INET)
ON CONFLICT (network_prefix_id) DO NOTHING`

// storeRegistrationAddressFloorSQL raises a locked prefix's floor past the
// addresses this transaction found settled, including the one it leased.
const storeRegistrationAddressFloorSQL = `UPDATE mesh_ops.registration_address_floor AS address_floor
SET floor_address = $2::INET,
    prefix = $3::CIDR
WHERE address_floor.network_prefix_id = $1::BIGINT`

// lowestReclaimableRegistrationAddressSQL finds the lowest address in
// [$2, $3) whose lease's quarantine has ended, through the prefix's
// quarantine index. Below the floor these are the only free addresses.
const lowestReclaimableRegistrationAddressSQL = `SELECT pg_catalog.host(lease.address)
FROM mesh.node_address_lease AS lease
WHERE lease.network_prefix_id = $1::BIGINT
  AND lease.state = 'quarantined'
  AND lease.address >= $2::INET
  AND lease.address < $3::INET
  AND lease.quarantine_until <= pg_catalog.clock_timestamp()
ORDER BY lease.address
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
