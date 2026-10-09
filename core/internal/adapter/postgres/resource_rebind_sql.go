package postgres

const previewResourceRebindImpactSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, resource_state,
    resource_version, current_target_generation, current_semantic_hash,
    current_device_public_id::TEXT, proposed_device_public_id::TEXT,
    proposed_device_state, proposed_device_already_bound,
    affected_resource_group_ids, approval_required
FROM mesh_ops.preview_device_resource_rebind_v1($1::UUID, $2::UUID)`

const lockResourceRebindImpactSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, resource_state,
    resource_version, current_target_generation, current_semantic_hash,
    current_device_public_id::TEXT, proposed_device_public_id::TEXT,
    proposed_device_state, proposed_device_already_bound,
    affected_resource_group_ids, approval_required
FROM mesh_ops.lock_device_resource_rebind_v1($1::UUID, $2::UUID)`

const rebindDeviceResourceSQL = `SELECT
    network_revision, inventory_revision, resource_version,
    target_generation, semantic_hash
FROM mesh_ops.rebind_device_resource_v1(
    $1::UUID, $2::BIGINT, $3::UUID, $4::UUID, $5::UUID,
    $6::BYTEA, $7::TIMESTAMPTZ
)`
