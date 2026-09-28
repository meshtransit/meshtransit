package postgres

const transitionResourceLifecycleSQL = `SELECT
    network_revision, inventory_revision, resource_version, resource_state, semantic_hash
FROM mesh_ops.transition_resource_lifecycle_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::UUID, $5::TIMESTAMPTZ
)`

const transitionResourceGroupLifecycleSQL = `SELECT
    network_revision, group_revision, group_version, group_state, semantic_hash
FROM mesh_ops.transition_resource_group_lifecycle_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::UUID, $5::TIMESTAMPTZ
)`
