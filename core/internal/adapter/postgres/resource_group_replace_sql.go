package postgres

const previewResourceGroupReplaceImpactSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, group_state,
    group_version, current_definition_version, current_semantic_hash,
    current_members, approval_required
FROM mesh_ops.preview_resource_group_replace_v1($1::UUID, $2::JSONB)`

const lockResourceGroupReplaceImpactSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, group_state,
    group_version, current_definition_version, current_semantic_hash,
    current_members, approval_required
FROM mesh_ops.lock_resource_group_replace_v1($1::UUID, $2::JSONB)`

const replaceResourceGroupDefinitionSQL = `SELECT
    network_revision, group_revision, group_version,
    definition_version, semantic_hash
FROM mesh_ops.replace_resource_group_definition_v1(
    $1::UUID, $2::BIGINT, $3::UUID, $4::UUID,
    $5::BYTEA, $6::TIMESTAMPTZ, $7::JSONB
)`
