package postgres

const readResourceCatalogRevisionSQL = `SELECT * FROM mesh_ops.read_network_revision_v1()`

const readResourceCatalogSQL = `SELECT
    resource_public_id::TEXT,
    display_name,
    owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT,
    device_public_id::TEXT,
    resource_state,
    resource_kind,
    provenance_kind,
    resource_version,
    target_generation,
    semantic_hash,
    activated_network_revision,
    inventory_revision,
    created_at,
    updated_at
FROM mesh_ops.read_resource_v2($1::UUID)`

const listResourceCatalogSQL = `SELECT mesh_ops.list_resources_v1(
    $1::UUID, $2::TEXT, $3::INTEGER
)::TEXT`

const readResourceGroupCatalogSQL = `SELECT
    group_public_id::TEXT,
    display_name,
    owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT,
    group_state,
    group_version,
    definition_version,
    semantic_hash,
    activated_network_revision,
    group_revision,
    created_at,
    updated_at,
    members::TEXT
FROM mesh_ops.read_resource_group_v2($1::UUID)`

const listResourceGroupCatalogSQL = `SELECT mesh_ops.list_resource_groups_v1(
    $1::UUID, $2::TEXT, $3::INTEGER
)::TEXT`
