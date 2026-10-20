package postgres

const explainActivePolicySQL = `SELECT
    network_revision,
    inventory_revision,
    group_revision,
    policy_revision,
    dns_revision,
    route_revision,
    sharing_revision,
    isolation_generation,
    has_active_release,
    release_public_id::TEXT,
    compiler_format_version,
    release_semantic_hash,
    target_device_public_id::TEXT,
    paths::TEXT,
    context::TEXT
FROM mesh_ops.explain_active_policy_v4(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::UUID, $13::UUID, $14::UUID, $15::UUID,
    $16::TEXT, $17::INTEGER, $18::TIMESTAMPTZ, $19::INTEGER
)`

// explainAddressAccessSQL returns the columns of explainActivePolicySQL,
// with the Site holding the address, or the Exit Pool an Internet address is
// reached through (schema 206), in place of the target Device; the context
// names which.
const explainAddressAccessSQL = `SELECT
    network_revision,
    inventory_revision,
    group_revision,
    policy_revision,
    dns_revision,
    route_revision,
    sharing_revision,
    isolation_generation,
    has_active_release,
    release_public_id::TEXT,
    compiler_format_version,
    release_semantic_hash,
    target_public_id::TEXT,
    paths::TEXT,
    context::TEXT
FROM mesh_ops.explain_address_access_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::UUID, $13::INET,
    $14::TEXT, $15::INTEGER, $16::TIMESTAMPTZ, $17::INTEGER
)`
