package postgres

const readPolicySimulationBaselineSQL = `SELECT
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
    rules::TEXT
FROM mesh_ops.read_policy_simulation_baseline_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::INTEGER
)`
