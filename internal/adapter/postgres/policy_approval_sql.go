package postgres

const configurePolicyApprovalTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setPolicyApprovalScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const authorizePolicyApprovalSQL = `SELECT
    role_binding_public_id::TEXT,
    role_definition_public_id::TEXT,
    scope_authority_generation,
    membership_authority_generation,
    binding_authority_generation,
    role_authority_generation,
    binding_expires_at IS NOT NULL,
    COALESCE(binding_expires_at, $13::TIMESTAMPTZ)
FROM mesh_ops.resolve_network_permission_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TEXT, $13::TIMESTAMPTZ
)
LIMIT 1`

const lockPolicyApprovalRevisionSQL = `SELECT *
FROM mesh_ops.lock_network_revision()`

const claimPolicyApprovalIdempotencySQL = `SELECT
    record_public_id::TEXT,
    stored_request_semantic_hash,
    record_state,
    result_kind,
    result_public_id::TEXT,
    result_version,
    result_network_revision,
    result_payload,
    record_expires_at,
    created
FROM mesh_ops.claim_network_idempotency(
    $1::UUID, $2::UUID, $3::TEXT, $4::TEXT, $5::BYTEA,
    $6::BYTEA, $7::TIMESTAMPTZ, $8::TIMESTAMPTZ
)`

const completePolicyApprovalIdempotencySQL = `SELECT mesh_ops.complete_network_idempotency(
    $1::UUID, $2::UUID, $3::TEXT, $4::TEXT, $5::BYTEA,
    $6::BYTEA, $7::TEXT, $8::UUID, $9::BIGINT, $10::BIGINT,
    $11::JSONB, $12::UUID, $13::TIMESTAMPTZ
)::TEXT`

const lockPolicyApprovalAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const setPolicyApprovalChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id', $1::TEXT, TRUE
)`

const createPolicyApprovalRequestSQL = `SELECT mesh_ops.create_policy_approval_request_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::UUID,
    $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT, $10::BIGINT,
    $11::BIGINT, $12::BIGINT, $13::BIGINT, $14::BIGINT,
    $15::BIGINT, $16::BIGINT, $17::BIGINT, $18::BIGINT,
    $19::BIGINT, $20::BIGINT, $21::BIGINT, $22::BIGINT,
    $23::BIGINT, $24::BIGINT, $25::BIGINT, $26::BIGINT,
    $27::BYTEA, $28::INTEGER, $29::BYTEA, $30::BYTEA,
    $31::TEXT, $32::TIMESTAMPTZ, $33::TIMESTAMPTZ
)`

const lockPolicyApprovalRequestSQL = `SELECT
    request_version, request_state,
    proposer_principal_public_id::TEXT, proposer_session_public_id::TEXT,
    baseline_network, baseline_inventory, baseline_group, baseline_policy,
    baseline_dns, baseline_route, baseline_sharing, baseline_isolation,
    proposed_network, proposed_inventory, proposed_group, proposed_policy,
    proposed_dns, proposed_route, proposed_sharing, proposed_isolation,
    candidate_hash, compiler_format, simulation_impact_hash,
    request_created_at, request_expires_at
FROM mesh_ops.lock_policy_approval_request_v1($1::UUID)`

const loadPolicyApprovalRequestSQL = `SELECT
    proposer_principal_public_id::TEXT, proposer_session_public_id::TEXT,
    baseline_network, baseline_inventory, baseline_group, baseline_policy,
    baseline_dns, baseline_route, baseline_sharing, baseline_isolation,
    proposed_network, proposed_inventory, proposed_group, proposed_policy,
    proposed_dns, proposed_route, proposed_sharing, proposed_isolation,
    candidate_hash, compiler_format, simulation_impact_hash,
    request_created_at, request_expires_at
FROM mesh_ops.load_policy_approval_request_v1($1::UUID)`

const approvePolicyApprovalRequestSQL = `SELECT
    approved_request_version, approval_evidence_version
FROM mesh_ops.approve_policy_approval_request_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    $7::UUID, $8::UUID, $9::UUID, $10::BIGINT, $11::BIGINT,
    $12::BIGINT, $13::BIGINT, $14::BIGINT, $15::BYTEA,
    $16::TEXT, $17::TIMESTAMPTZ
)`

const loadPolicyApprovalEvidenceSQL = `SELECT
    request_public_id::TEXT,
    proposer_principal_public_id::TEXT, proposer_session_public_id::TEXT,
    approver_principal_public_id::TEXT, approver_session_public_id::TEXT,
    baseline_network, baseline_inventory, baseline_group, baseline_policy,
    baseline_dns, baseline_route, baseline_sharing, baseline_isolation,
    proposed_network, proposed_inventory, proposed_group, proposed_policy,
    proposed_dns, proposed_route, proposed_sharing, proposed_isolation,
    candidate_hash, compiler_format, simulation_impact_hash,
    approved_request_version, approval_evidence_version,
    evidence_approved_at, evidence_expires_at
FROM mesh_ops.load_policy_approval_evidence_v1($1::UUID)`

const appendPolicyApprovalEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    $7::TEXT, $8::UUID, $9::BIGINT, $10::BIGINT, $11::UUID,
    $12::TEXT, $13::TEXT, $14::UUID, $15::BYTEA, $16::BYTEA,
    $17::JSONB, $18::TEXT, $19::JSONB
)`
