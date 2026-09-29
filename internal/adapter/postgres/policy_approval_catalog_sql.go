package postgres

const readPolicyApprovalCatalogSQL = `SELECT payload::TEXT
FROM mesh_ops.read_policy_approval_request_management_v1($1::UUID) AS payload
WHERE payload IS NOT NULL`

const listPolicyApprovalCatalogSQL = `SELECT
    mesh_ops.list_policy_approval_requests_management_v1(
        $1::UUID, $2::TEXT, $3::INTEGER
    )::TEXT`
