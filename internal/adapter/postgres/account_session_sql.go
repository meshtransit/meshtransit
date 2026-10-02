package postgres

const configureAccountSessionTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $2, TRUE)`

const resolveAccountSessionSQL = `SELECT
    session_public_id::TEXT,
    deployment_public_id::TEXT,
    principal_public_id::TEXT,
    identity_subject_public_id::TEXT,
    login_workspace_public_id::TEXT,
    authentication_time,
    acr,
    amr,
    session_version,
    principal_authority_generation,
    account_session_generation,
    provider_generation,
    deployment_recovery_epoch,
    idle_expires_at,
    absolute_expires_at
FROM mesh_ops.resolve_account_session_v2(
    $1::UUID,
    $2::BIGINT,
    $3::TEXT,
    $4::TEXT,
    $5::BYTEA
)`

const readAccountSessionManagementScopesSQL = `SELECT
    mesh_ops.read_console_management_scopes_v3(
        $1::UUID, $2::UUID, $3::UUID, $4::UUID,
        $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
        $10::UUID, $11::TIMESTAMPTZ, $12::UUID, $13::INTEGER
    )::TEXT`

const readAccountSessionDeploymentCapabilitiesSQL = `SELECT
    mesh_ops.read_console_deployment_capabilities_v1(
        $1::UUID, $2::UUID, $3::UUID, $4::UUID,
        $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
        $10::UUID, $11::TIMESTAMPTZ
    )::TEXT`
