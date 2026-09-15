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
