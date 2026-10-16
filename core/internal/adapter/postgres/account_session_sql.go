package postgres

const configureAccountSessionTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $2, TRUE)`

// The Console scope and capability reads evaluate authority at
// transaction_timestamp(), the database clock's time for the transaction.
//
// Only read paths select generic plans. PostgreSQL still executes every
// authority check against current rows; this caches no result or permission.
// The setting is transaction-local and does not affect mutation plans.
const configureAccountSessionReadTransactionSQL = configureAccountSessionTransactionSQL + `,
    pg_catalog.set_config('plan_cache_mode', 'force_generic_plan', TRUE)`

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

// resolveAccountSessionAtSQL is resolveAccountSessionSQL that also returns
// the transaction's database time, in the same round trip, for the renewal
// decision.
const resolveAccountSessionAtSQL = `SELECT resolved.*, pg_catalog.transaction_timestamp()
FROM (SELECT
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
)) AS resolved`

const touchAccountSessionSQL = `SELECT session_version, last_used_at, idle_expires_at
FROM mesh_ops.touch_account_session_v1(
    $1::UUID, $2::BIGINT, $3::UUID, $4::BIGINT,
    $5::TEXT, $6::TEXT, $7::BYTEA
)`

const appendAccountSessionTouchEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'account_session', $7::UUID, $8::BIGINT, NULL::BIGINT, $9::UUID,
    'account_session.touched', 'identity.session', $7::UUID,
    NULL::BYTEA, $10::BYTEA, $11::JSONB,
    'identity.account_session.touched', $11::JSONB
)`

const readAccountSessionManagementScopesSQL = `SELECT
    mesh_ops.read_console_management_scopes_v4(
        $1::UUID, $2::UUID, $3::UUID, $4::UUID,
        $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
        $10::UUID, pg_catalog.transaction_timestamp(), $11::UUID, $12::INTEGER
    )::TEXT`

const readAccountSessionDeploymentCapabilitiesSQL = `SELECT
    mesh_ops.read_console_deployment_capabilities_v2(
        $1::UUID, $2::UUID, $3::UUID, $4::UUID,
        $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
        $10::UUID, pg_catalog.transaction_timestamp()
    )::TEXT`
