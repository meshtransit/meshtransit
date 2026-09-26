package postgres

const configureAccountSessionLogoutSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const logoutAccountSessionSQL = `SELECT
    session_public_id::TEXT,
    session_version
FROM mesh_ops.logout_account_session_v1(
    $1::UUID,
    $2::BIGINT,
    $3::TEXT,
    $4::TEXT,
    $5::BYTEA
)`
