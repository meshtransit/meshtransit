package postgres

const configureAccountSessionLogoutSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setAccountSessionLogoutChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const logoutAccountSessionSQL = `SELECT
    session_public_id::TEXT,
    session_version,
    principal_public_id::TEXT,
    ended_at
FROM mesh_ops.logout_account_session_v2(
    $1::UUID,
    $2::BIGINT,
    $3::TEXT,
    $4::TEXT,
    $5::BYTEA
)`

const lockAccountSessionLogoutAuditStreamSQL = `SELECT
    stream_internal_id,
    next_sequence,
    latest_event_hash
FROM mesh_audit.lock_deployment_stream_head($1::UUID)`

const appendAccountSessionLogoutEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'account_session', $7::UUID, $8::BIGINT, NULL::BIGINT, $9::UUID,
    'account_session.revoked', 'identity.logout', $7::UUID,
    NULL::BYTEA, $10::BYTEA, $11::JSONB,
    'identity.account_session.revoked', $11::JSONB
)`
