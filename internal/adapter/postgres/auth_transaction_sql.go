package postgres

const configureAuthTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setAuthTransactionChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const createAuthTransactionSQL = `SELECT
    transaction_public_id::TEXT,
    transaction_version,
    transaction_created_at,
    transaction_expires_at
FROM mesh_ops.create_oidc_auth_transaction_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::UUID,
    $6::BIGINT, $7::BIGINT,
    $8::TEXT, $9::TEXT, $10::TEXT, $11::TEXT, $12::TEXT,
    $13::TEXT, $14::TEXT, $15::TEXT[], $16::TEXT[],
    $17::TEXT, $18::TEXT, $19::TEXT,
    $20::TEXT, $21::TEXT, $22::BYTEA,
    $23::TEXT, $24::TEXT, $25::BYTEA,
    $26::TEXT, $27::TEXT, $28::BYTEA,
    $29::BYTEA, $30::TIMESTAMPTZ, $31::TIMESTAMPTZ
)`

const lockAuthTransactionAuditStreamSQL = `SELECT
    stream_internal_id,
    next_sequence,
    latest_event_hash
FROM mesh_audit.lock_deployment_stream_head($1::UUID)`

const appendAuthTransactionEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'auth_transaction', $7::UUID, $8::BIGINT, NULL::BIGINT, NULL::UUID,
    'auth_transaction.created', 'identity.authenticate', $9::UUID,
    NULL::BYTEA, $10::BYTEA, $11::JSONB,
    'identity.auth_transaction.created', $12::JSONB
)`

const loadCommittedAuthTransactionSQL = `SELECT
    transaction_public_id::TEXT,
    transaction_version,
    transaction_created_at,
    transaction_expires_at
FROM mesh_ops.load_oidc_auth_transaction_creation_v1(
    $1::UUID, $2::UUID, $3::BYTEA
)`
