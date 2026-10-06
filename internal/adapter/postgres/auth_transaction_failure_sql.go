package postgres

const failAuthTransactionSQL = `SELECT transaction_public_id::TEXT, transaction_version,
    transaction_created_at, transaction_expires_at, transaction_consumed_at, transaction_binding_hash,
    terminal_state, terminal_failure_class, terminal_at, stream_internal_id, next_sequence, latest_event_hash
FROM mesh_ops.fail_oidc_browser_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::BIGINT, $5::BIGINT,
    $6::UUID, $7::BIGINT, $8::BYTEA, $9::TIMESTAMPTZ
)`

const appendAuthFailureEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'auth_transaction', $7::UUID, $8::BIGINT, NULL::BIGINT, NULL::UUID,
    'auth_transaction.terminated', 'identity.authenticate', $9::UUID,
    $10::BYTEA, $11::BYTEA, $12::JSONB,
    'identity.auth_transaction.terminated', $13::JSONB
)`
