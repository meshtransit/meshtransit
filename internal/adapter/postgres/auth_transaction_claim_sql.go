package postgres

const claimAuthTransactionSQL = `SELECT transaction_public_id::TEXT, transaction_version,
    transaction_created_at, transaction_expires_at, transaction_consumed_at, transaction_binding_hash
FROM mesh_ops.claim_oidc_browser_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT,
    $7::TEXT, $8::TEXT, $9::TEXT, $10::TEXT, $11::TEXT, $12::TEXT,
    $13::TEXT, $14::TEXT[], $15::TEXT[], $16::TEXT,
    $17::TEXT, $18::TEXT, $19::BYTEA, $20::TEXT, $21::TEXT,
    $22::UUID, $23::BIGINT, $24::BYTEA
)`

const authClaimClockSQL = `SELECT pg_catalog.clock_timestamp()`

const appendAuthClaimEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'auth_transaction', $7::UUID, $8::BIGINT, NULL::BIGINT, NULL::UUID,
    'auth_transaction.claimed', 'identity.authenticate', $9::UUID,
    $10::BYTEA, $11::BYTEA, $12::JSONB,
    'identity.auth_transaction.claimed', $13::JSONB
)`
