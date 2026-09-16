package postgres

const issueAuthTransactionSQL = `SELECT transaction_public_id::TEXT,transaction_version,transaction_binding_hash,
    transaction_consumed_at,terminal_state,result_kind,result_public_id::TEXT,session_public_id::TEXT,session_version,
    issued_at,idle_expires_at,absolute_expires_at,stream_internal_id,next_sequence,latest_event_hash
FROM mesh_ops.issue_oidc_existing_subject_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,
    $7::TEXT,$8::TEXT,$9::TEXT,$10::TEXT,$11::TEXT,$12::TEXT,$13::TEXT,$14::TEXT[],$15::TEXT[],$16::TEXT,
    $17::UUID,$18::BIGINT,$19::BYTEA,$20::TIMESTAMPTZ,$21::TEXT,$22::TEXT,
    $23::TEXT,$24::TEXT,$25::BYTEA,$26::TEXT,$27::BYTEA,
    $28::UUID,$29::UUID,$30::UUID,$31::BIGINT,$32::BIGINT,$33::BIGINT,$34::BIGINT,$35::BIGINT,$36::BIGINT,
    $37::TIMESTAMPTZ,$38::TIMESTAMPTZ,$39::UUID,$40::TEXT,$41::TEXT,$42::BYTEA,
    $43::TEXT,$44::TEXT,$45::BYTEA,$46::TIMESTAMPTZ,$47::TEXT,$48::TEXT[],$49::TIMESTAMPTZ,$50::BIGINT,$51::BIGINT
)`

const appendAuthIssueEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
    $7::TEXT,$8::UUID,$9::BIGINT,NULL::BIGINT,$10::UUID,
    $11::TEXT,'identity.authenticate',$12::UUID,$13::BYTEA,$14::BYTEA,$15::JSONB,$16::TEXT,$17::JSONB
)`
