-- No-grant, Deployment-assigned worker cleanup. Never widen the generic
-- active/verified Deployment head helper or serving auth/session table grants.
-- Enforce one authority mutation per cleanup transaction without a ledger scan.
CREATE INDEX authority_mutation_transaction_idx ON mesh_audit.authority_mutation (transaction_id);
CREATE FUNCTION mesh_ops.list_due_oidc_browser_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    result JSONB;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 128 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid browser expiry selection';
    END IF;
    SELECT COALESCE(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'deployment_public_id', p_deployment_public_id,
            'transaction_public_id', candidate.public_id,
            'state', candidate.state, 'version', candidate.version,
            'created_at', candidate.created_at, 'expires_at', candidate.expires_at,
            'consumed_at', candidate.consumed_at,
            'binding_hash', pg_catalog.encode(candidate.binding_semantic_hash, 'hex')
        ) ORDER BY candidate.expires_at, candidate.id
    ), '[]'::JSONB) INTO result
    FROM (
        SELECT auth.id, auth.public_id, auth.state, auth.version, auth.created_at,
            auth.expires_at, auth.consumed_at, auth.binding_semantic_hash
        FROM mesh.auth_transaction AS auth
        WHERE auth.deployment_id = (
            SELECT deployment.id FROM mesh.deployment AS deployment
            WHERE deployment.installation_public_id = p_deployment_public_id
        )
          AND auth.state IN ('pending', 'consuming') AND auth.expires_at <= decision_at
          AND ((auth.state = 'pending' AND auth.version = 1 AND auth.consumed_at IS NULL)
            OR (auth.state = 'consuming' AND auth.version = 2 AND auth.consumed_at < auth.expires_at))
          AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
          AND auth.workspace_id IS NOT NULL AND auth.principal_id IS NULL
          AND auth.account_session_generation IS NULL AND auth.operation_semantic_hash IS NULL
          AND auth.expected_organization_digest_algorithm IS NULL
          AND auth.expected_organization_digest_key_id IS NULL
          AND auth.expected_organization_digest IS NULL
          AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
          AND auth.failure_class IS NULL AND auth.pkce_verifier_ciphertext IS NOT NULL
          AND auth.binding_semantic_hash IS NOT NULL
          AND auth.binding_semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        ORDER BY auth.expires_at, auth.id LIMIT p_limit
    ) AS candidate;
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

CREATE FUNCTION mesh_ops.expire_oidc_browser_v1(
    p_deployment_public_id UUID, p_transaction_public_id UUID, p_expected_version BIGINT,
    p_created_at TIMESTAMPTZ, p_expires_at TIMESTAMPTZ, p_consumed_at TIMESTAMPTZ, p_binding_hash BYTEA
)
RETURNS TABLE (
    transaction_version BIGINT, transaction_consumed_at TIMESTAMPTZ, expired_at TIMESTAMPTZ,
    stream_internal_id BIGINT, next_sequence BIGINT, latest_event_hash BYTEA
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    auth_row mesh.auth_transaction%ROWTYPE;
    head_id BIGINT;
    head_sequence BIGINT;
    head_hash BYTEA;
    decision_at TIMESTAMPTZ;
    change_id UUID;
    transaction_value BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL OR p_transaction_public_id IS NULL
        OR p_expected_version IS NULL OR p_expected_version NOT IN (1, 2)
        OR p_created_at IS NULL OR p_expires_at IS NULL OR p_binding_hash IS NULL
        OR pg_catalog.octet_length(p_binding_hash) <> 32
        OR p_binding_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') THEN RETURN; END IF;
    change_id := pg_catalog.current_setting('mesh.change_public_id', TRUE)::UUID;
    IF change_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(change_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(change_id), 8) & 192 <> 128
        OR change_id = p_transaction_public_id
        OR EXISTS (SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = change_id)
        OR EXISTS (SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.transaction_id = transaction_value) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser expiry requires fresh owned unit';
    END IF;
    SELECT auth.* INTO auth_row
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND auth.public_id = p_transaction_public_id AND auth.version = p_expected_version
      AND auth.created_at = p_created_at AND auth.expires_at = p_expires_at
      AND auth.consumed_at IS NOT DISTINCT FROM p_consumed_at
      AND auth.binding_semantic_hash = p_binding_hash
      AND ((auth.state = 'pending' AND auth.version = 1 AND auth.consumed_at IS NULL)
        OR (auth.state = 'consuming' AND auth.version = 2 AND auth.consumed_at < auth.expires_at))
      AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
      AND auth.workspace_id IS NOT NULL AND auth.principal_id IS NULL
      AND auth.account_session_generation IS NULL AND auth.operation_semantic_hash IS NULL
      AND auth.expected_organization_digest_algorithm IS NULL
      AND auth.expected_organization_digest_key_id IS NULL AND auth.expected_organization_digest IS NULL
      AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
      AND auth.failure_class IS NULL AND auth.pkce_verifier_ciphertext IS NOT NULL
    FOR UPDATE OF auth;
    IF NOT FOUND THEN RETURN; END IF;

    -- Exact existing stream, no current serving/recovery admission. This gate
    -- grants only proof erasure; no generic head capability is exposed to worker.
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    INTO head_id, head_sequence, head_hash FROM mesh_audit.audit_stream AS stream
    WHERE stream.deployment_id = auth_row.deployment_id AND stream.scope_kind = 'deployment'
      AND stream.workspace_id IS NULL AND stream.network_id IS NULL FOR UPDATE OF stream;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'browser expiry stream unavailable';
    END IF;
    decision_at := pg_catalog.clock_timestamp();
    IF decision_at < auth_row.expires_at OR decision_at < auth_row.updated_at THEN
        -- A rejected post-lock decision must not let a direct caller continue
        -- with another Auth while retaining this row/head acquisition order.
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser expiry deadline not due';
    END IF;
    UPDATE mesh.auth_transaction AS auth
    SET state = 'expired', version = auth.version + 1, failure_class = 'deadline_expired',
        consumed_at = COALESCE(auth.consumed_at, decision_at), updated_at = decision_at,
        pkce_verifier_encryption_algorithm = NULL, pkce_verifier_encryption_key_id = NULL,
        pkce_verifier_ciphertext = NULL WHERE auth.id = auth_row.id;
    RETURN QUERY SELECT auth_row.version + 1, COALESCE(auth_row.consumed_at, decision_at),
        decision_at, head_id, head_sequence, head_hash;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

CREATE FUNCTION mesh_ops.append_oidc_expiry_evidence_v1(
    p_deployment_public_id UUID, p_transaction_public_id UUID, p_stream_id BIGINT,
    p_event_public_id UUID, p_outbox_public_id UUID, p_sequence BIGINT,
    p_previous_hash BYTEA, p_event_hash BYTEA, p_before_hash BYTEA, p_after_hash BYTEA, p_payload JSONB
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    change_id UUID;
    transaction_value BIGINT;
    auth_row mesh.auth_transaction%ROWTYPE;
    previous_version BIGINT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    change_id := pg_catalog.current_setting('mesh.change_public_id', TRUE)::UUID;
    transaction_value := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    IF p_deployment_public_id IS NULL OR p_transaction_public_id IS NULL
        OR p_stream_id IS NULL OR p_stream_id <= 0
        OR p_sequence IS NULL OR p_sequence <= 0 OR p_sequence = 9223372036854775807
        OR p_previous_hash IS NULL OR pg_catalog.octet_length(p_previous_hash) <> 32
        OR p_event_hash IS NULL OR pg_catalog.octet_length(p_event_hash) <> 32
        OR p_event_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR change_id IS NULL OR p_event_public_id IS NULL OR p_outbox_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_outbox_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 8) & 192 <> 128
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_outbox_public_id), 8) & 192 <> 128
        OR p_event_public_id = p_outbox_public_id OR p_event_public_id = change_id
        OR p_outbox_public_id = change_id OR p_event_public_id = p_transaction_public_id
        OR p_outbox_public_id = p_transaction_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid browser expiry evidence head';
    END IF;
    SELECT auth.* INTO auth_row
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
    JOIN mesh_audit.audit_stream AS stream ON stream.deployment_id = auth.deployment_id
      AND stream.id = p_stream_id AND stream.scope_kind = 'deployment'
      AND stream.workspace_id IS NULL AND stream.network_id IS NULL
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.change_public_id = change_id AND mutation.transaction_id = transaction_value
      AND mutation.aggregate_kind = 'auth_transaction' AND mutation.row_public_id = auth.public_id
      AND mutation.operation = 'update' AND mutation.before_version IN (1, 2)
      AND mutation.after_version = auth.version
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND auth.public_id = p_transaction_public_id AND auth.state = 'expired'
      AND auth.version IN (2, 3) AND auth.failure_class = 'deadline_expired'
      AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
      AND auth.principal_id IS NULL AND auth.consumed_result_kind IS NULL
      AND auth.consumed_result_public_id IS NULL
      AND auth.pkce_verifier_encryption_algorithm IS NULL
      AND auth.pkce_verifier_encryption_key_id IS NULL AND auth.pkce_verifier_ciphertext IS NULL;
    previous_version := auth_row.version - 1;
    IF NOT FOUND
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = change_id AND mutation.transaction_id = transaction_value) <> 1
        OR EXISTS (SELECT 1 FROM mesh_audit.audit_event_identity AS event
            WHERE event.change_public_id = change_id AND event.transaction_id = transaction_value)
        OR EXISTS (SELECT 1 FROM mesh_ops.outbox_event AS event
            WHERE event.change_public_id = change_id AND event.transaction_id = transaction_value)
        OR p_payload IS NULL OR pg_catalog.jsonb_typeof(p_payload) <> 'object'
        OR p_payload - ARRAY['transaction_public_id', 'previous_state', 'previous_version',
            'expires_at', 'consumed_at', 'expired_at']::TEXT[] <> '{}'::JSONB
        OR (p_payload->>'transaction_public_id') IS DISTINCT FROM p_transaction_public_id::TEXT
        OR (p_payload->>'previous_version')::BIGINT IS DISTINCT FROM previous_version
        OR (p_payload->>'previous_state') IS DISTINCT FROM
            (CASE previous_version WHEN 1 THEN 'pending' ELSE 'consuming' END)
        OR (p_payload->>'expires_at')::TIMESTAMPTZ IS DISTINCT FROM auth_row.expires_at
        OR (p_payload->>'consumed_at')::TIMESTAMPTZ IS DISTINCT FROM auth_row.consumed_at
        OR (p_payload->>'expired_at')::TIMESTAMPTZ IS DISTINCT FROM auth_row.updated_at
        OR p_before_hash IS NULL OR pg_catalog.octet_length(p_before_hash) <> 32
        OR p_after_hash IS NULL OR pg_catalog.octet_length(p_after_hash) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid browser expiry evidence';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'auth_transaction', p_transaction_public_id, auth_row.version, NULL::BIGINT, NULL::UUID,
        'auth_transaction.expired', 'system.lifecycle', p_transaction_public_id,
        p_before_hash, p_after_hash, p_payload, 'identity.auth_transaction.expired', p_payload
    );
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

ALTER FUNCTION mesh_ops.list_due_oidc_browser_v1(UUID, INTEGER) OWNER TO mesh_migrator;
ALTER FUNCTION mesh_ops.expire_oidc_browser_v1(UUID, UUID, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA)
    OWNER TO mesh_migrator;
ALTER FUNCTION mesh_ops.append_oidc_expiry_evidence_v1(UUID, UUID, BIGINT, UUID, UUID, BIGINT,
    BYTEA, BYTEA, BYTEA, BYTEA, JSONB) OWNER TO mesh_migrator;
REVOKE ALL ON FUNCTION mesh_ops.list_due_oidc_browser_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer;
REVOKE ALL ON FUNCTION mesh_ops.expire_oidc_browser_v1(UUID, UUID, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_observer;
REVOKE ALL ON FUNCTION mesh_ops.append_oidc_expiry_evidence_v1(UUID, UUID, BIGINT, UUID, UUID, BIGINT,
    BYTEA, BYTEA, BYTEA, BYTEA, JSONB) FROM PUBLIC, mesh_runtime, mesh_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_due_oidc_browser_v1(UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.expire_oidc_browser_v1(UUID, UUID, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.append_oidc_expiry_evidence_v1(UUID, UUID, BIGINT, UUID, UUID, BIGINT,
    BYTEA, BYTEA, BYTEA, BYTEA, JSONB) TO mesh_worker;
