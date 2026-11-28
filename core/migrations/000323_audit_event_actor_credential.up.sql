-- Schema 323 (V1-80 A2): record the actor's API key on audit events.
--
-- Expand-only migration on the partitioned mesh_audit.audit_event table:
-- adds two nullable columns (actor_credential_kind, actor_credential_public_id)
-- populated by mesh_audit.append_authority_evidence from transaction-local GUCs
-- (mesh.actor_credential_kind, mesh.actor_credential_public_id).
--
-- Existing callers and interactive sessions leave both GUCs unset, writing
-- NULL/NULL and keeping older running binaries and Seal v2 fully compatible.
-- When set, append_authority_evidence fails closed (23514) unless both GUCs
-- are valid, actor_principal_public_id is non-NULL, and the named API key
-- exists for that exact Deployment, Workspace stream, and Principal.

ALTER TABLE mesh_audit.audit_event
    ADD COLUMN actor_credential_kind TEXT,
    ADD COLUMN actor_credential_public_id UUID,
    ADD CONSTRAINT audit_event_actor_credential_check CHECK (
        (actor_credential_kind IS NULL AND actor_credential_public_id IS NULL)
        OR (
            actor_credential_kind = 'api_key'
            AND actor_credential_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(actor_credential_public_id), 6) >> 4 = 7
            AND actor_principal_public_id IS NOT NULL
        )
    ) NOT VALID;

ALTER TABLE mesh_audit.audit_event
    VALIDATE CONSTRAINT audit_event_actor_credential_check;

CREATE OR REPLACE FUNCTION mesh_audit.append_authority_evidence(
    p_stream_id BIGINT,
    p_event_public_id UUID,
    p_outbox_public_id UUID,
    p_expected_sequence BIGINT,
    p_expected_previous_hash BYTEA,
    p_event_hash BYTEA,
    p_aggregate_kind TEXT,
    p_aggregate_public_id UUID,
    p_aggregate_version BIGINT,
    p_network_revision BIGINT,
    p_actor_principal_public_id UUID,
    p_action TEXT,
    p_permission TEXT,
    p_correlation_public_id UUID,
    p_before_semantic_hash BYTEA,
    p_after_semantic_hash BYTEA,
    p_audit_payload JSONB,
    p_outbox_event_class TEXT,
    p_outbox_payload JSONB
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh_ops, mesh
AS $function$
DECLARE
    change_id UUID;
    transaction_value BIGINT;
    occurred TIMESTAMPTZ;
    stream_deployment_id BIGINT;
    stream_workspace_id BIGINT;
    stream_network_id BIGINT;
    stream_next_sequence BIGINT;
    stream_latest_hash BYTEA;
    identity_id BIGINT;
    v_credential_kind TEXT;
    v_credential_id_text TEXT;
    v_credential_id UUID;
BEGIN
    BEGIN
        change_id := pg_catalog.current_setting('mesh.change_public_id', TRUE)::UUID;
    EXCEPTION
        WHEN invalid_text_representation THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid authority change context';
    END;
    IF change_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(change_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid authority change context';
    END IF;
    transaction_value := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;

    v_credential_kind := NULLIF(pg_catalog.current_setting('mesh.actor_credential_kind', TRUE), '');
    v_credential_id_text := NULLIF(pg_catalog.current_setting('mesh.actor_credential_public_id', TRUE), '');
    IF (v_credential_kind IS NULL) <> (v_credential_id_text IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid actor credential context';
    END IF;
    IF v_credential_kind IS NOT NULL THEN
        IF v_credential_kind <> 'api_key' OR p_actor_principal_public_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid actor credential context';
        END IF;
        BEGIN
            v_credential_id := v_credential_id_text::UUID;
        EXCEPTION
            WHEN invalid_text_representation THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid actor credential context';
        END;
        IF pg_catalog.get_byte(pg_catalog.uuid_send(v_credential_id), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid actor credential context';
        END IF;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = change_id
          AND mutation.transaction_id = transaction_value
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'authority mutation evidence is missing';
    END IF;

    SELECT
        stream.deployment_id,
        stream.workspace_id,
        stream.network_id,
        stream.next_sequence,
        stream.latest_event_hash
    INTO STRICT
        stream_deployment_id,
        stream_workspace_id,
        stream_network_id,
        stream_next_sequence,
        stream_latest_hash
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.id = p_stream_id
    FOR UPDATE;

    IF v_credential_id IS NOT NULL THEN
        IF stream_workspace_id IS NULL OR NOT EXISTS (
            SELECT 1
            FROM mesh.api_key AS key_row
            JOIN mesh.principal AS principal
              ON principal.deployment_id = key_row.deployment_id
             AND principal.id = key_row.principal_id
            WHERE key_row.deployment_id = stream_deployment_id
              AND key_row.workspace_id = stream_workspace_id
              AND key_row.public_id = v_credential_id
              AND principal.public_id = p_actor_principal_public_id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid actor credential context';
        END IF;
    END IF;

    IF stream_next_sequence <> p_expected_sequence
        OR stream_latest_hash <> p_expected_previous_hash THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'audit stream head changed';
    END IF;

    occurred := pg_catalog.transaction_timestamp();
    INSERT INTO mesh_audit.audit_event_identity (
        public_id,
        stream_id,
        stream_sequence,
        occurred_at,
        previous_event_hash,
        event_hash,
        change_public_id,
        transaction_id
    ) VALUES (
        p_event_public_id,
        p_stream_id,
        stream_next_sequence,
        occurred,
        stream_latest_hash,
        p_event_hash,
        change_id,
        transaction_value
    )
    RETURNING id INTO identity_id;

    INSERT INTO mesh_audit.audit_event (
        event_identity_id,
        occurred_at,
        deployment_id,
        workspace_id,
        network_id,
        actor_principal_public_id,
        actor_credential_kind,
        actor_credential_public_id,
        action,
        permission,
        target_kind,
        target_public_id,
        before_semantic_hash,
        after_semantic_hash,
        correlation_public_id,
        result,
        payload
    ) VALUES (
        identity_id,
        occurred,
        stream_deployment_id,
        stream_workspace_id,
        stream_network_id,
        p_actor_principal_public_id,
        v_credential_kind,
        v_credential_id,
        p_action,
        p_permission,
        p_aggregate_kind,
        p_aggregate_public_id,
        p_before_semantic_hash,
        p_after_semantic_hash,
        p_correlation_public_id,
        'succeeded',
        p_audit_payload
    );

    INSERT INTO mesh_ops.outbox_event (
        public_id,
        change_public_id,
        transaction_id,
        deployment_id,
        workspace_id,
        network_id,
        aggregate_kind,
        aggregate_public_id,
        aggregate_version,
        network_revision,
        event_class,
        payload,
        available_at
    ) VALUES (
        p_outbox_public_id,
        change_id,
        transaction_value,
        stream_deployment_id,
        stream_workspace_id,
        stream_network_id,
        p_aggregate_kind,
        p_aggregate_public_id,
        p_aggregate_version,
        p_network_revision,
        p_outbox_event_class,
        p_outbox_payload,
        occurred
    );

    UPDATE mesh_audit.audit_stream
    SET next_sequence = stream_next_sequence + 1,
        latest_event_hash = p_event_hash,
        updated_at = pg_catalog.clock_timestamp()
    WHERE id = p_stream_id;

    RETURN stream_next_sequence;
EXCEPTION
    WHEN no_data_found THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'audit stream is unavailable';
END;
$function$;
