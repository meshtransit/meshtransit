-- The browser decision and its interactive pending registration are one
-- authority mutation. The caller must append audit/outbox evidence in this
-- transaction before commit; the deferred integrity trigger enforces that.
ALTER TABLE mesh.browser_registration_intent
    ADD COLUMN approved_session_public_id UUID,
    ADD COLUMN approved_workspace_public_id UUID,
    ADD COLUMN approved_network_public_id UUID,
    ADD CONSTRAINT browser_registration_intent_approval_session_fk
        FOREIGN KEY (approved_session_public_id)
        REFERENCES mesh.account_session (public_id) ON DELETE RESTRICT,
    ADD CONSTRAINT browser_registration_intent_approval_network_fk
        FOREIGN KEY (approved_network_public_id)
        REFERENCES mesh.network (public_id) ON DELETE RESTRICT,
    ADD CONSTRAINT browser_registration_intent_approval_workspace_fk
        FOREIGN KEY (approved_workspace_public_id)
        REFERENCES mesh.workspace (public_id) ON DELETE RESTRICT,
    ADD CONSTRAINT browser_registration_intent_approval_session_shape_check CHECK (
        (state = 'pending' AND approved_session_public_id IS NULL
            AND approved_workspace_public_id IS NULL
            AND approved_network_public_id IS NULL)
        OR (state IN ('approved', 'completed')
            AND approved_session_public_id IS NOT NULL
            AND approved_workspace_public_id IS NOT NULL
            AND approved_network_public_id IS NOT NULL)
        OR state IN ('rejected', 'expired')
    );

CREATE FUNCTION mesh_ops.guard_browser_registration_approval_session_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF TG_OP = 'UPDATE'
        AND ((OLD.approved_session_public_id IS NOT NULL
              AND OLD.approved_session_public_id IS DISTINCT FROM NEW.approved_session_public_id)
          OR (OLD.approved_workspace_public_id IS NOT NULL
              AND OLD.approved_workspace_public_id IS DISTINCT FROM NEW.approved_workspace_public_id)
          OR (OLD.approved_network_public_id IS NOT NULL
              AND OLD.approved_network_public_id IS DISTINCT FROM NEW.approved_network_public_id)) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'browser approval Session and Network are immutable';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.guard_browser_registration_approval_session_v1()
    FROM PUBLIC;
CREATE TRIGGER browser_registration_intent_approval_session_guard
BEFORE UPDATE ON mesh.browser_registration_intent
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_browser_registration_approval_session_v1();

CREATE FUNCTION mesh_ops.record_browser_registration_approval_v1(
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT,
    p_session_digest BYTEA,
    p_intent_token_digest BYTEA,
    p_network_public_id UUID,
    p_registration_public_id UUID,
    p_change_public_id UUID
)
RETURNS TABLE (
    approved_registration_public_id UUID,
    approved_registration_version BIGINT,
    approved_intent_public_id UUID,
    approved_session_public_id UUID,
    approved_principal_public_id UUID,
    approved_network_revision BIGINT,
    approved_request_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    authority RECORD;
    pending_internal_id BIGINT;
    request_hash_value BYTEA;
    previous_change_public_id TEXT;
    approved_at TIMESTAMPTZ;
BEGIN
    IF p_registration_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_registration_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser approval evidence identity';
    END IF;

    SELECT * INTO authority
    FROM mesh_ops.lock_browser_registration_approval_authority_v1(
        p_deployment_public_id, p_recovery_epoch,
        p_session_digest_key_id, p_session_digest,
        p_intent_token_digest, p_network_public_id
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;

    approved_at := pg_catalog.clock_timestamp();
    IF authority.intent_expires_at <= approved_at THEN
        RETURN;
    END IF;
    request_hash_value := pg_catalog.sha256(
        pg_catalog.convert_to('meshtransit/browser-registration-approval/v1', 'UTF8')
        || pg_catalog.uuid_send(authority.intent_public_id)
        || pg_catalog.uuid_send(authority.workspace_public_id)
        || pg_catalog.uuid_send(authority.network_public_id)
        || pg_catalog.uuid_send(authority.profile_public_id)
        || pg_catalog.uuid_send(authority.principal_public_id)
        || pg_catalog.uuid_send(authority.session_public_id)
        || authority.machine_key
        || authority.requested_node_key
        || pg_catalog.convert_to(authority.requested_hostname, 'UTF8')
        || pg_catalog.int8send(p_recovery_epoch)
    );

    previous_change_public_id := pg_catalog.current_setting('mesh.change_public_id', TRUE);
    PERFORM pg_catalog.set_config(
        'mesh.change_public_id', p_change_public_id::TEXT, TRUE
    );
    INSERT INTO mesh.pending_registration (
        public_id, workspace_id, network_id, enrollment_profile_id,
        authorization_kind, browser_authorization_public_id,
        authorized_principal_id, machine_key_fingerprint,
        expires_at, state, intent_format_version, request_hash,
        requested_node_key, created_at, updated_at
    ) VALUES (
        p_registration_public_id, authority.workspace_internal_id,
        authority.network_internal_id, authority.profile_internal_id,
        'interactive', authority.intent_public_id,
        authority.principal_internal_id, authority.machine_key_fingerprint,
        authority.intent_expires_at, 'authorized', 2, request_hash_value,
        authority.requested_node_key, approved_at, approved_at
    ) RETURNING id INTO pending_internal_id;

    UPDATE mesh.browser_registration_intent AS intent
    SET pending_registration_public_id = p_registration_public_id,
        approved_session_public_id = authority.session_public_id,
        approved_workspace_public_id = authority.workspace_public_id,
        approved_network_public_id = authority.network_public_id,
        state = 'approved',
        version = intent.version + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE intent.id = authority.intent_internal_id
      AND intent.state = 'pending'
      AND intent.pending_registration_public_id IS NULL;
    IF NOT FOUND OR pending_internal_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'browser approval authority changed';
    END IF;

    approved_registration_public_id := p_registration_public_id;
    approved_registration_version := 1;
    approved_intent_public_id := authority.intent_public_id;
    approved_session_public_id := authority.session_public_id;
    approved_principal_public_id := authority.principal_public_id;
    approved_network_revision := authority.current_network_revision;
    approved_request_hash := request_hash_value;
    RETURN NEXT;

    -- Keep the change context until the caller appends matching audit/outbox
    -- evidence. The explicit transaction is dedicated to this one decision.
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.change_public_id', COALESCE(previous_change_public_id, ''), TRUE
        );
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.record_browser_registration_approval_v1(
    UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_browser_registration_approval_v1(
    UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID, UUID, UUID
) TO mesh_runtime;
