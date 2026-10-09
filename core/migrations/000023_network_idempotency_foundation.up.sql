CREATE TABLE mesh_ops.idempotency_record (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT,
    principal_id BIGINT NOT NULL,
    operation TEXT NOT NULL,
    digest_algorithm TEXT NOT NULL,
    digest_key_id TEXT NOT NULL,
    key_digest BYTEA NOT NULL,
    request_semantic_hash BYTEA NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    result_kind TEXT,
    result_public_id UUID,
    result_version BIGINT,
    result_network_revision BIGINT,
    result_payload JSONB,
    outbox_public_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT idempotency_record_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT idempotency_record_operation_check CHECK (
        pg_catalog.char_length(operation) BETWEEN 1 AND 128
        AND operation ~ '^[a-z][a-z0-9_.]*$'
    ),
    CONSTRAINT idempotency_record_digest_check CHECK (
        digest_algorithm = 'hmac-sha256-v1'
        AND pg_catalog.char_length(digest_key_id) BETWEEN 1 AND 128
        AND digest_key_id = pg_catalog.btrim(digest_key_id)
        AND pg_catalog.octet_length(key_digest) = 32
        AND pg_catalog.octet_length(request_semantic_hash) = 32
    ),
    CONSTRAINT idempotency_record_result_public_id_v7_check CHECK (
        result_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(result_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT idempotency_record_outbox_public_id_v7_check CHECK (
        outbox_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(outbox_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT idempotency_record_result_kind_check CHECK (
        result_kind IS NULL
        OR (
            pg_catalog.char_length(result_kind) BETWEEN 1 AND 64
            AND result_kind ~ '^[a-z][a-z0-9_]*$'
        )
    ),
    CONSTRAINT idempotency_record_payload_check CHECK (
        result_payload IS NULL
        OR (
            pg_catalog.jsonb_typeof(result_payload) = 'object'
            AND pg_catalog.octet_length(result_payload::TEXT) <= 4096
        )
    ),
    CONSTRAINT idempotency_record_state_check CHECK (state IN ('pending', 'completed')),
    CONSTRAINT idempotency_record_state_shape_check CHECK (
        (
            state = 'pending'
            AND result_kind IS NULL
            AND result_public_id IS NULL
            AND result_version IS NULL
            AND result_network_revision IS NULL
            AND result_payload IS NULL
            AND outbox_public_id IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'completed'
            AND result_kind IS NOT NULL
            AND result_public_id IS NOT NULL
            AND result_version > 0
            AND (
                (network_id IS NULL AND result_network_revision IS NULL)
                OR (network_id IS NOT NULL AND result_network_revision > 0)
            )
            AND result_payload IS NOT NULL
            AND outbox_public_id IS NOT NULL
            AND completed_at >= created_at
            AND completed_at < expires_at
        )
    ),
    CONSTRAINT idempotency_record_timestamps_check CHECK (
        updated_at >= created_at
        AND expires_at > created_at
    ),
    CONSTRAINT idempotency_record_workspace_fk FOREIGN KEY (workspace_id)
        REFERENCES mesh.workspace (id) ON DELETE RESTRICT,
    CONSTRAINT idempotency_record_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT idempotency_record_principal_fk FOREIGN KEY (principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT idempotency_record_outbox_fk FOREIGN KEY (outbox_public_id)
        REFERENCES mesh_ops.outbox_event (public_id) ON DELETE RESTRICT,
    CONSTRAINT idempotency_record_outbox_unique UNIQUE (outbox_public_id),
    CONSTRAINT idempotency_record_key_unique UNIQUE NULLS NOT DISTINCT (
        workspace_id,
        network_id,
        principal_id,
        operation,
        digest_key_id,
        key_digest
    )
);

CREATE INDEX idempotency_record_expiry_idx
    ON mesh_ops.idempotency_record (expires_at, id);
CREATE INDEX idempotency_record_result_idx
    ON mesh_ops.idempotency_record (
        workspace_id,
        network_id,
        result_kind,
        result_public_id,
        created_at DESC,
        id DESC
    )
    WHERE state = 'completed';

CREATE FUNCTION mesh_ops.claim_network_idempotency(
    p_record_public_id UUID,
    p_actor_principal_public_id UUID,
    p_operation TEXT,
    p_digest_key_id TEXT,
    p_key_digest BYTEA,
    p_request_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    record_public_id UUID,
    stored_request_semantic_hash BYTEA,
    record_state TEXT,
    result_kind TEXT,
    result_public_id UUID,
    result_version BIGINT,
    result_network_revision BIGINT,
    result_payload JSONB,
    record_expires_at TIMESTAMPTZ,
    created BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops, mesh
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    actor_principal_id BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;

    SELECT principal.id
    INTO STRICT actor_principal_id
    FROM mesh.principal AS principal
    JOIN mesh.workspace AS workspace
      ON workspace.id = scoped_workspace_id
     AND workspace.deployment_id = principal.deployment_id
    WHERE principal.public_id = p_actor_principal_public_id
      AND principal.state = 'active'
      AND principal.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL;

    INSERT INTO mesh_ops.idempotency_record (
        public_id,
        workspace_id,
        network_id,
        principal_id,
        operation,
        digest_algorithm,
        digest_key_id,
        key_digest,
        request_semantic_hash,
        created_at,
        updated_at,
        expires_at
    ) VALUES (
        p_record_public_id,
        scoped_workspace_id,
        scoped_network_id,
        actor_principal_id,
        p_operation,
        'hmac-sha256-v1',
        p_digest_key_id,
        p_key_digest,
        p_request_semantic_hash,
        p_occurred_at,
        p_occurred_at,
        p_expires_at
    )
    ON CONFLICT ON CONSTRAINT idempotency_record_key_unique DO NOTHING
    RETURNING
        idempotency_record.public_id,
        idempotency_record.request_semantic_hash,
        idempotency_record.state,
        idempotency_record.result_kind,
        idempotency_record.result_public_id,
        idempotency_record.result_version,
        idempotency_record.result_network_revision,
        idempotency_record.result_payload,
        idempotency_record.expires_at,
        TRUE
    INTO
        record_public_id,
        stored_request_semantic_hash,
        record_state,
        result_kind,
        result_public_id,
        result_version,
        result_network_revision,
        result_payload,
        record_expires_at,
        created;

    IF FOUND THEN
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT
        record.public_id,
        record.request_semantic_hash,
        record.state,
        record.result_kind,
        record.result_public_id,
        record.result_version,
        record.result_network_revision,
        record.result_payload,
        record.expires_at,
        FALSE
    INTO STRICT
        record_public_id,
        stored_request_semantic_hash,
        record_state,
        result_kind,
        result_public_id,
        result_version,
        result_network_revision,
        result_payload,
        record_expires_at,
        created
    FROM mesh_ops.idempotency_record AS record
    WHERE record.workspace_id = scoped_workspace_id
      AND record.network_id = scoped_network_id
      AND record.principal_id = actor_principal_id
      AND record.operation = p_operation
      AND record.digest_algorithm = 'hmac-sha256-v1'
      AND record.digest_key_id = p_digest_key_id
      AND record.key_digest = p_key_digest
    FOR UPDATE;

    RETURN NEXT;
EXCEPTION
    WHEN no_data_found THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'idempotency authority is unavailable';
END;
$function$;

CREATE FUNCTION mesh_ops.load_network_idempotency(
    p_actor_principal_public_id UUID,
    p_operation TEXT,
    p_digest_key_id TEXT,
    p_key_digest BYTEA
)
RETURNS TABLE (
    record_public_id UUID,
    stored_request_semantic_hash BYTEA,
    record_state TEXT,
    result_kind TEXT,
    result_public_id UUID,
    result_version BIGINT,
    result_network_revision BIGINT,
    result_payload JSONB,
    record_expires_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops, mesh
AS $function$
    SELECT
        record.public_id,
        record.request_semantic_hash,
        record.state,
        record.result_kind,
        record.result_public_id,
        record.result_version,
        record.result_network_revision,
        record.result_payload,
        record.expires_at
    FROM mesh_ops.idempotency_record AS record
    JOIN mesh.principal AS principal
      ON principal.id = record.principal_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
     AND principal.deleted_at IS NULL
    JOIN mesh.workspace AS workspace
      ON workspace.id = record.workspace_id
     AND workspace.deployment_id = principal.deployment_id
     AND workspace.state = 'active'
     AND workspace.deleted_at IS NULL
    WHERE record.workspace_id = mesh_ops.current_workspace_id()
      AND record.network_id = mesh_ops.current_network_id()
      AND record.operation = p_operation
      AND record.digest_algorithm = 'hmac-sha256-v1'
      AND record.digest_key_id = p_digest_key_id
      AND record.key_digest = p_key_digest
$function$;

CREATE FUNCTION mesh_ops.complete_network_idempotency(
    p_record_public_id UUID,
    p_actor_principal_public_id UUID,
    p_operation TEXT,
    p_digest_key_id TEXT,
    p_key_digest BYTEA,
    p_request_semantic_hash BYTEA,
    p_result_kind TEXT,
    p_result_public_id UUID,
    p_result_version BIGINT,
    p_result_network_revision BIGINT,
    p_result_payload JSONB,
    p_outbox_public_id UUID,
    p_completed_at TIMESTAMPTZ
)
RETURNS UUID
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops, mesh
AS $function$
    UPDATE mesh_ops.idempotency_record AS record
    SET state = 'completed',
        result_kind = p_result_kind,
        result_public_id = p_result_public_id,
        result_version = p_result_version,
        result_network_revision = p_result_network_revision,
        result_payload = p_result_payload,
        outbox_public_id = p_outbox_public_id,
        updated_at = p_completed_at,
        completed_at = p_completed_at
    FROM mesh.principal AS principal,
         mesh.workspace AS workspace
    WHERE record.public_id = p_record_public_id
      AND record.workspace_id = mesh_ops.current_workspace_id()
      AND record.network_id = mesh_ops.current_network_id()
      AND record.principal_id = principal.id
      AND principal.public_id = p_actor_principal_public_id
      AND principal.state = 'active'
      AND principal.deleted_at IS NULL
      AND workspace.id = record.workspace_id
      AND workspace.deployment_id = principal.deployment_id
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND record.operation = p_operation
      AND record.digest_algorithm = 'hmac-sha256-v1'
      AND record.digest_key_id = p_digest_key_id
      AND record.key_digest = p_key_digest
      AND record.request_semantic_hash = p_request_semantic_hash
      AND record.state = 'pending'
    RETURNING record.public_id
$function$;

CREATE FUNCTION mesh_ops.enforce_idempotency_record_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.expires_at > pg_catalog.transaction_timestamp() THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid idempotency record transition';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.state <> 'pending'
        OR NEW.state <> 'completed'
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.public_id IS DISTINCT FROM OLD.public_id
        OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
        OR NEW.network_id IS DISTINCT FROM OLD.network_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.operation IS DISTINCT FROM OLD.operation
        OR NEW.digest_algorithm IS DISTINCT FROM OLD.digest_algorithm
        OR NEW.digest_key_id IS DISTINCT FROM OLD.digest_key_id
        OR NEW.key_digest IS DISTINCT FROM OLD.key_digest
        OR NEW.request_semantic_hash IS DISTINCT FROM OLD.request_semantic_hash
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid idempotency record transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION mesh_ops.enforce_idempotency_record_completion()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    record_state TEXT;
    record_workspace_id BIGINT;
    record_network_id BIGINT;
    record_result_public_id UUID;
    record_result_network_revision BIGINT;
    record_outbox_public_id UUID;
BEGIN
    SELECT
        record.state,
        record.workspace_id,
        record.network_id,
        record.result_public_id,
        record.result_network_revision,
        record.outbox_public_id
    INTO STRICT
        record_state,
        record_workspace_id,
        record_network_id,
        record_result_public_id,
        record_result_network_revision,
        record_outbox_public_id
    FROM mesh_ops.idempotency_record AS record
    WHERE record.id = NEW.id;

    IF record_state <> 'completed'
        OR NOT EXISTS (
            SELECT 1
            FROM mesh_ops.outbox_event AS event
            WHERE event.public_id = record_outbox_public_id
              AND event.workspace_id = record_workspace_id
              AND event.network_id IS NOT DISTINCT FROM record_network_id
              AND event.aggregate_public_id = record_result_public_id
              AND event.network_revision IS NOT DISTINCT FROM record_result_network_revision
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'idempotency completion evidence is missing';
    END IF;
    RETURN NULL;
END;
$function$;

CREATE TRIGGER idempotency_record_transition
BEFORE UPDATE OR DELETE ON mesh_ops.idempotency_record
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_idempotency_record_transition();

CREATE CONSTRAINT TRIGGER idempotency_record_completion
AFTER INSERT OR UPDATE ON mesh_ops.idempotency_record
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_idempotency_record_completion();

ALTER TABLE mesh_ops.idempotency_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.idempotency_record FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_record_migrator_policy ON mesh_ops.idempotency_record
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY idempotency_record_exact_scope_policy ON mesh_ops.idempotency_record
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IS NOT DISTINCT FROM mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IS NOT DISTINCT FROM mesh_ops.current_network_id()
    );

REVOKE ALL ON mesh_ops.idempotency_record
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON SEQUENCE mesh_ops.idempotency_record_id_seq
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_idempotency_record_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.enforce_idempotency_record_completion() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.claim_network_idempotency(
    UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_network_idempotency(
    UUID, TEXT, TEXT, BYTEA
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.complete_network_idempotency(
    UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT,
    JSONB, UUID, TIMESTAMPTZ
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mesh_ops.claim_network_idempotency(
    UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.load_network_idempotency(
    UUID, TEXT, TEXT, BYTEA
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.complete_network_idempotency(
    UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT,
    JSONB, UUID, TIMESTAMPTZ
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
