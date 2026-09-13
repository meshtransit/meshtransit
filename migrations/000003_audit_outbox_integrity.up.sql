DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
    EXECUTE pg_catalog.format(
        'GRANT CONNECT ON DATABASE %I TO mesh_runtime, mesh_worker',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

CREATE TABLE mesh_ops.outbox_event (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    change_public_id UUID NOT NULL,
    transaction_id BIGINT NOT NULL CHECK (transaction_id > 0),
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT,
    network_id BIGINT,
    aggregate_kind TEXT NOT NULL,
    aggregate_public_id UUID NOT NULL,
    aggregate_version BIGINT NOT NULL CHECK (aggregate_version > 0),
    network_revision BIGINT,
    event_class TEXT NOT NULL,
    payload_version INTEGER NOT NULL DEFAULT 1 CHECK (payload_version > 0),
    payload JSONB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    available_at TIMESTAMPTZ NOT NULL,
    claim_token UUID,
    claimed_by TEXT,
    claimed_at TIMESTAMPTZ,
    claim_expires_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT outbox_event_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT outbox_event_change_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(change_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT outbox_event_aggregate_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(aggregate_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT outbox_event_scope_check CHECK (
        network_id IS NULL OR workspace_id IS NOT NULL
    ),
    CONSTRAINT outbox_event_revision_scope_check CHECK (
        (network_id IS NULL AND network_revision IS NULL)
        OR (network_id IS NOT NULL AND network_revision IS NOT NULL AND network_revision > 0)
    ),
    CONSTRAINT outbox_event_aggregate_kind_check CHECK (
        pg_catalog.char_length(aggregate_kind) BETWEEN 1 AND 64
        AND aggregate_kind ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT outbox_event_class_check CHECK (
        pg_catalog.char_length(event_class) BETWEEN 1 AND 128
        AND event_class ~ '^[a-z][a-z0-9_.]*$'
    ),
    CONSTRAINT outbox_event_payload_check CHECK (
        pg_catalog.jsonb_typeof(payload) = 'object'
        AND pg_catalog.octet_length(payload::TEXT) <= 16384
    ),
    CONSTRAINT outbox_event_state_check CHECK (
        state IN ('pending', 'claimed', 'delivered', 'terminal')
    ),
    CONSTRAINT outbox_event_claimed_by_check CHECK (
        claimed_by IS NULL
        OR (
            pg_catalog.char_length(claimed_by) BETWEEN 1 AND 128
            AND claimed_by = pg_catalog.btrim(claimed_by)
        )
    ),
    CONSTRAINT outbox_event_error_class_check CHECK (
        last_error_class IS NULL
        OR (
            pg_catalog.char_length(last_error_class) BETWEEN 1 AND 64
            AND last_error_class ~ '^[a-z][a-z0-9_]*$'
        )
    ),
    CONSTRAINT outbox_event_state_shape_check CHECK (
        (
            state = 'pending'
            AND claim_token IS NULL
            AND claimed_by IS NULL
            AND claimed_at IS NULL
            AND claim_expires_at IS NULL
            AND completed_at IS NULL
            AND last_error_class IS NULL
        )
        OR (
            state = 'claimed'
            AND claim_token IS NOT NULL
            AND claimed_by IS NOT NULL
            AND claimed_at IS NOT NULL
            AND claim_expires_at > claimed_at
            AND completed_at IS NULL
        )
        OR (
            state = 'delivered'
            AND claim_token IS NOT NULL
            AND claimed_by IS NOT NULL
            AND claimed_at IS NOT NULL
            AND claim_expires_at > claimed_at
            AND completed_at >= claimed_at
            AND last_error_class IS NULL
        )
        OR (
            state = 'terminal'
            AND claim_token IS NOT NULL
            AND claimed_by IS NOT NULL
            AND claimed_at IS NOT NULL
            AND claim_expires_at > claimed_at
            AND completed_at >= claimed_at
            AND last_error_class IS NOT NULL
        )
    ),
    CONSTRAINT outbox_event_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT outbox_event_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT outbox_event_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);

CREATE INDEX outbox_event_pending_idx
    ON mesh_ops.outbox_event (available_at, id)
    INCLUDE (workspace_id, network_id, event_class)
    WHERE completed_at IS NULL;
CREATE INDEX outbox_event_network_revision_idx
    ON mesh_ops.outbox_event (workspace_id, network_id, network_revision, id)
    WHERE network_id IS NOT NULL;
CREATE INDEX outbox_event_change_transaction_idx
    ON mesh_ops.outbox_event (change_public_id, transaction_id);
CREATE INDEX outbox_event_deployment_workspace_idx
    ON mesh_ops.outbox_event (deployment_id, workspace_id);

CREATE TABLE mesh_ops.outbox_attempt (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    outbox_event_id BIGINT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    worker_id TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    result TEXT NOT NULL,
    error_class TEXT,
    next_retry_at TIMESTAMPTZ,
    CONSTRAINT outbox_attempt_worker_check CHECK (
        pg_catalog.char_length(worker_id) BETWEEN 1 AND 128
        AND worker_id = pg_catalog.btrim(worker_id)
    ),
    CONSTRAINT outbox_attempt_result_check CHECK (
        result IN ('delivered', 'retry', 'terminal')
    ),
    CONSTRAINT outbox_attempt_error_class_check CHECK (
        error_class IS NULL
        OR (
            pg_catalog.char_length(error_class) BETWEEN 1 AND 64
            AND error_class ~ '^[a-z][a-z0-9_]*$'
        )
    ),
    CONSTRAINT outbox_attempt_result_shape_check CHECK (
        (result = 'delivered' AND error_class IS NULL AND next_retry_at IS NULL)
        OR (result = 'retry' AND error_class IS NOT NULL AND next_retry_at > finished_at)
        OR (result = 'terminal' AND error_class IS NOT NULL AND next_retry_at IS NULL)
    ),
    CONSTRAINT outbox_attempt_timestamps_check CHECK (finished_at >= started_at),
    CONSTRAINT outbox_attempt_event_fk FOREIGN KEY (outbox_event_id)
        REFERENCES mesh_ops.outbox_event (id) ON DELETE RESTRICT,
    UNIQUE (outbox_event_id, attempt_number)
);

CREATE TABLE mesh_audit.audit_stream (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT,
    network_id BIGINT,
    scope_kind TEXT NOT NULL,
    next_sequence BIGINT NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
    latest_event_hash BYTEA NOT NULL DEFAULT pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT audit_stream_scope_check CHECK (
        (scope_kind = 'deployment' AND workspace_id IS NULL AND network_id IS NULL)
        OR (scope_kind = 'workspace' AND workspace_id IS NOT NULL AND network_id IS NULL)
        OR (scope_kind = 'network' AND workspace_id IS NOT NULL AND network_id IS NOT NULL)
    ),
    CONSTRAINT audit_stream_hash_check CHECK (
        pg_catalog.octet_length(latest_event_hash) = 32
    ),
    CONSTRAINT audit_stream_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT audit_stream_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT audit_stream_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT audit_stream_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX audit_stream_deployment_uidx
    ON mesh_audit.audit_stream (deployment_id)
    WHERE scope_kind = 'deployment';
CREATE UNIQUE INDEX audit_stream_workspace_uidx
    ON mesh_audit.audit_stream (deployment_id, workspace_id)
    WHERE scope_kind = 'workspace';
CREATE UNIQUE INDEX audit_stream_network_uidx
    ON mesh_audit.audit_stream (workspace_id, network_id)
    WHERE scope_kind = 'network';
CREATE INDEX audit_stream_workspace_network_idx
    ON mesh_audit.audit_stream (workspace_id, network_id);

CREATE TABLE mesh_audit.audit_event_identity (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    stream_id BIGINT NOT NULL,
    stream_sequence BIGINT NOT NULL CHECK (stream_sequence > 0),
    occurred_at TIMESTAMPTZ NOT NULL,
    previous_event_hash BYTEA NOT NULL,
    event_hash BYTEA NOT NULL,
    change_public_id UUID NOT NULL,
    transaction_id BIGINT NOT NULL CHECK (transaction_id > 0),
    CONSTRAINT audit_event_identity_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT audit_event_identity_change_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(change_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT audit_event_identity_hashes_check CHECK (
        pg_catalog.octet_length(previous_event_hash) = 32
        AND pg_catalog.octet_length(event_hash) = 32
    ),
    CONSTRAINT audit_event_identity_stream_fk FOREIGN KEY (stream_id)
        REFERENCES mesh_audit.audit_stream (id) ON DELETE RESTRICT,
    UNIQUE (stream_id, stream_sequence),
    UNIQUE (id, occurred_at)
);

CREATE INDEX audit_event_identity_change_transaction_idx
    ON mesh_audit.audit_event_identity (change_public_id, transaction_id);

CREATE TABLE mesh_audit.authority_mutation (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    change_public_id UUID NOT NULL,
    transaction_id BIGINT NOT NULL CHECK (transaction_id > 0),
    aggregate_kind TEXT NOT NULL,
    row_public_id UUID NOT NULL,
    operation TEXT NOT NULL,
    before_version BIGINT,
    after_version BIGINT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
    CONSTRAINT authority_mutation_change_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(change_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT authority_mutation_row_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(row_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT authority_mutation_aggregate_kind_check CHECK (
        pg_catalog.char_length(aggregate_kind) BETWEEN 1 AND 64
        AND aggregate_kind ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT authority_mutation_operation_check CHECK (
        (operation = 'insert' AND before_version IS NULL AND after_version > 0)
        OR (
            operation = 'update'
            AND before_version > 0
            AND after_version = before_version + 1
        )
        OR (operation = 'delete' AND before_version > 0 AND after_version IS NULL)
    )
);

ALTER TABLE mesh_audit.authority_mutation
    ADD CONSTRAINT authority_mutation_change_transaction_excl
    EXCLUDE USING gist (
        change_public_id WITH =,
        transaction_id WITH <>
    );

CREATE INDEX authority_mutation_change_transaction_idx
    ON mesh_audit.authority_mutation (change_public_id, transaction_id);
CREATE INDEX authority_mutation_row_idx
    ON mesh_audit.authority_mutation (aggregate_kind, row_public_id, occurred_at DESC, id DESC);

CREATE TABLE mesh_audit.audit_event (
    event_identity_id BIGINT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT,
    network_id BIGINT,
    actor_principal_public_id UUID,
    action TEXT NOT NULL,
    permission TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_public_id UUID NOT NULL,
    before_semantic_hash BYTEA,
    after_semantic_hash BYTEA,
    correlation_public_id UUID,
    result TEXT NOT NULL,
    payload_version INTEGER NOT NULL DEFAULT 1 CHECK (payload_version > 0),
    payload JSONB NOT NULL,
    PRIMARY KEY (occurred_at, event_identity_id),
    CONSTRAINT audit_event_scope_check CHECK (
        network_id IS NULL OR workspace_id IS NOT NULL
    ),
    CONSTRAINT audit_event_actor_public_id_v7_check CHECK (
        actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(actor_principal_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT audit_event_target_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(target_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT audit_event_correlation_public_id_v7_check CHECK (
        correlation_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(correlation_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT audit_event_action_check CHECK (
        pg_catalog.char_length(action) BETWEEN 1 AND 128
        AND action ~ '^[a-z][a-z0-9_.]*$'
    ),
    CONSTRAINT audit_event_permission_check CHECK (
        pg_catalog.char_length(permission) BETWEEN 1 AND 128
        AND permission ~ '^[a-z][a-z0-9_.]*$'
    ),
    CONSTRAINT audit_event_target_kind_check CHECK (
        pg_catalog.char_length(target_kind) BETWEEN 1 AND 64
        AND target_kind ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT audit_event_hashes_check CHECK (
        (before_semantic_hash IS NULL OR pg_catalog.octet_length(before_semantic_hash) = 32)
        AND (after_semantic_hash IS NULL OR pg_catalog.octet_length(after_semantic_hash) = 32)
    ),
    CONSTRAINT audit_event_result_check CHECK (result IN ('succeeded', 'denied', 'failed')),
    CONSTRAINT audit_event_payload_check CHECK (
        pg_catalog.jsonb_typeof(payload) = 'object'
        AND pg_catalog.octet_length(payload::TEXT) <= 16384
    ),
    CONSTRAINT audit_event_identity_fk FOREIGN KEY (event_identity_id, occurred_at)
        REFERENCES mesh_audit.audit_event_identity (id, occurred_at) ON DELETE RESTRICT,
    CONSTRAINT audit_event_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT audit_event_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT audit_event_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
) PARTITION BY RANGE (occurred_at);

CREATE TABLE mesh_audit.audit_event_2026_09
    PARTITION OF mesh_audit.audit_event
    FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');
CREATE TABLE mesh_audit.audit_event_2026_10
    PARTITION OF mesh_audit.audit_event
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
CREATE TABLE mesh_audit.audit_event_default
    PARTITION OF mesh_audit.audit_event DEFAULT;

CREATE INDEX audit_event_workspace_occurred_id_idx
    ON mesh_audit.audit_event (workspace_id, occurred_at DESC, event_identity_id DESC);
CREATE INDEX audit_event_stream_scope_idx
    ON mesh_audit.audit_event (deployment_id, workspace_id, network_id, occurred_at DESC);

CREATE FUNCTION mesh_audit.capture_authority_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh_ops, mesh
AS $function$
DECLARE
    change_id UUID;
    transaction_value BIGINT;
    before_row JSONB;
    after_row JSONB;
    before_public_id UUID;
    after_public_id UUID;
    before_version_value BIGINT;
    after_version_value BIGINT;
BEGIN
    IF TG_NARGS <> 2 OR TG_ARGV[0] !~ '^[a-z][a-z0-9_]{0,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid authority mutation trigger configuration';
    END IF;

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
    IF TG_OP <> 'INSERT' THEN
        before_row := pg_catalog.to_jsonb(OLD);
        BEGIN
            before_public_id := (before_row ->> TG_ARGV[1])::UUID;
            before_version_value := (before_row ->> 'version')::BIGINT;
        EXCEPTION
            WHEN invalid_text_representation OR numeric_value_out_of_range THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid authority row identity';
        END;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        after_row := pg_catalog.to_jsonb(NEW);
        BEGIN
            after_public_id := (after_row ->> TG_ARGV[1])::UUID;
            after_version_value := (after_row ->> 'version')::BIGINT;
        EXCEPTION
            WHEN invalid_text_representation OR numeric_value_out_of_range THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid authority row identity';
        END;
    END IF;

    IF (TG_OP = 'INSERT' AND (after_public_id IS NULL OR after_version_value <= 0))
        OR (TG_OP = 'UPDATE' AND (
            before_public_id IS NULL
            OR before_public_id <> after_public_id
            OR before_version_value <= 0
            OR after_version_value <> before_version_value + 1
        ))
        OR (TG_OP = 'DELETE' AND (before_public_id IS NULL OR before_version_value <= 0)) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid authority row transition';
    END IF;

    INSERT INTO mesh_audit.authority_mutation (
        change_public_id,
        transaction_id,
        aggregate_kind,
        row_public_id,
        operation,
        before_version,
        after_version
    ) VALUES (
        change_id,
        transaction_value,
        TG_ARGV[0],
        COALESCE(after_public_id, before_public_id),
        pg_catalog.lower(TG_OP),
        before_version_value,
        after_version_value
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION mesh_audit.enforce_authority_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh_ops, mesh
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM mesh_audit.audit_event_identity AS identity
        JOIN mesh_audit.audit_event AS event
          ON event.event_identity_id = identity.id
         AND event.occurred_at = identity.occurred_at
        WHERE identity.change_public_id = NEW.change_public_id
          AND identity.transaction_id = NEW.transaction_id
    ) OR NOT EXISTS (
        SELECT 1
        FROM mesh_ops.outbox_event AS event
        WHERE event.change_public_id = NEW.change_public_id
          AND event.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'authority evidence is incomplete';
    END IF;
    RETURN NULL;
END;
$function$;

CREATE FUNCTION mesh_audit.reject_immutable_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh_ops, mesh
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'immutable security evidence cannot be changed';
END;
$function$;

CREATE FUNCTION mesh_audit.append_authority_evidence(
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

REVOKE ALL ON FUNCTION mesh_audit.capture_authority_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_audit.enforce_authority_evidence() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_audit.reject_immutable_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_audit.append_authority_evidence(
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT,
    UUID, TEXT, TEXT, UUID, BYTEA, BYTEA, JSONB, TEXT, JSONB
) FROM PUBLIC;

ALTER TABLE mesh_ops.outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.outbox_event FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_event_migrator_policy ON mesh_ops.outbox_event
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE mesh_audit.audit_stream ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.audit_stream FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_stream_migrator_policy ON mesh_audit.audit_stream
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE mesh_audit.audit_event_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.audit_event_identity FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_identity_migrator_policy ON mesh_audit.audit_event_identity
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE mesh_audit.authority_mutation ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.authority_mutation FORCE ROW LEVEL SECURITY;
CREATE POLICY authority_mutation_migrator_policy ON mesh_audit.authority_mutation
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE mesh_audit.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_migrator_policy ON mesh_audit.audit_event
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE mesh_audit.audit_event_2026_09 ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.audit_event_2026_09 FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_2026_09_migrator_policy ON mesh_audit.audit_event_2026_09
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE mesh_audit.audit_event_2026_10 ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.audit_event_2026_10 FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_2026_10_migrator_policy ON mesh_audit.audit_event_2026_10
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE mesh_audit.audit_event_default ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.audit_event_default FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_default_migrator_policy ON mesh_audit.audit_event_default
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE CONSTRAINT TRIGGER authority_mutation_evidence_check
AFTER INSERT ON mesh_audit.authority_mutation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_audit.enforce_authority_evidence();

CREATE TRIGGER deployment_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.deployment
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('deployment', 'installation_public_id');
CREATE TRIGGER principal_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.principal
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('principal', 'public_id');
CREATE TRIGGER workspace_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.workspace
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('workspace', 'public_id');
CREATE TRIGGER network_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network', 'public_id');
CREATE TRIGGER address_realm_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.address_realm
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('address_realm', 'public_id');
CREATE TRIGGER address_pool_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.address_pool
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('address_pool', 'public_id');
CREATE TRIGGER network_prefix_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_prefix
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_prefix', 'public_id');

CREATE TRIGGER audit_event_identity_immutable
BEFORE UPDATE OR DELETE ON mesh_audit.audit_event_identity
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER authority_mutation_immutable
BEFORE UPDATE OR DELETE ON mesh_audit.authority_mutation
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER audit_event_immutable
BEFORE UPDATE OR DELETE ON mesh_audit.audit_event
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER outbox_attempt_immutable
BEFORE UPDATE OR DELETE ON mesh_ops.outbox_attempt
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

REVOKE ALL ON ALL TABLES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mesh_ops FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mesh_audit FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh, mesh_ops, mesh_audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh, mesh_ops, mesh_audit FROM PUBLIC;

REVOKE ALL ON mesh_ops.outbox_event, mesh_ops.outbox_attempt
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON ALL TABLES IN SCHEMA mesh_audit
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh_ops, mesh_audit
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh_audit
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT USAGE ON SCHEMA mesh_ops, mesh_audit TO mesh_migrator;
GRANT SELECT, INSERT, UPDATE ON mesh_ops.outbox_event TO mesh_migrator;
GRANT SELECT, INSERT ON mesh_audit.audit_stream TO mesh_migrator;
GRANT UPDATE (next_sequence, latest_event_hash, updated_at)
    ON mesh_audit.audit_stream TO mesh_migrator;
GRANT SELECT, INSERT ON mesh_audit.audit_event_identity TO mesh_migrator;
GRANT SELECT, INSERT ON mesh_audit.authority_mutation TO mesh_migrator;
GRANT SELECT, INSERT ON mesh_audit.audit_event TO mesh_migrator;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA mesh_ops, mesh_audit TO mesh_migrator;
GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence(
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT,
    UUID, TEXT, TEXT, UUID, BYTEA, BYTEA, JSONB, TEXT, JSONB
) TO mesh_migrator;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
