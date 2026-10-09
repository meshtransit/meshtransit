-- Schema 136 (R1-69 increment B): enforcement evidence enters the audit trail
-- and the time machine.
--
-- Each Device reports the policy digest of the rules its packet filter
-- enforces; the control plane keeps the last delivery and report in Redis.
-- The enforcement-ledger worker classifies every active or suspended Device
-- as the distribution read does and records what it observed here:
--
-- * device_enforcement_history keeps validity intervals per Device: whether
--   it enforced the delivered rules ('enforced') or other rules ('mismatch'),
--   with both digests, the Network revision and the times. A new interval
--   opens when the state or either digest changes. Applying, unreported and
--   unknown observations change nothing: the last evidence stands.
-- * device_enforcement_event is written for each change into or out of
--   'mismatch'. The authority mutation trigger covers the insert, so the event
--   cannot be written without its sealed audit event
--   (device.enforcement_mismatch or device.enforcement_restored) on the
--   Network stream in the same transaction.
--
-- Known limits: evidence lags the Device by the delivery grace and the poll
-- interval, and a mismatch shorter than that may not be recorded. Retention
-- is 13 months, as for audit and the access edge ledger.

CREATE TABLE mesh_ops.device_enforcement_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_public_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('enforced', 'mismatch')),
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    delivered_digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(delivered_digest) = 32),
    delivered_grants INTEGER NOT NULL CHECK (delivered_grants BETWEEN 0 AND 1048576),
    enforced_digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(enforced_digest) = 32),
    enforced_grants INTEGER NOT NULL CHECK (enforced_grants BETWEEN 0 AND 1048576),
    applied_at TIMESTAMPTZ NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ,
    CONSTRAINT device_enforcement_history_state_digest_check CHECK (
        (state = 'enforced') = (delivered_digest = enforced_digest)
    ),
    CONSTRAINT device_enforcement_history_interval_check CHECK (valid_to IS NULL OR valid_to >= valid_from),
    CONSTRAINT device_enforcement_history_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX device_enforcement_history_open_uidx
    ON mesh_ops.device_enforcement_history (workspace_id, network_id, device_public_id)
    WHERE valid_to IS NULL;
CREATE INDEX device_enforcement_history_device_idx
    ON mesh_ops.device_enforcement_history (workspace_id, network_id, device_public_id, valid_from DESC);
CREATE INDEX device_enforcement_history_closed_idx
    ON mesh_ops.device_enforcement_history (valid_to)
    WHERE valid_to IS NOT NULL;

-- One row per audited change. version and public_id let the authority
-- mutation trigger cover the insert.
CREATE TABLE mesh_ops.device_enforcement_event (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_public_id UUID NOT NULL,
    hostname TEXT NOT NULL CHECK (pg_catalog.length(hostname) BETWEEN 1 AND 253),
    action TEXT NOT NULL CHECK (action IN ('device.enforcement_mismatch', 'device.enforcement_restored')),
    previous_state TEXT CHECK (previous_state IN ('enforced', 'mismatch')),
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    delivered_digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(delivered_digest) = 32),
    delivered_grants INTEGER NOT NULL CHECK (delivered_grants BETWEEN 0 AND 1048576),
    enforced_digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(enforced_digest) = 32),
    enforced_grants INTEGER NOT NULL CHECK (enforced_grants BETWEEN 0 AND 1048576),
    applied_at TIMESTAMPTZ NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_enforcement_event_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_enforcement_event_action_digest_check CHECK (
        (action = 'device.enforcement_mismatch' AND delivered_digest <> enforced_digest
            AND previous_state IS DISTINCT FROM 'mismatch')
        OR (action = 'device.enforcement_restored' AND delivered_digest = enforced_digest
            AND previous_state = 'mismatch')
    ),
    CONSTRAINT device_enforcement_event_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX device_enforcement_event_time_idx
    ON mesh_ops.device_enforcement_event (observed_at);

ALTER TABLE mesh_ops.device_enforcement_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.device_enforcement_history FORCE ROW LEVEL SECURITY;
CREATE POLICY device_enforcement_history_migrator_policy ON mesh_ops.device_enforcement_history
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.device_enforcement_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.device_enforcement_event FORCE ROW LEVEL SECURITY;
CREATE POLICY device_enforcement_event_migrator_policy ON mesh_ops.device_enforcement_event
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

CREATE TRIGGER device_enforcement_event_authority_mutation
AFTER INSERT ON mesh_ops.device_enforcement_event
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_enforcement_event', 'public_id');

-- Resolves one Network of the installation and sets its exact scope for the
-- rest of the transaction. Workspace and Network rows are readable by the
-- owner only while mesh.access_ledger_scan is on (schema 134).
CREATE FUNCTION mesh_ops.enforcement_scope_internal_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    OUT workspace_id BIGINT, OUT network_id BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT network.workspace_id, network.id
    INTO workspace_id, network_id
    FROM mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND workspace.public_id = p_workspace_public_id
      AND network.public_id = p_network_public_id
      AND network.state <> 'deleted';
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    IF network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enforcement ledger scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', network_id::TEXT, TRUE);
END;
$function$;

-- One page of the installation's Networks, ordered by public ID.
CREATE FUNCTION mesh_ops.list_enforcement_networks_v1(
    p_deployment_public_id UUID, p_after_network_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    IF p_deployment_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid enforcement ledger discovery input';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT pg_catalog.jsonb_build_object('items', COALESCE(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object('workspace_id', page.workspace_public_id, 'network_id', page.network_public_id)
        ORDER BY page.network_public_id), '[]'::JSONB))
    FROM (
        SELECT workspace.public_id AS workspace_public_id, network.public_id AS network_public_id
        FROM mesh.network AS network
        JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
        JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND network.state <> 'deleted'
          AND (p_after_network_public_id IS NULL OR network.public_id > p_after_network_public_id)
        ORDER BY network.public_id
        LIMIT p_limit
    ) AS page
    INTO v_result;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    RETURN v_result;
END;
$function$;

-- One page of a Network's active or suspended Devices with their open
-- enforcement interval, if any.
CREATE FUNCTION mesh_ops.list_enforcement_devices_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_after_device_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_scope RECORD;
    v_result JSONB;
BEGIN
    IF p_deployment_public_id IS NULL OR p_workspace_public_id IS NULL OR p_network_public_id IS NULL
        OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid enforcement ledger device input';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.enforcement_scope_internal_v1(
        p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    SELECT pg_catalog.jsonb_build_object('items', COALESCE(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'device_id', page.public_id,
            'state', open.state,
            'delivered_digest', pg_catalog.encode(open.delivered_digest, 'hex'),
            'enforced_digest', pg_catalog.encode(open.enforced_digest, 'hex')
        ) ORDER BY page.public_id), '[]'::JSONB))
    FROM (
        SELECT device.public_id
        FROM mesh.device AS device
        WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
          AND device.deleted_at IS NULL AND device.state IN ('active', 'suspended')
          AND (p_after_device_public_id IS NULL OR device.public_id > p_after_device_public_id)
        ORDER BY device.public_id
        LIMIT p_limit
    ) AS page
    LEFT JOIN mesh_ops.device_enforcement_history AS open
      ON open.workspace_id = v_scope.workspace_id AND open.network_id = v_scope.network_id
     AND open.device_public_id = page.public_id AND open.valid_to IS NULL
    INTO v_result;
    RETURN v_result;
END;
$function$;

CREATE FUNCTION mesh_ops.device_enforcement_event_payload_internal_v1(p_event_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'format', 'device-enforcement/v1',
        'event_id', event.public_id,
        'device_id', event.device_public_id,
        'hostname', event.hostname,
        'previous_state', event.previous_state,
        'state', CASE WHEN event.action = 'device.enforcement_mismatch' THEN 'mismatch' ELSE 'enforced' END,
        'network_revision', event.network_revision,
        'delivered_digest', 'sha256:' || pg_catalog.encode(event.delivered_digest, 'hex'),
        'delivered_grants', event.delivered_grants,
        'enforced_digest', 'sha256:' || pg_catalog.encode(event.enforced_digest, 'hex'),
        'enforced_grants', event.enforced_grants,
        'applied_at', event.applied_at,
        'reported_at', event.reported_at,
        'observed_at', event.observed_at
    )
    FROM mesh_ops.device_enforcement_event AS event
    WHERE event.id = p_event_id
$function$;

-- Records one observation of one Device. Returns recorded=false when the open
-- interval already says the same, or another worker holds the Device. A
-- change into or out of 'mismatch' also writes the event under p_change,
-- locks the Network audit stream and returns the head and payload for the
-- caller to hash and append.
CREATE FUNCTION mesh_ops.record_device_enforcement_v1(
    p_deployment_public_id UUID,
    p_workspace_public_id UUID,
    p_network_public_id UUID,
    p_device_public_id UUID,
    p_network_revision BIGINT,
    p_delivered_digest BYTEA,
    p_delivered_grants INTEGER,
    p_enforced_digest BYTEA,
    p_enforced_grants INTEGER,
    p_applied_at TIMESTAMPTZ,
    p_reported_at TIMESTAMPTZ,
    p_event_public_id UUID,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    v_scope RECORD;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_state TEXT;
    v_hostname TEXT;
    v_open mesh_ops.device_enforcement_history%ROWTYPE;
    v_action TEXT;
    v_event_id BIGINT;
    v_stream RECORD;
BEGIN
    IF p_deployment_public_id IS NULL OR p_workspace_public_id IS NULL OR p_network_public_id IS NULL
        OR p_device_public_id IS NULL OR p_network_revision IS NULL OR p_network_revision < 1
        OR p_delivered_digest IS NULL OR pg_catalog.octet_length(p_delivered_digest) <> 32
        OR p_enforced_digest IS NULL OR pg_catalog.octet_length(p_enforced_digest) <> 32
        OR p_delivered_grants IS NULL OR p_delivered_grants NOT BETWEEN 0 AND 1048576
        OR p_enforced_grants IS NULL OR p_enforced_grants NOT BETWEEN 0 AND 1048576
        OR p_applied_at IS NULL OR p_reported_at IS NULL OR p_applied_at > p_reported_at
        OR p_reported_at > v_now + INTERVAL '1 minute'
        OR p_event_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_event_public_id = p_change_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid enforcement ledger input';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.enforcement_scope_internal_v1(
        p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    SELECT device.hostname INTO v_hostname
    FROM mesh.device AS device
    WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
      AND device.public_id = p_device_public_id
      AND device.deleted_at IS NULL AND device.state IN ('active', 'suspended');
    IF v_hostname IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enforcement ledger Device is unavailable';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(
        pg_catalog.hashtextextended('meshtransit/enforcement-ledger/' || p_device_public_id::TEXT, 0)) THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', TRUE, 'audited', FALSE);
    END IF;

    v_state := CASE WHEN p_delivered_digest = p_enforced_digest THEN 'enforced' ELSE 'mismatch' END;
    SELECT history.* INTO v_open
    FROM mesh_ops.device_enforcement_history AS history
    WHERE history.workspace_id = v_scope.workspace_id AND history.network_id = v_scope.network_id
      AND history.device_public_id = p_device_public_id AND history.valid_to IS NULL
    FOR UPDATE;
    IF v_open.id IS NOT NULL AND v_open.state = v_state
        AND v_open.delivered_digest = p_delivered_digest AND v_open.enforced_digest = p_enforced_digest THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', FALSE, 'audited', FALSE);
    END IF;
    IF v_open.id IS NOT NULL THEN
        UPDATE mesh_ops.device_enforcement_history SET valid_to = GREATEST(v_now, v_open.valid_from)
        WHERE id = v_open.id;
    END IF;
    INSERT INTO mesh_ops.device_enforcement_history (
        workspace_id, network_id, device_public_id, state, network_revision,
        delivered_digest, delivered_grants, enforced_digest, enforced_grants,
        applied_at, reported_at, valid_from
    ) VALUES (
        v_scope.workspace_id, v_scope.network_id, p_device_public_id, v_state, p_network_revision,
        p_delivered_digest, p_delivered_grants, p_enforced_digest, p_enforced_grants,
        p_applied_at, p_reported_at, v_now
    );

    v_action := CASE
        WHEN v_state = 'mismatch' AND v_open.state IS DISTINCT FROM 'mismatch' THEN 'device.enforcement_mismatch'
        WHEN v_state = 'enforced' AND v_open.state = 'mismatch' THEN 'device.enforcement_restored'
    END;
    IF v_action IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('recorded', TRUE, 'busy', FALSE, 'audited', FALSE);
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh_ops.device_enforcement_event (
        public_id, workspace_id, network_id, device_public_id, hostname, action, previous_state,
        network_revision, delivered_digest, delivered_grants, enforced_digest, enforced_grants,
        applied_at, reported_at, observed_at
    ) VALUES (
        p_event_public_id, v_scope.workspace_id, v_scope.network_id, p_device_public_id, v_hostname,
        v_action, v_open.state, p_network_revision, p_delivered_digest, p_delivered_grants,
        p_enforced_digest, p_enforced_grants, p_applied_at, p_reported_at, v_now
    )
    RETURNING id INTO v_event_id;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_scope.workspace_id AND stream.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;

    RETURN pg_catalog.jsonb_build_object(
        'recorded', TRUE,
        'busy', FALSE,
        'audited', TRUE,
        'event_id', p_event_public_id,
        'action', v_action,
        'network_revision', p_network_revision,
        'digest', pg_catalog.encode(p_enforced_digest, 'hex'),
        'stream_id', v_stream.id,
        'sequence', v_stream.next_sequence,
        'previous_hash', pg_catalog.encode(v_stream.latest_event_hash, 'hex'),
        'payload', mesh_ops.device_enforcement_event_payload_internal_v1(v_event_id)::TEXT
    );
END;
$function$;

-- Appends the audit event for the enforcement event written by
-- record_device_enforcement_v1 in this transaction and change.
CREATE FUNCTION mesh_ops.append_device_enforcement_evidence_v1(
    p_event_public_id UUID,
    p_stream_id BIGINT,
    p_sequence BIGINT,
    p_previous_hash BYTEA,
    p_event_hash BYTEA,
    p_audit_event_public_id UUID,
    p_outbox_public_id UUID,
    p_payload JSONB
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    v_change UUID;
    v_transaction BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    v_event mesh_ops.device_enforcement_event%ROWTYPE;
BEGIN
    BEGIN
        v_change := NULLIF(pg_catalog.current_setting('mesh.change_public_id', TRUE), '')::UUID;
    EXCEPTION WHEN invalid_text_representation THEN
        v_change := NULL;
    END;
    IF v_change IS NULL OR p_event_public_id IS NULL OR p_stream_id IS NULL
        OR p_sequence IS NULL OR p_sequence <= 0
        OR p_previous_hash IS NULL OR pg_catalog.octet_length(p_previous_hash) <> 32
        OR p_event_hash IS NULL OR pg_catalog.octet_length(p_event_hash) <> 32
        OR p_audit_event_public_id IS NULL OR p_outbox_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_audit_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_outbox_public_id), 6) >> 4 <> 7
        OR p_audit_event_public_id = p_outbox_public_id
        OR p_audit_event_public_id IN (v_change, p_event_public_id)
        OR p_outbox_public_id IN (v_change, p_event_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid enforcement ledger evidence';
    END IF;
    SELECT event.* INTO v_event
    FROM mesh_ops.device_enforcement_event AS event
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
     AND mutation.aggregate_kind = 'device_enforcement_event' AND mutation.row_public_id = event.public_id
     AND mutation.operation = 'insert' AND mutation.after_version = 1
    JOIN mesh_audit.audit_stream AS stream
      ON stream.id = p_stream_id AND stream.scope_kind = 'network'
     AND stream.workspace_id = event.workspace_id AND stream.network_id = event.network_id
    WHERE event.public_id = p_event_public_id;
    IF v_event.id IS NULL
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR p_payload IS DISTINCT FROM mesh_ops.device_enforcement_event_payload_internal_v1(v_event.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid enforcement ledger evidence';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_audit_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'device_enforcement_event', v_event.public_id, 1, v_event.network_revision, NULL::UUID,
        v_event.action, 'system.reconcile', NULL::UUID, NULL::BYTEA, v_event.enforced_digest,
        p_payload, v_event.action, p_payload
    );
END;
$function$;

-- Removes closed intervals and events older than 13 months. Bounded per
-- call; returns rows removed.
CREATE FUNCTION mesh_ops.prune_device_enforcement_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_cutoff TIMESTAMPTZ := pg_catalog.clock_timestamp() - INTERVAL '13 months';
    v_deployment_id BIGINT;
    v_history INTEGER;
    v_events INTEGER;
BEGIN
    IF p_deployment_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid enforcement ledger retention input';
    END IF;
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enforcement ledger installation is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    WITH doomed AS (
        SELECT history.id
        FROM mesh_ops.device_enforcement_history AS history
        JOIN mesh.workspace AS workspace ON workspace.id = history.workspace_id
        WHERE workspace.deployment_id = v_deployment_id
          AND history.valid_to IS NOT NULL AND history.valid_to < v_cutoff
        ORDER BY history.valid_to
        LIMIT p_limit
    )
    DELETE FROM mesh_ops.device_enforcement_history AS history
    USING doomed WHERE history.id = doomed.id;
    GET DIAGNOSTICS v_history = ROW_COUNT;
    WITH doomed AS (
        SELECT event.id
        FROM mesh_ops.device_enforcement_event AS event
        JOIN mesh.workspace AS workspace ON workspace.id = event.workspace_id
        WHERE workspace.deployment_id = v_deployment_id AND event.observed_at < v_cutoff
        ORDER BY event.observed_at
        LIMIT GREATEST(p_limit - v_history, 0)
    )
    DELETE FROM mesh_ops.device_enforcement_event AS event
    USING doomed WHERE event.id = doomed.id;
    GET DIAGNOSTICS v_events = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    RETURN v_history + v_events;
END;
$function$;

-- The time machine read: what each Device was shown to enforce at p_at, under
-- the same exact-scope device.read authority as the Device inventory. Devices
-- without evidence at that time are absent. Returns NULL when the scope or
-- authority does not resolve.
CREATE FUNCTION mesh_ops.read_device_enforcement_history_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_at TIMESTAMPTZ,
    p_after_device_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace BIGINT;
    resolved_network BIGINT;
    v_since TIMESTAMPTZ;
    result JSONB;
BEGIN
    IF p_at IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 101 OR
       (p_after_device_public_id IS NOT NULL AND
        pg_catalog.get_byte(pg_catalog.uuid_send(p_after_device_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid enforcement history input';
    END IF;
    BEGIN
        SELECT workspace_internal_id, network_internal_id
        INTO resolved_workspace, resolved_network
        FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    EXCEPTION WHEN foreign_key_violation OR insufficient_privilege THEN
        RETURN NULL;
    END;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
        )
    ) THEN
        RETURN NULL;
    END IF;
    SELECT pg_catalog.min(history.valid_from) INTO v_since
    FROM mesh_ops.device_enforcement_history AS history
    WHERE history.workspace_id = resolved_workspace AND history.network_id = resolved_network;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id,
        'network_id', p_network_public_id,
        'at', p_at,
        'recorded_since', v_since,
        'devices', COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id', page.device_public_id,
            'hostname', device.hostname,
            'state', page.state,
            'network_revision', page.network_revision,
            'delivered_digest', 'sha256:' || pg_catalog.encode(page.delivered_digest, 'hex'),
            'delivered_grants', page.delivered_grants,
            'enforced_digest', 'sha256:' || pg_catalog.encode(page.enforced_digest, 'hex'),
            'enforced_grants', page.enforced_grants,
            'applied_at', page.applied_at,
            'reported_at', page.reported_at,
            'valid_from', page.valid_from,
            'valid_to', page.valid_to
        ) ORDER BY page.device_public_id), '[]'::JSONB)
    ) INTO result
    FROM (
        SELECT history.*
        FROM mesh_ops.device_enforcement_history AS history
        WHERE history.workspace_id = resolved_workspace AND history.network_id = resolved_network
          AND history.valid_from <= p_at AND (history.valid_to IS NULL OR history.valid_to > p_at)
          AND (p_after_device_public_id IS NULL OR history.device_public_id > p_after_device_public_id)
        ORDER BY history.device_public_id
        LIMIT p_limit
    ) AS page
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = resolved_workspace AND device.network_id = resolved_network
     AND device.public_id = page.device_public_id;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforcement_scope_internal_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.device_enforcement_event_payload_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_enforcement_networks_v1(UUID, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_enforcement_devices_v1(UUID, UUID, UUID, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_device_enforcement_v1(
    UUID, UUID, UUID, UUID, BIGINT, BYTEA, INTEGER, BYTEA, INTEGER, TIMESTAMPTZ, TIMESTAMPTZ, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.append_device_enforcement_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prune_device_enforcement_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_enforcement_networks_v1(UUID, UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.list_enforcement_devices_v1(UUID, UUID, UUID, UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.record_device_enforcement_v1(
    UUID, UUID, UUID, UUID, BIGINT, BYTEA, INTEGER, BYTEA, INTEGER, TIMESTAMPTZ, TIMESTAMPTZ, UUID, UUID
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.append_device_enforcement_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_device_enforcement_v1(UUID, INTEGER) TO mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.read_device_enforcement_history_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_device_enforcement_history_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
