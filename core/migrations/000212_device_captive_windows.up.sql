-- Schema 212: captive portal windows enter the audit trail (exit node design
-- §17.12, C6). Root on a Device that uses an exit node may open a short
-- window to sign in to a hotel or airport Wi-Fi; the Device reports each
-- window once it reaches Core again: when it opened and closed and how it
-- ended, never the portal's address, which would tell where the Device was.
--
-- The control plane records each window as a device_captive_window row under
-- the Device's Network, in the same transaction as its sealed audit event
-- (device.captive_window, system.reconcile, no actor): the authority
-- mutation trigger covers the insert. A window is recorded once per Device
-- by its ID; a Device records at most 48 windows a day, so a compromised one
-- cannot flood its Network's stream. Retention is 13 months, as for audit.

CREATE TABLE mesh_ops.device_captive_window (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_public_id UUID NOT NULL,
    hostname TEXT NOT NULL CHECK (pg_catalog.length(hostname) BETWEEN 1 AND 253),
    window_id TEXT NOT NULL CHECK (window_id ~ '^[0-9a-f]{32}$'),
    opened_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ NOT NULL,
    ended TEXT NOT NULL CHECK (ended IN ('expired', 'closed', 'tunnel_back')),
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    recorded_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_captive_window_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_captive_window_times_check CHECK (
        closed_at >= opened_at AND closed_at - opened_at <= INTERVAL '6 minutes'
    ),
    CONSTRAINT device_captive_window_once_uidx UNIQUE (workspace_id, network_id, device_public_id, window_id),
    CONSTRAINT device_captive_window_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX device_captive_window_device_idx
    ON mesh_ops.device_captive_window (workspace_id, network_id, device_public_id, recorded_at DESC);
CREATE INDEX device_captive_window_time_idx ON mesh_ops.device_captive_window (recorded_at);

ALTER TABLE mesh_ops.device_captive_window ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.device_captive_window FORCE ROW LEVEL SECURITY;
CREATE POLICY device_captive_window_migrator_policy ON mesh_ops.device_captive_window
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

CREATE TRIGGER device_captive_window_authority_mutation
AFTER INSERT ON mesh_ops.device_captive_window
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_captive_window', 'public_id');

CREATE FUNCTION mesh_ops.device_captive_window_payload_internal_v1(p_window_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'format', 'device-captive-window/v1',
        'event_id', captive.public_id,
        'device_id', captive.device_public_id,
        'hostname', captive.hostname,
        'window_id', captive.window_id,
        'opened_at', captive.opened_at,
        'closed_at', captive.closed_at,
        'seconds', pg_catalog.floor(pg_catalog.date_part('epoch', captive.closed_at - captive.opened_at))::INTEGER,
        'ended', captive.ended,
        'recorded_at', captive.recorded_at
    )
    FROM mesh_ops.device_captive_window AS captive
    WHERE captive.id = p_window_id
$function$;

-- Records one captive portal window a Device reported. Returns
-- recorded=false for a window recorded before, or past the Device's daily
-- budget. Otherwise writes the row under p_change, locks the Network audit
-- stream and returns the head, payload and semantic hash for the caller to
-- hash and append. p_device_public_id is the Device of the authenticated map
-- session that reported it.
CREATE FUNCTION mesh_ops.record_device_captive_window_v1(
    p_workspace_public_id UUID,
    p_network_public_id UUID,
    p_device_public_id UUID,
    p_window_id TEXT,
    p_opened_at TIMESTAMPTZ,
    p_closed_at TIMESTAMPTZ,
    p_ended TEXT,
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
    v_hostname TEXT;
    v_revision BIGINT;
    v_row_id BIGINT;
    v_stream RECORD;
    v_payload JSONB;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_device_public_id IS NULL
        OR p_window_id IS NULL OR p_window_id !~ '^[0-9a-f]{32}$'
        OR p_opened_at IS NULL OR p_closed_at IS NULL OR p_closed_at < p_opened_at
        OR p_closed_at - p_opened_at > INTERVAL '6 minutes'
        OR p_closed_at > v_now + INTERVAL '1 minute' OR p_opened_at < v_now - INTERVAL '30 days'
        OR p_ended IS NULL OR p_ended NOT IN ('expired', 'closed', 'tunnel_back')
        OR p_event_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_event_public_id = p_change_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid captive portal window';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    SELECT device.hostname INTO v_hostname
    FROM mesh.device AS device
    WHERE device.workspace_id = v_scope.workspace_internal_id AND device.network_id = v_scope.network_internal_id
      AND device.public_id = p_device_public_id
      AND device.deleted_at IS NULL AND device.state IN ('active', 'suspended');
    IF v_hostname IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'captive portal window Device is unavailable';
    END IF;
    -- One Device's reports serialize; another session's is not waited for.
    IF NOT pg_catalog.pg_try_advisory_xact_lock(
        pg_catalog.hashtextextended('meshtransit/captive-window/' || p_device_public_id::TEXT, 0)) THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', TRUE, 'limited', FALSE);
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh_ops.device_captive_window AS captive
        WHERE captive.workspace_id = v_scope.workspace_internal_id
          AND captive.network_id = v_scope.network_internal_id
          AND captive.device_public_id = p_device_public_id AND captive.window_id = p_window_id
    ) THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', FALSE, 'limited', FALSE);
    END IF;
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.device_captive_window AS captive
        WHERE captive.workspace_id = v_scope.workspace_internal_id
          AND captive.network_id = v_scope.network_internal_id
          AND captive.device_public_id = p_device_public_id
          AND captive.recorded_at > v_now - INTERVAL '1 day') >= 48 THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', FALSE, 'limited', TRUE);
    END IF;
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_internal_id
      AND revision.network_id = v_scope.network_internal_id;
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh_ops.device_captive_window (
        public_id, workspace_id, network_id, device_public_id, hostname, window_id, opened_at, closed_at,
        ended, network_revision, recorded_at
    ) VALUES (
        p_event_public_id, v_scope.workspace_internal_id, v_scope.network_internal_id, p_device_public_id,
        v_hostname, p_window_id, p_opened_at, p_closed_at, p_ended, v_revision, v_now
    )
    RETURNING id INTO v_row_id;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_scope.workspace_internal_id AND stream.network_id = v_scope.network_internal_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    v_payload := mesh_ops.device_captive_window_payload_internal_v1(v_row_id);

    RETURN pg_catalog.jsonb_build_object(
        'recorded', TRUE,
        'busy', FALSE,
        'limited', FALSE,
        'event_id', p_event_public_id,
        'network_revision', v_revision,
        'semantic_hash', pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_payload::TEXT, 'UTF8')), 'hex'),
        'stream_id', v_stream.id,
        'sequence', v_stream.next_sequence,
        'previous_hash', pg_catalog.encode(v_stream.latest_event_hash, 'hex'),
        'payload', v_payload::TEXT
    );
END;
$function$;

-- Appends the audit event of the window record_device_captive_window_v1
-- wrote in this transaction and change.
CREATE FUNCTION mesh_ops.append_device_captive_window_evidence_v1(
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
    v_window mesh_ops.device_captive_window%ROWTYPE;
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
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid captive portal window evidence';
    END IF;
    SELECT captive.* INTO v_window
    FROM mesh_ops.device_captive_window AS captive
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
     AND mutation.aggregate_kind = 'device_captive_window' AND mutation.row_public_id = captive.public_id
     AND mutation.operation = 'insert' AND mutation.after_version = 1
    JOIN mesh_audit.audit_stream AS stream
      ON stream.id = p_stream_id AND stream.scope_kind = 'network'
     AND stream.workspace_id = captive.workspace_id AND stream.network_id = captive.network_id
    WHERE captive.public_id = p_event_public_id;
    IF v_window.id IS NULL
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR p_payload IS DISTINCT FROM mesh_ops.device_captive_window_payload_internal_v1(v_window.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid captive portal window evidence';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_audit_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'device_captive_window', v_window.public_id, 1, v_window.network_revision, NULL::UUID,
        'device.captive_window', 'system.reconcile', NULL::UUID, NULL::BYTEA,
        pg_catalog.sha256(pg_catalog.convert_to(p_payload::TEXT, 'UTF8')),
        p_payload, 'device.captive_window', p_payload
    );
END;
$function$;

-- Removes the installation's windows older than 13 months; bounded per call.
CREATE FUNCTION mesh_ops.prune_device_captive_windows_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_removed INTEGER;
BEGIN
    IF p_deployment_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid captive portal window retention input';
    END IF;
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'captive portal window installation is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    WITH doomed AS (
        SELECT captive.id
        FROM mesh_ops.device_captive_window AS captive
        JOIN mesh.workspace AS workspace ON workspace.id = captive.workspace_id
        WHERE workspace.deployment_id = v_deployment_id
          AND captive.recorded_at < pg_catalog.clock_timestamp() - INTERVAL '13 months'
        ORDER BY captive.recorded_at
        LIMIT p_limit
    )
    DELETE FROM mesh_ops.device_captive_window AS captive
    USING doomed WHERE captive.id = doomed.id;
    GET DIAGNOSTICS v_removed = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    RETURN v_removed;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.device_captive_window_payload_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_device_captive_window_v1(
    UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.append_device_captive_window_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prune_device_captive_windows_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- The control plane records what its map sessions' Devices report.
GRANT EXECUTE ON FUNCTION mesh_ops.record_device_captive_window_v1(
    UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, UUID
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.append_device_captive_window_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) TO mesh_runtime;
-- The enforcement ledger worker prunes them with its own rows.
GRANT EXECUTE ON FUNCTION mesh_ops.prune_device_captive_windows_v1(UUID, INTEGER) TO mesh_worker;
