-- Schema 246 (K1c-T, docs/k8s-k1c-t-gateway-token-handshake-design.md v2.1):
-- a Kubernetes gateway presents its pod token on every session.
--
-- kubernetes_gateway_token_proof is the ratchet of each gateway Device: once
-- a session of the Device proved its pod token, Core refuses the Device's
-- sessions without one. commit_mtcp_gateway_timestamp_v2 records the
-- handshake timestamp and the ratchet in one transaction, one per Device at
-- a time, so a session without a token on one control replica cannot slip
-- past a ratchet another replica is writing. accept_mtcp_timestamp_v3 says
-- whether the Device is ratcheted, in the read every handshake already
-- makes. Older Core keeps v2 and v1, which neither read nor write the
-- ratchet.
--
-- Sessions refused for their pod token enter the audit trail as
-- kubernetes_gateway.session_token_refused, through the bounded key event
-- reporter. The database derives an event's action from its reason, so
-- session refusals have reasons of their own (session_*). The cluster and
-- signing reads keep filtering by action, so older Core and Consoles never
-- meet them.

CREATE TABLE mesh_ops.kubernetes_gateway_token_proof (
    device_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    first_proven_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_gateway_token_proof_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE
);
ALTER TABLE mesh_ops.kubernetes_gateway_token_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_token_proof FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_token_proof_migrator_policy ON mesh_ops.kubernetes_gateway_token_proof
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_token_proof
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The gateway Device that holds p_machine_fingerprint and p_node_key as its
-- current keys now, if any, locked against other ratchet writers of the
-- same Device for this transaction. Waiting more than 2 s for the lock
-- raises 55P03, which Core answers as an unavailable check; the timeout
-- holds for this function only.
CREATE FUNCTION mesh_ops.lock_current_kubernetes_gateway_internal_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA
)
RETURNS mesh.device
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET lock_timeout = '2s'
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
BEGIN
    SELECT device.* INTO v_device
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
     AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
    WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND node_key.public_key = p_node_key AND node_key.state = 'active'
      AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp();
    IF v_device.id IS NULL THEN
        RETURN NULL;
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('meshtransit/gateway-token-proof/' || v_device.public_id::TEXT, 0));
    RETURN v_device;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_current_kubernetes_gateway_internal_v1(BYTEA, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- As v2, and whether the gateway Device holding the machine key now is
-- ratcheted: a session of it proved its pod token before.
CREATE FUNCTION mesh_ops.accept_mtcp_timestamp_v3(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_timestamp_ms BIGINT
)
RETURNS TABLE (accepted BOOLEAN, gateway BOOLEAN, machine_state TEXT, node_current BOOLEAN, token_ratcheted BOOLEAN)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_check RECORD;
    v_ratcheted BOOLEAN := FALSE;
BEGIN
    SELECT * INTO STRICT v_check
    FROM mesh_ops.accept_mtcp_timestamp_v2(p_machine_fingerprint, p_node_key, p_timestamp_ms);
    IF v_check.gateway AND v_check.machine_state = 'current' THEN
        SELECT EXISTS (
            SELECT 1
            FROM mesh.device_machine_key_epoch AS machine
            JOIN mesh.device AS device
              ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
             AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
            JOIN mesh_ops.kubernetes_gateway_token_proof AS proof ON proof.device_id = device.id
            WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
        ) INTO v_ratcheted;
    END IF;
    RETURN QUERY SELECT v_check.accepted, v_check.gateway, v_check.machine_state, v_check.node_current, v_ratcheted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.accept_mtcp_timestamp_v3(BYTEA, BYTEA, BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.accept_mtcp_timestamp_v3(BYTEA, BYTEA, BIGINT) TO mesh_runtime;

-- Records a gateway's handshake timestamp once its session proved its node
-- key, as v1, and its ratchet, one Device at a time:
--   token_required  the session proved no pod token and the Device is
--                   ratcheted (modes ratchet and required) or the mode is
--                   required; nothing is written;
--   not_committed   the keys are no longer the gateway's current ones, or
--                   the timestamp is not newer;
--   committed       written; a proven token ratchets the Device.
-- ratcheted is whether the Device is ratcheted when the function returns.
-- Mode observe commits a session without a token on a ratcheted Device:
-- Core counts what it would have refused.
CREATE FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v2(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_timestamp_ms BIGINT, p_token_proven BOOLEAN, p_mode TEXT
)
RETURNS TABLE (result TEXT, ratcheted BOOLEAN)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
    v_ratcheted BOOLEAN;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_timestamp_ms IS NULL OR p_timestamp_ms <= 0 OR p_token_proven IS NULL
        OR p_mode IS NULL OR p_mode NOT IN ('observe', 'ratchet', 'required') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid MTCP timestamp input';
    END IF;
    v_device := mesh_ops.lock_current_kubernetes_gateway_internal_v1(p_machine_fingerprint, p_node_key);
    IF v_device.id IS NULL THEN
        RETURN QUERY SELECT 'not_committed'::TEXT, FALSE;
        RETURN;
    END IF;
    -- Read after the lock: a ratchet another replica committed is seen.
    SELECT EXISTS (
        SELECT 1 FROM mesh_ops.kubernetes_gateway_token_proof AS proof WHERE proof.device_id = v_device.id
    ) INTO v_ratcheted;
    IF NOT p_token_proven AND (p_mode = 'required' OR (v_ratcheted AND p_mode = 'ratchet')) THEN
        RETURN QUERY SELECT 'token_required'::TEXT, v_ratcheted;
        RETURN;
    END IF;
    IF NOT mesh_ops.commit_mtcp_gateway_timestamp_v1(p_machine_fingerprint, p_node_key, p_timestamp_ms) THEN
        RETURN QUERY SELECT 'not_committed'::TEXT, v_ratcheted;
        RETURN;
    END IF;
    IF p_token_proven AND NOT v_ratcheted THEN
        INSERT INTO mesh_ops.kubernetes_gateway_token_proof (device_id, workspace_id, network_id, first_proven_at)
        VALUES (v_device.id, v_device.workspace_id, v_device.network_id, pg_catalog.clock_timestamp())
        ON CONFLICT (device_id) DO NOTHING;
        v_ratcheted := TRUE;
    END IF;
    RETURN QUERY SELECT 'committed'::TEXT, v_ratcheted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v2(BYTEA, BYTEA, BIGINT, BOOLEAN, TEXT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v2(BYTEA, BYTEA, BIGINT, BOOLEAN, TEXT)
    TO mesh_runtime;

-- Ratchets the gateway Device holding both keys now, for the session that
-- completed its cluster join with a pod token Core checked (mtcp-v1 §6.6).
-- FALSE when no gateway Device holds them.
CREATE FUNCTION mesh_ops.ratchet_kubernetes_gateway_token_v1(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway ratchet input';
    END IF;
    v_device := mesh_ops.lock_current_kubernetes_gateway_internal_v1(p_machine_fingerprint, p_node_key);
    IF v_device.id IS NULL THEN
        RETURN FALSE;
    END IF;
    INSERT INTO mesh_ops.kubernetes_gateway_token_proof (device_id, workspace_id, network_id, first_proven_at)
    VALUES (v_device.id, v_device.workspace_id, v_device.network_id, pg_catalog.clock_timestamp())
    ON CONFLICT (device_id) DO NOTHING;
    RETURN TRUE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.ratchet_kubernetes_gateway_token_v1(BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.ratchet_kubernetes_gateway_token_v1(BYTEA, BYTEA) TO mesh_runtime;

-- The reason CHECK swapped, with the session refusals. The table holds at
-- most 144 events per gateway and action a day for 13 months.
ALTER TABLE mesh_ops.kubernetes_gateway_key_event
    ADD CONSTRAINT kubernetes_gateway_key_event_reason_v3_check CHECK (
        (action = 'kubernetes_gateway.stale_key_presented' AND reason IN ('retired_machine_key', 'stale_node_key'))
        OR (action = 'kubernetes_gateway.keys_contested' AND reason IN ('session_fight', 'replayed_handshake'))
        OR (action = 'kubernetes_gateway.rotation_token_refused' AND reason IN (
            'token_missing', 'token_malformed', 'token_unknown_key', 'token_signature', 'token_expired',
            'token_audience', 'token_identity', 'trust_missing', 'trust_unavailable'
        ))
        OR (action = 'kubernetes_gateway.session_token_refused' AND reason IN (
            'session_token_missing', 'session_token_malformed', 'session_token_unknown_key',
            'session_token_signature', 'session_token_expired', 'session_token_audience',
            'session_token_identity', 'session_trust_missing', 'session_trust_unavailable', 'session_clock_skew'
        ))
    ) NOT VALID;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event VALIDATE CONSTRAINT kubernetes_gateway_key_event_reason_v3_check;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event DROP CONSTRAINT kubernetes_gateway_key_event_reason_v2_check;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event
    ADD CONSTRAINT kubernetes_gateway_key_event_token_kid_v2_check CHECK (
        token_kid IS NULL OR (reason IN ('token_unknown_key', 'session_token_unknown_key')
            AND pg_catalog.octet_length(token_kid) BETWEEN 1 AND 128 AND token_kid ~ '^[!-~]+$')
    ) NOT VALID;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event
    VALIDATE CONSTRAINT kubernetes_gateway_key_event_token_kid_v2_check;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event DROP CONSTRAINT kubernetes_gateway_key_event_token_kid_check;

-- As in schema 235, with the session refusals; its parameters do not
-- change, so Core 235 to 245 call it as before and never send them.
CREATE OR REPLACE FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v3(
    p_machine_fingerprint BYTEA,
    p_reason TEXT,
    p_suppressed INTEGER,
    p_event_public_id UUID,
    p_change_public_id UUID,
    p_token_kid TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_action TEXT;
    v_device mesh.device%ROWTYPE;
    v_key_state TEXT;
    v_workspace_public UUID;
    v_network_public UUID;
    v_session_workspace TEXT;
    v_session_network TEXT;
    v_scope RECORD;
    v_revision BIGINT;
    v_row_id BIGINT;
    v_stream RECORD;
    v_payload JSONB;
BEGIN
    v_action := CASE
        WHEN p_reason IN ('retired_machine_key', 'stale_node_key') THEN 'kubernetes_gateway.stale_key_presented'
        WHEN p_reason IN ('session_fight', 'replayed_handshake') THEN 'kubernetes_gateway.keys_contested'
        WHEN p_reason IN (
            'token_missing', 'token_malformed', 'token_unknown_key', 'token_signature', 'token_expired',
            'token_audience', 'token_identity', 'trust_missing', 'trust_unavailable'
        ) THEN 'kubernetes_gateway.rotation_token_refused'
        WHEN p_reason IN (
            'session_token_missing', 'session_token_malformed', 'session_token_unknown_key',
            'session_token_signature', 'session_token_expired', 'session_token_audience',
            'session_token_identity', 'session_trust_missing', 'session_trust_unavailable', 'session_clock_skew'
        ) THEN 'kubernetes_gateway.session_token_refused'
    END;
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR v_action IS NULL OR p_suppressed IS NULL OR p_suppressed NOT BETWEEN 0 AND 1000000
        OR p_event_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_event_public_id = p_change_public_id
        OR (p_token_kid IS NOT NULL AND (p_reason NOT IN ('token_unknown_key', 'session_token_unknown_key')
            OR pg_catalog.octet_length(p_token_kid) NOT BETWEEN 1 AND 128 OR p_token_kid !~ '^[!-~]+$')) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway key event';
    END IF;
    -- The gateway the key belongs or belonged to: one Device per key in the
    -- history, else the newest epoch of a gateway Device.
    SELECT device.* INTO v_device
    FROM mesh_ops.kubernetes_gateway_machine_key_history AS history
    JOIN mesh.device AS device ON device.id = history.device_id
    WHERE history.fingerprint = p_machine_fingerprint;
    IF v_device.id IS NULL THEN
        SELECT device.* INTO v_device
        FROM mesh.device_machine_key_epoch AS machine
        JOIN mesh.device AS device
          ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
         AND device.id = machine.device_id
        WHERE machine.fingerprint = p_machine_fingerprint AND device.kind = 'kubernetes_gateway'
        ORDER BY machine.valid_from DESC, machine.id DESC
        LIMIT 1;
    END IF;
    IF v_device.id IS NULL OR v_device.kubernetes_cluster_id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'unknown');
    END IF;
    -- As the gate sees it: a key is current only for an active, unexpired
    -- Device that holds it now.
    v_key_state := CASE
        WHEN v_device.deleted_at IS NOT NULL OR v_device.state IN ('revoked', 'deleted') THEN 'device_removed'
        WHEN v_device.state = 'expired' OR v_device.expires_at <= v_now THEN 'device_expired'
        -- Gateways are never suspended today (device_kind_check); kept so a
        -- later suspension does not read as current.
        WHEN v_device.state = 'suspended' THEN 'device_suspended'
        WHEN EXISTS (
            SELECT 1 FROM mesh.device_machine_key_epoch AS machine
            WHERE machine.device_id = v_device.id AND machine.fingerprint = p_machine_fingerprint
              AND machine.epoch = v_device.current_machine_key_epoch AND machine.state = 'active'
        ) THEN 'current'
        ELSE 'rotated'
    END;
    -- The Device's own scope: its Workspace and Network rows are visible
    -- only under the map session scope settings, restored once read.
    v_session_workspace := pg_catalog.current_setting('mesh.map_session_workspace_id', TRUE);
    v_session_network := pg_catalog.current_setting('mesh.map_session_network_id', TRUE);
    PERFORM pg_catalog.set_config('mesh.map_session_workspace_id', v_device.workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.map_session_network_id', v_device.network_id::TEXT, TRUE);
    SELECT workspace.public_id, network.public_id INTO v_workspace_public, v_network_public
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = v_device.workspace_id AND network.id = v_device.network_id;
    PERFORM pg_catalog.set_config('mesh.map_session_workspace_id', COALESCE(v_session_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.map_session_network_id', COALESCE(v_session_network, ''), TRUE);
    SELECT * INTO STRICT v_scope FROM mesh_ops.set_network_scope(v_workspace_public, v_network_public);
    -- One gateway's events serialize; a short wait, then busy. Reports of
    -- different gateways of one Network do not, so its daily ceiling may
    -- be passed by about as many reports as there are control replicas.
    BEGIN
        PERFORM pg_catalog.set_config('lock_timeout', '200ms', TRUE);
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended('meshtransit/gateway-key-event/' || v_device.public_id::TEXT, 0));
    EXCEPTION WHEN lock_not_available THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END;
    IF EXISTS (
        SELECT 1 FROM mesh_ops.kubernetes_gateway_key_event AS event
        WHERE event.device_id = v_device.id AND event.recorded_at > v_now - INTERVAL '10 minutes'
          AND event.machine_key_fingerprint = p_machine_fingerprint AND event.reason = p_reason
    ) OR (
        SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_key_event AS event
        WHERE event.device_id = v_device.id AND event.recorded_at > v_now - INTERVAL '1 day'
          AND event.action = v_action
    ) >= 144 OR (
        SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_key_event AS event
        WHERE event.workspace_id = v_device.workspace_id AND event.network_id = v_device.network_id
          AND event.action = v_action AND event.recorded_at > v_now - INTERVAL '1 day'
    ) >= 2000 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited');
    END IF;
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_device.workspace_id AND revision.network_id = v_device.network_id;
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh_ops.kubernetes_gateway_key_event (
        public_id, workspace_id, network_id, kubernetes_cluster_id, device_id, device_public_id, hostname,
        action, reason, machine_key_fingerprint, key_state, suppressed, network_revision, recorded_at, token_kid
    ) VALUES (
        p_event_public_id, v_device.workspace_id, v_device.network_id, v_device.kubernetes_cluster_id,
        v_device.id, v_device.public_id, v_device.hostname, v_action, p_reason, p_machine_fingerprint,
        v_key_state, p_suppressed, v_revision, v_now, p_token_kid
    )
    RETURNING id INTO v_row_id;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_device.workspace_id AND stream.network_id = v_device.network_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    v_payload := mesh_ops.kubernetes_gateway_key_event_payload_internal_v1(v_row_id);

    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'recorded',
        'action', v_action,
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

