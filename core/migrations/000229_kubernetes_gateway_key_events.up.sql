-- Schema 229 (TD-SEC-52a, K1a1 plan §15): a Kubernetes gateway that
-- presents a retired machine key or a stale node key, or whose keys two
-- holders fight over, leaves a sealed audit event in its Network. The owner
-- chose to audit and warn, never to quarantine on its own (Q-K1a1.4-1).
--
-- The control plane reports these off the handshake path. Each event names
-- the gateway Device the machine key belongs or belonged to, found the way
-- the handshake gate finds it, and how the key stands now. Events are
-- bounded: one per (Device, key, reason) per 10 minutes, 144 per (Device,
-- action) and 2,000 per (Network, action) a day, so neither kind can crowd
-- out the other. Retention is 13 months, as for audit.

CREATE TABLE mesh_ops.kubernetes_gateway_key_event (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    device_public_id UUID NOT NULL,
    hostname TEXT NOT NULL CHECK (pg_catalog.length(hostname) BETWEEN 1 AND 253),
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    machine_key_fingerprint BYTEA NOT NULL CHECK (pg_catalog.octet_length(machine_key_fingerprint) = 32),
    key_state TEXT NOT NULL CHECK (
        key_state IN ('current', 'rotated', 'device_removed', 'device_expired', 'device_suspended')
    ),
    suppressed INTEGER NOT NULL CHECK (suppressed BETWEEN 0 AND 1000000),
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    recorded_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_gateway_key_event_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_gateway_key_event_reason_check CHECK (
        (action = 'kubernetes_gateway.stale_key_presented' AND reason IN ('retired_machine_key', 'stale_node_key'))
        OR (action = 'kubernetes_gateway.keys_contested' AND reason IN ('session_fight', 'replayed_handshake'))
    ),
    CONSTRAINT kubernetes_gateway_key_event_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX kubernetes_gateway_key_event_network_idx
    ON mesh_ops.kubernetes_gateway_key_event (workspace_id, network_id, action, recorded_at);
CREATE INDEX kubernetes_gateway_key_event_device_idx
    ON mesh_ops.kubernetes_gateway_key_event (device_id, recorded_at);
CREATE INDEX kubernetes_gateway_key_event_cluster_idx
    ON mesh_ops.kubernetes_gateway_key_event (workspace_id, network_id, kubernetes_cluster_id, recorded_at DESC);
CREATE INDEX kubernetes_gateway_key_event_time_idx ON mesh_ops.kubernetes_gateway_key_event (recorded_at);

ALTER TABLE mesh_ops.kubernetes_gateway_key_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_key_event_migrator_policy ON mesh_ops.kubernetes_gateway_key_event
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_key_event
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER kubernetes_gateway_key_event_authority_mutation
AFTER INSERT ON mesh_ops.kubernetes_gateway_key_event
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_gateway_key_event', 'public_id');

CREATE FUNCTION mesh_ops.kubernetes_gateway_key_event_payload_internal_v1(p_event_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'format', 'kubernetes-gateway-key-event/v1',
        'event_id', event.public_id,
        'device_id', event.device_public_id,
        'hostname', event.hostname,
        'cluster_id', cluster.public_id,
        'reason', event.reason,
        'machine_key_fingerprint', pg_catalog.encode(event.machine_key_fingerprint, 'hex'),
        'key_state', event.key_state,
        'suppressed', event.suppressed,
        'recorded_at', event.recorded_at
    )
    FROM mesh_ops.kubernetes_gateway_key_event AS event
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = event.kubernetes_cluster_id
    WHERE event.id = p_event_id
$function$;

-- Records one key event a control plane replica saw on a handshake.
-- p_machine_fingerprint is the node-domain fingerprint of the session's
-- machine key; the Device is the gateway that holds or held it, found as
-- accept_mtcp_timestamp_v2 finds it: through the gateway key history first,
-- then the newest key epoch of a gateway Device. Returns outcome:
-- 'unknown' (not a gateway's key), 'busy', 'limited', or 'recorded' with the
-- head of the Network's audit stream, payload and semantic hash for the
-- caller to hash and append in the same transaction.
CREATE FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v1(
    p_machine_fingerprint BYTEA,
    p_reason TEXT,
    p_suppressed INTEGER,
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
    END;
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR v_action IS NULL OR p_suppressed IS NULL OR p_suppressed NOT BETWEEN 0 AND 1000000
        OR p_event_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_event_public_id = p_change_public_id THEN
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
        action, reason, machine_key_fingerprint, key_state, suppressed, network_revision, recorded_at
    ) VALUES (
        p_event_public_id, v_device.workspace_id, v_device.network_id, v_device.kubernetes_cluster_id,
        v_device.id, v_device.public_id, v_device.hostname, v_action, p_reason, p_machine_fingerprint,
        v_key_state, p_suppressed, v_revision, v_now
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

-- Appends the audit event of the key event record_kubernetes_gateway_key_event_v1
-- wrote in this transaction and change.
CREATE FUNCTION mesh_ops.append_kubernetes_gateway_key_event_evidence_v1(
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
    v_event mesh_ops.kubernetes_gateway_key_event%ROWTYPE;
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
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes gateway key event evidence';
    END IF;
    SELECT event.* INTO v_event
    FROM mesh_ops.kubernetes_gateway_key_event AS event
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
     AND mutation.aggregate_kind = 'kubernetes_gateway_key_event' AND mutation.row_public_id = event.public_id
     AND mutation.operation = 'insert' AND mutation.after_version = 1
    JOIN mesh_audit.audit_stream AS stream
      ON stream.id = p_stream_id AND stream.scope_kind = 'network'
     AND stream.workspace_id = event.workspace_id AND stream.network_id = event.network_id
    WHERE event.public_id = p_event_public_id;
    IF v_event.id IS NULL
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR p_payload IS DISTINCT FROM mesh_ops.kubernetes_gateway_key_event_payload_internal_v1(v_event.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes gateway key event evidence';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_audit_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'kubernetes_gateway_key_event', v_event.public_id, 1, v_event.network_revision, NULL::UUID,
        v_event.action, 'system.reconcile', NULL::UUID, NULL::BYTEA,
        pg_catalog.sha256(pg_catalog.convert_to(p_payload::TEXT, 'UTF8')),
        p_payload, v_event.action, p_payload
    );
END;
$function$;

-- Removes the installation's key events older than 13 months; bounded per call.
CREATE FUNCTION mesh_ops.prune_kubernetes_gateway_key_events_v1(p_deployment_public_id UUID, p_limit INTEGER)
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway key event retention input';
    END IF;
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes gateway key event installation is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    WITH doomed AS (
        SELECT event.id
        FROM mesh_ops.kubernetes_gateway_key_event AS event
        JOIN mesh.workspace AS workspace ON workspace.id = event.workspace_id
        WHERE workspace.deployment_id = v_deployment_id
          AND event.recorded_at < pg_catalog.clock_timestamp() - INTERVAL '13 months'
        ORDER BY event.recorded_at
        LIMIT p_limit
    )
    DELETE FROM mesh_ops.kubernetes_gateway_key_event AS event
    USING doomed WHERE event.id = doomed.id;
    GET DIAGNOSTICS v_removed = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    RETURN v_removed;
END;
$function$;

-- A cluster's read with a summary of its gateways' key events in the last
-- 7 days, for those who manage or approve the cluster (null for readers of
-- the Network): one entry per gateway Device, removed ones included, newest
-- first, at most 64 with a truncated flag. v1 keeps its shape for older Core.
CREATE FUNCTION mesh_ops.read_kubernetes_cluster_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_key_limit INTEGER, p_request_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_read JSONB;
    v_cluster RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_warnings JSONB;
BEGIN
    v_read := mesh_ops.read_kubernetes_cluster_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id, p_key_limit, p_request_limit);
    IF pg_catalog.jsonb_typeof(v_read -> 'keys') IS DISTINCT FROM 'array' THEN
        RETURN v_read || pg_catalog.jsonb_build_object('key_warnings', NULL::JSONB);
    END IF;
    SELECT cluster.id, cluster.workspace_id, cluster.network_id INTO STRICT v_cluster
    FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.workspace AS workspace ON workspace.id = cluster.workspace_id
    JOIN mesh.network AS network ON network.workspace_id = cluster.workspace_id AND network.id = cluster.network_id
    WHERE workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND cluster.public_id = p_cluster_public_id;
    WITH recent AS (
        SELECT event.* FROM mesh_ops.kubernetes_gateway_key_event AS event
        WHERE event.workspace_id = v_cluster.workspace_id AND event.network_id = v_cluster.network_id
          AND event.kubernetes_cluster_id = v_cluster.id AND event.recorded_at > v_now - INTERVAL '7 days'
    ), counted AS (
        SELECT recent.device_id,
            pg_catalog.count(*) FILTER (WHERE recent.recorded_at > v_now - INTERVAL '1 day') AS day,
            pg_catalog.count(*) AS week
        FROM recent GROUP BY recent.device_id
    ), latest AS (
        SELECT DISTINCT ON (recent.device_id) recent.*
        FROM recent
        ORDER BY recent.device_id, recent.recorded_at DESC, recent.id DESC
    ), per_device AS (
        SELECT latest.device_public_id, latest.hostname, latest.reason, latest.key_state, latest.recorded_at,
            counted.day, counted.week
        FROM latest JOIN counted ON counted.device_id = latest.device_id
        ORDER BY latest.recorded_at DESC, latest.device_public_id
        LIMIT 65
    )
    SELECT pg_catalog.jsonb_build_object(
        'devices', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'device_id', listed.device_public_id, 'hostname', listed.hostname,
                'count_24h', listed.day, 'count_7d', listed.week, 'last_at', listed.recorded_at,
                'last_reason', listed.reason, 'key_state', listed.key_state
            ) ORDER BY listed.recorded_at DESC, listed.device_public_id)
            FROM (SELECT * FROM per_device ORDER BY recorded_at DESC, device_public_id LIMIT 64) AS listed
        ), '[]'::JSONB),
        'truncated', (SELECT pg_catalog.count(*) FROM per_device) > 64
    ) INTO v_warnings;
    RETURN v_read || pg_catalog.jsonb_build_object('key_warnings', v_warnings);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_key_event_payload_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v1(BYTEA, TEXT, INTEGER, UUID, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.append_kubernetes_gateway_key_event_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prune_kubernetes_gateway_key_events_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- The control plane records what its handshakes see.
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v1(BYTEA, TEXT, INTEGER, UUID, UUID)
    TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.append_kubernetes_gateway_key_event_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) TO mesh_runtime;
-- The enforcement ledger worker prunes them with captive portal windows.
GRANT EXECUTE ON FUNCTION mesh_ops.prune_kubernetes_gateway_key_events_v1(UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, INTEGER
) TO mesh_runtime;
