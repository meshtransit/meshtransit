-- Schema 233 (K1.1 design §8.4, §9): the rest of K1.1a's schema.
--
-- A Kubernetes gateway's rotation refused for its pod token or its
-- cluster's trust enters the audit trail as
-- kubernetes_gateway.rotation_token_refused, through the bounded key event
-- reporter of schema 229; token_missing is the main sign of a copy of the
-- gateway's Secret. A token used before is not reported. The cluster's v2
-- read keeps summing only the older actions, so older Core and Console
-- never meet the new reasons. Everything new reaches the Console through
-- its own read, read_kubernetes_cluster_signing_v1, so the routes older
-- Consoles use keep their shape.

-- The reason CHECK swapped. The migration is one transaction, so the
-- table stays locked while VALIDATE scans it; it holds at most 144 events
-- per gateway and action a day for 13 months.
ALTER TABLE mesh_ops.kubernetes_gateway_key_event
    ADD CONSTRAINT kubernetes_gateway_key_event_reason_v2_check CHECK (
        (action = 'kubernetes_gateway.stale_key_presented' AND reason IN ('retired_machine_key', 'stale_node_key'))
        OR (action = 'kubernetes_gateway.keys_contested' AND reason IN ('session_fight', 'replayed_handshake'))
        OR (action = 'kubernetes_gateway.rotation_token_refused' AND reason IN (
            'token_missing', 'token_malformed', 'token_unknown_key', 'token_signature', 'token_expired',
            'token_audience', 'token_identity', 'trust_missing', 'trust_unavailable'
        ))
    ) NOT VALID;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event VALIDATE CONSTRAINT kubernetes_gateway_key_event_reason_v2_check;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event DROP CONSTRAINT kubernetes_gateway_key_event_reason_check;

-- As v1 of schema 229, with the reasons of a refused rotation token.
CREATE FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v2(
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
        WHEN p_reason IN (
            'token_missing', 'token_malformed', 'token_unknown_key', 'token_signature', 'token_expired',
            'token_audience', 'token_identity', 'trust_missing', 'trust_unavailable'
        ) THEN 'kubernetes_gateway.rotation_token_refused'
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

-- v1 keeps its reasons for older Core.
CREATE OR REPLACE FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v1(
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
BEGIN
    IF p_reason IS NULL
        OR p_reason NOT IN ('retired_machine_key', 'stale_node_key', 'session_fight', 'replayed_handshake') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway key event';
    END IF;
    RETURN mesh_ops.record_kubernetes_gateway_key_event_v2(
        p_machine_fingerprint, p_reason, p_suppressed, p_event_public_id, p_change_public_id);
END;
$function$;

-- As in schema 229, summing only the actions it summed then.
CREATE OR REPLACE FUNCTION mesh_ops.read_kubernetes_cluster_v2(
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
          AND event.action IN ('kubernetes_gateway.stale_key_presented', 'kubernetes_gateway.keys_contested')
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

-- A cluster's signing read: its trust, and its gateway Devices that are not
-- deleted with the pod each one's join named and when it last rotated a
-- key (each rotation since schema 232 carried a valid pod token). Those who manage or approve
-- the cluster also get the signing material of its waiting requests, at
-- most 64, and its gateways' refused rotation tokens of the last 7 days,
-- summed as read_kubernetes_cluster_v2 sums key events (null for readers).
CREATE FUNCTION mesh_ops.read_kubernetes_cluster_signing_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_manager BOOLEAN;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_trust JSONB;
    v_warnings JSONB;
BEGIN
    IF p_cluster_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    v_manager := EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'kubernetes_cluster.manage', pg_catalog.transaction_timestamp()))
        OR EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'kubernetes_cluster.approve', pg_catalog.transaction_timestamp()));
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'issuer', trust.issuer,
        'key_thumbprints', pg_catalog.to_jsonb(ARRAY(
            SELECT pg_catalog.encode(listed.thumbprint, 'hex')
            FROM pg_catalog.unnest(trust.key_thumbprints) WITH ORDINALITY AS listed (thumbprint, position)
            ORDER BY listed.position)),
        'namespace', trust.namespace, 'service_account', trust.service_account,
        'statefulset', trust.statefulset, 'version', trust.version, 'source', trust.source,
        'set_at', trust.set_at
    ) INTO v_trust
    FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.workspace_id = v_cluster.workspace_id AND trust.network_id = v_cluster.network_id
      AND trust.kubernetes_cluster_id = v_cluster.id;
    IF v_manager THEN
        WITH recent AS (
            SELECT event.* FROM mesh_ops.kubernetes_gateway_key_event AS event
            WHERE event.workspace_id = v_cluster.workspace_id AND event.network_id = v_cluster.network_id
              AND event.kubernetes_cluster_id = v_cluster.id AND event.recorded_at > v_now - INTERVAL '7 days'
              AND event.action = 'kubernetes_gateway.rotation_token_refused'
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
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'cluster_id', p_cluster_public_id,
        'trust', v_trust,
        'replicas', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'device_id', device.public_id, 'pod_name', request.sa_pod_name,
                'last_token_rotation_at', GREATEST(
                    (SELECT pg_catalog.max(machine.created_at) FROM mesh.device_machine_key_epoch AS machine
                     WHERE machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
                       AND machine.device_id = device.id AND machine.epoch > 1),
                    (SELECT pg_catalog.max(node_key.created_at) FROM mesh.device_node_key_epoch AS node_key
                     WHERE node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
                       AND node_key.device_id = device.id AND node_key.epoch > 1))
            ) ORDER BY device.kubernetes_ordinal, device.id)
            FROM mesh.device AS device
            JOIN mesh.kubernetes_replica_request AS request
              ON request.device_id = device.id AND request.state = 'completed' AND request.code_version = 2
            WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
              AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
        ), '[]'::JSONB),
        'requests', CASE WHEN v_manager THEN COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'request_id', listed.public_id, 'code_version', listed.code_version,
                'issuer', listed.sa_issuer, 'namespace', listed.sa_namespace,
                'service_account', listed.sa_service_account, 'statefulset', listed.sa_statefulset,
                'pod_name', listed.sa_pod_name,
                'join_key_thumbprint', pg_catalog.encode(listed.sa_join_key_thumbprint, 'hex')
            ) ORDER BY listed.created_at DESC, listed.id DESC)
            FROM (
                SELECT request.* FROM mesh.kubernetes_replica_request AS request
                WHERE request.workspace_id = v_cluster.workspace_id AND request.network_id = v_cluster.network_id
                  AND request.kubernetes_cluster_id = v_cluster.id
                  AND ((request.state = 'pending' AND request.expires_at > v_now)
                       OR (request.state = 'approved' AND request.completion_deadline > v_now))
                ORDER BY request.created_at DESC, request.id DESC
                LIMIT 64
            ) AS listed
        ), '[]'::JSONB) END,
        'token_warnings', v_warnings
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v2(BYTEA, TEXT, INTEGER, UUID, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_signing_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- The control plane records what its rotations refuse.
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v2(BYTEA, TEXT, INTEGER, UUID, UUID)
    TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_signing_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;
