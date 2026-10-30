-- Schema 254 (K1d d3, docs/k8s-k1d-console-design.md §6, Q169-Q174): a
-- Kubernetes gateway reports its groups' RBAC check over MTCP
-- (gateway.groups1, mtcp-v1 §6.11). Core keeps the latest report of each
-- gateway Device for people to read; it never decides access from it.
--
-- A group newly turned off is audited as kubernetes_gateway.group_disabled,
-- at most 4 times a cluster, group and UTC day across the cluster's
-- replicas, one event a report. A gateway names its groups itself, so the
-- audit is bounded however it names them (review d3 H1): at most 64 names a
-- Device and day (a Device's budget, so one replica never spends another's),
-- 48 events a Device and day, 2,000 a Network and day. The event row is the authority change its
-- sealed audit event proves, as for the gateway key events (schema 229).

-- The latest report of a gateway Device; supported false: its meshgw does
-- not report (it opened a session without gateway.groups1).
CREATE TABLE mesh_ops.kubernetes_gateway_group_report (
    device_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    supported BOOLEAN NOT NULL,
    groups JSONB NOT NULL DEFAULT '[]'::JSONB,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    checked_at TIMESTAMPTZ,
    reported_at TIMESTAMPTZ NOT NULL,
    -- When the Core replica that writes it took the report from the
    -- gateway: an older one retried on another replica never replaces it.
    received_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_gateway_group_report_groups_check CHECK (
        pg_catalog.jsonb_typeof(groups) = 'array' AND pg_catalog.jsonb_array_length(groups) <= 64
        AND (supported OR (pg_catalog.jsonb_array_length(groups) = 0 AND NOT truncated AND checked_at IS NULL))
    ),
    CONSTRAINT kubernetes_gateway_group_report_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE,
    CONSTRAINT kubernetes_gateway_group_report_cluster_fk
        FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE CASCADE
);
CREATE INDEX kubernetes_gateway_group_report_cluster_idx
    ON mesh_ops.kubernetes_gateway_group_report (kubernetes_cluster_id);
ALTER TABLE mesh_ops.kubernetes_gateway_group_report ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_group_report FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_group_report_migrator_policy ON mesh_ops.kubernetes_gateway_group_report
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_group_report
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- How often a cluster's group was audited as turned off on a UTC day (Q173).
CREATE TABLE mesh_ops.kubernetes_gateway_group_alert (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    group_name TEXT NOT NULL,
    day DATE NOT NULL,
    alerts SMALLINT NOT NULL CHECK (alerts BETWEEN 1 AND 4),
    PRIMARY KEY (kubernetes_cluster_id, group_name, day),
    CONSTRAINT kubernetes_gateway_group_alert_cluster_fk
        FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE CASCADE
);
ALTER TABLE mesh_ops.kubernetes_gateway_group_alert ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_group_alert FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_group_alert_migrator_policy ON mesh_ops.kubernetes_gateway_group_alert
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_group_alert
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The groups a report turned off, as the authority change its audit event
-- proves. No Device FK: the evidence outlives the Device.
CREATE TABLE mesh_ops.kubernetes_gateway_group_event (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    device_public_id UUID NOT NULL,
    hostname TEXT NOT NULL,
    groups TEXT[] NOT NULL,
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    recorded_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_gateway_group_event_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_gateway_group_event_groups_check CHECK (
        pg_catalog.cardinality(groups) BETWEEN 1 AND 64
    ),
    CONSTRAINT kubernetes_gateway_group_event_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX kubernetes_gateway_group_event_device_idx
    ON mesh_ops.kubernetes_gateway_group_event (device_id, recorded_at);
CREATE INDEX kubernetes_gateway_group_event_network_idx
    ON mesh_ops.kubernetes_gateway_group_event (workspace_id, network_id, recorded_at);
CREATE TRIGGER kubernetes_gateway_group_event_authority_mutation
AFTER INSERT ON mesh_ops.kubernetes_gateway_group_event
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_gateway_group_event', 'public_id');
ALTER TABLE mesh_ops.kubernetes_gateway_group_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_group_event FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_group_event_migrator_policy ON mesh_ops.kubernetes_gateway_group_event
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_group_event
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether a report's groups are as mtcp-v1 §6.11 has them; Core checks the
-- message before, this keeps the table to it whatever the caller.
CREATE FUNCTION mesh_ops.kubernetes_gateway_groups_are_valid_v1(p_groups JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_groups IS NOT NULL AND pg_catalog.jsonb_typeof(p_groups) = 'array'
        AND pg_catalog.jsonb_array_length(p_groups) <= 64
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_groups) AS item(value)
            WHERE pg_catalog.jsonb_typeof(item.value) <> 'object'
               OR (SELECT pg_catalog.array_agg(key ORDER BY key) FROM pg_catalog.jsonb_object_keys(item.value) AS key)
                  IS DISTINCT FROM ARRAY['group', 'privileged', 'reason', 'state']
               OR pg_catalog.jsonb_typeof(item.value -> 'group') <> 'string'
               OR (item.value ->> 'group') !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
               OR pg_catalog.jsonb_typeof(item.value -> 'privileged') <> 'boolean'
               OR (item.value ->> 'state') IS NULL OR (item.value ->> 'state') NOT IN ('enabled', 'disabled', 'pending')
               -- A state with the reasons that fit it (§6.11).
               OR NOT (
                   (item.value ->> 'state') = 'enabled' AND ((item.value ->> 'reason') = 'none'
                       OR (item.value ->> 'reason') = 'impersonation_off'
                          AND (item.value -> 'privileged') = 'true'::JSONB)
                   OR (item.value ->> 'state') = 'pending' AND (item.value ->> 'reason') = 'not_checked'
                   OR (item.value ->> 'state') = 'disabled' AND (item.value ->> 'reason') IN (
                       'not_checked', 'check_stale', 'api_error', 'rbac_exceeds'))
        )
        AND (SELECT pg_catalog.count(DISTINCT item.value ->> 'group') = pg_catalog.count(*)
             FROM pg_catalog.jsonb_array_elements(p_groups) AS item(value))
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_groups_are_valid_v1(JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- An audit event's payload.
CREATE FUNCTION mesh_ops.kubernetes_gateway_group_event_payload_internal_v1(p_event_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'format', 'kubernetes-gateway-group-event/v1',
        'event_id', event.public_id,
        'device_id', event.device_public_id,
        'hostname', event.hostname,
        'cluster_id', cluster.public_id,
        'groups', pg_catalog.to_jsonb(event.groups),
        'recorded_at', event.recorded_at
    )
    FROM mesh_ops.kubernetes_gateway_group_event AS event
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = event.kubernetes_cluster_id
    WHERE event.id = p_event_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_group_event_payload_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Records a gateway's report (p_supported) or that its session does not
-- report (NOT p_supported), received by Core at p_received_at, for the
-- gateway Device holding both keys now, under the Device's lock. Returns
-- outcome unknown (no such gateway), busy (the lock is held: a handshake
-- goes first), stored, or recorded with the stream head the caller binds
-- the audit event of the groups it turned off to.
CREATE FUNCTION mesh_ops.record_kubernetes_gateway_group_report_v1(
    p_machine_fingerprint BYTEA,
    p_node_key BYTEA,
    p_supported BOOLEAN,
    p_groups JSONB,
    p_truncated BOOLEAN,
    p_checked_at TIMESTAMPTZ,
    p_received_at TIMESTAMPTZ,
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
    v_day DATE := (pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')::DATE;
    v_device mesh.device%ROWTYPE;
    v_previous JSONB;
    v_disabled TEXT[];
    v_alerted TEXT[] := ARRAY[]::TEXT[];
    v_group TEXT;
    v_alerts SMALLINT;
    v_workspace_public UUID;
    v_network_public UUID;
    v_session_workspace TEXT;
    v_session_network TEXT;
    v_scope RECORD;
    v_revision BIGINT;
    v_row_id BIGINT;
    v_stream RECORD;
    v_payload JSONB;
    v_holder UUID;
    v_stored TIMESTAMPTZ;
    v_named TEXT[];
BEGIN
    IF p_received_at IS NULL OR p_received_at > v_now + INTERVAL '5 minutes'
        OR p_received_at < v_now - INTERVAL '1 hour' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway group report';
    END IF;
    -- A last check far off the database's clock is not shown; the report is.
    IF p_checked_at > v_now + INTERVAL '10 minutes' OR p_checked_at < v_now - INTERVAL '31 days' THEN
        p_checked_at := NULL;
    END IF;
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_supported IS NULL OR p_truncated IS NULL
        OR NOT mesh_ops.kubernetes_gateway_groups_are_valid_v1(p_groups)
        OR (NOT p_supported AND (pg_catalog.jsonb_array_length(p_groups) <> 0 OR p_truncated
            OR p_checked_at IS NOT NULL))
        OR p_event_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_event_public_id = p_change_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway group report';
    END IF;
    -- Handshakes go first: the Device's lock taken now or never (review d3
    -- M4); the lock function then finds it held by this transaction.
    SELECT device.public_id INTO v_holder
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
     AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
    WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND device.kind = 'kubernetes_gateway';
    IF v_holder IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'unknown');
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(
        pg_catalog.hashtextextended('meshtransit/gateway-token-proof/' || v_holder::TEXT, 0)) THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    v_device := mesh_ops.lock_current_kubernetes_gateway_internal_v1(p_machine_fingerprint, p_node_key);
    IF v_device.id IS NULL OR v_device.kubernetes_cluster_id IS NULL OR v_device.public_id <> v_holder THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'unknown');
    END IF;
    SELECT CASE WHEN report.supported THEN report.groups END, report.received_at INTO v_previous, v_stored
    FROM mesh_ops.kubernetes_gateway_group_report AS report
    WHERE report.device_id = v_device.id;
    -- A report another Core replica took later is newer news.
    IF v_stored > p_received_at THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stored');
    END IF;
    INSERT INTO mesh_ops.kubernetes_gateway_group_report (
        device_id, workspace_id, network_id, kubernetes_cluster_id, supported, groups, truncated, checked_at,
        reported_at, received_at
    ) VALUES (
        v_device.id, v_device.workspace_id, v_device.network_id, v_device.kubernetes_cluster_id, p_supported,
        p_groups, p_truncated, p_checked_at, v_now, p_received_at
    )
    ON CONFLICT (device_id) DO UPDATE SET
        supported = EXCLUDED.supported, groups = EXCLUDED.groups, truncated = EXCLUDED.truncated,
        checked_at = EXCLUDED.checked_at, reported_at = EXCLUDED.reported_at, received_at = EXCLUDED.received_at;

    -- Groups turned off by this report: off now, and not off in the last
    -- report this Device sent (none counts as not off).
    SELECT pg_catalog.array_agg(item.value ->> 'group' ORDER BY item.value ->> 'group') INTO v_disabled
    FROM pg_catalog.jsonb_array_elements(p_groups) AS item(value)
    WHERE item.value ->> 'state' = 'disabled'
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.jsonb_array_elements(COALESCE(v_previous, '[]'::JSONB)) AS earlier(value)
          WHERE earlier.value ->> 'group' = item.value ->> 'group' AND earlier.value ->> 'state' = 'disabled');
    -- The Device's and the Network's events of the day are bounded first:
    -- past them the report is kept, unaudited.
    IF v_disabled IS NULL OR (
        SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_group_event AS event
        WHERE event.device_id = v_device.id AND event.recorded_at > v_now - INTERVAL '1 day'
    ) >= 48 OR (
        SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_group_event AS event
        WHERE event.workspace_id = v_device.workspace_id AND event.network_id = v_device.network_id
          AND event.recorded_at > v_now - INTERVAL '1 day'
    ) >= 2000 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stored');
    END IF;
    -- At most 4 a cluster, group and day, whichever replica reports, and
    -- at most 64 names this Device audited today: names past them go
    -- unaudited, other replicas' budgets untouched (review d3 M1).
    DELETE FROM mesh_ops.kubernetes_gateway_group_alert AS alert
    WHERE alert.kubernetes_cluster_id = v_device.kubernetes_cluster_id AND alert.day < v_day - 1;
    SELECT COALESCE(pg_catalog.array_agg(DISTINCT named.name), ARRAY[]::TEXT[]) INTO v_named
    FROM mesh_ops.kubernetes_gateway_group_event AS event
    CROSS JOIN LATERAL pg_catalog.unnest(event.groups) AS named(name)
    WHERE event.device_id = v_device.id
      AND event.recorded_at >= (v_day::TIMESTAMP AT TIME ZONE 'UTC');
    FOREACH v_group IN ARRAY v_disabled LOOP
        IF NOT (v_group = ANY (v_named)) THEN
            IF pg_catalog.cardinality(v_named) >= 64 THEN
                CONTINUE;
            END IF;
            v_named := v_named || v_group;
        END IF;
        INSERT INTO mesh_ops.kubernetes_gateway_group_alert AS alert (
            workspace_id, network_id, kubernetes_cluster_id, group_name, day, alerts
        ) VALUES (v_device.workspace_id, v_device.network_id, v_device.kubernetes_cluster_id, v_group, v_day, 1)
        ON CONFLICT (kubernetes_cluster_id, group_name, day) DO UPDATE SET alerts = alert.alerts + 1
        WHERE alert.alerts < 4
        RETURNING alert.alerts INTO v_alerts;
        IF FOUND THEN
            v_alerted := v_alerted || v_group;
        END IF;
    END LOOP;
    IF pg_catalog.cardinality(v_alerted) = 0 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stored');
    END IF;

    -- The Device's own scope, as for its key events (schema 229).
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
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_device.workspace_id AND revision.network_id = v_device.network_id;
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;
    -- The Device's older events go after a month: the audit stream keeps
    -- the events themselves.
    DELETE FROM mesh_ops.kubernetes_gateway_group_event AS event
    WHERE event.device_id = v_device.id AND event.recorded_at < v_now - INTERVAL '30 days';

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh_ops.kubernetes_gateway_group_event (
        public_id, workspace_id, network_id, kubernetes_cluster_id, device_id, device_public_id, hostname,
        groups, network_revision, recorded_at
    ) VALUES (
        p_event_public_id, v_device.workspace_id, v_device.network_id, v_device.kubernetes_cluster_id,
        v_device.id, v_device.public_id, v_device.hostname, v_alerted, v_revision, v_now
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
    v_payload := mesh_ops.kubernetes_gateway_group_event_payload_internal_v1(v_row_id);
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'recorded',
        'action', 'kubernetes_gateway.group_disabled',
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

-- Appends the sealed audit event of the groups a report turned off, bound
-- to the event row this transaction inserted.
CREATE FUNCTION mesh_ops.append_kubernetes_gateway_group_event_evidence_v1(
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
    v_event mesh_ops.kubernetes_gateway_group_event%ROWTYPE;
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
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes gateway group event evidence';
    END IF;
    SELECT event.* INTO v_event
    FROM mesh_ops.kubernetes_gateway_group_event AS event
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
     AND mutation.aggregate_kind = 'kubernetes_gateway_group_event' AND mutation.row_public_id = event.public_id
     AND mutation.operation = 'insert' AND mutation.after_version = 1
    JOIN mesh_audit.audit_stream AS stream
      ON stream.id = p_stream_id AND stream.scope_kind = 'network'
     AND stream.workspace_id = event.workspace_id AND stream.network_id = event.network_id
    WHERE event.public_id = p_event_public_id;
    IF v_event.id IS NULL
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR p_payload IS DISTINCT FROM mesh_ops.kubernetes_gateway_group_event_payload_internal_v1(v_event.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes gateway group event evidence';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_audit_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'kubernetes_gateway_group_event', v_event.public_id, 1, v_event.network_revision, NULL::UUID,
        'kubernetes_gateway.group_disabled', 'system.reconcile', NULL::UUID, NULL::BYTEA,
        pg_catalog.sha256(pg_catalog.convert_to(p_payload::TEXT, 'UTF8')),
        p_payload, 'kubernetes_gateway.group_disabled', p_payload
    );
END;
$function$;

-- A replica as its v2 document, and its gateway's latest group report:
-- status current, stale (over 20 minutes old), unsupported (its meshgw does
-- not report) or none.
CREATE FUNCTION mesh_ops.kubernetes_cluster_replica_document_internal_v3(p_device mesh.device)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.kubernetes_cluster_replica_document_internal_v2(p_device) || pg_catalog.jsonb_build_object(
        'groups', COALESCE((
            SELECT pg_catalog.jsonb_build_object(
                'status', CASE
                    WHEN NOT report.supported THEN 'unsupported'
                    WHEN report.reported_at < pg_catalog.clock_timestamp() - INTERVAL '20 minutes' THEN 'stale'
                    ELSE 'current' END,
                'reported_at', report.reported_at,
                'checked_at', report.checked_at,
                'truncated', report.truncated,
                'items', report.groups)
            FROM mesh_ops.kubernetes_gateway_group_report AS report
            WHERE report.device_id = p_device.id AND report.workspace_id = p_device.workspace_id
              AND report.network_id = p_device.network_id),
            pg_catalog.jsonb_build_object('status', 'none', 'reported_at', NULL, 'checked_at', NULL,
                'truncated', FALSE, 'items', '[]'::JSONB)))
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_replica_document_internal_v3(mesh.device)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- As v2, with the v3 document.
CREATE FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v3(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_after_at TIMESTAMPTZ, p_after_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR (p_after_at IS NULL) <> (p_after_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_cluster_replica_document_internal_v3(listed)
            ORDER BY listed.created_at DESC, listed.public_id DESC)
        FROM (
            SELECT device.* FROM mesh.device AS device
            WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
              AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
              AND (p_after_at IS NULL OR (device.created_at, device.public_id) < (p_after_at, p_after_id))
            ORDER BY device.created_at DESC, device.public_id DESC
            LIMIT p_limit + 1
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

CREATE FUNCTION mesh_ops.read_kubernetes_cluster_replica_v3(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_device_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_document JSONB;
BEGIN
    IF p_device_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT mesh_ops.kubernetes_cluster_replica_document_internal_v3(device) INTO v_document
    FROM mesh.device AS device
    WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
      AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
      AND device.public_id = p_device_public_id;
    IF v_document IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes replica';
    END IF;
    RETURN v_document;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_gateway_group_report_v1(
    BYTEA, BYTEA, BOOLEAN, JSONB, BOOLEAN, TIMESTAMPTZ, TIMESTAMPTZ, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_gateway_group_report_v1(
    BYTEA, BYTEA, BOOLEAN, JSONB, BOOLEAN, TIMESTAMPTZ, TIMESTAMPTZ, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.append_kubernetes_gateway_group_event_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.append_kubernetes_gateway_group_event_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_replica_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_replica_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
