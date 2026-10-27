-- Schema 235 (K1.1b, docs/k8s-k1-1b-signing-trust-paste.md): an
-- administrator pastes the cluster's signing keys.
--
-- replace_kubernetes_cluster_signing_trust_v1 sets or replaces a cluster's
-- signing trust from keys an administrator who both manages and approves
-- the cluster pasted (owner's Q3, option B). The cluster is locked first,
-- as approvals and completions lock it, so they run one at a time; the
-- version precondition guards against a concurrent paste; the identity
-- (namespace, ServiceAccount, StatefulSet) stays while a gateway runs or an
-- approval waits to complete. The audit event is appended by Core in the
-- same transaction, on the Network's stream.
--
-- A token signed by a key the trust lacks now leaves its kid with its key
-- event, so the Console can say which key the cluster signs with. A new
-- signing read serves Core 235; Core 234 keeps reading v1, whose shape stays.

-- Schema 232's comment on public_id said a new one at every set; the
-- authority journal needs it kept, so a paste keeps it and bumps version.
COMMENT ON COLUMN mesh.kubernetes_cluster_signing_trust.public_id IS
    'Names the trust in the authority journal and as the aggregate of its audit events; kept across versions.';

ALTER TABLE mesh_ops.kubernetes_gateway_key_event ADD COLUMN token_kid TEXT;
ALTER TABLE mesh_ops.kubernetes_gateway_key_event
    ADD CONSTRAINT kubernetes_gateway_key_event_token_kid_check CHECK (
        token_kid IS NULL OR (reason = 'token_unknown_key'
            AND pg_catalog.octet_length(token_kid) BETWEEN 1 AND 128 AND token_kid ~ '^[!-~]+$')
    );

-- As in schema 229, naming the kid when the event has one.
CREATE OR REPLACE FUNCTION mesh_ops.kubernetes_gateway_key_event_payload_internal_v1(p_event_id BIGINT)
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
    ) || CASE WHEN event.token_kid IS NULL THEN '{}'::JSONB
              ELSE pg_catalog.jsonb_build_object('token_kid', event.token_kid) END
    FROM mesh_ops.kubernetes_gateway_key_event AS event
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = event.kubernetes_cluster_id
    WHERE event.id = p_event_id
$function$;

-- As v2 of schema 233, with the kid of a token signed by a key the trust
-- lacks.
CREATE FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v3(
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
    END;
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR v_action IS NULL OR p_suppressed IS NULL OR p_suppressed NOT BETWEEN 0 AND 1000000
        OR p_event_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_event_public_id = p_change_public_id
        OR (p_token_kid IS NOT NULL AND (p_reason <> 'token_unknown_key'
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

-- v2 keeps its parameters for Core 233 and 234.
CREATE OR REPLACE FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v2(
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
    RETURN mesh_ops.record_kubernetes_gateway_key_event_v3(
        p_machine_fingerprint, p_reason, p_suppressed, p_event_public_id, p_change_public_id, NULL);
END;
$function$;

-- A trust as the reads and the replacement return it: the canonical JWKS
-- (Core derives each key's kid and thumbprint from it), and who set it for
-- those who manage or approve the cluster.
CREATE FUNCTION mesh_ops.kubernetes_signing_trust_document_internal_v1(
    p_trust mesh.kubernetes_cluster_signing_trust, p_with_setter BOOLEAN
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'trust_id', p_trust.public_id,
        'issuer', p_trust.issuer,
        'jwks', pg_catalog.encode(p_trust.jwks, 'base64'),
        'key_thumbprints', pg_catalog.to_jsonb(ARRAY(
            SELECT pg_catalog.encode(listed.thumbprint, 'hex')
            FROM pg_catalog.unnest(p_trust.key_thumbprints) WITH ORDINALITY AS listed (thumbprint, position)
            ORDER BY listed.position)),
        'namespace', p_trust.namespace, 'service_account', p_trust.service_account,
        'statefulset', p_trust.statefulset, 'version', p_trust.version, 'source', p_trust.source,
        'set_at', p_trust.set_at,
        'set_by', CASE WHEN p_with_setter THEN (
            SELECT principal.public_id FROM mesh.principal AS principal
            WHERE principal.id = p_trust.set_by_principal_id) END
    )
$function$;

-- Sets or replaces a cluster's signing trust from pasted keys (K1.1b).
-- p_expected_version is the trust's version, 0 when the cluster has none.
-- The same trust again changes nothing, whatever the version, so a retry
-- after success succeeds. Returns the trust before and after, the Network
-- revision and the caller's authority for the audit event.
CREATE FUNCTION mesh_ops.replace_kubernetes_cluster_signing_trust_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_expected_version BIGINT, p_issuer TEXT, p_jwks BYTEA, p_key_thumbprints BYTEA[],
    p_namespace TEXT, p_service_account TEXT, p_statefulset TEXT, p_reason TEXT,
    p_trust_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_after mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_revision BIGINT;
BEGIN
    IF p_cluster_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 0
        OR NOT COALESCE(mesh_ops.kubernetes_issuer_is_valid_v1(p_issuer), FALSE)
        OR p_jwks IS NULL OR pg_catalog.octet_length(p_jwks) NOT BETWEEN 2 AND 16384
        OR NOT COALESCE(mesh_ops.kubernetes_thumbprints_are_valid_v1(p_key_thumbprints), FALSE)
        OR NOT COALESCE(mesh_ops.kubernetes_namespace_is_valid_v1(p_namespace), FALSE)
        OR NOT COALESCE(mesh_ops.kubernetes_name_is_valid_v1(p_service_account), FALSE)
        OR NOT COALESCE(mesh_ops.kubernetes_name_is_valid_v1(p_statefulset), FALSE)
        OR p_reason IS NULL OR pg_catalog.char_length(p_reason) NOT BETWEEN 1 AND 200
        OR p_reason ~ '[[:cntrl:]]' OR p_reason <> pg_catalog.btrim(p_reason)
        OR p_trust_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_trust_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    -- Both manage and approve (owner's Q3, option B).
    IF NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'kubernetes_cluster.approve', pg_catalog.transaction_timestamp())) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: permission';
    END IF;
    -- The cluster first, as approvals and completions lock it.
    SELECT cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR UPDATE OF cluster;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT trust.* INTO v_trust FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.workspace_id = v_cluster.workspace_id AND trust.network_id = v_cluster.network_id
      AND trust.kubernetes_cluster_id = v_cluster.id
    FOR UPDATE OF trust;
    IF FOUND AND v_trust.issuer = p_issuer AND v_trust.jwks = p_jwks AND v_trust.namespace = p_namespace
        AND v_trust.service_account = p_service_account AND v_trust.statefulset = p_statefulset THEN
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id, 'cluster_id', p_cluster_public_id, 'changed', FALSE,
            'network_revision', NULL::BIGINT, 'authority', v_grant.authority, 'before', NULL::JSONB,
            'trust', mesh_ops.kubernetes_signing_trust_document_internal_v1(v_trust, TRUE));
    END IF;
    IF COALESCE(v_trust.version, 0) <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK21', MESSAGE = 'the cluster''s signing trust changed';
    END IF;
    -- The identity stays while a gateway runs or an approval may complete.
    IF v_trust.kubernetes_cluster_id IS NOT NULL
        AND (v_trust.namespace <> p_namespace OR v_trust.service_account <> p_service_account
             OR v_trust.statefulset <> p_statefulset)
        AND (EXISTS (SELECT 1 FROM mesh.device AS device
                     WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
                       AND device.kubernetes_cluster_id = v_cluster.id AND device.state = 'active'
                       AND device.deleted_at IS NULL)
             OR EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS request
                        WHERE request.kubernetes_cluster_id = v_cluster.id AND request.state = 'approved'
                          AND request.completion_deadline > v_now)) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK22', MESSAGE = 'replicas still run under the cluster''s identity';
    END IF;
    IF v_trust.kubernetes_cluster_id IS NULL THEN
        BEGIN
            INSERT INTO mesh.kubernetes_cluster_signing_trust (
                kubernetes_cluster_id, public_id, workspace_id, network_id, issuer, jwks, key_thumbprints,
                namespace, service_account, statefulset, version, source, source_request_id,
                set_by_principal_id, set_at
            ) VALUES (
                v_cluster.id, p_trust_public_id, v_cluster.workspace_id, v_cluster.network_id, p_issuer, p_jwks,
                p_key_thumbprints, p_namespace, p_service_account, p_statefulset, 1, 'admin_paste', NULL,
                v_grant.actor_id, v_now
            )
            RETURNING * INTO v_after;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK21', MESSAGE = 'the cluster''s signing trust changed';
        END;
    ELSE
        UPDATE mesh.kubernetes_cluster_signing_trust AS trust
        -- The row keeps its public ID: the authority journal names a row by
        -- it across versions. p_trust_public_id names a first trust only.
        SET issuer = p_issuer, jwks = p_jwks, key_thumbprints = p_key_thumbprints,
            namespace = p_namespace, service_account = p_service_account, statefulset = p_statefulset,
            version = trust.version + 1, source = 'admin_paste', source_request_id = NULL,
            set_by_principal_id = v_grant.actor_id, set_at = v_now
        WHERE trust.kubernetes_cluster_id = v_cluster.id
        RETURNING trust.* INTO v_after;
    END IF;
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_cluster.workspace_id AND revision.network_id = v_cluster.network_id;
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id, 'cluster_id', p_cluster_public_id, 'changed', TRUE,
        'network_revision', v_revision, 'authority', v_grant.authority,
        'before', CASE WHEN v_trust.kubernetes_cluster_id IS NULL THEN NULL::JSONB
                       ELSE mesh_ops.kubernetes_signing_trust_document_internal_v1(v_trust, TRUE) END,
        'trust', mesh_ops.kubernetes_signing_trust_document_internal_v1(v_after, TRUE));
END;
$function$;

-- As v1 of schema 234, with the trust's canonical JWKS and setter, the
-- kids the cluster signs with that the trust lacks, refused tokens counted
-- only since the trust was set, and whether the caller may replace it.
CREATE FUNCTION mesh_ops.read_kubernetes_cluster_signing_v2(
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
    v_can_manage BOOLEAN;
    v_can_approve BOOLEAN;
    v_trust_set_at TIMESTAMPTZ := '-infinity';
    v_unknown_kids JSONB;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_trust JSONB;
    v_warnings JSONB;
    v_requests JSONB;
    v_truncated BOOLEAN := FALSE;
BEGIN
    IF p_cluster_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    v_can_manage := EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'kubernetes_cluster.manage', pg_catalog.transaction_timestamp()));
    v_can_approve := EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'kubernetes_cluster.approve', pg_catalog.transaction_timestamp()));
    v_manager := v_can_manage OR v_can_approve;
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT mesh_ops.kubernetes_signing_trust_document_internal_v1(trust, v_manager), trust.set_at
    INTO v_trust, v_trust_set_at
    FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.workspace_id = v_cluster.workspace_id AND trust.network_id = v_cluster.network_id
      AND trust.kubernetes_cluster_id = v_cluster.id;
    v_trust_set_at := COALESCE(v_trust_set_at, '-infinity');
    IF v_manager THEN
        -- At most 64 waiting requests, newest first; a 65th says the list
        -- was cut.
        SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'request_id', listed.public_id, 'code_version', listed.code_version,
                'issuer', listed.sa_issuer, 'namespace', listed.sa_namespace,
                'service_account', listed.sa_service_account, 'statefulset', listed.sa_statefulset,
                'pod_name', listed.sa_pod_name,
                'join_key_thumbprint', pg_catalog.encode(listed.sa_join_key_thumbprint, 'hex')
            ) ORDER BY listed.created_at DESC, listed.id DESC) FILTER (WHERE listed.position <= 64), '[]'::JSONB),
            pg_catalog.count(*) > 64
        INTO v_requests, v_truncated
        FROM (
            SELECT request.*, pg_catalog.row_number() OVER (ORDER BY request.created_at DESC, request.id DESC)
                AS position
            FROM mesh.kubernetes_replica_request AS request
            WHERE request.workspace_id = v_cluster.workspace_id AND request.network_id = v_cluster.network_id
              AND request.kubernetes_cluster_id = v_cluster.id
              AND request.state IN ('pending', 'approved')
              AND ((request.state = 'pending' AND request.expires_at > v_now)
                   OR (request.state = 'approved' AND request.completion_deadline > v_now))
            ORDER BY request.created_at DESC, request.id DESC
            LIMIT 65
        ) AS listed;
        WITH recent AS (
            SELECT event.* FROM mesh_ops.kubernetes_gateway_key_event AS event
            WHERE event.workspace_id = v_cluster.workspace_id AND event.network_id = v_cluster.network_id
              AND event.kubernetes_cluster_id = v_cluster.id AND event.recorded_at > v_now - INTERVAL '7 days'
              AND event.action = 'kubernetes_gateway.rotation_token_refused'
              AND event.recorded_at > v_trust_set_at
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
    IF v_manager THEN
        -- The kids the cluster signed with that the trust lacks, newest
        -- first, since the trust was last set.
        SELECT COALESCE(pg_catalog.jsonb_agg(listed.token_kid ORDER BY listed.last_at DESC), '[]'::JSONB)
        INTO v_unknown_kids
        FROM (
            SELECT event.token_kid, pg_catalog.max(event.recorded_at) AS last_at
            FROM mesh_ops.kubernetes_gateway_key_event AS event
            WHERE event.workspace_id = v_cluster.workspace_id AND event.network_id = v_cluster.network_id
              AND event.kubernetes_cluster_id = v_cluster.id AND event.reason = 'token_unknown_key'
              AND event.token_kid IS NOT NULL AND event.recorded_at > v_now - INTERVAL '7 days'
              AND event.recorded_at > v_trust_set_at
            GROUP BY event.token_kid
            ORDER BY last_at DESC
            LIMIT 8
        ) AS listed;
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
              AND device.kubernetes_cluster_id = v_cluster.id AND device.state = 'active'
              AND device.deleted_at IS NULL
        ), '[]'::JSONB),
        'requests', v_requests,
        'requests_truncated', v_truncated,
        'token_warnings', v_warnings,
        'unknown_kids', v_unknown_kids,
        'can_replace_trust', v_can_manage AND v_can_approve
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.kubernetes_signing_trust_document_internal_v1(mesh.kubernetes_cluster_signing_trust, BOOLEAN)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v3(BYTEA, TEXT, INTEGER, UUID, UUID, TEXT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.replace_kubernetes_cluster_signing_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    BIGINT, TEXT, BYTEA, BYTEA[], TEXT, TEXT, TEXT, TEXT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_signing_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_gateway_key_event_v3(BYTEA, TEXT, INTEGER, UUID, UUID, TEXT)
    TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.replace_kubernetes_cluster_signing_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    BIGINT, TEXT, BYTEA, BYTEA[], TEXT, TEXT, TEXT, TEXT, UUID, UUID
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_signing_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;
