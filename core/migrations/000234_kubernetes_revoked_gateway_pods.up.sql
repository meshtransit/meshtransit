-- Schema 234 (TD-CORE-98): a revoked gateway Device holds its pod no more.
--
-- Revoking a Device leaves deleted_at null, so the pod checks of schema 232
-- (approve, MTK16, and completion) kept counting a revoked gateway as the
-- pod's holder, and its pod could never join again. Only an active gateway
-- Device holds its pod now. The signing read lists only active replicas,
-- which are the pods' holders, and says when it cut the waiting requests;
-- a partial index serves that list.

CREATE INDEX kubernetes_replica_request_waiting_idx
    ON mesh.kubernetes_replica_request (kubernetes_cluster_id, created_at DESC, id DESC)
    WHERE state IN ('pending', 'approved');

-- As in schema 232, with the pod held by an active gateway Device only.
CREATE OR REPLACE FUNCTION mesh_ops.approve_kubernetes_replica_request_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_code BIGINT, p_change_public_id UUID
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_epoch BIGINT;
    v_ordinal SMALLINT;
    v_hostname TEXT;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_trust_set JSONB;
    v_trust_public_id UUID;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_before := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    IF v_before.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    SELECT cluster.* INTO STRICT v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.id = v_before.kubernetes_cluster_id;
    -- Schema 232: a request opened without trust is cancelled, never
    -- approved; the replica joins again with its signing keys.
    IF v_before.code_version = 1 THEN
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.id = v_before.id
        RETURNING * INTO v_request;
        RETURN pg_catalog.jsonb_build_object(
            'outcome', 'cancelled',
            'network_id', p_network_public_id,
            'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
                v_grant.workspace_id, v_grant.network_id),
            'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
            'authority', v_grant.authority
        );
    END IF;
    -- The code v2 is checked here too, not only by Core: it binds the keys,
    -- the cluster, the nonce and the trust digest (shared/kubejoin).
    IF p_code IS DISTINCT FROM mesh_ops.kubernetes_join_code_v2(v_before.machine_key, v_before.node_key,
        v_cluster.public_id, v_before.request_nonce, v_before.sa_digest) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK09', MESSAGE = 'the code does not match the request';
    END IF;
    SELECT credential.* INTO v_credential FROM mesh.enrollment_credential AS credential
    WHERE credential.id = v_before.enrollment_credential_id;
    SELECT deployment.recovery_epoch INTO v_epoch FROM mesh.deployment AS deployment
    WHERE deployment.id = v_grant.deployment_id;
    IF v_credential.state <> 'active' OR v_credential.expires_at <= v_now OR v_credential.valid_from > v_now
        OR v_credential.used_count >= v_credential.max_uses
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch THEN
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.id = v_before.id
        RETURNING * INTO v_request;
        RETURN pg_catalog.jsonb_build_object(
            'outcome', 'cancelled',
            'network_id', p_network_public_id,
            'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
                v_grant.workspace_id, v_grant.network_id),
            'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
            'authority', v_grant.authority
        );
    END IF;
    -- Requests of this cluster past their deadline expire first, so an
    -- approval that lapsed holds its pod no longer.
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(NULL, v_cluster.id, NULL, NULL);
    -- Schema 232: the first replica's trust becomes the cluster's; later
    -- replicas must match it (design §6.4). The cluster's row lock, taken
    -- above, orders approvals of one cluster, so the trust is only read.
    SELECT trust.* INTO v_trust FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_cluster.id
    FOR SHARE;
    IF v_trust.kubernetes_cluster_id IS NULL THEN
        v_trust_public_id := pg_catalog.uuidv7();
        INSERT INTO mesh.kubernetes_cluster_signing_trust (
            kubernetes_cluster_id, public_id, workspace_id, network_id, issuer, jwks, key_thumbprints, namespace,
            service_account, statefulset, version, source, source_request_id, set_by_principal_id, set_at
        ) VALUES (
            v_cluster.id, v_trust_public_id, v_cluster.workspace_id, v_cluster.network_id, v_before.sa_issuer,
            v_before.sa_jwks, v_before.sa_key_thumbprints, v_before.sa_namespace, v_before.sa_service_account,
            v_before.sa_statefulset, 1, 'replica_approval', v_before.id, v_grant.actor_id, v_now
        );
        -- What the approval anchored, for its audit event.
        v_trust_set := pg_catalog.jsonb_build_object(
            'trust_id', v_trust_public_id, 'version', 1, 'issuer', v_before.sa_issuer,
            'namespace', v_before.sa_namespace, 'service_account', v_before.sa_service_account,
            'statefulset', v_before.sa_statefulset,
            'key_thumbprints', pg_catalog.to_jsonb(ARRAY(
                SELECT pg_catalog.encode(thumbprint, 'hex')
                FROM pg_catalog.unnest(v_before.sa_key_thumbprints) AS thumbprint))
        );
    ELSIF v_trust.issuer <> v_before.sa_issuer OR v_trust.namespace <> v_before.sa_namespace
        OR v_trust.service_account <> v_before.sa_service_account
        OR v_trust.statefulset <> v_before.sa_statefulset
        OR NOT (v_before.sa_join_key_thumbprint = ANY (v_trust.key_thumbprints)) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK15', MESSAGE = 'the replica''s signing keys differ from the cluster''s';
    END IF;
    -- One Device per pod: none alive bound to it, and no other approval.
    IF EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
               JOIN mesh.device AS device ON device.id = other.device_id
               WHERE other.kubernetes_cluster_id = v_cluster.id AND other.state = 'completed'
                 AND other.sa_pod_name = v_before.sa_pod_name AND device.state = 'active' AND device.deleted_at IS NULL)
        OR EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
                   WHERE other.kubernetes_cluster_id = v_cluster.id AND other.state = 'approved'
                     AND other.completion_deadline > v_now
                     AND other.sa_pod_name = v_before.sa_pod_name AND other.id <> v_before.id) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK16', MESSAGE = 'a Device or an approval already holds this pod';
    END IF;
    -- Ordinals of one cluster are reserved under its row lock, taken above.
    SELECT candidate.ordinal INTO v_ordinal
    FROM pg_catalog.generate_series(0, 63) AS candidate(ordinal)
    WHERE NOT EXISTS (
        SELECT 1 FROM mesh.device AS device
        WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
          AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
          AND device.kubernetes_ordinal = candidate.ordinal
    ) AND NOT EXISTS (
        SELECT 1 FROM mesh.kubernetes_replica_request AS request
        WHERE request.kubernetes_cluster_id = v_cluster.id AND request.state = 'approved'
          AND request.reserved_ordinal = candidate.ordinal
    )
    ORDER BY candidate.ordinal
    LIMIT 1;
    IF v_ordinal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK07', MESSAGE = 'the Kubernetes cluster has 64 replicas';
    END IF;
    v_hostname := v_cluster.name || '-' || v_ordinal::TEXT;
    UPDATE mesh.enrollment_credential AS credential
    SET used_count = credential.used_count + 1, version = credential.version + 1,
        updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.id = v_credential.id;
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'approved', approved_by_principal_id = v_grant.actor_id, approved_at = v_now,
        completion_deadline = v_now + INTERVAL '15 minutes', reserved_ordinal = v_ordinal,
        reserved_hostname = v_hostname, version = request.version + 1,
        updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'approved',
        'trust_set', v_trust_set,
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

-- As in schema 232, with the pod held by an active gateway Device only.
CREATE OR REPLACE FUNCTION mesh_ops.complete_kubernetes_replica_request_v1(
    p_request_internal_id BIGINT, p_device_internal_id BIGINT, p_credential_use_public_id UUID,
    p_network_revision BIGINT, p_occurred_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_trusted mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_request_internal_id IS NULL OR p_device_internal_id IS NULL OR p_credential_use_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_credential_use_public_id), 6) >> 4 <> 7
        OR p_network_revision IS NULL OR p_network_revision <= 0 OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica completion is invalid';
    END IF;
    -- Schema 232: only a request with trust completes, and only while no
    -- other live Device holds its pod (the caller holds the cluster lock).
    SELECT request.* INTO v_trusted FROM mesh.kubernetes_replica_request AS request
    WHERE request.id = p_request_internal_id AND request.workspace_id = v_workspace
      AND request.network_id = v_network;
    IF v_trusted.code_version = 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK14', MESSAGE = 'the replica must join again with its signing keys';
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
               JOIN mesh.device AS device ON device.id = other.device_id
               WHERE other.kubernetes_cluster_id = v_trusted.kubernetes_cluster_id AND other.state = 'completed'
                 AND other.sa_pod_name = v_trusted.sa_pod_name AND device.state = 'active' AND device.deleted_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK16', MESSAGE = 'a Device already holds this pod';
    END IF;
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'completed', device_id = p_device_internal_id, completed_network_revision = p_network_revision,
        version = request.version + 1, updated_at = GREATEST(p_occurred_at, request.updated_at)
    FROM mesh.device AS device
    WHERE request.id = p_request_internal_id AND request.workspace_id = v_workspace
      AND request.network_id = v_network AND request.state = 'approved'
      AND device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.id = p_device_internal_id AND device.kind = 'kubernetes_gateway'
      AND device.kubernetes_cluster_id = request.kubernetes_cluster_id
      AND device.kubernetes_ordinal = request.reserved_ordinal
    RETURNING request.* INTO v_request;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the replica request cannot complete';
    END IF;
    -- The Device holds exactly the keys the administrator's code bound.
    PERFORM 1 FROM mesh.device_machine_key_epoch AS epoch
    WHERE epoch.device_id = p_device_internal_id AND epoch.state = 'active'
      AND epoch.public_key = v_request.machine_key AND epoch.fingerprint = v_request.machine_key_fingerprint;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the Device does not hold the approved machine key';
    END IF;
    PERFORM 1 FROM mesh.device_node_key_epoch AS epoch
    WHERE epoch.device_id = p_device_internal_id AND epoch.state = 'active'
      AND epoch.public_key = v_request.node_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the Device does not hold the approved node key';
    END IF;
    -- Schema 226: a gateway's machine keys are never used again, by any
    -- gateway; its first one enters the history here.
    INSERT INTO mesh_ops.kubernetes_gateway_machine_key_history (fingerprint, device_id, created_at)
    VALUES (v_request.machine_key_fingerprint, p_device_internal_id, p_occurred_at)
    ON CONFLICT (fingerprint) DO NOTHING;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the machine key was used by a gateway before';
    END IF;
    INSERT INTO mesh.enrollment_credential_use (
        public_id, workspace_id, network_id, enrollment_credential_id, pending_registration_id,
        kubernetes_replica_request_id, device_id, machine_key_fingerprint, result, used_at, created_at
    ) VALUES (
        p_credential_use_public_id, v_workspace, v_network, v_request.enrollment_credential_id, NULL,
        v_request.id, p_device_internal_id, v_request.machine_key_fingerprint, 'created', p_occurred_at,
        p_occurred_at
    );
    RETURN TRUE;
END;
$function$;

-- As in schema 233, listing active replicas only, and saying whether the
-- waiting requests were cut at 64.
CREATE OR REPLACE FUNCTION mesh_ops.read_kubernetes_cluster_signing_v1(
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
              AND device.kubernetes_cluster_id = v_cluster.id AND device.state = 'active'
              AND device.deleted_at IS NULL
        ), '[]'::JSONB),
        'requests', v_requests,
        'requests_truncated', v_truncated,
        'token_warnings', v_warnings
    );
END;
$function$;
