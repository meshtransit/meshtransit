-- Schema 225: completing a Kubernetes replica request (K1a1.3). An approved
-- request completes in one Go transaction that reuses registration's address,
-- name, revision and evidence steps; the gateway Device itself is written by
-- insert_kubernetes_gateway_device_v1 (only the migrator writes gateway
-- rows, schema 224), and complete_kubernetes_replica_request_v1 marks the
-- request completed and records the key's use without counting it again
-- (approval did). Opening a request now returns the replica's own request,
-- waiting, approved or completed, before it checks the key, so a replica that
-- reconnects after approvals used the key up still finds it.
--
-- Errors: 22023 invalid input, 42501 no scope, P0002 unknown request, MTK10
-- the request cannot complete (not approved, past its deadline, its key
-- revoked, its cluster deleted).

-- A gateway Device gets its own mesh DNS name like any Device, written by
-- the Device insert trigger of schema 169; schema 224's guard on DNS labels
-- refused it. Names other Devices give to a gateway stay refused
-- (network_dns_name), and a gateway's name never changes.
DROP TRIGGER device_dns_label_kubernetes_gateway ON mesh.device_dns_label;

ALTER TABLE mesh.kubernetes_replica_request ADD COLUMN completed_network_revision BIGINT;
ALTER TABLE mesh.kubernetes_replica_request
    ADD CONSTRAINT kubernetes_replica_request_completed_revision_check CHECK (
        (state = 'completed') = (completed_network_revision IS NOT NULL)
        AND (completed_network_revision IS NULL OR completed_network_revision > 0)
    ) NOT VALID;
ALTER TABLE mesh.kubernetes_replica_request
    VALIDATE CONSTRAINT kubernetes_replica_request_completed_revision_check;

CREATE OR REPLACE FUNCTION mesh_ops.open_kubernetes_replica_request_v1(
    p_credential_public_id UUID, p_request_public_id UUID, p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA, p_node_key BYTEA, p_node_key_fingerprint BYTEA, p_hostname TEXT,
    p_reported JSONB, p_request_nonce BYTEA, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_epoch BIGINT;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_waiting BIGINT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_credential_public_id IS NULL OR p_request_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR p_machine_key IS NULL OR p_machine_key_fingerprint IS NULL OR p_node_key IS NULL
        OR p_node_key_fingerprint IS NULL
        OR p_hostname IS NULL OR p_reported IS NULL OR p_request_nonce IS NULL
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT credential.* INTO v_credential FROM mesh.enrollment_credential AS credential
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id
    FOR UPDATE;
    SELECT cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.enrollment_profile AS profile ON profile.kubernetes_cluster_id = cluster.id
    WHERE profile.id = v_credential.enrollment_profile_id AND profile.device_kind = 'kubernetes_gateway'
      AND profile.deleted_at IS NULL AND cluster.state = 'active';
    SELECT deployment.recovery_epoch INTO v_epoch FROM mesh.workspace AS workspace
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE workspace.id = v_workspace;
    -- The same replica asking again gets its request back whatever its key
    -- has become since, waiting, approved or completed: approvals consume
    -- the key's uses, and a reconnecting replica must still find its way.
    IF v_credential.id IS NOT NULL THEN
        PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(
            v_credential.id, NULL, p_machine_key_fingerprint, p_node_key);
        SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
        WHERE request.machine_key_fingerprint = p_machine_key_fingerprint
          AND request.enrollment_credential_id = v_credential.id
          AND request.state IN ('pending', 'approved', 'completed')
        ORDER BY request.id DESC
        LIMIT 1;
        IF FOUND AND v_request.node_key = p_node_key AND v_request.machine_key = p_machine_key THEN
            RETURN pg_catalog.jsonb_build_object(
                'created', FALSE,
                'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
                'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
            );
        END IF;
        v_request := NULL;
    END IF;
    IF v_credential.id IS NULL OR v_cluster.id IS NULL OR v_credential.state <> 'active'
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch
        OR v_credential.valid_from > v_now OR v_credential.expires_at <= v_now
        OR v_credential.used_count >= v_credential.max_uses THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK04', MESSAGE = 'the join key is not usable';
    END IF;
    -- Past-deadline requests of this key, or holding these keys under
    -- another key, are moved to expired first. Those other requests are
    -- taken out of the usual lock order; a deadlock with another key's
    -- approval is possible only over two stale rows, and PostgreSQL resolves
    -- it (40P01, a conflict the caller retries).
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(
        v_credential.id, NULL, p_machine_key_fingerprint, p_node_key);

    SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
    WHERE request.machine_key_fingerprint = p_machine_key_fingerprint
      AND request.state IN ('pending', 'approved');
    IF FOUND THEN
        IF v_request.node_key <> p_node_key OR v_request.enrollment_credential_id <> v_credential.id
            OR v_request.machine_key <> p_machine_key THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK06', MESSAGE = 'the keys are already in use';
        END IF;
        RETURN pg_catalog.jsonb_build_object(
            'created', FALSE,
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
            'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
        );
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.device_machine_key_epoch AS epoch
               WHERE epoch.fingerprint = p_machine_key_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh.device_node_key_epoch AS epoch WHERE epoch.public_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS request
                   WHERE request.node_key = p_node_key AND request.state IN ('pending', 'approved'))
        OR EXISTS (SELECT 1 FROM mesh.pending_registration AS pending
                   WHERE pending.state IN ('pending', 'authorized') AND pending.requested_node_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.pending_registration AS pending
                   WHERE pending.state IN ('pending', 'authorized')
                     AND pending.machine_key_fingerprint = p_machine_key_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh.browser_registration_intent AS intent
                   WHERE intent.state IN ('pending', 'approved') AND intent.requested_node_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.browser_registration_intent AS intent
                   JOIN mesh.workspace AS workspace ON workspace.deployment_id = intent.deployment_id
                   WHERE workspace.id = v_workspace AND intent.state IN ('pending', 'approved')
                     AND intent.machine_key_fingerprint = p_machine_key_fingerprint) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK06', MESSAGE = 'the keys are already in use';
    END IF;
    SELECT pg_catalog.count(*) INTO v_waiting FROM mesh.kubernetes_replica_request AS request
    WHERE request.enrollment_credential_id = v_credential.id AND request.state = 'pending';
    IF v_waiting >= 2 * v_credential.max_uses THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK03', MESSAGE = 'too many replicas are waiting for this join key';
    END IF;
    INSERT INTO mesh.kubernetes_replica_request (
        public_id, workspace_id, network_id, kubernetes_cluster_id, enrollment_credential_id,
        machine_key, machine_key_fingerprint, node_key, node_key_fingerprint, hostname, request_nonce, reported,
        expires_at, created_at, updated_at
    ) VALUES (
        p_request_public_id, v_workspace, v_network, v_cluster.id, v_credential.id,
        p_machine_key, p_machine_key_fingerprint, p_node_key, p_node_key_fingerprint, p_hostname, p_request_nonce,
        p_reported,
        v_credential.expires_at, v_now, v_now
    ) RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'created', TRUE,
        'key_issuer_principal_id', (SELECT issuer.public_id FROM mesh.principal AS issuer
                                    WHERE issuer.id = v_credential.issuer_principal_id),
        'network_id', (SELECT network.public_id FROM mesh.network AS network
                       WHERE network.workspace_id = v_workspace AND network.id = v_network),
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_workspace, v_network),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
    );
END;
$function$;


-- Locks an approved request of the transaction's Network for its replica's
-- session to complete: cluster, then key, then request (schema 224's
-- order). The request must belong to the session's machine key and node
-- key. A request still waiting comes back unlocked with its state; one past
-- its completion deadline comes back expired, unchanged. A completed
-- request comes back with its Device, for the session to authorize again,
-- while that Device is active.
CREATE FUNCTION mesh_ops.lock_kubernetes_replica_completion_v1(
    p_request_public_id UUID, p_machine_key_fingerprint BYTEA, p_node_key BYTEA, p_change_public_id UUID
)
RETURNS TABLE (
    request_internal_id BIGINT, request_state TEXT, request_version BIGINT,
    completion_deadline TIMESTAMPTZ, reserved_ordinal SMALLINT, reserved_hostname TEXT,
    credential_internal_id BIGINT, credential_state TEXT, cluster_internal_id BIGINT,
    profile_internal_id BIGINT, owner_principal_internal_id BIGINT,
    device_public_id UUID, device_hostname TEXT, completed_network_revision BIGINT,
    approver_public_id UUID, cluster_public_id UUID
)
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
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_profile BIGINT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_request_public_id IS NULL OR p_machine_key_fingerprint IS NULL OR p_node_key IS NULL
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica completion is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
    WHERE request.workspace_id = v_workspace AND request.network_id = v_network
      AND request.public_id = p_request_public_id
      AND request.machine_key_fingerprint = p_machine_key_fingerprint AND request.node_key = p_node_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown replica request';
    END IF;
    IF v_request.state = 'approved' THEN
        PERFORM 1 FROM mesh.kubernetes_cluster AS cluster
        WHERE cluster.id = v_request.kubernetes_cluster_id AND cluster.state = 'active' FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the cluster is gone';
        END IF;
        SELECT credential.* INTO STRICT v_credential FROM mesh.enrollment_credential AS credential
        WHERE credential.id = v_request.enrollment_credential_id FOR UPDATE;
        SELECT request.* INTO STRICT v_request FROM mesh.kubernetes_replica_request AS request
        WHERE request.id = v_request.id FOR UPDATE;
        -- Reported, not written: a write would need its own evidence. Open
        -- and approve move such rows to expired; the ordinal reservation
        -- already ends at the deadline.
        IF v_request.state = 'approved' AND v_request.completion_deadline <= pg_catalog.transaction_timestamp() THEN
            v_request.state := 'expired';
        END IF;
        SELECT profile.id INTO STRICT v_profile FROM mesh.enrollment_profile AS profile
        WHERE profile.kubernetes_cluster_id = v_request.kubernetes_cluster_id AND profile.deleted_at IS NULL;
    END IF;
    -- A completed request authorizes again only while its Device lives: a
    -- revoked or deleted gateway's pod gets a final answer, not a loop.
    IF v_request.state = 'completed' THEN
        PERFORM 1 FROM mesh.device AS device
        WHERE device.id = v_request.device_id AND device.state = 'active' AND device.deleted_at IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the gateway Device is no longer active';
        END IF;
    END IF;
    RETURN QUERY
    SELECT v_request.id, v_request.state, v_request.version, v_request.completion_deadline,
        v_request.reserved_ordinal, v_request.reserved_hostname, v_request.enrollment_credential_id,
        v_credential.state, v_request.kubernetes_cluster_id, v_profile,
        CASE WHEN v_request.state = 'approved' THEN mesh_ops.workspace_device_principal_internal_v1(v_workspace) END,
        device.public_id, device.hostname, v_request.completed_network_revision,
        approver.public_id, cluster.public_id
    FROM mesh.kubernetes_cluster AS cluster
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = v_request.workspace_id AND device.network_id = v_request.network_id
     AND device.id = v_request.device_id
    LEFT JOIN mesh.principal AS approver ON approver.id = v_request.approved_by_principal_id
    WHERE cluster.id = v_request.kubernetes_cluster_id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_kubernetes_replica_completion_v1(UUID, BYTEA, BYTEA, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_kubernetes_replica_completion_v1(UUID, BYTEA, BYTEA, UUID) TO mesh_runtime;

-- Writes the gateway Device of a request locked by
-- lock_kubernetes_replica_completion_v1 in this transaction: Workspace-owned,
-- never expiring, named p_hostname (the reserved name, or Go's next free
-- variant of it), with the reserved ordinal. Only this migrator-owned
-- function writes gateway Devices (schema 224's writer guard).
CREATE FUNCTION mesh_ops.insert_kubernetes_gateway_device_v1(
    p_request_internal_id BIGINT, p_device_public_id UUID, p_hostname TEXT, p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (device_internal_id BIGINT, device_version BIGINT)
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
    v_profile BIGINT;
    v_owner BIGINT;
    v_stem TEXT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_request_internal_id IS NULL OR p_device_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7
        OR p_hostname IS NULL OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'gateway Device is invalid';
    END IF;
    SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
    WHERE request.id = p_request_internal_id AND request.workspace_id = v_workspace
      AND request.network_id = v_network
    FOR UPDATE;
    IF NOT FOUND OR v_request.state <> 'approved' OR v_request.device_id IS NOT NULL
        OR v_request.completion_deadline <= pg_catalog.transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the replica request cannot complete';
    END IF;
    -- The reserved name, or a "-<n>" variant of it if a Device took it; a
    -- variant that would pass 63 bytes keeps a shortened stem
    -- (node.NextAvailableHostname).
    v_stem := pg_catalog.regexp_replace(p_hostname, '-[1-9][0-9]{0,5}$', '');
    IF p_hostname <> v_request.reserved_hostname
        AND (v_stem = p_hostname OR v_stem = ''
             OR (v_stem <> v_request.reserved_hostname
                 AND (pg_catalog.octet_length(p_hostname) <> 63
                      OR NOT pg_catalog.starts_with(v_request.reserved_hostname, v_stem)))) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'gateway Device name is not the reserved one';
    END IF;
    PERFORM 1 FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.id = v_request.kubernetes_cluster_id AND cluster.state = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the cluster is gone';
    END IF;
    PERFORM 1 FROM mesh.enrollment_credential AS credential
    WHERE credential.id = v_request.enrollment_credential_id AND credential.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the join key was revoked';
    END IF;
    SELECT profile.id INTO STRICT v_profile FROM mesh.enrollment_profile AS profile
    WHERE profile.kubernetes_cluster_id = v_request.kubernetes_cluster_id AND profile.deleted_at IS NULL;
    v_owner := mesh_ops.workspace_device_principal_internal_v1(v_workspace);
    RETURN QUERY
    INSERT INTO mesh.device (
        public_id, workspace_id, network_id, enrollment_profile_id, owner_principal_id, custodian_principal_id,
        registered_by_kind, registered_by_credential_id, hostname, hostname_key, is_ephemeral, expires_at,
        state, ownership, hostname_locked, kind, kubernetes_cluster_id, kubernetes_ordinal,
        created_at, updated_at
    ) VALUES (
        p_device_public_id, v_workspace, v_network, v_profile, v_owner, v_owner,
        'credential', v_request.enrollment_credential_id, p_hostname, p_hostname, FALSE,
        mesh_ops.device_never_expires_v1(), 'active', 'workspace', TRUE, 'kubernetes_gateway',
        v_request.kubernetes_cluster_id, v_request.reserved_ordinal, p_occurred_at, p_occurred_at
    )
    RETURNING id, version;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.insert_kubernetes_gateway_device_v1(BIGINT, UUID, TEXT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.insert_kubernetes_gateway_device_v1(BIGINT, UUID, TEXT, TIMESTAMPTZ)
    TO mesh_runtime;

-- Marks the request completed with its Device and records the key's use,
-- without counting it: approval consumed it.
CREATE FUNCTION mesh_ops.complete_kubernetes_replica_request_v1(
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
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_request_internal_id IS NULL OR p_device_internal_id IS NULL OR p_credential_use_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_credential_use_public_id), 6) >> 4 <> 7
        OR p_network_revision IS NULL OR p_network_revision <= 0 OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica completion is invalid';
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
REVOKE ALL ON FUNCTION mesh_ops.complete_kubernetes_replica_request_v1(BIGINT, BIGINT, UUID, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.complete_kubernetes_replica_request_v1(BIGINT, BIGINT, UUID, BIGINT, TIMESTAMPTZ)
    TO mesh_runtime;
