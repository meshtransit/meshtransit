-- Schema 309 (V1-12 step 1c, docs k8s-v1-12-install-token-design.md v4.1
-- §3.3–3.4): a replica that joins with an install token is approved by
-- Core, in the name of the token's maker, against the cluster's pinned
-- trust; and the functions an administrator uses on that trust.
--
-- * preapprove_kubernetes_replica_request_v1 (the join path, control and
--   api): runs in its own transaction after the request is opened. It
--   locks the cluster, then the key, then the request (the order of every
--   approval), recomputes the cluster trust digest from the request's
--   stored signing material (never a caller's digest) and:
--     - pins it, unconfirmed, when the cluster trusts nothing yet;
--     - contests an unconfirmed install-token trust whose digest differs
--       (one key more or less is a difference): the trust keeps both
--       sides, every gateway Device of the cluster is suspended (never
--       revoked: the right side gets its Devices back), every install
--       token of the cluster is revoked. A contested trust admits nothing;
--     - against a confirmed trust, admits only the same identity with a
--       signing key the trust holds (it never widens the trust);
--   then checks the token (live, one use per pod ordinal; the same pod UID
--   replaces its own unfinished request), the maker's rights now (approve
--   and manage on the Network), the pod (no live Device, no other
--   approval) and spends the pod token's jti once per cluster. A refusal
--   cancels the request and says why; nothing is raised for it, so the
--   refusal and a contest are kept.
-- * confirm_kubernetes_cluster_trust_v1: an administrator with approve and
--   manage confirms the unconfirmed trust whose digest they compared.
-- * choose_kubernetes_cluster_trust_v1: on a contested trust, the side
--   whose digest the administrator names becomes the confirmed trust; the
--   suspended gateway Devices approved under it resume, the others are
--   revoked.
-- * reset_kubernetes_cluster_trust_v1: an install-token trust is removed,
--   the cluster goes back to code mode, its gateway Devices and install
--   tokens are revoked (design §3.4 suspended them for an administrator to
--   revoke; nothing could resume them, and a later trust's choice must not).
--
-- Every administrator function takes the cluster version the person saw
-- (If-Match, 40001 when it moved) and needs kubernetes_cluster.approve and
-- .manage. Devices are suspended and resumed only here, under the
-- transaction flag mesh.kubernetes_trust_change of schema 308.
--
-- * set_kubernetes_cluster_trust_mode_v1 and issue_..._v1 (schema 307)
--   lock the cluster FOR NO KEY UPDATE, as everything here does.
-- * open_kubernetes_replica_request_v2 (schema 232) opens a request with an
--   install token whose uses are all spent: the approval decides.
--
-- Error codes: MTK53 the trust is contested; MTK54 the digest is not the
-- trust's; MTK55 the cluster has no install-token trust in that state.

-- The cluster trust digest of a request's stored signing material.
CREATE FUNCTION mesh_ops.kubernetes_request_trust_digest_internal_v1(p_request mesh.kubernetes_replica_request)
RETURNS BYTEA
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.kubernetes_cluster_trust_digest_v1(p_request.sa_issuer, p_request.sa_jwks,
        p_request.sa_namespace, p_request.sa_service_account, p_request.sa_statefulset)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_request_trust_digest_internal_v1(mesh.kubernetes_replica_request)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The trust as the functions below return it (no key material).
CREATE FUNCTION mesh_ops.kubernetes_trust_document_internal_v1(p_trust mesh.kubernetes_cluster_signing_trust)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT CASE WHEN p_trust.kubernetes_cluster_id IS NULL THEN NULL ELSE pg_catalog.jsonb_build_object(
        'trust_id', p_trust.public_id, 'version', p_trust.version, 'source', p_trust.source,
        'state', p_trust.state, 'digest', pg_catalog.encode(p_trust.digest, 'hex'),
        'issuer', p_trust.issuer, 'namespace', p_trust.namespace, 'service_account', p_trust.service_account,
        'statefulset', p_trust.statefulset,
        'key_thumbprints', pg_catalog.to_jsonb(ARRAY(
            SELECT pg_catalog.encode(thumbprint, 'hex') FROM pg_catalog.unnest(p_trust.key_thumbprints) AS thumbprint)),
        'contested_digest', pg_catalog.encode(p_trust.contested_digest, 'hex'),
        'contested_at', p_trust.contested_at,
        'confirmed_at', p_trust.confirmed_at
    ) END
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_trust_document_internal_v1(mesh.kubernetes_cluster_signing_trust)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Gateway Device changes serialize with registration, publication and other
-- map inputs on the Network revision (locked after the cluster, key and
-- request, before any Device, as completions and lifecycle changes do),
-- and advance it so maps and inventories are rebuilt.
CREATE FUNCTION mesh_ops.kubernetes_trust_revision_internal_v1(p_cluster_id BIGINT, p_advance BOOLEAN)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_revision BIGINT;
BEGIN
    IF p_advance THEN
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            inventory_revision = revision.inventory_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        FROM mesh.kubernetes_cluster AS cluster
        WHERE cluster.id = p_cluster_id AND revision.workspace_id = cluster.workspace_id
          AND revision.network_id = cluster.network_id
        RETURNING revision.network_revision INTO v_revision;
    ELSE
        SELECT revision.network_revision INTO v_revision FROM mesh_ops.network_revision AS revision
        JOIN mesh.kubernetes_cluster AS cluster
          ON revision.workspace_id = cluster.workspace_id AND revision.network_id = cluster.network_id
        WHERE cluster.id = p_cluster_id
        FOR UPDATE OF revision;
    END IF;
    IF v_revision IS NULL THEN
        -- The revision row is visible only in the cluster's Network scope.
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'a gateway changes only in its Network scope';
    END IF;
    RETURN v_revision;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_trust_revision_internal_v1(BIGINT, BOOLEAN)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Suspends every active gateway Device of a cluster for a contested trust
-- (their live sessions end: session_generation moves). Returns their public
-- IDs. The caller holds the cluster's row.
CREATE FUNCTION mesh_ops.suspend_kubernetes_gateways_internal_v1(p_cluster_id BIGINT, p_now TIMESTAMPTZ)
RETURNS UUID[]
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_devices UUID[];
    -- The trust change is on only while this runs (schema 308's guard also
    -- requires the migrator, so the flag alone grants no one anything).
    v_previous TEXT := pg_catalog.current_setting('mesh.kubernetes_trust_change', TRUE);
BEGIN
    PERFORM mesh_ops.kubernetes_trust_revision_internal_v1(p_cluster_id, FALSE);
    PERFORM pg_catalog.set_config('mesh.kubernetes_trust_change', 'on', TRUE);
    WITH suspended AS (
        UPDATE mesh.device AS device
        SET state = 'suspended', suspended_reason = 'trust_contested',
            session_generation = device.session_generation + 1, version = device.version + 1,
            updated_at = GREATEST(p_now, device.updated_at)
        WHERE device.kubernetes_cluster_id = p_cluster_id AND device.kind = 'kubernetes_gateway'
          AND device.state = 'active' AND device.deleted_at IS NULL
        RETURNING device.public_id
    )
    SELECT COALESCE(pg_catalog.array_agg(public_id ORDER BY public_id), ARRAY[]::UUID[]) INTO v_devices
    FROM suspended;
    PERFORM pg_catalog.set_config('mesh.kubernetes_trust_change', COALESCE(v_previous, ''), TRUE);
    IF pg_catalog.cardinality(v_devices) > 0 THEN
        PERFORM mesh_ops.kubernetes_trust_revision_internal_v1(p_cluster_id, TRUE);
    END IF;
    RETURN v_devices;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.suspend_kubernetes_gateways_internal_v1(BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Resumes one gateway Device suspended for a contested trust (it joins its
-- cluster's group again, schema 308). The caller holds the cluster's row.
CREATE FUNCTION mesh_ops.resume_kubernetes_gateway_internal_v1(p_device_id BIGINT, p_now TIMESTAMPTZ)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_previous TEXT := pg_catalog.current_setting('mesh.kubernetes_trust_change', TRUE);
    v_resumed BOOLEAN;
BEGIN
    PERFORM pg_catalog.set_config('mesh.kubernetes_trust_change', 'on', TRUE);
    UPDATE mesh.device AS device
    SET state = 'active', suspended_reason = NULL, version = device.version + 1,
        updated_at = GREATEST(p_now, device.updated_at)
    WHERE device.id = p_device_id AND device.kind = 'kubernetes_gateway' AND device.state = 'suspended'
      AND device.suspended_reason = 'trust_contested' AND device.deleted_at IS NULL;
    v_resumed := FOUND;
    PERFORM pg_catalog.set_config('mesh.kubernetes_trust_change', COALESCE(v_previous, ''), TRUE);
    RETURN v_resumed;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.resume_kubernetes_gateway_internal_v1(BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Revokes one gateway Device, its current keys and its addresses (as
-- revoke_device_v2, schema 296, without a session: the caller authorized).
CREATE FUNCTION mesh_ops.revoke_kubernetes_gateway_internal_v1(p_device_id BIGINT, p_reason TEXT, p_now TIMESTAMPTZ)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
BEGIN
    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.id = p_device_id AND device.kind = 'kubernetes_gateway'
    FOR UPDATE;
    IF v_device.id IS NULL OR v_device.state NOT IN ('active', 'suspended') OR v_device.deleted_at IS NOT NULL THEN
        RETURN;
    END IF;
    UPDATE mesh.device AS device
    SET state = 'revoked', suspended_reason = NULL, handover_principal_id = NULL,
        session_generation = device.session_generation + 1, version = device.version + 1,
        updated_at = GREATEST(p_now, device.updated_at)
    WHERE device.id = v_device.id;
    UPDATE mesh.device_machine_key_epoch AS key_epoch
    SET valid_until = GREATEST(p_now, key_epoch.valid_from), revocation_reason = p_reason, state = 'revoked',
        version = key_epoch.version + 1, updated_at = GREATEST(p_now, key_epoch.updated_at)
    WHERE key_epoch.device_id = v_device.id AND key_epoch.epoch = v_device.current_machine_key_epoch
      AND key_epoch.state = 'active' AND key_epoch.valid_until IS NULL;
    UPDATE mesh.device_node_key_epoch AS key_epoch
    SET valid_until = GREATEST(p_now, key_epoch.valid_from), revocation_reason = p_reason, state = 'revoked',
        version = key_epoch.version + 1, updated_at = GREATEST(p_now, key_epoch.updated_at)
    WHERE key_epoch.device_id = v_device.id AND key_epoch.epoch = v_device.current_node_key_epoch
      AND key_epoch.state = 'active' AND key_epoch.valid_until IS NULL;
    PERFORM mesh_ops.quarantine_device_leases_v1(v_device.id, p_now);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.revoke_kubernetes_gateway_internal_v1(BIGINT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Cancels a request the install-token approval refuses and says why.
CREATE FUNCTION mesh_ops.refuse_kubernetes_preapproval_internal_v1(
    p_request mesh.kubernetes_replica_request, p_approver UUID, p_reason TEXT, p_cluster mesh.kubernetes_cluster,
    p_now TIMESTAMPTZ, p_trust JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(p_now, request.updated_at)
    WHERE request.id = p_request.id AND request.state IN ('pending', 'approved')
    RETURNING * INTO v_request;
    IF v_request.id IS NULL THEN
        SELECT * INTO STRICT v_request FROM mesh.kubernetes_replica_request AS request WHERE request.id = p_request.id;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'refused', 'reason', p_reason, 'approver_principal_id', p_approver,
        'cluster_id', p_cluster.public_id,
        'network_id', (SELECT network.public_id FROM mesh.network AS network
                       WHERE network.workspace_id = p_cluster.workspace_id AND network.id = p_cluster.network_id),
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(p_cluster.workspace_id, p_cluster.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(p_request),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'trust', p_trust
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.refuse_kubernetes_preapproval_internal_v1(
    mesh.kubernetes_replica_request, UUID, TEXT, mesh.kubernetes_cluster, TIMESTAMPTZ, JSONB
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.preapprove_kubernetes_replica_request_v1(
    p_request_public_id UUID, p_pod_uid UUID, p_jti TEXT, p_jti_expires_at TIMESTAMPTZ, p_change_public_id UUID
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
    v_found mesh.kubernetes_replica_request%ROWTYPE;
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_preapproval mesh.kubernetes_join_key_preapproval%ROWTYPE;
    v_use mesh.kubernetes_join_key_ordinal_use%ROWTYPE;
    v_used_request mesh.kubernetes_replica_request%ROWTYPE;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_digest BYTEA;
    v_epoch BIGINT;
    v_suffix TEXT;
    v_pod_ordinal INTEGER;
    v_ordinal SMALLINT;
    v_trust_set BOOLEAN := FALSE;
    v_suspended UUID[];
    v_revoked BIGINT;
    v_new_use BOOLEAN := FALSE;
    v_approver UUID;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_request_public_id IS NULL OR p_pod_uid IS NULL OR p_jti IS NULL
        OR pg_catalog.octet_length(p_jti) NOT BETWEEN 1 AND 128 OR p_jti !~ '^[!-~]+$'
        OR p_jti_expires_at IS NULL OR p_jti_expires_at > v_now + INTERVAL '1 hour'
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'install-token approval is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    -- Read unlocked only to learn the cluster and the key; both are locked
    -- before the request, which is read again under its lock.
    SELECT request.* INTO v_found FROM mesh.kubernetes_replica_request AS request
    WHERE request.workspace_id = v_workspace AND request.network_id = v_network
      AND request.public_id = p_request_public_id;
    IF v_found.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown replica request';
    END IF;
    -- FOR NO KEY UPDATE: an open holds the key and takes KEY SHARE on the
    -- cluster through its foreign key; a full lock would deadlock with it.
    SELECT cluster.* INTO STRICT v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.id = v_found.kubernetes_cluster_id
    FOR NO KEY UPDATE;
    SELECT credential.* INTO STRICT v_credential FROM mesh.enrollment_credential AS credential
    WHERE credential.id = v_found.enrollment_credential_id
    FOR UPDATE;
    SELECT request.* INTO STRICT v_before FROM mesh.kubernetes_replica_request AS request
    WHERE request.id = v_found.id
    FOR UPDATE;
    SELECT preapproval.* INTO v_preapproval FROM mesh.kubernetes_join_key_preapproval AS preapproval
    WHERE preapproval.enrollment_credential_id = v_credential.id
    FOR SHARE;
    -- An ordinary key's request waits for an administrator.
    IF v_preapproval.enrollment_credential_id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'not_preapproved',
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before));
    END IF;
    -- The token's maker: the named approver, and the actor of what follows.
    SELECT principal.public_id INTO STRICT v_approver FROM mesh.principal AS principal
    WHERE principal.id = v_preapproval.created_by_principal_id;
    IF v_before.state <> 'pending' OR v_before.code_version <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    -- The pod token is checked again on this clock: a token Core's clock
    -- still took, whose spent jti this clock has pruned, is not spent twice.
    IF p_jti_expires_at <= v_now THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'pod_token_expired',
            v_cluster, v_now, NULL);
    END IF;
    IF v_cluster.state <> 'active' OR v_cluster.trust_mode <> 'private_tofu' THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'install_tokens_off', v_cluster, v_now, NULL);
    END IF;

    -- The cluster's trust first, before the token's use is checked, so a
    -- party that used the token up is still found out.
    v_digest := mesh_ops.kubernetes_request_trust_digest_internal_v1(v_before);
    IF v_digest IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'the replica request holds no signing material';
    END IF;
    SELECT trust.* INTO v_trust FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_cluster.id
    FOR UPDATE;
    IF v_trust.kubernetes_cluster_id IS NOT NULL AND v_trust.state = 'contested' THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'trust_contested', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    END IF;
    IF v_trust.kubernetes_cluster_id IS NOT NULL AND v_trust.state = 'unconfirmed'
        AND v_trust.digest IS DISTINCT FROM v_digest THEN
        UPDATE mesh.kubernetes_cluster_signing_trust AS trust
        SET state = 'contested', contested_digest = v_digest, contested_issuer = v_before.sa_issuer,
            contested_jwks = v_before.sa_jwks, contested_key_thumbprints = v_before.sa_key_thumbprints,
            contested_namespace = v_before.sa_namespace, contested_service_account = v_before.sa_service_account,
            contested_statefulset = v_before.sa_statefulset, contested_request_id = v_before.id,
            contested_at = v_now, version = trust.version + 1
        WHERE trust.kubernetes_cluster_id = v_cluster.id
        RETURNING * INTO v_trust;
        v_suspended := mesh_ops.suspend_kubernetes_gateways_internal_v1(v_cluster.id, v_now);
        -- Revokes the install tokens and cancels their requests, this one
        -- included.
        v_revoked := mesh_ops.revoke_kubernetes_install_tokens_internal_v1(v_cluster.id, v_now);
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.id = v_before.id AND request.state = 'pending';
        UPDATE mesh.kubernetes_cluster AS cluster
        SET version = cluster.version + 1, updated_at = GREATEST(v_now, cluster.updated_at)
        WHERE cluster.id = v_cluster.id
        RETURNING * INTO v_cluster;
        SELECT request.* INTO STRICT v_request FROM mesh.kubernetes_replica_request AS request
        WHERE request.id = v_before.id;
        RETURN pg_catalog.jsonb_build_object(
            'outcome', 'contested', 'approver_principal_id', v_approver,
            'cluster_id', v_cluster.public_id,
            'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
            'network_id', (SELECT network.public_id FROM mesh.network AS network
                           WHERE network.workspace_id = v_cluster.workspace_id AND network.id = v_cluster.network_id),
            'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_cluster.workspace_id,
                v_cluster.network_id),
            'trust', mesh_ops.kubernetes_trust_document_internal_v1(v_trust),
            'suspended_devices', pg_catalog.to_jsonb(v_suspended),
            'revoked_tokens', v_revoked,
            'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request)
        );
    END IF;
    -- A confirmed trust is never widened: the same identity, signed by a key
    -- it holds (the pod's keys may be a superset after rotation).
    IF v_trust.kubernetes_cluster_id IS NOT NULL AND v_trust.state = 'confirmed' AND (
        v_trust.issuer <> v_before.sa_issuer OR v_trust.namespace <> v_before.sa_namespace
        OR v_trust.service_account <> v_before.sa_service_account
        OR v_trust.statefulset <> v_before.sa_statefulset
        OR NOT (v_before.sa_join_key_thumbprint = ANY (v_trust.key_thumbprints))) THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'differs_from_trust', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    END IF;

    -- The pod: <statefulset>-<n>, n below the replicas the token covers.
    v_suffix := pg_catalog.substr(v_before.sa_pod_name, pg_catalog.char_length(v_before.sa_statefulset) + 2);
    IF pg_catalog.left(v_before.sa_pod_name, pg_catalog.char_length(v_before.sa_statefulset) + 1)
            <> v_before.sa_statefulset || '-'
        OR v_suffix !~ '^(0|[1-9][0-9]?)$' OR v_suffix::INTEGER >= v_preapproval.replicas THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'pod_ordinal', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    END IF;
    v_pod_ordinal := v_suffix::INTEGER;

    -- The token: live now (it may have lapsed since the request opened).
    SELECT deployment.recovery_epoch INTO v_epoch FROM mesh.workspace AS workspace
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE workspace.id = v_cluster.workspace_id;
    IF v_credential.state <> 'active' OR v_credential.expires_at <= v_now OR v_credential.valid_from > v_now
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'token_unusable', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    END IF;
    -- One use per pod ordinal; the same pod (UID) asking again replaces its
    -- own unfinished request and spends nothing more.
    SELECT ordinal_use.* INTO v_use FROM mesh.kubernetes_join_key_ordinal_use AS ordinal_use
    WHERE ordinal_use.enrollment_credential_id = v_credential.id AND ordinal_use.ordinal = v_pod_ordinal
    FOR UPDATE;
    IF v_use.enrollment_credential_id IS NOT NULL THEN
        SELECT request.* INTO STRICT v_used_request FROM mesh.kubernetes_replica_request AS request
        WHERE request.id = v_use.replica_request_id
        FOR UPDATE;
        IF v_use.pod_uid <> p_pod_uid THEN
            RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'ordinal_used', v_cluster, v_now,
                mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
        END IF;
        IF v_used_request.state = 'completed' THEN
            RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'pod_held', v_cluster, v_now,
                mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
        END IF;
        -- Its earlier request is cancelled only once every check below
        -- passed: a refused attempt (a replayed token) changes nothing.
    ELSIF v_credential.used_count >= v_credential.max_uses THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'token_used', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    ELSE
        v_new_use := TRUE;
    END IF;

    -- The maker approves every replica the token admits: their rights are
    -- read again now (a maker who lost them approves nothing).
    IF NOT mesh_ops.kubernetes_principal_holds_permission_internal_v1(v_preapproval.created_by_principal_id,
            v_cluster.workspace_id, v_cluster.network_id, 'kubernetes_cluster.approve', v_now)
        OR NOT mesh_ops.kubernetes_principal_holds_permission_internal_v1(v_preapproval.created_by_principal_id,
            v_cluster.workspace_id, v_cluster.network_id, 'kubernetes_cluster.manage', v_now) THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'approver_unauthorized', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    END IF;

    -- Requests of this cluster past their deadline expire first.
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(NULL, v_cluster.id, NULL, NULL);
    -- One Device per pod: none alive bound to it, and no other approval.
    IF EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
               JOIN mesh.device AS device ON device.id = other.device_id
               WHERE other.kubernetes_cluster_id = v_cluster.id AND other.state = 'completed'
                 AND other.sa_pod_name = v_before.sa_pod_name AND device.state IN ('active', 'suspended')
                 AND device.deleted_at IS NULL)
        OR EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
                   WHERE other.kubernetes_cluster_id = v_cluster.id AND other.state = 'approved'
                     AND other.completion_deadline > v_now
                     AND other.sa_pod_name = v_before.sa_pod_name AND other.id <> v_before.id
                     AND other.id IS DISTINCT FROM v_used_request.id) THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'pod_held', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    END IF;

    -- The pod token is spent once, whatever the cluster (schema 308).
    DELETE FROM mesh_ops.kubernetes_join_token_use AS token_use
    WHERE token_use.expires_at < v_now;
    INSERT INTO mesh_ops.kubernetes_join_token_use (kubernetes_cluster_id, jti, replica_request_id, expires_at, used_at)
    VALUES (v_cluster.id, p_jti, v_before.id, GREATEST(p_jti_expires_at, v_now), v_now)
    ON CONFLICT (jti) DO NOTHING;
    IF NOT FOUND THEN
        RETURN mesh_ops.refuse_kubernetes_preapproval_internal_v1(v_before, v_approver, 'token_replayed', v_cluster, v_now,
            mesh_ops.kubernetes_trust_document_internal_v1(v_trust));
    END IF;

    -- Every check passed: the same pod's earlier, unfinished request ends.
    IF v_used_request.id IS NOT NULL THEN
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.id = v_used_request.id AND request.state IN ('pending', 'approved');
    END IF;
    -- The first replica pins the cluster's trust, unconfirmed. Its version
    -- is the cluster's (never reused after a reset: a trust read before is
    -- not taken for this one); the cluster's version moves with it.
    IF v_trust.kubernetes_cluster_id IS NULL THEN
        UPDATE mesh.kubernetes_cluster AS cluster
        SET version = cluster.version + 1, updated_at = GREATEST(v_now, cluster.updated_at)
        WHERE cluster.id = v_cluster.id
        RETURNING * INTO v_cluster;
        INSERT INTO mesh.kubernetes_cluster_signing_trust (
            kubernetes_cluster_id, public_id, workspace_id, network_id, issuer, jwks, key_thumbprints, namespace,
            service_account, statefulset, version, source, source_request_id, set_by_principal_id, set_at,
            state, digest
        ) VALUES (
            v_cluster.id, pg_catalog.uuidv7(), v_cluster.workspace_id, v_cluster.network_id, v_before.sa_issuer,
            v_before.sa_jwks, v_before.sa_key_thumbprints, v_before.sa_namespace, v_before.sa_service_account,
            v_before.sa_statefulset, v_cluster.version, 'install_token', v_before.id,
            v_preapproval.created_by_principal_id, v_now, 'unconfirmed', v_digest
        ) RETURNING * INTO v_trust;
        v_trust_set := TRUE;
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
    IF v_new_use THEN
        UPDATE mesh.enrollment_credential AS credential
        SET used_count = credential.used_count + 1, version = credential.version + 1,
            updated_at = GREATEST(v_now, credential.updated_at)
        WHERE credential.id = v_credential.id;
        INSERT INTO mesh.kubernetes_join_key_ordinal_use (
            enrollment_credential_id, ordinal, public_id, workspace_id, network_id, pod_uid, replica_request_id,
            used_at
        ) VALUES (
            v_credential.id, v_pod_ordinal, pg_catalog.uuidv7(), v_cluster.workspace_id, v_cluster.network_id,
            p_pod_uid, v_before.id, v_now
        );
    ELSE
        UPDATE mesh.kubernetes_join_key_ordinal_use AS ordinal_use
        SET replica_request_id = v_before.id, version = ordinal_use.version + 1, used_at = v_now
        WHERE ordinal_use.enrollment_credential_id = v_credential.id AND ordinal_use.ordinal = v_pod_ordinal;
    END IF;
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'approved', approved_by_principal_id = v_preapproval.created_by_principal_id, approved_at = v_now,
        completion_deadline = v_now + INTERVAL '15 minutes', reserved_ordinal = v_ordinal,
        reserved_hostname = v_cluster.name || '-' || v_ordinal::TEXT, version = request.version + 1,
        updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'approved',
        'trust_set', v_trust_set,
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'trust', mesh_ops.kubernetes_trust_document_internal_v1(v_trust),
        'approver_principal_id', v_approver,
        'pod_ordinal', v_pod_ordinal,
        'new_use', v_new_use,
        'cluster_id', v_cluster.public_id,
        'network_id', (SELECT network.public_id FROM mesh.network AS network
                       WHERE network.workspace_id = v_cluster.workspace_id AND network.id = v_cluster.network_id),
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_cluster.workspace_id,
            v_cluster.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.preapprove_kubernetes_replica_request_v1(UUID, UUID, TEXT, TIMESTAMPTZ, UUID)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.preapprove_kubernetes_replica_request_v1(UUID, UUID, TEXT, TIMESTAMPTZ, UUID)
    TO mesh_api_rights, mesh_control_rights;

-- The authorization and locks every administrator function below starts
-- with: approve and manage, the cluster held, its version the caller's.
CREATE FUNCTION mesh_ops.kubernetes_trust_admin_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_cluster_version BIGINT, p_change_public_id UUID
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT, actor_id BIGINT, authority JSONB,
    cluster_id BIGINT)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_approve RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_cluster_version IS NULL OR p_cluster_version <= 0
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'trust request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    SELECT * INTO v_approve FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT kubernetes_cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS kubernetes_cluster
    WHERE kubernetes_cluster.workspace_id = v_grant.workspace_id
      AND kubernetes_cluster.network_id = v_grant.network_id
      AND kubernetes_cluster.public_id = p_cluster_public_id AND kubernetes_cluster.state = 'active'
    FOR NO KEY UPDATE;
    IF v_cluster.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    IF v_cluster.version <> p_cluster_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'the Kubernetes cluster changed';
    END IF;
    PERFORM 1 FROM mesh.kubernetes_cluster_signing_trust AS signing_trust
    WHERE signing_trust.kubernetes_cluster_id = v_cluster.id
    FOR UPDATE;
    RETURN QUERY SELECT v_grant.deployment_id, v_grant.workspace_id, v_grant.network_id, v_grant.actor_id,
        v_grant.authority, v_cluster.id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_trust_admin_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The result every administrator function returns.
CREATE FUNCTION mesh_ops.kubernetes_trust_result_internal_v1(
    p_authority JSONB, p_network_public_id UUID, p_before_cluster mesh.kubernetes_cluster,
    p_cluster mesh.kubernetes_cluster, p_before mesh.kubernetes_cluster_signing_trust,
    p_trust mesh.kubernetes_cluster_signing_trust, p_extra JSONB
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(p_cluster.workspace_id,
            p_cluster.network_id),
        'trust_mode', p_cluster.trust_mode,
        'before_cluster', mesh_ops.kubernetes_cluster_document_internal_v1(p_before_cluster),
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(p_cluster),
        'before', mesh_ops.kubernetes_trust_document_internal_v1(p_before),
        'trust', mesh_ops.kubernetes_trust_document_internal_v1(p_trust),
        'authority', p_authority
    ) || p_extra
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_trust_result_internal_v1(
    JSONB, UUID, mesh.kubernetes_cluster, mesh.kubernetes_cluster, mesh.kubernetes_cluster_signing_trust,
    mesh.kubernetes_cluster_signing_trust, JSONB
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.confirm_kubernetes_cluster_trust_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_digest BYTEA, p_cluster_version BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_admin RECORD;
    v_old_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_old mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
BEGIN
    IF p_digest IS NULL OR pg_catalog.octet_length(p_digest) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'trust request is invalid';
    END IF;
    SELECT * INTO v_admin FROM mesh_ops.kubernetes_trust_admin_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id, p_cluster_version, p_change_public_id);
    SELECT cluster.* INTO STRICT v_old_cluster FROM mesh.kubernetes_cluster AS cluster WHERE cluster.id = v_admin.cluster_id;
    SELECT trust.* INTO v_old FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_admin.cluster_id;
    IF v_old.kubernetes_cluster_id IS NULL OR v_old.source <> 'install_token' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK55', MESSAGE = 'the Kubernetes cluster has no install-token trust';
    END IF;
    IF v_old.state = 'contested' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK53', MESSAGE = 'the Kubernetes cluster''s trust is contested';
    END IF;
    IF v_old.digest IS DISTINCT FROM p_digest THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK54', MESSAGE = 'the digest is not the trust''s';
    END IF;
    IF v_old.state = 'confirmed' THEN
        RETURN mesh_ops.kubernetes_trust_result_internal_v1(v_admin.authority, p_network_public_id,
            v_old_cluster, v_old_cluster, v_old, v_old,
            pg_catalog.jsonb_build_object('changed', FALSE));
    END IF;
    UPDATE mesh.kubernetes_cluster_signing_trust AS trust
    SET state = 'confirmed', confirmed_by_principal_id = v_admin.actor_id, confirmed_at = v_now,
        version = trust.version + 1
    WHERE trust.kubernetes_cluster_id = v_old_cluster.id
    RETURNING * INTO v_trust;
    UPDATE mesh.kubernetes_cluster AS cluster
    SET version = cluster.version + 1, updated_at = GREATEST(v_now, cluster.updated_at)
    WHERE cluster.id = v_old_cluster.id
    RETURNING * INTO v_cluster;
    RETURN mesh_ops.kubernetes_trust_result_internal_v1(v_admin.authority, p_network_public_id,
        v_old_cluster, v_cluster, v_old, v_trust, pg_catalog.jsonb_build_object('changed', TRUE));
END;
$function$;

CREATE FUNCTION mesh_ops.choose_kubernetes_cluster_trust_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_digest BYTEA, p_cluster_version BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_admin RECORD;
    v_old_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_old mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_device RECORD;
    v_resumed UUID[] := ARRAY[]::UUID[];
    v_revoked UUID[] := ARRAY[]::UUID[];
BEGIN
    IF p_digest IS NULL OR pg_catalog.octet_length(p_digest) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'trust request is invalid';
    END IF;
    SELECT * INTO v_admin FROM mesh_ops.kubernetes_trust_admin_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id, p_cluster_version, p_change_public_id);
    SELECT cluster.* INTO STRICT v_old_cluster FROM mesh.kubernetes_cluster AS cluster WHERE cluster.id = v_admin.cluster_id;
    SELECT trust.* INTO v_old FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_admin.cluster_id;
    v_before := v_old;
    IF v_before.kubernetes_cluster_id IS NULL OR v_before.state <> 'contested' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK55', MESSAGE = 'the Kubernetes cluster''s trust is not contested';
    END IF;
    IF p_digest = v_before.digest THEN
        UPDATE mesh.kubernetes_cluster_signing_trust AS trust
        SET state = 'confirmed', confirmed_by_principal_id = v_admin.actor_id, confirmed_at = v_now,
            contested_digest = NULL, contested_issuer = NULL, contested_jwks = NULL,
            contested_key_thumbprints = NULL, contested_namespace = NULL, contested_service_account = NULL,
            contested_statefulset = NULL, contested_request_id = NULL, contested_at = NULL,
            version = trust.version + 1
        WHERE trust.kubernetes_cluster_id = v_before.kubernetes_cluster_id
        RETURNING * INTO v_trust;
    ELSIF p_digest = v_before.contested_digest THEN
        -- The other side becomes the trust, under a new name (the authority
        -- journal keeps a row's name, so the row is replaced).
        DELETE FROM mesh.kubernetes_cluster_signing_trust AS trust
        WHERE trust.kubernetes_cluster_id = v_before.kubernetes_cluster_id;
        INSERT INTO mesh.kubernetes_cluster_signing_trust (
            kubernetes_cluster_id, public_id, workspace_id, network_id, issuer, jwks, key_thumbprints, namespace,
            service_account, statefulset, version, source, source_request_id, set_by_principal_id, set_at,
            state, digest, confirmed_by_principal_id, confirmed_at
        ) VALUES (
            v_before.kubernetes_cluster_id, pg_catalog.uuidv7(), v_before.workspace_id, v_before.network_id,
            v_before.contested_issuer, v_before.contested_jwks, v_before.contested_key_thumbprints,
            v_before.contested_namespace, v_before.contested_service_account, v_before.contested_statefulset,
            v_before.version + 1, 'install_token', v_before.contested_request_id, v_admin.actor_id, v_now,
            'confirmed', v_before.contested_digest, v_admin.actor_id, v_now
        ) RETURNING * INTO v_trust;
    ELSE
        RAISE EXCEPTION USING ERRCODE = 'MTK54', MESSAGE = 'the digest is neither side of the contest';
    END IF;
    -- Each gateway Device approved from a request whose digest is the
    -- chosen one resumes; every other one of the cluster is revoked.
    PERFORM mesh_ops.kubernetes_trust_revision_internal_v1(v_before.kubernetes_cluster_id, FALSE);
    FOR v_device IN
        SELECT device.id, device.public_id, device.state, device.suspended_reason,
            mesh_ops.kubernetes_request_trust_digest_internal_v1(request) IS NOT DISTINCT FROM v_trust.digest
                AND request.id IS NOT NULL AS chosen
        FROM mesh.device AS device
        LEFT JOIN mesh.kubernetes_replica_request AS request
          ON request.device_id = device.id AND request.state = 'completed' AND request.code_version = 2
        WHERE device.kubernetes_cluster_id = v_before.kubernetes_cluster_id AND device.kind = 'kubernetes_gateway'
          AND device.state IN ('active', 'suspended') AND device.deleted_at IS NULL
        ORDER BY device.id
        FOR UPDATE OF device
    LOOP
        IF v_device.chosen IS TRUE THEN
            IF mesh_ops.resume_kubernetes_gateway_internal_v1(v_device.id, v_now) THEN
                v_resumed := v_resumed || v_device.public_id;
            END IF;
        ELSE
            PERFORM mesh_ops.revoke_kubernetes_gateway_internal_v1(v_device.id, 'kubernetes trust not chosen', v_now);
            v_revoked := v_revoked || v_device.public_id;
        END IF;
    END LOOP;
    IF pg_catalog.cardinality(v_resumed) + pg_catalog.cardinality(v_revoked) > 0 THEN
        PERFORM mesh_ops.kubernetes_trust_revision_internal_v1(v_before.kubernetes_cluster_id, TRUE);
    END IF;
    UPDATE mesh.kubernetes_cluster AS cluster
    SET version = cluster.version + 1, updated_at = GREATEST(v_now, cluster.updated_at)
    WHERE cluster.id = v_before.kubernetes_cluster_id
    RETURNING * INTO v_cluster;
    RETURN mesh_ops.kubernetes_trust_result_internal_v1(v_admin.authority, p_network_public_id,
        v_old_cluster, v_cluster, v_before, v_trust, pg_catalog.jsonb_build_object(
            'changed', TRUE, 'resumed_devices', pg_catalog.to_jsonb(v_resumed),
            'revoked_devices', pg_catalog.to_jsonb(v_revoked)));
END;
$function$;

CREATE FUNCTION mesh_ops.reset_kubernetes_cluster_trust_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_reason TEXT, p_cluster_version BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_admin RECORD;
    v_old_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_old mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_device RECORD;
    v_devices UUID[] := ARRAY[]::UUID[];
    v_revoked BIGINT;
BEGIN
    IF p_reason IS NULL OR pg_catalog.char_length(p_reason) NOT BETWEEN 1 AND 256
        OR p_reason <> pg_catalog.btrim(p_reason) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'trust request is invalid';
    END IF;
    SELECT * INTO v_admin FROM mesh_ops.kubernetes_trust_admin_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id, p_cluster_version, p_change_public_id);
    SELECT cluster.* INTO STRICT v_old_cluster FROM mesh.kubernetes_cluster AS cluster WHERE cluster.id = v_admin.cluster_id;
    SELECT trust.* INTO v_old FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_admin.cluster_id;
    IF v_old.kubernetes_cluster_id IS NULL OR v_old.source <> 'install_token' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK55', MESSAGE = 'the Kubernetes cluster has no install-token trust';
    END IF;
    -- The gateways approved under the trust are revoked: nothing could
    -- bring a suspended one back once the trust is gone, and a later trust
    -- must not resume them.
    PERFORM mesh_ops.kubernetes_trust_revision_internal_v1(v_old_cluster.id, FALSE);
    FOR v_device IN
        SELECT device.id, device.public_id FROM mesh.device AS device
        WHERE device.kubernetes_cluster_id = v_old_cluster.id AND device.kind = 'kubernetes_gateway'
          AND device.state IN ('active', 'suspended') AND device.deleted_at IS NULL
        ORDER BY device.id
        FOR UPDATE
    LOOP
        PERFORM mesh_ops.revoke_kubernetes_gateway_internal_v1(v_device.id, 'kubernetes trust reset', v_now);
        v_devices := v_devices || v_device.public_id;
    END LOOP;
    IF pg_catalog.cardinality(v_devices) > 0 THEN
        PERFORM mesh_ops.kubernetes_trust_revision_internal_v1(v_old_cluster.id, TRUE);
    END IF;
    v_revoked := mesh_ops.revoke_kubernetes_install_tokens_internal_v1(v_old_cluster.id, v_now);
    -- Approvals of the cluster not completed yet end with the trust.
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.kubernetes_cluster_id = v_old_cluster.id AND request.state IN ('pending', 'approved');
    DELETE FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_old_cluster.id;
    UPDATE mesh.kubernetes_cluster AS cluster
    SET trust_mode = 'code', version = cluster.version + 1, updated_at = GREATEST(v_now, cluster.updated_at)
    WHERE cluster.id = v_old_cluster.id
    RETURNING * INTO v_cluster;
    RETURN mesh_ops.kubernetes_trust_result_internal_v1(v_admin.authority, p_network_public_id,
        v_old_cluster, v_cluster, v_old, NULL, pg_catalog.jsonb_build_object(
            'changed', TRUE, 'reason', p_reason, 'revoked_devices', pg_catalog.to_jsonb(v_devices),
            'revoked_tokens', v_revoked));
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.confirm_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BYTEA, BIGINT, UUID
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.confirm_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BYTEA, BIGINT, UUID
) TO mesh_api_rights, mesh_control_rights;
REVOKE ALL ON FUNCTION mesh_ops.choose_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BYTEA, BIGINT, UUID
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.choose_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BYTEA, BIGINT, UUID
) TO mesh_api_rights, mesh_control_rights;
REVOKE ALL ON FUNCTION mesh_ops.reset_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, BIGINT, UUID
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.reset_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, BIGINT, UUID
) TO mesh_api_rights, mesh_control_rights;

-- Schema 232's open, with one change: an install token whose uses are all
-- spent still opens requests (bounded by the waiting limit); the approval
-- above counts its uses per pod ordinal and contests another trust first.
CREATE OR REPLACE FUNCTION mesh_ops.open_kubernetes_replica_request_v2(
    p_credential_public_id UUID, p_request_public_id UUID, p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA, p_node_key BYTEA, p_node_key_fingerprint BYTEA, p_hostname TEXT,
    p_reported JSONB, p_request_nonce BYTEA, p_change_public_id UUID,
    p_sa_issuer TEXT, p_sa_jwks BYTEA, p_sa_key_thumbprints BYTEA[], p_sa_namespace TEXT,
    p_sa_service_account TEXT, p_sa_statefulset TEXT, p_sa_pod_name TEXT, p_sa_join_key_thumbprint BYTEA,
    p_sa_digest BYTEA
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
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_sa_digest IS NULL OR pg_catalog.octet_length(p_sa_digest) <> 32 THEN
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
            -- Schema 232: a request opened without trust, still waiting, is
            -- cancelled and the replica opens one with trust. Any other comes
            -- back, saying whether it holds other signing material.
            IF v_request.code_version = 1 AND v_request.state = 'pending' THEN
                UPDATE mesh.kubernetes_replica_request AS request
                SET state = 'cancelled', version = request.version + 1,
                    updated_at = GREATEST(v_now, request.updated_at)
                WHERE request.id = v_request.id AND request.state = 'pending';
            ELSE
                RETURN pg_catalog.jsonb_build_object(
                    'created', FALSE,
                    'trust_conflict', v_request.code_version = 2 AND v_request.sa_digest <> p_sa_digest
                        AND v_request.state IN ('pending', 'approved'),
                    'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
                    'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
                );
            END IF;
        END IF;
        v_request := NULL;
    END IF;
    IF v_credential.id IS NULL OR v_cluster.id IS NULL OR v_credential.state <> 'active'
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch
        OR v_credential.valid_from > v_now OR v_credential.expires_at <= v_now
        -- Schema 309: an install token's uses are counted per pod ordinal
        -- when Core approves, where the same pod coming back spends nothing
        -- and another trust is found out even when the uses are spent.
        OR (v_credential.used_count >= v_credential.max_uses AND NOT EXISTS (
            SELECT 1 FROM mesh.kubernetes_join_key_preapproval AS preapproval
            WHERE preapproval.enrollment_credential_id = v_credential.id)) THEN
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
        IF v_request.code_version = 1 AND v_request.state = 'pending' THEN
            UPDATE mesh.kubernetes_replica_request AS request
            SET state = 'cancelled', version = request.version + 1,
                updated_at = GREATEST(v_now, request.updated_at)
            WHERE request.id = v_request.id AND request.state = 'pending';
        ELSE
            RETURN pg_catalog.jsonb_build_object(
                'created', FALSE,
                'trust_conflict', v_request.code_version = 2 AND v_request.sa_digest <> p_sa_digest
                    AND v_request.state IN ('pending', 'approved'),
                'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
                'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
            );
        END IF;
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
        expires_at, created_at, updated_at, code_version, sa_issuer, sa_jwks, sa_key_thumbprints, sa_namespace,
        sa_service_account, sa_statefulset, sa_pod_name, sa_join_key_thumbprint, sa_digest
    ) VALUES (
        p_request_public_id, v_workspace, v_network, v_cluster.id, v_credential.id,
        p_machine_key, p_machine_key_fingerprint, p_node_key, p_node_key_fingerprint, p_hostname, p_request_nonce,
        p_reported,
        v_credential.expires_at, v_now, v_now, 2, p_sa_issuer, p_sa_jwks, p_sa_key_thumbprints, p_sa_namespace,
        p_sa_service_account, p_sa_statefulset, p_sa_pod_name, p_sa_join_key_thumbprint, p_sa_digest
    ) RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'created', TRUE,
        'trust_conflict', FALSE,
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

-- Schema 307's trust mode change and install token issue, locking the
-- cluster FOR NO KEY UPDATE (they change no key): an open holding a key
-- takes KEY SHARE on the cluster, and leaving private_tofu locks every
-- install token, which would otherwise deadlock with it.
CREATE OR REPLACE FUNCTION mesh_ops.set_kubernetes_cluster_trust_mode_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_trust_mode TEXT, p_cluster_version BIGINT, p_change_public_id UUID
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
    v_approve RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_cluster%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_revoked BIGINT := 0;
BEGIN
    IF p_cluster_public_id IS NULL OR p_trust_mode IS NULL OR p_trust_mode NOT IN ('code', 'private_tofu')
        OR p_cluster_version IS NULL OR p_cluster_version <= 0 OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'trust mode request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    SELECT * INTO v_approve FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT * INTO v_before FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    IF v_before.version <> p_cluster_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'the Kubernetes cluster changed';
    END IF;
    IF v_before.trust_mode = p_trust_mode THEN
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id,
            'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
                v_grant.workspace_id, v_grant.network_id),
            'changed', FALSE, 'revoked_tokens', 0, 'trust_mode', v_before.trust_mode,
            'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_before),
            'authority', v_grant.authority
        );
    END IF;
    -- The mode says how the first signing keys are anchored: a cluster that
    -- already trusts keys keeps its mode until its trust is reset.
    IF EXISTS (SELECT 1 FROM mesh.kubernetes_cluster_signing_trust AS trust
               WHERE trust.kubernetes_cluster_id = v_before.id) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK51', MESSAGE = 'the Kubernetes cluster already trusts signing keys';
    END IF;
    IF v_before.trust_mode = 'private_tofu' THEN
        v_revoked := mesh_ops.revoke_kubernetes_install_tokens_internal_v1(v_before.id, v_now);
    END IF;
    UPDATE mesh.kubernetes_cluster AS cluster
    SET trust_mode = p_trust_mode, version = cluster.version + 1, updated_at = GREATEST(v_now, cluster.updated_at)
    WHERE cluster.id = v_before.id
    RETURNING * INTO v_cluster;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'changed', TRUE, 'revoked_tokens', v_revoked, 'trust_mode', v_cluster.trust_mode,
        'before_trust_mode', v_before.trust_mode,
        'before', mesh_ops.kubernetes_cluster_document_internal_v1(v_before),
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'authority', v_grant.authority
    );
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.issue_kubernetes_preapproved_join_key_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_key_public_id UUID,
    p_preapproval_public_id UUID, p_digest_key_id TEXT, p_token_digest BYTEA, p_token_fingerprint BYTEA,
    p_key_lifetime_seconds BIGINT, p_replicas INTEGER, p_change_public_id UUID
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
    v_approve RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_profile BIGINT;
    v_usable BIGINT;
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_trust_state TEXT;
BEGIN
    IF p_key_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_key_public_id), 6) >> 4 <> 7
        OR p_preapproval_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_preapproval_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_cluster_public_id IS NULL OR p_digest_key_id IS NULL OR p_token_digest IS NULL
        OR p_token_fingerprint IS NULL
        OR p_key_lifetime_seconds IS NULL OR p_key_lifetime_seconds NOT BETWEEN 300 AND 86400
        OR p_replicas IS NULL OR p_replicas NOT BETWEEN 1 AND 5 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'install token request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    -- The maker approves every replica the token admits: they need approve
    -- too, checked again at each approval.
    SELECT * INTO v_approve FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    IF v_cluster.trust_mode <> 'private_tofu' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK50', MESSAGE = 'the Kubernetes cluster does not take install tokens';
    END IF;
    SELECT trust.state INTO v_trust_state FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_cluster.id;
    IF v_trust_state = 'contested' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK53', MESSAGE = 'the Kubernetes cluster''s trust is contested';
    END IF;
    SELECT profile.id INTO STRICT v_profile FROM mesh.enrollment_profile AS profile
    WHERE profile.kubernetes_cluster_id = v_cluster.id AND profile.deleted_at IS NULL
      AND profile.state = 'active' AND profile.device_kind = 'kubernetes_gateway';
    SELECT pg_catalog.count(*) INTO v_usable FROM mesh.enrollment_credential AS credential
    WHERE credential.workspace_id = v_grant.workspace_id AND credential.network_id = v_grant.network_id
      AND credential.enrollment_profile_id = v_profile AND credential.state = 'active'
      AND credential.deleted_at IS NULL AND credential.used_count < credential.max_uses
      AND credential.expires_at > v_now;
    IF v_usable >= 16 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK07', MESSAGE = 'the Kubernetes cluster already has 16 usable join keys';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.enrollment_credential (
        public_id, workspace_id, network_id, enrollment_profile_id, issuer_principal_id,
        digest_algorithm, digest_key_id, token_digest, token_fingerprint, issued_recovery_epoch,
        use_limit_kind, max_uses, used_count, valid_from, expires_at, state,
        device_lifetime_seconds, device_never_expires, description, created_at, updated_at
    ) VALUES (
        p_key_public_id, v_grant.workspace_id, v_grant.network_id, v_profile, v_grant.actor_id,
        'hmac-sha256-v1', p_digest_key_id, p_token_digest, p_token_fingerprint, p_deployment_recovery_epoch,
        'bounded', p_replicas, 0, v_now, v_now + pg_catalog.make_interval(secs => p_key_lifetime_seconds), 'active',
        NULL, TRUE, NULL, v_now, v_now
    )
    RETURNING * INTO v_credential;
    INSERT INTO mesh.kubernetes_join_key_preapproval (
        enrollment_credential_id, public_id, workspace_id, network_id, created_by_principal_id, replicas, created_at
    ) VALUES (
        v_credential.id, p_preapproval_public_id, v_grant.workspace_id, v_grant.network_id, v_grant.actor_id,
        p_replicas, v_now
    );
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'key', mesh_ops.kubernetes_join_key_document_internal_v1(v_credential),
        'preapproval', pg_catalog.jsonb_build_object('replicas', p_replicas),
        'authority', v_grant.authority
    );
END;
$function$;
