-- Schema 307 (V1-12 step 1b, docs k8s-v1-12-install-token-design.md v4.1
-- §3.2, k8s-v1-12-step1-plan.md): a cluster can take install tokens.
--
-- * set_kubernetes_cluster_trust_mode_v1: an administrator with approve and
--   manage puts a cluster that trusts no signing keys yet into
--   'private_tofu' (or back to 'code'). Leaving 'private_tofu' revokes its
--   install tokens. 'issuer' comes with step 3.
-- * issue_kubernetes_preapproved_join_key_v1: an install token, that is a
--   join key of a private_tofu cluster with a preapproval row. It needs
--   approve and manage: its maker is the named approver of every replica it
--   approves. It lives 5 minutes to 24 hours and covers 1-5 replicas (one
--   use per replica ordinal).
-- * Only an install token writes a private_tofu cluster's trust, and only
--   on such a cluster (a trigger), so pasted keys
--   (replace_kubernetes_cluster_signing_trust_v1) never replace it; and
--   approval by code (approve_kubernetes_replica_request_v2, replaced here
--   with that one check added) is refused on a cluster not in code mode,
--   whatever its trust holds (Opus reviews of schemas 306 and 307).
-- * The cluster document (v1) is unchanged: Core of the previous release
--   decodes it strictly during a rollout and after a rollback. The new
--   functions return the trust mode beside it.
--
-- Error codes: MTK50 the cluster does not take install tokens; MTK51 the
-- cluster already trusts signing keys; MTK52 only an install token anchors
-- this cluster's trust; MTK53 the cluster's trust is contested.

CREATE FUNCTION mesh_ops.guard_kubernetes_trust_source_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_mode TEXT;
BEGIN
    -- The cluster's row is held so a concurrent trust mode change cannot
    -- slip between this read and the write (the writers lock it already).
    SELECT cluster.trust_mode INTO v_mode FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.id = NEW.kubernetes_cluster_id
    FOR SHARE;
    IF (NEW.source = 'install_token') IS DISTINCT FROM (v_mode = 'private_tofu') THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK52',
            MESSAGE = 'only an install token anchors this Kubernetes cluster''s trust';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.guard_kubernetes_trust_source_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER kubernetes_cluster_signing_trust_source_guard
BEFORE INSERT OR UPDATE ON mesh.kubernetes_cluster_signing_trust
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_kubernetes_trust_source_v1();

-- Revokes every usable install token of a cluster (leaving private_tofu, a
-- contest, a reset) and cancels the waiting and approved requests of its
-- install tokens. Returns how many tokens it revoked.
CREATE FUNCTION mesh_ops.revoke_kubernetes_install_tokens_internal_v1(p_cluster_id BIGINT, p_now TIMESTAMPTZ)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count BIGINT;
BEGIN
    WITH revoked AS (
        UPDATE mesh.enrollment_credential AS credential
        SET state = 'revoked', revoked_at = GREATEST(p_now, credential.valid_from), version = credential.version + 1,
            updated_at = GREATEST(p_now, credential.updated_at)
        FROM mesh.kubernetes_join_key_preapproval AS preapproval, mesh.enrollment_profile AS profile
        WHERE preapproval.enrollment_credential_id = credential.id
          AND profile.id = credential.enrollment_profile_id AND profile.kubernetes_cluster_id = p_cluster_id
          AND credential.state = 'active'
        RETURNING credential.id
    )
    SELECT pg_catalog.count(*) INTO v_count FROM revoked;
    -- As revoke_kubernetes_join_key_v1: their waiting and approved requests
    -- are cancelled, so an approval never completes on a revoked token.
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(p_now, request.updated_at)
    FROM mesh.kubernetes_join_key_preapproval AS preapproval, mesh.enrollment_credential AS credential,
        mesh.enrollment_profile AS profile
    WHERE request.enrollment_credential_id = preapproval.enrollment_credential_id
      AND credential.id = preapproval.enrollment_credential_id AND credential.state = 'revoked'
      AND profile.id = credential.enrollment_profile_id AND profile.kubernetes_cluster_id = p_cluster_id
      AND request.state IN ('pending', 'approved');
    RETURN v_count;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.revoke_kubernetes_install_tokens_internal_v1(BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.set_kubernetes_cluster_trust_mode_v1(
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
    FOR UPDATE;
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
REVOKE ALL ON FUNCTION mesh_ops.set_kubernetes_cluster_trust_mode_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, BIGINT, UUID
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.set_kubernetes_cluster_trust_mode_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, BIGINT, UUID
) TO mesh_api_rights, mesh_control_rights;

CREATE FUNCTION mesh_ops.issue_kubernetes_preapproved_join_key_v1(
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
    FOR UPDATE;
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
REVOKE ALL ON FUNCTION mesh_ops.issue_kubernetes_preapproved_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID, TEXT, BYTEA,
    BYTEA, BIGINT, INTEGER, UUID
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.issue_kubernetes_preapproved_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID, TEXT, BYTEA,
    BYTEA, BIGINT, INTEGER, UUID
) TO mesh_api_rights, mesh_control_rights;

-- Schema 234's function with the trust mode check; owner and grants are kept.
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
    -- Schema 307: a cluster that is not in code mode anchors and admits
    -- replicas only through install tokens (V1-12): approval by code is
    -- refused whatever its trust holds, contested or not.
    IF v_cluster.trust_mode <> 'code' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK52',
            MESSAGE = 'only an install token admits replicas of this Kubernetes cluster';
    END IF;
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
