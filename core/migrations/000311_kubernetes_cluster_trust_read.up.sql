-- Schema 311 (V1-12 step 1g): what the Console shows of a cluster's trust
-- (design §3.4, §3.8): its trust mode, the trust's source and state, its
-- digest (computed for a trust set before install tokens), the other side
-- of a contest, who confirmed it; for those who manage the cluster, its
-- install tokens and the pod ordinals each has admitted. A new function, so
-- the cluster and signing documents older Cores decode strictly stay as
-- they are. Digests and thumbprints are not secret; the JWKS is not
-- returned.
CREATE FUNCTION mesh_ops.read_kubernetes_cluster_trust_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID
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
    v_manage BOOLEAN := FALSE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_trust_document JSONB;
    v_tokens JSONB;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_cluster_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO STRICT v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    BEGIN
        PERFORM 1 FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'kubernetes_cluster.manage');
        v_manage := TRUE;
    EXCEPTION WHEN insufficient_privilege THEN
        v_manage := FALSE;
    END;
    SELECT cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active';
    IF v_cluster.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT trust.* INTO v_trust FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_cluster.id;
    IF v_trust.kubernetes_cluster_id IS NOT NULL THEN
        v_trust_document := pg_catalog.jsonb_build_object(
            'trust_id', v_trust.public_id, 'version', v_trust.version, 'source', v_trust.source,
            'state', v_trust.state,
            'digest', pg_catalog.encode(COALESCE(v_trust.digest, mesh_ops.kubernetes_cluster_trust_digest_v1(
                v_trust.issuer, v_trust.jwks, v_trust.namespace, v_trust.service_account, v_trust.statefulset)), 'hex'),
            'issuer', v_trust.issuer, 'namespace', v_trust.namespace, 'service_account', v_trust.service_account,
            'statefulset', v_trust.statefulset,
            'key_thumbprints', pg_catalog.to_jsonb(ARRAY(
                SELECT pg_catalog.encode(thumbprint, 'hex') FROM pg_catalog.unnest(v_trust.key_thumbprints) AS thumbprint)),
            'set_at', v_trust.set_at,
            'confirmed_at', v_trust.confirmed_at,
            -- Who confirmed it, as who set a trust (schema 235): for those
            -- who manage the cluster only.
            'confirmed_by', CASE WHEN v_manage THEN (SELECT principal.public_id FROM mesh.principal AS principal
                             WHERE principal.id = v_trust.confirmed_by_principal_id) END,
            'contested', CASE WHEN v_trust.state = 'contested' THEN pg_catalog.jsonb_build_object(
                'digest', pg_catalog.encode(v_trust.contested_digest, 'hex'),
                'issuer', v_trust.contested_issuer, 'namespace', v_trust.contested_namespace,
                'service_account', v_trust.contested_service_account,
                'statefulset', v_trust.contested_statefulset,
                'key_thumbprints', pg_catalog.to_jsonb(ARRAY(
                    SELECT pg_catalog.encode(thumbprint, 'hex')
                    FROM pg_catalog.unnest(v_trust.contested_key_thumbprints) AS thumbprint)),
                'contested_at', v_trust.contested_at) END
        );
    END IF;
    IF v_manage THEN
        -- 32 install tokens: the usable ones first, newest first.
        SELECT COALESCE(pg_catalog.jsonb_agg(token.document ORDER BY token.usable DESC, token.created_at DESC,
            token.id DESC), '[]')
        INTO v_tokens
        FROM (
            SELECT credential.id, credential.created_at,
                credential.state = 'active' AND credential.expires_at > v_now AS usable,
                pg_catalog.jsonb_build_object(
                'key_id', credential.public_id,
                'state', CASE WHEN credential.state = 'active' AND credential.expires_at <= v_now THEN 'expired'
                              ELSE credential.state END,
                'replicas', preapproval.replicas,
                'used_ordinals', pg_catalog.to_jsonb(ARRAY(
                    SELECT ordinal_use.ordinal FROM mesh.kubernetes_join_key_ordinal_use AS ordinal_use
                    WHERE ordinal_use.enrollment_credential_id = credential.id ORDER BY ordinal_use.ordinal)),
                'created_by', (SELECT principal.public_id FROM mesh.principal AS principal
                               WHERE principal.id = preapproval.created_by_principal_id),
                'created_at', credential.created_at, 'expires_at', credential.expires_at
            ) AS document
            FROM mesh.kubernetes_join_key_preapproval AS preapproval
            JOIN mesh.enrollment_credential AS credential ON credential.id = preapproval.enrollment_credential_id
            JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
            WHERE profile.kubernetes_cluster_id = v_cluster.id
            ORDER BY credential.state = 'active' AND credential.expires_at > v_now DESC, credential.created_at DESC,
                credential.id DESC
            LIMIT 32
        ) AS token;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'cluster_id', v_cluster.public_id,
        'cluster_version', v_cluster.version,
        'trust_mode', v_cluster.trust_mode,
        'trust', v_trust_document,
        'can_manage', v_manage,
        'install_tokens', v_tokens
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_trust_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_api_rights, mesh_control_rights;
