-- Additive runtime-only authority function. No schema/backfill/generation
-- expansion. Released Session/auth/token contracts and migrations stay intact.
CREATE FUNCTION mesh_ops.issue_oidc_existing_subject_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID,
    p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_issuer TEXT, p_discovery_uri TEXT, p_authorization_endpoint TEXT,
    p_token_endpoint TEXT, p_jwks_uri TEXT, p_oidc_client_id TEXT,
    p_client_auth_method TEXT, p_scopes TEXT[], p_allowed_algorithms TEXT[], p_redirect_uri TEXT,
    p_transaction_public_id UUID, p_transaction_version BIGINT, p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ, p_redirect_id TEXT, p_return_route_id TEXT,
    p_subject_algorithm TEXT, p_active_key_id TEXT, p_active_digest BYTEA,
    p_previous_key_id TEXT, p_previous_digest BYTEA,
    p_principal_public_id UUID, p_subject_public_id UUID, p_membership_public_id UUID,
    p_subject_version BIGINT, p_account_version BIGINT, p_membership_version BIGINT,
    p_principal_generation BIGINT, p_account_session_generation BIGINT, p_membership_generation BIGINT,
    p_membership_expires_at TIMESTAMPTZ, p_snapshot_evaluated_at TIMESTAMPTZ,
    p_session_public_id UUID, p_token_algorithm TEXT, p_token_key_id TEXT, p_token_digest BYTEA,
    p_sid_algorithm TEXT, p_sid_key_id TEXT, p_sid_digest BYTEA,
    p_authentication_time TIMESTAMPTZ, p_acr TEXT, p_amr TEXT[], p_provider_expires_at TIMESTAMPTZ,
    p_idle_seconds BIGINT, p_absolute_seconds BIGINT
)
RETURNS TABLE (
    transaction_public_id UUID, transaction_version BIGINT, transaction_binding_hash BYTEA,
    transaction_consumed_at TIMESTAMPTZ, terminal_state TEXT, result_kind TEXT,
    result_public_id UUID, session_public_id UUID, session_version BIGINT,
    issued_at TIMESTAMPTZ, idle_expires_at TIMESTAMPTZ, absolute_expires_at TIMESTAMPTZ,
    stream_internal_id BIGINT, next_sequence BIGINT, latest_event_hash BYTEA
)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    current_subject RECORD;
    target mesh.auth_transaction%ROWTYPE;
    current_workspace_id BIGINT;
    current_provider_id BIGINT;
    current_principal_id BIGINT;
    current_subject_id BIGINT;
    current_client_id BIGINT;
    head_id BIGINT;
    head_sequence BIGINT;
    head_hash BYTEA;
    decision_at TIMESTAMPTZ;
    idle_at TIMESTAMPTZ;
    absolute_at TIMESTAMPTZ;
    key_id TEXT;
    method TEXT;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_session_public_id IS NULL OR p_session_public_id = p_transaction_public_id
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 8) >> 6 <> 2
        OR p_principal_public_id IS NULL OR p_subject_public_id IS NULL OR p_membership_public_id IS NULL
        OR p_subject_version IS NULL OR p_subject_version <= 0
        OR p_account_version IS NULL OR p_account_version <= 0
        OR p_membership_version IS NULL OR p_membership_version <= 0
        OR p_principal_generation IS NULL OR p_principal_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_membership_generation IS NULL OR p_membership_generation <= 0
        OR p_snapshot_evaluated_at IS NULL OR NOT pg_catalog.isfinite(p_snapshot_evaluated_at)
        OR (p_membership_expires_at IS NOT NULL AND NOT pg_catalog.isfinite(p_membership_expires_at))
        OR p_authentication_time IS NULL OR NOT pg_catalog.isfinite(p_authentication_time)
        OR p_authentication_time <= TIMESTAMPTZ '1970-01-01 00:00:00+00'
        OR pg_catalog.date_trunc('second', p_authentication_time) <> p_authentication_time
        OR p_provider_expires_at IS NULL OR NOT pg_catalog.isfinite(p_provider_expires_at)
        OR p_token_algorithm IS DISTINCT FROM 'hmac-sha256-v1'
        OR p_token_key_id IS NULL OR p_token_digest IS NULL
        OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_token_digest = pg_catalog.decode(pg_catalog.repeat('00',32),'hex')
        OR p_idle_seconds IS NULL OR p_idle_seconds <= 0
        OR p_absolute_seconds IS NULL OR p_absolute_seconds < p_idle_seconds OR p_absolute_seconds > 86400
        OR p_amr IS NULL OR COALESCE(pg_catalog.array_ndims(p_amr),1) <> 1
        OR pg_catalog.cardinality(p_amr) > 16 OR pg_catalog.array_position(p_amr,NULL) IS NOT NULL
        OR pg_catalog.octet_length(pg_catalog.array_to_string(p_amr,',')) > 1024
        OR (p_acr IS NOT NULL AND (pg_catalog.octet_length(p_acr) NOT BETWEEN 1 AND 128
            OR p_acr <> pg_catalog.btrim(p_acr) OR p_acr ~ '[[:cntrl:]]')) THEN RETURN; END IF;
    IF NOT (
        (p_sid_algorithm IS NULL AND p_sid_key_id IS NULL AND p_sid_digest IS NULL)
        OR (p_sid_algorithm = 'hmac-sha256-v1' AND p_sid_key_id IS NOT NULL AND p_sid_digest IS NOT NULL
            AND pg_catalog.octet_length(p_sid_digest) = 32
            AND p_sid_digest <> pg_catalog.decode(pg_catalog.repeat('00',32),'hex'))
    ) OR (p_sid_algorithm IS NULL) <> (p_sid_key_id IS NULL)
      OR (p_sid_key_id IS NULL) <> (p_sid_digest IS NULL) THEN RETURN; END IF;
    -- SQL NULL must not admit an unsupported non-NULL SID algorithm.
    IF p_sid_algorithm IS NOT NULL AND p_sid_algorithm <> 'hmac-sha256-v1' THEN RETURN; END IF;
    FOREACH key_id IN ARRAY ARRAY[p_token_key_id,p_sid_key_id] LOOP
        IF key_id IS NOT NULL AND (pg_catalog.octet_length(key_id) NOT BETWEEN 1 AND 128
            OR key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$') THEN RETURN; END IF;
    END LOOP;
    FOREACH method IN ARRAY p_amr LOOP
        IF pg_catalog.octet_length(method) NOT BETWEEN 1 AND 64 OR method <> pg_catalog.btrim(method)
            OR method ~ '[[:cntrl:]]' THEN RETURN; END IF;
    END LOOP;

    -- Bounded route/claim/candidate validation before locks; never a grant.
    IF NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_oidc_login_subject_v1(
        p_deployment_public_id,p_workspace_public_id,p_provider_public_id,p_client_public_id,
        p_provider_generation,p_recovery_epoch,p_issuer,p_discovery_uri,p_authorization_endpoint,
        p_token_endpoint,p_jwks_uri,p_oidc_client_id,p_client_auth_method,p_scopes,p_allowed_algorithms,p_redirect_uri,
        p_transaction_public_id,p_transaction_version,p_binding_hash,p_consumed_at,p_redirect_id,p_return_route_id,
        p_subject_algorithm,p_active_key_id,p_active_digest,p_previous_key_id,p_previous_digest
    )) THEN RETURN; END IF;

    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',p_workspace_public_id::TEXT,TRUE);
    <<issuance>>
    BEGIN
        -- Relation-first predicate barrier: provider FK key-share does not
        -- block FK-unchanged digest UPDATEs on previously nonmatching rows.
        -- Concurrent issuers SHARE; every future subject writer must acquire
        -- its relation lock before parent/authority/head row locks.
        LOCK TABLE mesh.identity_subject IN SHARE MODE;
        SELECT workspace.id INTO current_workspace_id FROM mesh.workspace AS workspace
            WHERE workspace.public_id=p_workspace_public_id ORDER BY workspace.id FOR SHARE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        PERFORM 1 FROM mesh.deployment WHERE installation_public_id=p_deployment_public_id ORDER BY id FOR SHARE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        -- Provider trust remains locked separately from the subject barrier.
        SELECT provider.id INTO current_provider_id FROM mesh.identity_provider AS provider
            JOIN mesh.deployment AS deployment ON deployment.id=provider.deployment_id
            WHERE deployment.installation_public_id=p_deployment_public_id AND provider.public_id=p_provider_public_id
            ORDER BY provider.id FOR UPDATE OF provider;
        IF NOT FOUND THEN EXIT issuance; END IF;
        PERFORM 1 FROM mesh.identity_provider_generation AS generation
            WHERE generation.identity_provider_id=current_provider_id AND generation.generation=p_provider_generation
            ORDER BY generation.id FOR SHARE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        SELECT client.id INTO current_client_id FROM mesh.identity_provider_client AS client
            WHERE client.identity_provider_id=current_provider_id AND client.public_id=p_client_public_id
            ORDER BY client.id FOR SHARE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        PERFORM 1 FROM mesh.workspace_identity_provider AS routing
            WHERE routing.workspace_id=current_workspace_id AND routing.identity_provider_id=current_provider_id
              AND routing.identity_provider_client_id=current_client_id ORDER BY routing.id FOR SHARE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        SELECT principal.id INTO current_principal_id FROM mesh.principal AS principal
            JOIN mesh.deployment AS deployment ON deployment.id=principal.deployment_id
            WHERE deployment.installation_public_id=p_deployment_public_id AND principal.public_id=p_principal_public_id
            ORDER BY principal.id FOR SHARE OF principal;
        IF NOT FOUND THEN EXIT issuance; END IF;
        PERFORM 1 FROM mesh.account WHERE principal_id=current_principal_id ORDER BY id FOR SHARE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        PERFORM 1 FROM mesh.identity_subject AS subject
            WHERE subject.identity_provider_id=current_provider_id AND subject.subject_digest_algorithm=p_subject_algorithm
              AND ((subject.subject_digest_key_id=p_active_key_id AND subject.subject_digest=p_active_digest)
                OR (subject.subject_digest_key_id=p_previous_key_id AND subject.subject_digest=p_previous_digest))
            ORDER BY subject.id LIMIT 2 FOR UPDATE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        PERFORM 1 FROM mesh.workspace_membership AS membership
            WHERE membership.workspace_id=current_workspace_id AND membership.principal_id=current_principal_id
              AND membership.public_id=p_membership_public_id ORDER BY membership.id FOR SHARE;
        IF NOT FOUND THEN EXIT issuance; END IF;
        SELECT auth.* INTO target FROM mesh.auth_transaction AS auth
            WHERE auth.public_id=p_transaction_public_id ORDER BY auth.id FOR UPDATE;
        IF NOT FOUND THEN EXIT issuance; END IF;

        SELECT head.stream_internal_id,head.next_sequence,head.latest_event_hash
            INTO STRICT head_id,head_sequence,head_hash
            FROM mesh_audit.lock_deployment_stream_head(p_deployment_public_id) AS head;

        -- All locks, including audit head, precede this fresh final decision.
        -- The released read helper clears requested scope; restore it afterwards.
        SELECT snapshot.principal_public_id,snapshot.subject_public_id,snapshot.membership_public_id,
            snapshot.subject_version,snapshot.account_version,snapshot.membership_version,
            snapshot.principal_authority_generation,snapshot.account_session_generation,
            snapshot.membership_authority_generation,snapshot.membership_expires_at,snapshot.evaluated_at
            INTO current_subject FROM mesh_ops.resolve_oidc_login_subject_v1(
                p_deployment_public_id,p_workspace_public_id,p_provider_public_id,p_client_public_id,
                p_provider_generation,p_recovery_epoch,p_issuer,p_discovery_uri,p_authorization_endpoint,
                p_token_endpoint,p_jwks_uri,p_oidc_client_id,p_client_auth_method,p_scopes,p_allowed_algorithms,p_redirect_uri,
                p_transaction_public_id,p_transaction_version,p_binding_hash,p_consumed_at,p_redirect_id,p_return_route_id,
                p_subject_algorithm,p_active_key_id,p_active_digest,p_previous_key_id,p_previous_digest
            ) AS snapshot;
        IF NOT FOUND THEN EXIT issuance; END IF;
        decision_at := pg_catalog.clock_timestamp();
        IF current_subject.principal_public_id IS DISTINCT FROM p_principal_public_id
            OR current_subject.subject_public_id IS DISTINCT FROM p_subject_public_id
            OR current_subject.membership_public_id IS DISTINCT FROM p_membership_public_id
            OR current_subject.subject_version IS DISTINCT FROM p_subject_version
            OR current_subject.account_version IS DISTINCT FROM p_account_version
            OR current_subject.membership_version IS DISTINCT FROM p_membership_version
            OR current_subject.principal_authority_generation IS DISTINCT FROM p_principal_generation
            OR current_subject.account_session_generation IS DISTINCT FROM p_account_session_generation
            OR current_subject.membership_authority_generation IS DISTINCT FROM p_membership_generation
            OR current_subject.membership_expires_at IS DISTINCT FROM p_membership_expires_at
            OR decision_at < p_snapshot_evaluated_at OR decision_at < p_consumed_at
            OR decision_at < p_authentication_time OR decision_at >= target.expires_at
            OR decision_at >= p_provider_expires_at
            OR (p_membership_expires_at IS NOT NULL AND decision_at >= p_membership_expires_at)
            OR target.account_session_generation IS NOT NULL OR target.operation_semantic_hash IS NOT NULL
            OR target.expected_organization_digest IS NOT NULL
            OR target.pkce_verifier_encryption_algorithm IS DISTINCT FROM 'aead-aes-256-gcm-v1'
            OR target.pkce_verifier_encryption_key_id IS NULL OR target.pkce_verifier_ciphertext IS NULL THEN EXIT issuance; END IF;
        PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',p_workspace_public_id::TEXT,TRUE);
        IF NOT EXISTS (SELECT 1 FROM mesh.workspace_identity_provider AS routing
            WHERE routing.workspace_id=current_workspace_id AND routing.identity_provider_id=current_provider_id
              AND routing.identity_provider_client_id=current_client_id
              AND (routing.minimum_assurance IS NULL OR routing.minimum_assurance=p_acr)) THEN EXIT issuance; END IF;
        SELECT subject.id INTO STRICT current_subject_id FROM mesh.identity_subject AS subject WHERE subject.public_id=p_subject_public_id;
        idle_at := decision_at + p_idle_seconds * INTERVAL '1 second';
        absolute_at := decision_at + p_absolute_seconds * INTERVAL '1 second';
        IF p_membership_expires_at IS NOT NULL THEN
            idle_at := LEAST(idle_at,p_membership_expires_at); absolute_at := LEAST(absolute_at,p_membership_expires_at);
        END IF;
        INSERT INTO mesh.account_session (
            public_id,deployment_id,principal_id,identity_provider_id,identity_subject_id,identity_provider_client_id,login_workspace_id,
            token_digest_algorithm,token_digest_key_id,token_digest,provider_generation,
            provider_sid_digest_algorithm,provider_sid_digest_key_id,provider_sid_digest,
            authentication_time,acr,amr,principal_authority_generation,account_session_generation,deployment_recovery_epoch,
            issued_at,last_used_at,idle_expires_at,absolute_expires_at,state,version,created_at,updated_at
        ) VALUES (
            p_session_public_id,target.deployment_id,current_principal_id,current_provider_id,current_subject_id,current_client_id,current_workspace_id,
            p_token_algorithm,p_token_key_id,p_token_digest,p_provider_generation,p_sid_algorithm,p_sid_key_id,p_sid_digest,
            p_authentication_time,p_acr,p_amr,p_principal_generation,p_account_session_generation,p_recovery_epoch,
            decision_at,decision_at,idle_at,absolute_at,'active',1,decision_at,decision_at
        );
        RETURN QUERY UPDATE mesh.auth_transaction AS auth
            SET state='succeeded',consumed_result_kind='account_session',consumed_result_public_id=p_session_public_id,
                pkce_verifier_encryption_algorithm=NULL,pkce_verifier_encryption_key_id=NULL,pkce_verifier_ciphertext=NULL,
                version=auth.version+1,updated_at=GREATEST(auth.updated_at,decision_at)
            WHERE auth.id=target.id AND auth.state='consuming' AND auth.version=2
            RETURNING auth.public_id,auth.version,auth.binding_semantic_hash,auth.consumed_at,auth.state,
                auth.consumed_result_kind,auth.consumed_result_public_id,p_session_public_id,1::BIGINT,
                decision_at,idle_at,absolute_at,head_id,head_sequence,head_hash;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='session issuance CAS rejected'; END IF;
    END issuance;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id','',TRUE);
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id','',TRUE);
    RAISE;
END;
$function$;

ALTER FUNCTION mesh_ops.issue_oidc_existing_subject_v1(
    UUID,UUID,UUID,UUID,BIGINT,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT[],TEXT,
    UUID,BIGINT,BYTEA,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,BYTEA,
    UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ,TIMESTAMPTZ,
    UUID,TEXT,TEXT,BYTEA,TEXT,TEXT,BYTEA,TIMESTAMPTZ,TEXT,TEXT[],TIMESTAMPTZ,BIGINT,BIGINT
) OWNER TO mesh_migrator;
REVOKE ALL ON FUNCTION mesh_ops.issue_oidc_existing_subject_v1(
    UUID,UUID,UUID,UUID,BIGINT,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT[],TEXT,
    UUID,BIGINT,BYTEA,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,BYTEA,
    UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ,TIMESTAMPTZ,
    UUID,TEXT,TEXT,BYTEA,TEXT,TEXT,BYTEA,TIMESTAMPTZ,TEXT,TEXT[],TIMESTAMPTZ,BIGINT,BIGINT
) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.issue_oidc_existing_subject_v1(
    UUID,UUID,UUID,UUID,BIGINT,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT[],TEXT,
    UUID,BIGINT,BYTEA,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT,BYTEA,TEXT,BYTEA,
    UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ,TIMESTAMPTZ,
    UUID,TEXT,TEXT,BYTEA,TEXT,TEXT,BYTEA,TIMESTAMPTZ,TEXT,TEXT[],TIMESTAMPTZ,BIGINT,BIGINT
) TO mesh_runtime;
