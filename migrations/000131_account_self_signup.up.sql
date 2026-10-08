-- Schema 131: self sign-up (R1-20 in docs/RELEASE-1-PLAN.md).
--
-- On a Cloud deployment whose entitlement allows Workspaces, a person who
-- signs in for the first time without an invitation gets an Account and a
-- default Workspace they own, in the same consuming sign-in. The provider's
-- subject is proof of identity; the display name only labels the Account and
-- the Workspace.
--
-- sign_up_account_v1 is bound to the exact consuming, Workspace-less browser
-- login of the route (as accept_workspace_invitation_v1 in schema 129). An
-- identity that already has an Account is returned untouched with no limit
-- applied. Otherwise:
--   - the deployment must be Cloud with a current entitlement (MTS01);
--   - the deployment must be under its active Workspace limit (MTS02);
--   - the source network (a keyed digest from Core) must be under its daily
--     sign-up limit, and the deployment under its hourly one (MTS03).
-- Then the principal, Account and identity subject are created and the
-- Workspace is provisioned with the sign-in's provider route, exactly as a
-- Workspace created from the Console. Each sign-up is recorded in
-- mesh.account_signup for the limits. The caller appends the evidence.

CREATE TABLE mesh.account_signup (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id BIGINT NOT NULL REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    principal_id BIGINT NOT NULL REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    workspace_id BIGINT NOT NULL REFERENCES mesh.workspace (id) ON DELETE RESTRICT,
    source_digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(source_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (principal_id)
);
CREATE INDEX account_signup_source_idx ON mesh.account_signup (deployment_id, source_digest, created_at);
CREATE INDEX account_signup_time_idx ON mesh.account_signup (deployment_id, created_at);
ALTER TABLE mesh.account_signup ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.account_signup FORCE ROW LEVEL SECURITY;
CREATE POLICY account_signup_migrator_policy ON mesh.account_signup
    FOR ALL TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.account_signup
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.sign_up_account_v1(
    p_deployment_public_id UUID, p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_transaction_public_id UUID, p_transaction_version BIGINT, p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ, p_subject_algorithm TEXT, p_active_key_id TEXT, p_active_digest BYTEA,
    p_previous_key_id TEXT, p_previous_digest BYTEA, p_display_name TEXT,
    p_workspace_public_id UUID, p_membership_public_id UUID, p_routing_public_id UUID,
    p_realm_public_id UUID, p_ipv4_pool_public_id UUID, p_ipv6_pool_public_id UUID, p_ipv6_prefix CIDR,
    p_source_digest BYTEA, p_source_daily_limit INTEGER, p_hourly_limit INTEGER,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_auth RECORD;
    v_deployment mesh.deployment%ROWTYPE;
    v_entitlement mesh.deployment_entitlement%ROWTYPE;
    v_matched BIGINT;
    v_principal BIGINT;
    v_principal_public UUID := pg_catalog.uuidv7();
    v_account_public UUID := pg_catalog.uuidv7();
    v_active BIGINT;
    v_recent BIGINT;
    v_workspace BIGINT;
BEGIN
    IF p_subject_algorithm IS DISTINCT FROM 'hmac-sha256-v1' OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL)
        OR p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR pg_catalog.btrim(p_display_name) <> p_display_name
        OR p_source_digest IS NULL OR pg_catalog.octet_length(p_source_digest) <> 32
        OR p_source_daily_limit IS NULL OR p_source_daily_limit NOT BETWEEN 1 AND 1000
        OR p_hourly_limit IS NULL OR p_hourly_limit NOT BETWEEN 1 AND 100000
        OR p_workspace_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'sign-up input is invalid';
    END IF;
    -- The exact consuming, Workspace-less browser login of this route.
    SELECT auth.deployment_id, auth.identity_provider_id, auth.identity_provider_client_id INTO v_auth
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = auth.deployment_id AND client.id = auth.identity_provider_client_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active' AND deployment.recovery_epoch = p_recovery_epoch
      AND provider.public_id = p_provider_public_id AND provider.current_generation = p_provider_generation
      AND client.public_id = p_client_public_id
      AND auth.public_id = p_transaction_public_id AND auth.workspace_id IS NULL
      AND auth.state = 'consuming' AND auth.version = p_transaction_version
      AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
      AND auth.principal_id IS NULL AND auth.binding_semantic_hash = p_binding_hash
      AND auth.consumed_at = p_consumed_at AND auth.expires_at > v_now
      AND auth.consumed_result_kind IS NULL AND auth.failure_class IS NULL;
    IF v_auth.deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sign-in transaction does not match';
    END IF;

    SELECT pg_catalog.count(*) INTO v_matched
    FROM mesh.identity_subject AS subject
    WHERE subject.deployment_id = v_auth.deployment_id
      AND subject.identity_provider_id = v_auth.identity_provider_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND subject.state <> 'deleted'
      AND ((subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
           OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest));
    IF v_matched > 1 THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the identity is ambiguous';
    END IF;
    IF v_matched = 1 THEN
        RETURN pg_catalog.jsonb_build_object('created', FALSE);
    END IF;

    -- Sign-ups in one deployment are serialized by its row lock.
    SELECT * INTO v_deployment FROM mesh.deployment AS deployment
    WHERE deployment.id = v_auth.deployment_id FOR UPDATE;
    SELECT * INTO v_entitlement FROM mesh.deployment_entitlement AS candidate
    WHERE candidate.deployment_id = v_deployment.id AND candidate.profile = v_deployment.profile
    ORDER BY candidate.generation DESC LIMIT 1
    FOR SHARE;
    IF v_deployment.profile <> 'cloud' OR v_entitlement.deployment_id IS NULL OR v_now < v_entitlement.not_before
        OR v_now >= v_entitlement.expires_at + pg_catalog.make_interval(secs => v_entitlement.grace_seconds) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTS01', MESSAGE = 'self sign-up is not available';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', 'on', TRUE);
    SELECT pg_catalog.count(*) INTO v_active FROM mesh.workspace AS workspace
    WHERE workspace.deployment_id = v_deployment.id AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL;
    PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
    IF v_active >= v_entitlement.max_active_workspaces THEN
        RAISE EXCEPTION USING ERRCODE = 'MTS02', MESSAGE = 'deployment_workspace_limit';
    END IF;
    SELECT pg_catalog.count(*) INTO v_recent FROM mesh.account_signup AS signup
    WHERE signup.deployment_id = v_deployment.id AND signup.source_digest = p_source_digest
      AND signup.created_at > v_now - INTERVAL '1 day';
    IF v_recent >= p_source_daily_limit THEN
        RAISE EXCEPTION USING ERRCODE = 'MTS03', MESSAGE = 'sign-up limit reached for this network';
    END IF;
    SELECT pg_catalog.count(*) INTO v_recent FROM mesh.account_signup AS signup
    WHERE signup.deployment_id = v_deployment.id AND signup.created_at > v_now - INTERVAL '1 hour';
    IF v_recent >= p_hourly_limit THEN
        RAISE EXCEPTION USING ERRCODE = 'MTS03', MESSAGE = 'sign-up limit reached for this deployment';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.principal (public_id, deployment_id, kind, state)
    VALUES (v_principal_public, v_deployment.id, 'account', 'active')
    RETURNING id INTO v_principal;
    INSERT INTO mesh.account (public_id, deployment_id, principal_id, display_name, recovery_state)
    VALUES (v_account_public, v_deployment.id, v_principal, p_display_name, 'verified');
    INSERT INTO mesh.identity_subject (
        public_id, deployment_id, identity_provider_id, principal_id, subject_digest_algorithm,
        subject_digest_key_id, subject_digest, last_seen_at, state
    ) VALUES (
        pg_catalog.uuidv7(), v_deployment.id, v_auth.identity_provider_id, v_principal,
        p_subject_algorithm, p_active_key_id, p_active_digest, v_now, 'active'
    );
    v_workspace := mesh_ops.provision_workspace_v1(
        v_deployment.id, v_principal, p_workspace_public_id, p_display_name,
        p_membership_public_id, p_routing_public_id, v_auth.identity_provider_id,
        v_auth.identity_provider_client_id, NULL, p_realm_public_id,
        p_ipv4_pool_public_id, p_ipv6_pool_public_id, p_ipv6_prefix, v_now);
    INSERT INTO mesh.account_signup (deployment_id, principal_id, workspace_id, source_digest, created_at)
    VALUES (v_deployment.id, v_principal, v_workspace, p_source_digest, v_now);

    RETURN pg_catalog.jsonb_build_object(
        'created', TRUE,
        'principal_id', v_principal_public,
        'account_id', v_account_public,
        'workspace_id', p_workspace_public_id
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.sign_up_account_v1(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, TEXT,
    UUID, UUID, UUID, UUID, UUID, UUID, CIDR, BYTEA, INTEGER, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.sign_up_account_v1(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, TEXT,
    UUID, UUID, UUID, UUID, UUID, UUID, CIDR, BYTEA, INTEGER, INTEGER, UUID
) TO mesh_runtime;
