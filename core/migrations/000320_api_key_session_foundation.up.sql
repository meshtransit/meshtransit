-- Schema 320 (V1-80 A1): the foundation of personal API keys.
--
-- An API key will be a row of mesh.account_session with kind 'api_key' and
-- state 'api_key' (A2 adds the table that creates them; no row of that kind
-- can be written before then). Design: api-key-design.md bản 2.1.
--
-- * A key's row is never 'active'. Every function that authenticates by
--   reading mesh.account_session with state = 'active' (sign-in, touch,
--   Workspace switch, logout, step-up, browser registration, policy
--   approval requests, Console reads...) refuses a key unchanged.
-- * The three permission resolvers every Network- and Workspace-scoped
--   operation goes through (resolve_network_permission_v1/v2,
--   resolve_workspace_permission_v1) admit a key only (a) in its own
--   Workspace, session.login_workspace_id = the Workspace resolved, and
--   (b) for a permission listed in mesh.api_key_permission. The list is the
--   database's own allowlist: a permission added later, or any permission
--   left out, refuses keys. This schema lists the read permissions only;
--   writes are added when the operations open to keys are chosen (A5).
--   Permissions stay live: the resolvers read role bindings at call time.
-- * A key's row is write-once until it ends (resolvers pin its version):
--   kind is immutable, the Workspace binding too, and the only change is
--   api_key -> revoked/expired. The default sign-in Workspace ignores keys.
--
-- Not yet: the UPDATEs that end Sessions (member suspension, removal,
-- session revocation, logout-all, recovery) still end only 'active' rows;
-- A2 extends them to key rows before any key can be created.
--
-- Older Core keeps working: it never writes kind (default 'interactive'),
-- and for interactive rows every function behaves as before.

-- One statement: one lock on the table and one validation pass.
ALTER TABLE mesh.account_session
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'interactive',
    ADD CONSTRAINT account_session_kind_check CHECK (kind IN ('interactive', 'api_key')),
    DROP CONSTRAINT account_session_state_check,
    ADD CONSTRAINT account_session_state_check CHECK (state IN ('active', 'revoked', 'expired', 'api_key')),
    -- A live key has not ended; a revoked key may say why ('api_key_revoked').
    DROP CONSTRAINT account_session_end_check,
    ADD CONSTRAINT account_session_end_check CHECK (
        (state IN ('active', 'api_key') AND ended_at IS NULL AND end_reason IS NULL)
        OR (state = 'revoked' AND ended_at IS NOT NULL AND end_reason IS NOT NULL
            AND end_reason IN ('local_logout', 'logout_all', 'account_suspended', 'membership_removed',
                'identity_unlinked', 'privilege_changed', 'provider_logout', 'provider_recovery',
                'deployment_recovery', 'administrative', 'api_key_revoked'))
        OR (state = 'expired' AND ended_at IS NOT NULL AND end_reason IS NOT NULL
            AND end_reason IN ('idle_expired', 'absolute_expired'))
    ),
    -- A key is bound to one Workspace, never idles out (its expiry is
    -- absolute), has no provider session, and is never 'active'; a human
    -- Session is never 'api_key' and never ends as a revoked key.
    ADD CONSTRAINT account_session_kind_shape_check CHECK (
        (kind = 'interactive' AND state <> 'api_key' AND end_reason IS DISTINCT FROM 'api_key_revoked')
        OR (kind = 'api_key' AND state IN ('api_key', 'revoked', 'expired')
            AND login_workspace_id IS NOT NULL
            AND idle_expires_at = absolute_expires_at
            AND provider_sid_digest_algorithm IS NULL
            AND provider_sid_digest_key_id IS NULL
            AND provider_sid_digest IS NULL)
    );

-- The permissions an API key may resolve. Written only by migrations: no
-- runtime role may read or change it except through the resolvers, which
-- run as its owner.
CREATE TABLE mesh.api_key_permission (
    permission_id BIGINT PRIMARY KEY REFERENCES mesh.permission (id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
);
REVOKE ALL ON TABLE mesh.api_key_permission FROM PUBLIC;
INSERT INTO mesh.api_key_permission (permission_id)
SELECT permission.id FROM mesh.permission AS permission WHERE permission.risk_class = 'read';

-- The transition trigger: a key starts and ends only as above; kind and
-- the Workspace binding were already outside the mutable columns.
CREATE OR REPLACE FUNCTION mesh_ops.enforce_human_auth_state_transition()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'human authentication history cannot be deleted';
    END IF;

    -- Schema 320: an Account Session starts 'active', an API key 'api_key'.
    IF TG_OP = 'INSERT' AND TG_TABLE_NAME = 'account_session' THEN
        IF NOT ((NEW.kind = 'interactive' AND NEW.state = 'active')
                OR (NEW.kind = 'api_key' AND NEW.state = 'api_key')) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid initial human authentication state';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF (TG_TABLE_NAME = 'auth_transaction' AND NEW.state <> 'pending')
            OR (TG_TABLE_NAME = 'identity_link_request' AND NEW.state <> 'pending')
            OR (TG_TABLE_NAME = 'oidc_logout_replay' AND NEW.state <> 'processing') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid initial human authentication state';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid human authentication row version transition';
    END IF;

    IF TG_TABLE_NAME = 'auth_transaction' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'consumed_at',
                'consumed_result_kind',
                'consumed_result_public_id',
                'failure_class',
                'pkce_verifier_encryption_algorithm',
                'pkce_verifier_encryption_key_id',
                'pkce_verifier_ciphertext',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'consumed_at',
                'consumed_result_kind',
                'consumed_result_public_id',
                'failure_class',
                'pkce_verifier_encryption_algorithm',
                'pkce_verifier_encryption_key_id',
                'pkce_verifier_ciphertext',
                'version',
                'updated_at'
            ]::TEXT[]) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'authentication transaction binding is immutable';
        END IF;
        IF NOT (
            (OLD.state = 'pending' AND NEW.state IN ('consuming', 'failed', 'expired'))
            OR (
                OLD.state = 'consuming'
                AND NEW.state IN ('succeeded', 'failed', 'expired')
            )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid authentication transaction state transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'account_session' THEN
        -- ADR-050 D4: an active Session may move to another Workspace only
        -- through switch_account_session_workspace_v1, which names this exact
        -- Session in mesh.account_session_workspace_switch and bumps version.
        IF NEW.login_workspace_id IS DISTINCT FROM OLD.login_workspace_id AND NOT (
            pg_catalog.current_setting('mesh.account_session_workspace_switch', TRUE) = NEW.public_id::TEXT
            AND OLD.state = 'active' AND NEW.state = 'active'
            AND NEW.version = OLD.version + 1
            AND NEW.login_workspace_id IS NOT NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'account session binding is immutable';
        END IF;
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'last_used_at',
                'idle_expires_at',
                'ended_at',
                'end_reason',
                'version',
                'updated_at',
                'login_workspace_id'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'last_used_at',
                'idle_expires_at',
                'ended_at',
                'end_reason',
                'version',
                'updated_at',
                'login_workspace_id'
            ]::TEXT[])
            OR NEW.last_used_at < OLD.last_used_at
            OR NEW.idle_expires_at < OLD.idle_expires_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'account session binding is immutable';
        END IF;
        -- Schema 320: an API key is write-once until it ends (resolvers pin
        -- its version): only api_key -> revoked/expired, nothing else moves.
        IF NOT (
            (OLD.state = 'active' AND NEW.state IN ('active', 'revoked', 'expired'))
            OR (OLD.state = 'api_key' AND NEW.state IN ('revoked', 'expired')
                AND NEW.last_used_at = OLD.last_used_at
                AND NEW.idle_expires_at = OLD.idle_expires_at)
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid account session state transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_link_request' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'resolved_at',
                'result_identity_subject_id',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'resolved_at',
                'result_identity_subject_id',
                'version',
                'updated_at'
            ]::TEXT[])
            OR OLD.state <> 'pending'
            OR NEW.state NOT IN ('linked', 'rejected', 'expired') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid identity link request transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'oidc_logout_replay' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'processed_at',
                'processing_result',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'processed_at',
                'processing_result',
                'version',
                'updated_at'
            ]::TEXT[])
            OR OLD.state <> 'processing'
            OR NEW.state NOT IN ('completed', 'failed') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid OIDC logout replay transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid human authentication trigger configuration';
    END IF;

    RETURN NEW;
END;
$function$;

-- resolve_network_permission_v1: a key resolves only in its own Workspace, and only listed permissions.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_network_permission_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_permission_key text, p_evaluated_at timestamp with time zone)
 RETURNS TABLE(role_binding_public_id uuid, role_definition_public_id uuid, scope_authority_generation bigint, membership_authority_generation bigint, binding_authority_generation bigint, role_authority_generation bigint, binding_expires_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Network permission resolution input';
    END IF;

    -- The Workspace row first. A member change holds it and then writes this
    -- session and membership, so locking those before waiting for the
    -- Workspace would deadlock with it.
    PERFORM 1 FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id
    FOR SHARE;

    RETURN QUERY
    SELECT
        binding.public_id,
        role_definition.public_id,
        network.authority_generation,
        membership.authority_generation,
        binding.authority_generation,
        role_definition.authority_generation,
        binding.expires_at
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment
      ON deployment.id = session.deployment_id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = session.deployment_id
     AND account.principal_id = session.principal_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id
     AND provider.id = session.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = session.deployment_id
     AND workspace.public_id = p_workspace_public_id
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.role_binding AS binding
      ON binding.deployment_id = session.deployment_id
     AND binding.workspace_id = workspace.id
     AND binding.network_id = network.id
     AND binding.principal_id = session.principal_id
     AND binding.workspace_membership_id = membership.id
    JOIN mesh.role_definition AS role_definition
      ON role_definition.deployment_id = session.deployment_id
     AND role_definition.workspace_id = workspace.id
     AND role_definition.id = binding.role_definition_id
    JOIN mesh.role_permission AS role_permission
      ON role_permission.deployment_id = session.deployment_id
     AND role_permission.workspace_id = workspace.id
     AND role_permission.role_definition_id = role_definition.id
    JOIN mesh.permission AS permission
      ON permission.id = role_permission.permission_id
     AND permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND (session.state = 'active' OR (session.state = 'api_key'
          AND session.login_workspace_id = workspace.id
          AND EXISTS (SELECT 1 FROM mesh.api_key_permission AS key_permission
                      WHERE key_permission.permission_id = permission.id)))
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND binding.state = 'active'
      AND binding.valid_from <= p_evaluated_at
      AND (binding.expires_at IS NULL OR binding.expires_at > p_evaluated_at)
      AND role_definition.state = 'active'
      AND role_permission.state = 'active'
    ORDER BY binding.id
    LIMIT 256
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, binding, role_definition, role_permission, permission;
END;
$function$;

-- resolve_network_permission_v2: a key resolves only in its own Workspace, and only listed permissions.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_network_permission_v2(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_permission_key text, p_evaluated_at timestamp with time zone)
 RETURNS TABLE(role_binding_public_id uuid, role_definition_public_id uuid, scope_authority_generation bigint, membership_authority_generation bigint, binding_authority_generation bigint, role_authority_generation bigint, binding_expires_at timestamp with time zone, workspace_owner_authority_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Network permission resolution input';
    END IF;

    -- The Workspace row first. A member change holds it and then writes this
    -- session and membership, so locking those before waiting for the
    -- Workspace would deadlock with it.
    PERFORM 1 FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id
    FOR SHARE;

    RETURN QUERY
    SELECT
        NULL::UUID,
        NULL::UUID,
        network.authority_generation,
        membership.authority_generation,
        0::BIGINT,
        0::BIGINT,
        NULL::TIMESTAMPTZ,
        workspace.authority_generation
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment
      ON deployment.id = session.deployment_id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = session.deployment_id
     AND account.principal_id = session.principal_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id
     AND provider.id = session.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = session.deployment_id
     AND workspace.public_id = p_workspace_public_id
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND (session.state = 'active' OR (session.state = 'api_key'
          AND session.login_workspace_id = workspace.id
          AND EXISTS (SELECT 1 FROM mesh.api_key_permission AS key_permission
                      WHERE key_permission.permission_id = permission.id)))
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND workspace.owner_principal_id = principal.id
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, permission;
    IF FOUND THEN RETURN; END IF;

    -- Built-in roles: a Workspace-scope assignment covers every Network of the
    -- Workspace; a Network-scope one only its Network. The exact Network
    -- assignment is preferred so evidence names the narrowest grant.
    RETURN QUERY
    SELECT
        assignment.public_id,
        role.public_id,
        network.authority_generation,
        membership.authority_generation,
        assignment.authority_generation,
        role.catalog_version::BIGINT,
        assignment.expires_at,
        0::BIGINT
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment
      ON deployment.id = session.deployment_id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = session.deployment_id
     AND account.principal_id = session.principal_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id
     AND provider.id = session.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = session.deployment_id
     AND workspace.public_id = p_workspace_public_id
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.deployment_id = session.deployment_id
     AND assignment.workspace_id = workspace.id
     AND assignment.principal_id = principal.id
     AND assignment.workspace_membership_id = membership.id
     AND (assignment.network_id IS NULL OR assignment.network_id = network.id)
    JOIN mesh.builtin_role AS role
      ON role.role_key = assignment.role_key
    JOIN mesh.builtin_role_permission AS role_permission
      ON role_permission.role_key = role.role_key
     AND role_permission.permission_id = permission.id
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND (session.state = 'active' OR (session.state = 'api_key'
          AND session.login_workspace_id = workspace.id
          AND EXISTS (SELECT 1 FROM mesh.api_key_permission AS key_permission
                      WHERE key_permission.permission_id = permission.id)))
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND assignment.state = 'active'
      AND assignment.valid_from <= p_evaluated_at
      AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
    ORDER BY assignment.network_id IS NULL, assignment.id
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, permission, assignment;
    IF FOUND THEN RETURN; END IF;

    -- Members retain the existing exact-Network role resolver and its locks.
    RETURN QUERY
    SELECT resolved.role_binding_public_id, resolved.role_definition_public_id,
        resolved.scope_authority_generation, resolved.membership_authority_generation,
        resolved.binding_authority_generation, resolved.role_authority_generation,
        resolved.binding_expires_at, 0::BIGINT
    FROM mesh_ops.resolve_network_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission_key, p_evaluated_at
    ) AS resolved;

END;
$function$;

-- resolve_workspace_permission_v1: a key resolves only in its own Workspace, and only listed permissions.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_workspace_permission_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_permission_key text, p_evaluated_at timestamp with time zone)
 RETURNS TABLE(role_binding_public_id uuid, role_definition_public_id uuid, scope_authority_generation bigint, membership_authority_generation bigint, binding_authority_generation bigint, role_authority_generation bigint, binding_expires_at timestamp with time zone, workspace_owner_authority_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    resolved RECORD;
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Workspace permission resolution input';
    END IF;

    -- The Workspace row first. A member change holds it and then writes this
    -- session and membership, so locking those before waiting for the
    -- Workspace would deadlock with it.
    PERFORM 1 FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id
    FOR SHARE;

    SELECT
        workspace.owner_principal_id = principal.id AS is_owner,
        assignment.id AS assignment_id,
        assignment.public_id AS assignment_public_id,
        role.public_id AS role_public_id,
        role.catalog_version AS role_generation,
        assignment.authority_generation AS assignment_generation,
        assignment.expires_at AS assignment_expires_at,
        workspace.authority_generation AS workspace_generation,
        membership.authority_generation AS membership_generation
    INTO resolved
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment
      ON deployment.id = session.deployment_id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = session.deployment_id
     AND account.principal_id = session.principal_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id
     AND provider.id = session.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = session.deployment_id
     AND workspace.public_id = p_workspace_public_id
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = session.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = session.identity_provider_id
     AND route.identity_provider_client_id = session.identity_provider_client_id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
     AND (route.minimum_assurance IS NULL OR route.minimum_assurance = session.acr)
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'workspace' = ANY(permission.allowed_scope_kinds)
    LEFT JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.deployment_id = session.deployment_id
     AND assignment.workspace_id = workspace.id
     AND assignment.principal_id = principal.id
     AND assignment.workspace_membership_id = membership.id
     AND assignment.network_id IS NULL
     AND assignment.state = 'active'
     AND assignment.valid_from <= p_evaluated_at
     AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
     AND EXISTS (
        SELECT 1 FROM mesh.builtin_role_permission AS role_permission
        WHERE role_permission.role_key = assignment.role_key
          AND role_permission.permission_id = permission.id
     )
    LEFT JOIN mesh.builtin_role AS role
      ON role.role_key = assignment.role_key
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND (session.state = 'active' OR (session.state = 'api_key'
          AND session.login_workspace_id = workspace.id
          AND EXISTS (SELECT 1 FROM mesh.api_key_permission AS key_permission
                      WHERE key_permission.permission_id = permission.id)))
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND (workspace.owner_principal_id = principal.id OR assignment.id IS NOT NULL)
    ORDER BY workspace.owner_principal_id = principal.id DESC, assignment.id
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, membership, permission;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    scope_authority_generation := resolved.workspace_generation;
    membership_authority_generation := resolved.membership_generation;
    IF resolved.is_owner THEN
        role_binding_public_id := NULL;
        role_definition_public_id := NULL;
        binding_authority_generation := 0;
        role_authority_generation := 0;
        binding_expires_at := NULL;
        workspace_owner_authority_generation := resolved.workspace_generation;
        RETURN NEXT;
        RETURN;
    END IF;
    -- The outer join cannot lock the assignment, so lock it now and recheck it:
    -- a concurrent revocation that committed first denies this operation.
    PERFORM 1 FROM mesh.workspace_role_assignment AS assignment
    WHERE assignment.id = resolved.assignment_id
      AND assignment.state = 'active'
      AND assignment.authority_generation = resolved.assignment_generation
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    role_binding_public_id := resolved.assignment_public_id;
    role_definition_public_id := resolved.role_public_id;
    binding_authority_generation := resolved.assignment_generation;
    role_authority_generation := resolved.role_generation;
    binding_expires_at := resolved.assignment_expires_at;
    workspace_owner_authority_generation := 0;
    RETURN NEXT;
END;
$function$;

-- The default sign-in Workspace follows human Sessions only.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_oidc_login_subject_v2(p_deployment_public_id uuid, p_provider_public_id uuid, p_client_public_id uuid, p_provider_generation bigint, p_recovery_epoch bigint, p_issuer text, p_discovery_uri text, p_authorization_endpoint text, p_token_endpoint text, p_jwks_uri text, p_oidc_client_id text, p_client_auth_method text, p_scopes text[], p_allowed_algorithms text[], p_redirect_uri text, p_transaction_public_id uuid, p_transaction_version bigint, p_binding_hash bytea, p_consumed_at timestamp with time zone, p_redirect_id text, p_return_route_id text, p_subject_algorithm text, p_active_key_id text, p_active_digest bytea, p_previous_key_id text, p_previous_digest bytea)
 RETURNS TABLE(transaction_public_id uuid, transaction_version bigint, transaction_consumed_at timestamp with time zone, transaction_binding_hash bytea, principal_public_id uuid, subject_public_id uuid, membership_public_id uuid, subject_version bigint, account_version bigint, membership_version bigint, principal_authority_generation bigint, account_session_generation bigint, membership_authority_generation bigint, subject_algorithm text, subject_key_id text, subject_digest bytea, evaluated_at timestamp with time zone, membership_expires_at timestamp with time zone, workspace_public_id uuid)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
#variable_conflict use_column
DECLARE
    matched_count BIGINT;
    candidate_principal_id BIGINT;
    chosen_workspace UUID;
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    -- Never keep a caller-selected Workspace scope, as every login function does.
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_subject_algorithm IS DISTINCT FROM 'hmac-sha256-v1' OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL) THEN
        RETURN;
    END IF;
    -- The Workspace-less transaction must exist for this exact route before
    -- any candidate is considered.
    IF NOT EXISTS (
        SELECT 1 FROM mesh.auth_transaction AS auth
        JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = auth.deployment_id AND client.id = auth.identity_provider_client_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND provider.public_id = p_provider_public_id AND client.public_id = p_client_public_id
          AND auth.public_id = p_transaction_public_id AND auth.workspace_id IS NULL
          AND auth.state = 'consuming' AND auth.version = p_transaction_version
    ) THEN
        RETURN;
    END IF;

    SELECT pg_catalog.count(*), pg_catalog.min(subject.principal_id)
    INTO matched_count, candidate_principal_id
    FROM mesh.identity_subject AS subject
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = subject.deployment_id AND provider.id = subject.identity_provider_id
    JOIN mesh.deployment AS deployment ON deployment.id = subject.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND provider.public_id = p_provider_public_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND (
          (subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
          OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest)
      );
    IF matched_count <> 1 THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', candidate_principal_id::TEXT, TRUE);
    BEGIN
        SELECT workspace.public_id INTO chosen_workspace
        FROM mesh.workspace_membership AS membership
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = membership.deployment_id AND workspace.id = membership.workspace_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = membership.deployment_id AND provider.public_id = p_provider_public_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = provider.deployment_id AND client.identity_provider_id = provider.id
         AND client.public_id = p_client_public_id
        JOIN mesh.workspace_identity_provider AS routing
          ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
         AND routing.identity_provider_id = provider.id AND routing.identity_provider_client_id = client.id
        WHERE membership.principal_id = candidate_principal_id
          AND membership.state = 'active' AND membership.valid_from <= decision_at
          AND (membership.expires_at IS NULL OR membership.expires_at > decision_at)
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND routing.state = 'active' AND routing.deleted_at IS NULL
          AND routing.organization_digest_algorithm IS NULL
          AND routing.organization_digest_key_id IS NULL AND routing.organization_digest IS NULL
        ORDER BY (
            SELECT pg_catalog.max(session.issued_at) FROM mesh.account_session AS session
            WHERE session.deployment_id = membership.deployment_id
              AND session.principal_id = candidate_principal_id
              AND session.login_workspace_id = workspace.id
              AND session.kind = 'interactive'
        ) DESC NULLS LAST,
            (workspace.owner_principal_id = candidate_principal_id) DESC,
            membership.valid_from, workspace.id
        LIMIT 1;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.login_candidate_principal_id', '', TRUE);
    IF chosen_workspace IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT resolved.transaction_public_id, resolved.transaction_version, resolved.transaction_consumed_at,
        resolved.transaction_binding_hash, resolved.principal_public_id, resolved.subject_public_id,
        resolved.membership_public_id, resolved.subject_version, resolved.account_version,
        resolved.membership_version, resolved.principal_authority_generation,
        resolved.account_session_generation, resolved.membership_authority_generation,
        resolved.subject_algorithm, resolved.subject_key_id, resolved.subject_digest,
        resolved.evaluated_at, resolved.membership_expires_at, chosen_workspace
    FROM mesh_ops.resolve_oidc_login_subject_v1(
        p_deployment_public_id, chosen_workspace, p_provider_public_id, p_client_public_id,
        p_provider_generation, p_recovery_epoch, p_issuer, p_discovery_uri, p_authorization_endpoint,
        p_token_endpoint, p_jwks_uri, p_oidc_client_id, p_client_auth_method, p_scopes,
        p_allowed_algorithms, p_redirect_uri, p_transaction_public_id, p_transaction_version,
        p_binding_hash, p_consumed_at, p_redirect_id, p_return_route_id, p_subject_algorithm,
        p_active_key_id, p_active_digest, p_previous_key_id, p_previous_digest
    ) AS resolved;
END;
$function$;
