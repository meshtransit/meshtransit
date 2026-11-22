-- Schema 319 (TD-SEC-103): an Account's verified email remembers the
-- identity provider that verified it, and the Workspace member directory
-- shows it only to a Workspace that routes that provider. mesh.account_email
-- held one email per Account across the deployment: the one the last sign-in
-- verified, through whichever Workspace's provider. On Cloud a person in
-- Workspaces A and B showed A the email B's provider (say a company IdP)
-- verified: personal data across tenants.
--
-- * account_email.identity_provider_id: the provider of the sign-in that
--   recorded the email; null for rows written before this schema, for which
--   the directory takes the Account's provider when all its subjects are on
--   one (schema 288 recorded only from such a sign-in), and shows nothing
--   otherwise until the person signs in again.
-- * record_account_verified_email_v1 (schema 288's body) stores it, and
--   writes again when the same email arrives through another provider.
-- * list_workspace_members_v2 (schema 304's body) names the email only when
--   the Workspace has an active route for that provider. A person's own
--   Devices still show their email (read_map_self_identity_v2): it is theirs.
--
-- Older Core keeps working: it calls the same functions, and the new column is
-- nullable.

ALTER TABLE mesh.account_email
    ADD COLUMN identity_provider_id BIGINT,
    ADD CONSTRAINT account_email_identity_provider_fk FOREIGN KEY (deployment_id, identity_provider_id)
        REFERENCES mesh.identity_provider (deployment_id, id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION mesh_ops.record_account_verified_email_v1(
    p_deployment_public_id UUID, p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_transaction_public_id UUID, p_transaction_version BIGINT, p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ, p_subject_algorithm TEXT, p_active_key_id TEXT, p_active_digest BYTEA,
    p_previous_key_id TEXT, p_previous_digest BYTEA, p_email TEXT,
    p_row_public_id UUID, p_change_public_id UUID
)
RETURNS TABLE (
    changed BOOLEAN, principal_public_id UUID, account_email_public_id UUID,
    account_email_version BIGINT, verified_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_auth RECORD;
    v_matched BIGINT;
    v_principal BIGINT;
    v_principal_public UUID;
    v_account BIGINT;
    v_row mesh.account_email%ROWTYPE;
BEGIN
    IF p_subject_algorithm IS DISTINCT FROM 'hmac-sha256-v1' OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL)
        OR p_email IS NULL OR pg_catalog.char_length(p_email) NOT BETWEEN 3 AND 254
        OR pg_catalog.octet_length(p_email) <> pg_catalog.char_length(p_email)
        OR p_email !~ '^[!#-;=?-~]+$' OR p_email !~ '^[^@]+@[^@]+$'
        OR p_row_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_row_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'account email input is invalid';
    END IF;
    -- The exact consuming browser login of this route.
    SELECT auth.deployment_id, auth.identity_provider_id, auth.identity_provider_client_id, auth.workspace_id
    INTO v_auth
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = auth.deployment_id AND client.id = auth.identity_provider_client_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL AND deployment.recovery_epoch = p_recovery_epoch
      AND provider.public_id = p_provider_public_id AND provider.current_generation = p_provider_generation
      AND provider.state = 'active' AND provider.recovery_state = 'verified' AND provider.deleted_at IS NULL
      AND client.public_id = p_client_public_id AND client.state = 'active' AND client.deleted_at IS NULL
      AND auth.public_id = p_transaction_public_id
      AND auth.state = 'consuming' AND auth.version = p_transaction_version
      AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
      AND auth.provider_generation = p_provider_generation
      AND auth.deployment_recovery_epoch = p_recovery_epoch
      AND auth.principal_id IS NULL AND auth.binding_semantic_hash = p_binding_hash
      AND auth.consumed_at = p_consumed_at AND auth.consumed_at <= v_now AND auth.expires_at > v_now
      AND auth.consumed_result_kind IS NULL AND auth.failure_class IS NULL;
    IF v_auth.deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sign-in transaction does not match';
    END IF;

    -- Unique across every state, as subject resolution counts it.
    SELECT pg_catalog.count(*) INTO v_matched
    FROM mesh.identity_subject AS subject
    WHERE subject.deployment_id = v_auth.deployment_id
      AND subject.identity_provider_id = v_auth.identity_provider_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND ((subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
           OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest));
    IF v_matched <> 1 THEN
        RETURN;
    END IF;
    SELECT principal.id, principal.public_id, account.id INTO v_principal, v_principal_public, v_account
    FROM mesh.identity_subject AS subject
    JOIN mesh.principal AS principal
      ON principal.deployment_id = subject.deployment_id AND principal.id = subject.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
    WHERE subject.deployment_id = v_auth.deployment_id
      AND subject.identity_provider_id = v_auth.identity_provider_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND subject.state = 'active' AND subject.deleted_at IS NULL
      AND ((subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
           OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest))
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND account.recovery_state = 'verified';
    IF v_account IS NULL THEN
        RETURN;
    END IF;
    -- A Workspace-bound login counts only for an active member of an active
    -- Workspace that routes this provider and client.
    IF v_auth.workspace_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM mesh.workspace_membership AS membership
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = membership.deployment_id AND workspace.id = membership.workspace_id
        JOIN mesh.workspace_identity_provider AS workspace_provider
          ON workspace_provider.deployment_id = workspace.deployment_id
         AND workspace_provider.workspace_id = workspace.id
         AND workspace_provider.identity_provider_id = v_auth.identity_provider_id
         AND workspace_provider.identity_provider_client_id = v_auth.identity_provider_client_id
        WHERE membership.deployment_id = v_auth.deployment_id
          AND membership.workspace_id = v_auth.workspace_id
          AND membership.principal_id = v_principal
          AND membership.state = 'active' AND membership.valid_from <= v_now
          AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND workspace_provider.state = 'active' AND workspace_provider.deleted_at IS NULL
    ) THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    -- The first sign-in inserts; one at the same time finds that row below.
    INSERT INTO mesh.account_email AS stored (
        public_id, deployment_id, account_id, email, identity_provider_id, verified_at, version, created_at,
        updated_at
    ) VALUES (p_row_public_id, v_auth.deployment_id, v_account, p_email, v_auth.identity_provider_id, v_now, 1,
        v_now, v_now)
    ON CONFLICT (account_id) DO NOTHING
    RETURNING * INTO v_row;
    IF v_row.id IS NOT NULL THEN
        RETURN QUERY SELECT TRUE, v_principal_public, v_row.public_id, v_row.version, v_row.verified_at;
        RETURN;
    END IF;
    SELECT * INTO v_row FROM mesh.account_email AS stored
    WHERE stored.account_id = v_account FOR UPDATE;
    IF v_row.email = p_email AND v_row.identity_provider_id IS NOT DISTINCT FROM v_auth.identity_provider_id THEN
        RETURN QUERY SELECT FALSE, v_principal_public, v_row.public_id, v_row.version, v_row.verified_at;
        RETURN;
    END IF;
    UPDATE mesh.account_email AS stored
    SET email = p_email, identity_provider_id = v_auth.identity_provider_id, verified_at = v_now,
        version = stored.version + 1,
        updated_at = GREATEST(v_now, stored.updated_at)
    WHERE stored.id = v_row.id
    RETURNING * INTO v_row;
    RETURN QUERY SELECT TRUE, v_principal_public, v_row.public_id, v_row.version, v_row.verified_at;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.list_workspace_members_v2(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    evaluated_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    scoped_workspace_id BIGINT;
    result JSONB;
BEGIN
    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN NULL;
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'member.read', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', workspace.public_id,
        'workspace_version', workspace.version,
        'truncated', (SELECT pg_catalog.count(*) > 1000 FROM mesh.workspace_membership AS counted
            WHERE counted.workspace_id = workspace.id AND counted.state <> 'revoked'),
        'members', COALESCE((
            SELECT pg_catalog.jsonb_agg(member.payload ORDER BY member.sort_name, member.principal_public_id)
            FROM (
                SELECT
                    pg_catalog.lower(account.display_name) AS sort_name,
                    principal.public_id AS principal_public_id,
                    pg_catalog.jsonb_build_object(
                        'principal_id', principal.public_id,
                        'display_name', account.display_name,
                        'membership_state', membership.state,
                        'membership_expires_at', membership.expires_at,
                        -- Only an email the provider this Workspace routes verified (TD-SEC-103).
                        'email', CASE WHEN EXISTS (
                            SELECT 1 FROM mesh.workspace_identity_provider AS route
                            WHERE route.deployment_id = workspace.deployment_id
                              AND route.workspace_id = workspace.id
                              -- A row from before schema 319: the Account's one provider (an
                              -- Account's subjects are all on one; 288 recorded only from it).
                              AND route.identity_provider_id = COALESCE(account_email.identity_provider_id, (
                                  SELECT CASE WHEN pg_catalog.count(DISTINCT subject.identity_provider_id) = 1
                                      THEN pg_catalog.min(subject.identity_provider_id) END
                                  FROM mesh.identity_subject AS subject
                                  WHERE subject.deployment_id = account.deployment_id
                                    AND subject.principal_id = principal.id))
                              AND route.state = 'active' AND route.deleted_at IS NULL
                        ) THEN account_email.email END,
                        'joined_at', membership.created_at,
                        'owner', workspace.owner_principal_id = principal.id,
                        'role_assignments', COALESCE((
                            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                                'assignment_id', assignment.public_id,
                                'role', assignment.role_key,
                                'network_id', network.public_id,
                                'expires_at', assignment.expires_at,
                                'version', assignment.version,
                                'created_at', assignment.created_at
                            ) ORDER BY assignment.role_key, network.public_id NULLS FIRST, assignment.public_id)
                            FROM mesh.workspace_role_assignment AS assignment
                            LEFT JOIN mesh.network AS network
                              ON network.workspace_id = assignment.workspace_id
                             AND network.id = assignment.network_id
                            WHERE assignment.workspace_id = workspace.id
                              AND assignment.workspace_membership_id = membership.id
                              AND assignment.state = 'active'
                        ), '[]'::JSONB)
                    ) AS payload
                FROM mesh.workspace_membership AS membership
                JOIN mesh.principal AS principal
                  ON principal.deployment_id = membership.deployment_id
                 AND principal.id = membership.principal_id
                JOIN mesh.account AS account
                  ON account.deployment_id = principal.deployment_id
                 AND account.principal_id = principal.id
                LEFT JOIN mesh.account_email AS account_email
                  ON account_email.deployment_id = account.deployment_id
                 AND account_email.account_id = account.id
                WHERE membership.workspace_id = workspace.id
                  AND membership.state <> 'revoked'
                  AND principal.deleted_at IS NULL
                ORDER BY pg_catalog.lower(account.display_name), principal.public_id
                LIMIT 1000
            ) AS member
        ), '[]'::JSONB)
    ) INTO result
    FROM mesh.workspace AS workspace
    WHERE workspace.id = scoped_workspace_id;
    RETURN result;
END;
$function$;
