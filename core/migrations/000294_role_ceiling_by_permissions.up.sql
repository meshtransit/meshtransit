-- Schema 294: role review 2026-11-15 (techdebt security.md), the three it_admin HIGHs.
--
-- TD-SEC-84: the delegation ceiling compared role names, so it_admin could grant network_admin (policy publish,
-- sharing, Kubernetes CA approval, connection logs), billing_admin and auditor, none of which it holds. Whoever may
-- assign a role now holds every permission it grants: network_admin, billing_admin and auditor are assignable by owner
-- and admin only; it_admin still assigns it_admin. A unit test keeps the Go catalog to that rule and the parity test
-- keeps this table equal to it. Existing assignments are not rewritten: they stay until someone with the ceiling
-- revokes them. Acceptance also added the invited role to an existing member, so an it_admin could invite their own
-- address with any role within the old ceiling and accept it; a role now comes only with joining (MTV08), and a
-- member gets roles through assign_workspace_role_v1.
--
-- TD-SEC-85: acceptance did not look at the inviter again, so someone removed, suspended or stripped of a role could
-- still use an invitation they sent before (to their own private address, say) for up to 30 days. Acceptance now
-- requires the inviter to still be allowed to invite (an active account and membership that owns the Workspace or
-- holds an active Workspace-scope role granting member.invite) and, for a role, to still be within its ceiling
-- (MTV07). Pending invitations are not revoked here: they simply cannot be accepted, and the Console's revoke still
-- ends them. A resend keeps the original inviter (schema 128 fixes it), so it cannot revive such an invitation.
--
-- TD-SEC-86: device_group.manage and device_group.members.manage let it_admin put any Device of a Network (its own
-- laptop included) into a group the Network's rules admit, changing access without publishing policy. Schema 228
-- moved identity groups and tags to network_admin for this reason; Device Groups follow. network_admin and admin
-- keep them. device_group.delegation.manage, which no function checks yet, leaves it_admin too.
--
-- accept_workspace_invitation_v1 is replaced in place (v2 calls it), body as in 000182 plus the two checks;
-- CREATE OR REPLACE keeps its owner and grants. The previous image maps MTV07/MTV08 to an unavailable invitation
-- (fails closed).

ALTER TABLE mesh.builtin_role DISABLE TRIGGER builtin_role_immutable;
UPDATE mesh.builtin_role SET assignable_by = ARRAY['owner', 'admin']
WHERE role_key IN ('network_admin', 'billing_admin', 'auditor');
ALTER TABLE mesh.builtin_role ENABLE TRIGGER builtin_role_immutable;

ALTER TABLE mesh.builtin_role_permission DISABLE TRIGGER builtin_role_permission_immutable;
DELETE FROM mesh.builtin_role_permission AS grant_row
USING mesh.permission AS permission
WHERE permission.id = grant_row.permission_id AND grant_row.role_key = 'it_admin'
  AND permission.permission_key IN (
      'device_group.manage', 'device_group.members.manage', 'device_group.delegation.manage');
ALTER TABLE mesh.builtin_role_permission ENABLE TRIGGER builtin_role_permission_immutable;

-- Internal: whether an invitation's inviter may still issue it now, as the
-- Workspace permission resolver would decide for them: an active account with
-- an active membership that owns the Workspace or holds an active
-- Workspace-scope built-in role granting member.invite. A role also needs the
-- inviter's current assigners to reach its ceiling.
CREATE FUNCTION mesh_ops.workspace_inviter_authorized_v1(
    p_workspace_id BIGINT,
    p_inviter_id BIGINT,
    p_role_key TEXT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.workspace AS workspace
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = workspace.id AND membership.principal_id = p_inviter_id
         AND membership.state = 'active' AND membership.valid_from <= p_evaluated_at
         AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
        JOIN mesh.principal AS principal
          ON principal.id = membership.principal_id AND principal.kind = 'account'
         AND principal.state = 'active' AND principal.deleted_at IS NULL
        WHERE workspace.id = p_workspace_id
          AND (workspace.owner_principal_id = p_inviter_id OR EXISTS (
              SELECT 1
              FROM mesh.workspace_role_assignment AS assignment
              JOIN mesh.builtin_role_permission AS grant_row ON grant_row.role_key = assignment.role_key
              JOIN mesh.permission AS permission
                ON permission.id = grant_row.permission_id AND permission.permission_key = 'member.invite'
              WHERE assignment.workspace_membership_id = membership.id
                AND assignment.workspace_id = workspace.id
                AND assignment.principal_id = p_inviter_id
                AND assignment.network_id IS NULL
                AND assignment.state = 'active'
                AND assignment.valid_from <= p_evaluated_at
                AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
          ))
    ) AND (
        p_role_key IS NULL OR EXISTS (
            SELECT 1 FROM mesh.builtin_role AS role
            WHERE role.role_key = p_role_key
              AND role.assignable_by && mesh_ops.workspace_role_assigners_v1(
                  p_workspace_id, p_inviter_id, p_evaluated_at)
        )
    );
$function$;
REVOKE ALL ON FUNCTION mesh_ops.workspace_inviter_authorized_v1(BIGINT, BIGINT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.accept_workspace_invitation_v1(p_deployment_public_id uuid, p_provider_public_id uuid, p_client_public_id uuid, p_provider_generation bigint, p_recovery_epoch bigint, p_transaction_public_id uuid, p_transaction_version bigint, p_binding_hash bytea, p_consumed_at timestamp with time zone, p_subject_algorithm text, p_active_key_id text, p_active_digest bytea, p_previous_key_id text, p_previous_digest bytea, p_token_digest bytea, p_change_public_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_auth RECORD;
    v_invitation mesh.workspace_invitation%ROWTYPE;
    v_workspace RECORD;
    v_principal BIGINT;
    v_principal_public UUID;
    v_matched BIGINT;
    v_created BOOLEAN := FALSE;
    v_membership mesh.workspace_membership%ROWTYPE;
    v_joined BOOLEAN := FALSE;
    v_networks INTEGER := 0;
    v_role_added BOOLEAN := FALSE;
BEGIN
    IF p_subject_algorithm IS DISTINCT FROM 'hmac-sha256-v1' OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL)
        OR p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invitation acceptance input is invalid';
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

    SELECT * INTO v_invitation FROM mesh.workspace_invitation AS invitation
    WHERE invitation.token_digest = p_token_digest AND invitation.deployment_id = v_auth.deployment_id
    FOR UPDATE;
    IF v_invitation.id IS NULL OR v_invitation.state <> 'pending' OR v_invitation.expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no pending invitation for this link';
    END IF;
    -- The Workspace must admit this provider and client. Its exact scope lets
    -- the policies admit the Workspace, its Networks and its members.
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_invitation.workspace_id::TEXT, TRUE);
    SELECT workspace.id, workspace.public_id, workspace.deployment_id INTO v_workspace
    FROM mesh.workspace AS workspace
    JOIN mesh.workspace_identity_provider AS routing
      ON routing.deployment_id = workspace.deployment_id AND routing.workspace_id = workspace.id
     AND routing.identity_provider_id = v_auth.identity_provider_id
     AND routing.identity_provider_client_id = v_auth.identity_provider_client_id
    WHERE workspace.id = v_invitation.workspace_id AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL AND routing.state = 'active' AND routing.deleted_at IS NULL
      AND routing.organization_digest IS NULL
    FOR NO KEY UPDATE OF workspace;
    IF v_workspace.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no pending invitation for this link';
    END IF;
    PERFORM mesh_ops.enter_workspace_management_scope_v1(v_workspace.public_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    -- TD-SEC-85: the invitation carries only the authority its inviter still
    -- holds now, checked before anything is created.
    IF NOT mesh_ops.workspace_inviter_authorized_v1(
            v_workspace.id, v_invitation.invited_by_principal_id, v_invitation.role_key, v_now) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTV07', MESSAGE = 'the inviter can no longer grant this invitation';
    END IF;

    SELECT pg_catalog.count(*), pg_catalog.min(subject.principal_id) INTO v_matched, v_principal
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
    IF v_matched = 0 THEN
        INSERT INTO mesh.principal (public_id, deployment_id, kind, state)
        VALUES (pg_catalog.uuidv7(), v_auth.deployment_id, 'account', 'active')
        RETURNING id INTO v_principal;
        INSERT INTO mesh.account (public_id, deployment_id, principal_id, display_name, recovery_state)
        VALUES (pg_catalog.uuidv7(), v_auth.deployment_id, v_principal, v_invitation.email, 'verified');
        INSERT INTO mesh.identity_subject (
            public_id, deployment_id, identity_provider_id, principal_id, subject_digest_algorithm,
            subject_digest_key_id, subject_digest, last_seen_at, state
        ) VALUES (
            pg_catalog.uuidv7(), v_auth.deployment_id, v_auth.identity_provider_id, v_principal,
            p_subject_algorithm, p_active_key_id, p_active_digest, v_now, 'active'
        );
        v_created := TRUE;
    END IF;
    SELECT principal.public_id INTO v_principal_public FROM mesh.principal AS principal
    WHERE principal.id = v_principal AND principal.kind = 'account' AND principal.state = 'active'
      AND principal.deleted_at IS NULL;
    IF v_principal_public IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the account is not active';
    END IF;

    SELECT * INTO v_membership FROM mesh.workspace_membership AS membership
    WHERE membership.workspace_id = v_workspace.id AND membership.principal_id = v_principal
      AND membership.state <> 'revoked'
    FOR UPDATE;
    IF v_membership.id IS NOT NULL AND v_membership.state = 'suspended' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTV05', MESSAGE = 'a suspended member cannot accept an invitation';
    END IF;
    -- TD-SEC-84: a role comes only with joining. A member, the inviter
    -- included, gets roles through role assignment and its ceiling.
    IF v_invitation.role_key IS NOT NULL AND v_membership.id IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTV08', MESSAGE = 'a member gets roles through role assignment';
    END IF;
    IF v_membership.id IS NULL THEN
        INSERT INTO mesh.workspace_membership (public_id, deployment_id, workspace_id, principal_id, state, valid_from)
        VALUES (pg_catalog.uuidv7(), v_workspace.deployment_id, v_workspace.id, v_principal, 'active', v_now)
        RETURNING * INTO v_membership;
        v_joined := TRUE;
        -- Schema 50's projection policy admits this Workspace's Networks.
        PERFORM pg_catalog.set_config('mesh.console_management_scope_workspace_public_id',
            v_workspace.public_id::TEXT, TRUE);
        INSERT INTO mesh.network_membership (
            public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id,
            state, valid_from
        )
        SELECT pg_catalog.uuidv7(), v_workspace.deployment_id, network.workspace_id, network.id, v_principal,
            v_membership.id, 'active', v_now
        FROM mesh.network AS network
        WHERE network.workspace_id = v_workspace.id AND network.state = 'active' AND network.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM mesh.network_membership AS existing
              WHERE existing.workspace_id = network.workspace_id AND existing.network_id = network.id
                AND existing.principal_id = v_principal AND existing.state <> 'revoked'
          )
        ORDER BY network.id;
        GET DIAGNOSTICS v_networks = ROW_COUNT;
        PERFORM pg_catalog.set_config('mesh.console_management_scope_workspace_public_id', '', TRUE);
    END IF;
    IF v_invitation.role_key IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM mesh.workspace_role_assignment AS assignment
        WHERE assignment.workspace_membership_id = v_membership.id AND assignment.role_key = v_invitation.role_key
          AND assignment.network_id IS NULL AND assignment.state = 'active'
    ) AND NOT EXISTS (
        SELECT 1 FROM mesh.workspace AS owned WHERE owned.id = v_workspace.id AND owned.owner_principal_id = v_principal
    ) THEN
        INSERT INTO mesh.workspace_role_assignment (
            public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id,
            role_key, state, valid_from, created_at, updated_at
        ) VALUES (
            pg_catalog.uuidv7(), v_workspace.deployment_id, v_workspace.id, NULL, v_principal, v_membership.id,
            v_invitation.role_key, 'active', v_now, v_now, v_now
        );
        v_role_added := TRUE;
    END IF;
    UPDATE mesh.workspace_invitation SET state = 'accepted', accepted_by_principal_id = v_principal,
        accepted_at = v_now, version = version + 1, updated_at = v_now
    WHERE id = v_invitation.id
    RETURNING * INTO v_invitation;

    RETURN pg_catalog.jsonb_build_object(
        'invitation_id', v_invitation.public_id,
        'invitation_version', v_invitation.version,
        'workspace_id', v_workspace.public_id,
        'principal_id', v_principal_public,
        'account_created', v_created,
        'joined', v_joined,
        'network_count', v_networks,
        'role', CASE WHEN v_role_added THEN v_invitation.role_key END
    );
END;
$function$;
