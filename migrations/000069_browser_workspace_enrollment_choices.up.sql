-- Only the validated Account Session's Principal can supply this private
-- projection context. Runtime has no general Workspace or membership grants.
CREATE POLICY workspace_browser_enrollment_membership_projection_policy ON mesh.workspace
FOR SELECT TO mesh_migrator
USING (EXISTS (
    SELECT 1 FROM mesh.workspace_membership AS membership
    JOIN mesh.principal AS principal
      ON principal.deployment_id=membership.deployment_id
     AND principal.id=membership.principal_id
    WHERE membership.workspace_id=workspace.id
      AND membership.deployment_id=workspace.deployment_id
      AND principal.public_id=NULLIF(pg_catalog.current_setting(
          'mesh.browser_enrollment_choice_principal_public_id', TRUE), '')::UUID
      AND membership.state='active'
      AND membership.valid_from <= pg_catalog.transaction_timestamp()
      AND (membership.expires_at IS NULL
           OR membership.expires_at > pg_catalog.transaction_timestamp())
));

CREATE FUNCTION mesh_ops.list_browser_enrollment_workspaces_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT, p_session_digest BYTEA,
    p_after_workspace_public_id UUID, p_limit INTEGER
)
RETURNS JSONB LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    admitted RECORD;
    result JSONB;
    previous_principal TEXT;
BEGIN
    previous_principal := pg_catalog.current_setting(
        'mesh.browser_enrollment_choice_principal_public_id', TRUE);
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 101
        OR (p_after_workspace_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_after_workspace_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid browser Workspace page';
    END IF;
    SELECT * INTO admitted FROM mesh_ops.resolve_account_session_v2(
        p_deployment_public_id, p_recovery_epoch, 'hmac-sha256-v1',
        p_session_digest_key_id, p_session_digest);
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM pg_catalog.set_config('mesh.browser_enrollment_choice_principal_public_id',
        admitted.principal_public_id::TEXT, TRUE);
    WITH choices AS (
        SELECT workspace.public_id, workspace.display_name
        FROM mesh.account_session AS session
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id=session.deployment_id
         AND membership.principal_id=session.principal_id
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id=membership.deployment_id
         AND workspace.id=membership.workspace_id
        JOIN mesh.workspace_identity_provider AS route
          ON route.deployment_id=session.deployment_id
         AND route.workspace_id=workspace.id
         AND route.identity_provider_id=session.identity_provider_id
         AND route.identity_provider_client_id=session.identity_provider_client_id
        WHERE session.public_id=admitted.session_public_id
          AND session.version=admitted.session_version
          AND workspace.state='active' AND workspace.deleted_at IS NULL
          AND membership.state='active'
          AND membership.valid_from <= pg_catalog.transaction_timestamp()
          AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
          AND route.state='active' AND route.deleted_at IS NULL
          AND route.organization_digest_algorithm IS NULL
          AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
          AND (route.minimum_assurance IS NULL OR route.minimum_assurance=session.acr)
          AND (p_after_workspace_public_id IS NULL OR workspace.public_id > p_after_workspace_public_id)
        ORDER BY workspace.public_id LIMIT p_limit
    ) SELECT pg_catalog.jsonb_build_object('workspaces', COALESCE(
        (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'workspace_id', choices.public_id, 'display_name', choices.display_name)
            ORDER BY choices.public_id) FROM choices), '[]'::JSONB)) INTO result;
    PERFORM pg_catalog.set_config('mesh.browser_enrollment_choice_principal_public_id',
        COALESCE(previous_principal, ''), TRUE);
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.browser_enrollment_choice_principal_public_id',
        COALESCE(previous_principal, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_browser_enrollment_workspaces_v1(
    UUID, BIGINT, TEXT, BYTEA, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_browser_enrollment_workspaces_v1(
    UUID, BIGINT, TEXT, BYTEA, UUID, INTEGER
) TO mesh_runtime;

-- Selecting a Workspace does not rotate a Session or grant membership. Each
-- page independently admits the exact chosen Workspace and accepted SSO route.
CREATE FUNCTION mesh_ops.list_browser_enrollment_networks_v2(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT, p_session_digest BYTEA,
    p_workspace_public_id UUID, p_after_network_public_id UUID, p_limit INTEGER
)
RETURNS JSONB LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    admitted RECORD;
    result JSONB;
    previous_requested TEXT;
    previous_choice TEXT;
BEGIN
    previous_requested := pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE);
    previous_choice := pg_catalog.current_setting('mesh.browser_enrollment_choice_workspace_public_id', TRUE);
    IF p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 101
        OR (p_after_network_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_after_network_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid scoped browser Network page';
    END IF;
    SELECT * INTO admitted FROM mesh_ops.resolve_account_session_v2(
        p_deployment_public_id, p_recovery_epoch, 'hmac-sha256-v1',
        p_session_digest_key_id, p_session_digest);
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.browser_enrollment_choice_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    WITH authority AS MATERIALIZED (
        SELECT session.deployment_id, session.principal_id, workspace.id AS workspace_id,
            workspace.public_id, workspace.display_name, membership.id AS membership_id
        FROM mesh.account_session AS session
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id=session.deployment_id
         AND workspace.public_id=p_workspace_public_id
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id=session.deployment_id
         AND membership.workspace_id=workspace.id AND membership.principal_id=session.principal_id
        JOIN mesh.workspace_identity_provider AS route
          ON route.deployment_id=session.deployment_id AND route.workspace_id=workspace.id
         AND route.identity_provider_id=session.identity_provider_id
         AND route.identity_provider_client_id=session.identity_provider_client_id
        WHERE session.public_id=admitted.session_public_id
          AND session.version=admitted.session_version
          AND workspace.state='active' AND workspace.deleted_at IS NULL
          AND membership.state='active'
          AND membership.valid_from <= pg_catalog.transaction_timestamp()
          AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
          AND route.state='active' AND route.deleted_at IS NULL
          AND route.organization_digest_algorithm IS NULL
          AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
          AND (route.minimum_assurance IS NULL OR route.minimum_assurance=session.acr)
        LIMIT 1
    ), choices AS (
        SELECT network.public_id, network.display_name
        FROM authority JOIN mesh.network_membership AS membership
          ON membership.deployment_id=authority.deployment_id
         AND membership.workspace_id=authority.workspace_id
         AND membership.workspace_membership_id=authority.membership_id
         AND membership.principal_id=authority.principal_id
        JOIN mesh.network AS network
          ON network.workspace_id=membership.workspace_id AND network.id=membership.network_id
        WHERE membership.state='active'
          AND membership.valid_from <= pg_catalog.transaction_timestamp()
          AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
          AND network.state='active' AND network.deleted_at IS NULL
          AND (p_after_network_public_id IS NULL OR network.public_id > p_after_network_public_id)
          AND EXISTS (SELECT 1 FROM mesh.enrollment_profile AS profile
              WHERE profile.workspace_id=network.workspace_id AND profile.network_id=network.id
                AND profile.state='active' AND profile.deleted_at IS NULL
                AND profile.interactive_authorization_enabled)
        ORDER BY network.public_id LIMIT p_limit
    ) SELECT pg_catalog.jsonb_build_object(
        'workspace_id', authority.public_id, 'workspace_display_name', authority.display_name,
        'networks', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'network_id', choices.public_id, 'display_name', choices.display_name)
            ORDER BY choices.public_id) FROM choices), '[]'::JSONB)) INTO result FROM authority;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', COALESCE(previous_requested, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.browser_enrollment_choice_workspace_public_id', COALESCE(previous_choice, ''), TRUE);
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', COALESCE(previous_requested, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.browser_enrollment_choice_workspace_public_id', COALESCE(previous_choice, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_browser_enrollment_networks_v2(
    UUID, BIGINT, TEXT, BYTEA, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_browser_enrollment_networks_v2(
    UUID, BIGINT, TEXT, BYTEA, UUID, UUID, INTEGER
) TO mesh_runtime;
