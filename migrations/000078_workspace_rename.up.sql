-- Owners rename their exact login Workspace. Names are labels, never scopes.
-- Account-owned names allow separate cloud owners to each use "Default".
DROP INDEX mesh.workspace_deployment_name_active_uidx;
CREATE UNIQUE INDEX workspace_owner_name_active_uidx
ON mesh.workspace(deployment_id,owner_principal_id,name_key) WHERE deleted_at IS NULL;

CREATE FUNCTION mesh_ops.read_console_management_scopes_v3(
    p_session_public_id UUID,p_deployment_public_id UUID,p_principal_public_id UUID,
    p_identity_subject_public_id UUID,p_session_version BIGINT,
    p_principal_authority_generation BIGINT,p_account_session_generation BIGINT,
    p_provider_generation BIGINT,p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,p_evaluated_at TIMESTAMPTZ,p_after_network_public_id UUID,p_limit INTEGER
) RETURNS JSONB LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,mesh,mesh_ops
AS $function$
DECLARE result JSONB; projected RECORD; previous_workspace TEXT;
BEGIN
    result:=mesh_ops.read_console_management_scopes_v2(
      p_session_public_id,p_deployment_public_id,p_principal_public_id,p_identity_subject_public_id,
      p_session_version,p_principal_authority_generation,p_account_session_generation,
      p_provider_generation,p_deployment_recovery_epoch,p_workspace_public_id,p_evaluated_at,
      p_after_network_public_id,p_limit);
    IF result IS NULL THEN RETURN NULL; END IF;
    previous_workspace:=pg_catalog.current_setting('mesh.requested_workspace_public_id',TRUE);
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',p_workspace_public_id::TEXT,TRUE);
    SELECT workspace.version,workspace.display_name,
      EXISTS(SELECT 1 FROM mesh.principal AS principal
             WHERE principal.id=workspace.owner_principal_id
               AND principal.deployment_id=workspace.deployment_id
               AND principal.public_id=p_principal_public_id) AS can_rename
    INTO STRICT projected FROM mesh.workspace AS workspace WHERE workspace.public_id=p_workspace_public_id;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',COALESCE(previous_workspace,''),TRUE);
    RETURN result || pg_catalog.jsonb_build_object(
      'workspace_display_name',projected.display_name,'workspace_version',projected.version,
      'workspace_can_rename',projected.can_rename);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_management_scopes_v3(
 UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,TIMESTAMPTZ,UUID,INTEGER
) FROM PUBLIC,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_management_scopes_v3(
 UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,TIMESTAMPTZ,UUID,INTEGER
) TO mesh_runtime;

CREATE FUNCTION mesh_ops.rename_owned_workspace_v1(
    p_session_public_id UUID,p_deployment_public_id UUID,p_principal_public_id UUID,
    p_identity_subject_public_id UUID,p_session_version BIGINT,
    p_principal_authority_generation BIGINT,p_account_session_generation BIGINT,
    p_provider_generation BIGINT,p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,p_expected_version BIGINT,p_display_name TEXT,p_change_public_id UUID
) RETURNS TABLE(renamed_workspace_public_id UUID,previous_display_name TEXT,
    renamed_display_name TEXT,renamed_display_code TEXT,renamed_version BIGINT,
    workspace_owner_authority_generation BIGINT,membership_authority_generation BIGINT)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,mesh,mesh_ops
AS $function$
DECLARE
    selected RECORD;
    identifier UUID;
    scoped_workspace_id BIGINT;
    previous_workspace TEXT;
    evaluated_at TIMESTAMPTZ:=pg_catalog.transaction_timestamp();
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id,p_deployment_public_id,
      p_principal_public_id,p_identity_subject_public_id,p_workspace_public_id,p_change_public_id] LOOP
      IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier),6)>>4<>7 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Workspace rename input';
      END IF;
    END LOOP;
    IF p_expected_version IS NULL OR p_expected_version<=0 OR p_expected_version=9223372036854775807
      OR p_session_version IS NULL OR p_session_version<=0
      OR p_principal_authority_generation IS NULL OR p_principal_authority_generation<=0
      OR p_account_session_generation IS NULL OR p_account_session_generation<=0
      OR p_provider_generation IS NULL OR p_provider_generation<=0
      OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch<=0
      OR p_display_name IS NULL OR pg_catalog.octet_length(p_display_name) NOT BETWEEN 1 AND 128
      OR p_display_name<>pg_catalog.btrim(p_display_name) OR p_display_name ~ '[[:cntrl:]]' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Workspace rename input';
    END IF;
    previous_workspace:=pg_catalog.current_setting('mesh.requested_workspace_public_id',TRUE);
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',p_workspace_public_id::TEXT,TRUE);
    -- This exact-ID selection establishes RLS scope, not authority.
    SELECT workspace.id INTO scoped_workspace_id FROM mesh.workspace AS workspace
      WHERE workspace.public_id=p_workspace_public_id;
    IF scoped_workspace_id IS NULL THEN
      PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',COALESCE(previous_workspace,''),TRUE);
      RETURN;
    END IF;
    IF COALESCE(pg_catalog.current_setting('mesh.workspace_id',TRUE),'')<>''
      AND mesh_ops.current_workspace_id()<>scoped_workspace_id THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Workspace scope cannot be replaced';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id',scoped_workspace_id::TEXT,TRUE);
    PERFORM workspace.id FROM mesh.workspace AS workspace
      WHERE workspace.id=scoped_workspace_id FOR UPDATE;
    SELECT workspace.id,workspace.version,workspace.display_name,
      workspace.authority_generation AS owner_generation,
      membership.authority_generation AS membership_generation,
      session.authentication_time,session.idle_expires_at,session.absolute_expires_at,
      membership.valid_from,membership.expires_at,workspace.updated_at
    INTO selected
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
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = 'workspace.update'
     AND 'workspace' = ANY(permission.allowed_scope_kinds)
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND session.state = 'active'
      AND session.authentication_time <= evaluated_at
      AND session.idle_expires_at > evaluated_at
      AND session.absolute_expires_at > evaluated_at
      AND deployment.state = 'active'
      AND deployment.deleted_at IS NULL
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.deleted_at IS NULL
      AND principal.kind = 'account'
      AND session.login_workspace_id = workspace.id
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
      AND workspace.deleted_at IS NULL
      AND membership.state = 'active'
      AND membership.valid_from <= evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > evaluated_at)
    LIMIT 1
    FOR UPDATE OF workspace
    FOR SHARE OF session, deployment, principal, account, subject, provider, client, membership, permission;

    IF selected.id IS NULL THEN
      PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id',COALESCE(previous_workspace,''),TRUE);
      RETURN;
    END IF;
    IF selected.version<>p_expected_version THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Workspace version changed';
    END IF;
    IF COALESCE(pg_catalog.current_setting('mesh.workspace_id',TRUE),'')<>''
      AND mesh_ops.current_workspace_id()<>selected.id THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Workspace scope cannot be replaced';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id',selected.id::TEXT,TRUE);
    -- All authority and audit-head locks precede the final expiry decision.
    PERFORM head.stream_internal_id FROM mesh_audit.lock_deployment_stream_head(p_deployment_public_id) AS head;
    evaluated_at:=pg_catalog.clock_timestamp();
    IF selected.authentication_time>evaluated_at OR selected.idle_expires_at<=evaluated_at
      OR selected.absolute_expires_at<=evaluated_at OR selected.valid_from>evaluated_at
      OR (selected.expires_at IS NOT NULL AND selected.expires_at<=evaluated_at) THEN
      RETURN;
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id',p_change_public_id::TEXT,TRUE);
    UPDATE mesh.workspace AS workspace SET display_name=p_display_name,
      name_key=pg_catalog.lower(p_display_name),version=version+1,updated_at=GREATEST(selected.updated_at,evaluated_at)
    WHERE workspace.id=selected.id AND workspace.version=p_expected_version;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Workspace version changed'; END IF;
    SELECT identity.display_code INTO STRICT renamed_display_code
      FROM mesh_ops.tenant_display_identity AS identity WHERE identity.workspace_public_id=p_workspace_public_id;
    renamed_workspace_public_id:=p_workspace_public_id;
    previous_display_name:=selected.display_name;
    renamed_display_name:=p_display_name;
    renamed_version:=p_expected_version+1;
    workspace_owner_authority_generation:=selected.owner_generation;
    membership_authority_generation:=selected.membership_generation;
    RETURN NEXT;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.rename_owned_workspace_v1(
 UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,TEXT,UUID
) FROM PUBLIC,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.rename_owned_workspace_v1(
 UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,BIGINT,TEXT,UUID
) TO mesh_runtime;
