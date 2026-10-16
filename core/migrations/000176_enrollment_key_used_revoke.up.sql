-- A key that enrolled its Device is no longer managed as a key: its
-- Device is. Revoking it is refused; ending the Device's access goes through
-- the Device.
CREATE OR REPLACE FUNCTION mesh_ops.revoke_enrollment_key_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_key_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.enrollment_credential%ROWTYPE;
    v_after mesh.enrollment_credential%ROWTYPE;
    v_revision BIGINT;
BEGIN
    IF p_key_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'enrollment key revocation is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enrollment key revocation is not authorized';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'enrollment_credential.revoke', v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enrollment key revocation is not authorized';
    END IF;
    SELECT credential.* INTO v_before FROM mesh.enrollment_credential AS credential
    JOIN mesh.enrollment_profile AS profile
      ON profile.workspace_id = credential.workspace_id AND profile.network_id = credential.network_id
     AND profile.id = credential.enrollment_profile_id
    WHERE credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
      AND credential.public_id = p_key_public_id AND profile.name_key = 'enrollment-keys'
      AND credential.deleted_at IS NULL
    FOR UPDATE OF credential;
    IF v_before.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'enrollment key is unavailable';
    END IF;
    IF v_before.state <> 'active' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTE01', MESSAGE = 'enrollment key is already revoked';
    END IF;
    IF v_before.used_count > 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTE03', MESSAGE = 'enrollment key already enrolled its Device';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = GREATEST(v_now, credential.valid_from),
        version = credential.version + 1, updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.id = v_before.id
    RETURNING * INTO v_after;
    SELECT revision.network_revision INTO STRICT v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id;

    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', v_revision,
        'before', mesh_ops.enrollment_key_document_internal_v1(v_before),
        'key', mesh_ops.enrollment_key_document_internal_v1(v_after),
        'authority', mesh_ops.enrollment_key_authority_internal_v1(
            v_grant.role_binding_public_id, v_grant.role_definition_public_id,
            v_grant.binding_authority_generation, v_grant.membership_authority_generation,
            v_grant.workspace_owner_authority_generation)
    );
END;
$function$;
