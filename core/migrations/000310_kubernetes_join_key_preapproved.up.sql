-- Schema 310 (V1-12 step 1d): whether a join key is an install token, so a
-- replica's session asks Core to approve only requests opened with one; an
-- ordinary key's join keeps its K1 path exactly (no second transaction, no
-- cluster lock). Read in the transaction that opened the request, in its
-- Network scope; nothing else.
CREATE FUNCTION mesh_ops.kubernetes_join_key_is_preapproved_v1(p_credential_public_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_credential_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'join key is invalid';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM mesh.enrollment_credential AS credential
        JOIN mesh.kubernetes_join_key_preapproval AS preapproval
          ON preapproval.enrollment_credential_id = credential.id
        WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
          AND credential.public_id = p_credential_public_id
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_join_key_is_preapproved_v1(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.kubernetes_join_key_is_preapproved_v1(UUID)
    TO mesh_api_rights, mesh_control_rights;
