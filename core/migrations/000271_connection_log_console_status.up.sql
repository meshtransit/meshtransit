-- Connection logs s6 (design §16i C91, C92): what a Network's reader sees
-- of its logging. The settings read now returns, beside the settings, the
-- rows behind their status: the receiver's last report for the Network,
-- when the newest receiver taking the protocol reported, and the
-- credential's key version that the destination ETag names. Core derives
-- what the Console shows from them; nothing here names a receiver
-- instance, fingerprint or version.
--
-- The report rows sit behind FORCE RLS for the status writer, so an
-- internal function that writer owns (operator step 271, after this
-- migration) reads them. Only the settings read, which checks the caller's
-- permission first, may call it: the migration owner keeps EXECUTE, the
-- runtime never gets it. Until the operator step the function runs as its
-- creator, mesh_migrator, whose schema 270 policies show every row; the
-- settings read still asks only for the granted Network, so the step
-- narrows privilege, it does not change what the Console sees.

CREATE FUNCTION mesh_ops.network_connection_log_status_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_protocol_version INTEGER
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'report', (SELECT pg_catalog.jsonb_build_object(
                       'tested_etag', pg_catalog.encode(status.tested_etag, 'hex'),
                       'test_result', status.test_result,
                       'tested_at', status.tested_at,
                       'delivered_at', status.last_delivered_at,
                       'delivery_error', status.delivery_error,
                       'received_at', status.received_at)
                   FROM mesh.network_connection_log_status AS status
                   WHERE status.workspace_id = p_workspace_id AND status.network_id = p_network_id),
        -- At most 1 024 receiver rows (schema 270).
        'receiver_at', (SELECT pg_catalog.max(receiver.received_at)
                        FROM mesh.connection_log_receiver AS receiver
                        WHERE p_protocol_version = ANY (receiver.accepted_versions)))
$function$;

REVOKE ALL ON FUNCTION mesh_ops.network_connection_log_status_internal_v1(BIGINT, BIGINT, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The settings read, as in schema 266, with the status rows: the
-- credential's sealed_version and sealing_key_id (never its secret), and
-- the internal status for receiver protocol 1, the version Core signs
-- tickets for.
CREATE OR REPLACE FUNCTION mesh_ops.read_network_connection_log_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID
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
    v_settings mesh.network_connection_log%ROWTYPE;
    v_credential mesh.storage_credential%ROWTYPE;
BEGIN
    SELECT * INTO v_grant FROM mesh_ops.connection_log_network_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    SELECT * INTO v_settings FROM mesh.network_connection_log AS settings
    WHERE settings.workspace_id = v_grant.workspace_id AND settings.network_id = v_grant.network_id;
    IF v_settings.credential_id IS NOT NULL THEN
        SELECT * INTO v_credential FROM mesh.storage_credential AS credential
        WHERE credential.workspace_id = v_grant.workspace_id AND credential.id = v_settings.credential_id;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'feature', mesh_ops.workspace_has_feature_internal_v1(v_grant.workspace_id, 'connection_logs'),
        'settings', mesh_ops.network_connection_log_document_internal_v1(v_settings),
        'status', mesh_ops.network_connection_log_status_internal_v1(v_grant.workspace_id, v_grant.network_id, 1)
            || pg_catalog.jsonb_build_object(
                'sealed_version', v_credential.sealed_version,
                'sealing_key_id', v_credential.sealing_key_id));
END;
$function$;
