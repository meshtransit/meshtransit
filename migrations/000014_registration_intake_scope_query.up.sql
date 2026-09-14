CREATE POLICY workspace_registration_intake_scope_policy ON mesh.workspace
    FOR SELECT
    TO mesh_migrator
    USING (
        EXISTS (
            SELECT 1
            FROM mesh.enrollment_credential AS credential
            WHERE credential.public_id = NULLIF(
                pg_catalog.current_setting(
                    'mesh.registration_intake_credential_public_id',
                    TRUE
                ),
                ''
            )::UUID
              AND credential.workspace_id = workspace.id
        )
    );

CREATE POLICY network_registration_intake_scope_policy ON mesh.network
    FOR SELECT
    TO mesh_migrator
    USING (
        EXISTS (
            SELECT 1
            FROM mesh.enrollment_credential AS credential
            WHERE credential.public_id = NULLIF(
                pg_catalog.current_setting(
                    'mesh.registration_intake_credential_public_id',
                    TRUE
                ),
                ''
            )::UUID
              AND credential.workspace_id = network.workspace_id
              AND credential.network_id = network.id
        )
    );

CREATE OR REPLACE FUNCTION mesh_ops.resolve_registration_intake_scope(
    p_credential_public_id UUID
)
RETURNS TABLE (
    deployment_public_id UUID,
    workspace_public_id UUID,
    network_public_id UUID,
    recovery_epoch BIGINT
)
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    previous_credential_public_id TEXT;
BEGIN
    previous_credential_public_id := pg_catalog.current_setting(
        'mesh.registration_intake_credential_public_id',
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.registration_intake_credential_public_id',
        COALESCE(p_credential_public_id::TEXT, ''),
        TRUE
    );

    RETURN QUERY
    SELECT
        deployment.installation_public_id,
        workspace.public_id,
        network.public_id,
        deployment.recovery_epoch
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.network AS network
      ON network.workspace_id = credential.workspace_id
     AND network.id = credential.network_id
    JOIN mesh.workspace AS workspace
      ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    WHERE credential.public_id = p_credential_public_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL;

    PERFORM pg_catalog.set_config(
        'mesh.registration_intake_credential_public_id',
        COALESCE(previous_credential_public_id, ''),
        TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.registration_intake_credential_public_id',
            COALESCE(previous_credential_public_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
