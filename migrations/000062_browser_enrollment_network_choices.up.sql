CREATE POLICY network_browser_enrollment_choice_scope_policy ON mesh.network
FOR SELECT
TO mesh_migrator
USING (
    EXISTS (
        SELECT 1
        FROM mesh.workspace AS chosen_workspace
        WHERE chosen_workspace.id = network.workspace_id
          AND chosen_workspace.public_id = NULLIF(
              pg_catalog.current_setting(
                  'mesh.browser_enrollment_choice_workspace_public_id',
                  TRUE
              ),
              ''
          )::UUID
    )
);

CREATE FUNCTION mesh_ops.list_browser_enrollment_networks_v1(
    p_deployment_public_id UUID,
    p_deployment_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT,
    p_session_digest BYTEA,
    p_after_network_public_id UUID,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    result JSONB;
    admitted_workspace_public_id UUID;
    previous_requested_workspace_public_id TEXT;
    previous_choice_workspace_public_id TEXT;
BEGIN
    previous_requested_workspace_public_id := pg_catalog.current_setting(
        'mesh.requested_workspace_public_id', TRUE
    );
    previous_choice_workspace_public_id := pg_catalog.current_setting(
        'mesh.browser_enrollment_choice_workspace_public_id', TRUE
    );
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_session_digest_key_id IS NULL
        OR pg_catalog.char_length(p_session_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_session_digest_key_id <> pg_catalog.btrim(p_session_digest_key_id)
        OR p_session_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_session_digest IS NULL OR pg_catalog.octet_length(p_session_digest) <> 32
        OR (p_after_network_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_after_network_public_id), 6) >> 4 <> 7)
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 101 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser enrollment choice input';
    END IF;

    SELECT admitted.login_workspace_public_id
    INTO admitted_workspace_public_id
    FROM mesh_ops.resolve_account_session_v2(
        p_deployment_public_id,
        p_deployment_recovery_epoch,
        'hmac-sha256-v1',
        p_session_digest_key_id,
        p_session_digest
    ) AS admitted;
    IF admitted_workspace_public_id IS NULL THEN
        RETURN NULL;
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        admitted_workspace_public_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.browser_enrollment_choice_workspace_public_id',
        admitted_workspace_public_id::TEXT,
        TRUE
    );

    WITH resolved AS MATERIALIZED (
        SELECT
            session.id AS session_id,
            session.deployment_id,
            session.principal_id,
            session.login_workspace_id,
            workspace.public_id AS workspace_public_id
        FROM mesh_ops.resolve_account_session_v2(
            p_deployment_public_id,
            p_deployment_recovery_epoch,
            'hmac-sha256-v1',
            p_session_digest_key_id,
            p_session_digest
        ) AS admitted
        JOIN mesh.account_session AS session
          ON session.public_id = admitted.session_public_id
         AND session.version = admitted.session_version
         AND session.principal_authority_generation = admitted.principal_authority_generation
         AND session.account_session_generation = admitted.account_session_generation
         AND session.provider_generation = admitted.provider_generation
         AND session.deployment_recovery_epoch = admitted.deployment_recovery_epoch
         AND session.state = 'active'
         AND session.idle_expires_at > pg_catalog.transaction_timestamp()
         AND session.absolute_expires_at > pg_catalog.transaction_timestamp()
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = session.deployment_id
         AND workspace.id = session.login_workspace_id
         AND workspace.public_id = admitted_workspace_public_id
         AND workspace.state = 'active'
         AND workspace.deleted_at IS NULL
        LIMIT 1
    ), choices AS (
        SELECT
            network.public_id,
            network.display_name
        FROM resolved
        JOIN mesh.workspace_membership AS workspace_membership
          ON workspace_membership.deployment_id = resolved.deployment_id
         AND workspace_membership.workspace_id = resolved.login_workspace_id
         AND workspace_membership.principal_id = resolved.principal_id
         AND workspace_membership.state = 'active'
         AND workspace_membership.valid_from <= pg_catalog.transaction_timestamp()
         AND (workspace_membership.expires_at IS NULL
              OR workspace_membership.expires_at > pg_catalog.transaction_timestamp())
        JOIN mesh.network_membership AS membership
          ON membership.deployment_id = resolved.deployment_id
         AND membership.workspace_id = resolved.login_workspace_id
         AND membership.principal_id = resolved.principal_id
         AND membership.workspace_membership_id = workspace_membership.id
         AND membership.state = 'active'
         AND membership.valid_from <= pg_catalog.transaction_timestamp()
         AND (membership.expires_at IS NULL
              OR membership.expires_at > pg_catalog.transaction_timestamp())
        JOIN mesh.network AS network
          ON network.workspace_id = membership.workspace_id
         AND network.id = membership.network_id
         AND network.state = 'active'
         AND network.deleted_at IS NULL
        WHERE (p_after_network_public_id IS NULL
            OR network.public_id > p_after_network_public_id)
          AND EXISTS (
              SELECT 1
              FROM mesh.enrollment_profile AS profile
              WHERE profile.workspace_id = network.workspace_id
                AND profile.network_id = network.id
                AND profile.state = 'active'
                AND profile.deleted_at IS NULL
                AND profile.interactive_authorization_enabled
          )
        ORDER BY network.public_id
        LIMIT p_limit
    )
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', resolved.workspace_public_id,
        'networks', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'network_id', choices.public_id,
                        'display_name', choices.display_name
                    ) ORDER BY choices.public_id
                )
                FROM choices
            ),
            '[]'::JSONB
        )
    )
    INTO result
    FROM resolved;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        COALESCE(previous_requested_workspace_public_id, ''),
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.browser_enrollment_choice_workspace_public_id',
        COALESCE(previous_choice_workspace_public_id, ''),
        TRUE
    );
    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.requested_workspace_public_id',
            COALESCE(previous_requested_workspace_public_id, ''),
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.browser_enrollment_choice_workspace_public_id',
            COALESCE(previous_choice_workspace_public_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_browser_enrollment_networks_v1(
    UUID, BIGINT, TEXT, BYTEA, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_browser_enrollment_networks_v1(
    UUID, BIGINT, TEXT, BYTEA, UUID, INTEGER
) TO mesh_runtime;
