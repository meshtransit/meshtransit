DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

CREATE FUNCTION mesh_ops.resolve_account_session_v2(
    p_expected_deployment_public_id UUID,
    p_expected_recovery_epoch BIGINT,
    p_token_digest_algorithm TEXT,
    p_token_digest_key_id TEXT,
    p_token_digest BYTEA
)
RETURNS TABLE (
    session_public_id UUID,
    deployment_public_id UUID,
    principal_public_id UUID,
    identity_subject_public_id UUID,
    login_workspace_public_id UUID,
    authentication_time TIMESTAMPTZ,
    acr TEXT,
    amr TEXT[],
    session_version BIGINT,
    principal_authority_generation BIGINT,
    account_session_generation BIGINT,
    provider_generation BIGINT,
    deployment_recovery_epoch BIGINT,
    idle_expires_at TIMESTAMPTZ,
    absolute_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace_id BIGINT;
    previous_workspace_id TEXT;
BEGIN
    IF p_expected_deployment_public_id IS NULL
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(p_expected_deployment_public_id),
            6
        ) >> 4 <> 7
        OR p_expected_recovery_epoch IS NULL
        OR p_expected_recovery_epoch <= 0
        OR p_token_digest_algorithm IS NULL
        OR p_token_digest_algorithm <> 'hmac-sha256-v1'
        OR p_token_digest_key_id IS NULL
        OR pg_catalog.char_length(p_token_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_token_digest_key_id <> pg_catalog.btrim(p_token_digest_key_id)
        OR p_token_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_token_digest IS NULL
        OR pg_catalog.octet_length(p_token_digest) <> 32 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid account session resolution input';
    END IF;

    SELECT session.login_workspace_id
    INTO resolved_workspace_id
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment
      ON deployment.id = session.deployment_id
    WHERE deployment.installation_public_id = p_expected_deployment_public_id
      AND session.deployment_recovery_epoch = p_expected_recovery_epoch
      AND session.token_digest_algorithm = p_token_digest_algorithm
      AND session.token_digest_key_id = p_token_digest_key_id
      AND session.token_digest = p_token_digest;

    previous_workspace_id := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    PERFORM pg_catalog.set_config(
        'mesh.workspace_id',
        COALESCE(resolved_workspace_id::TEXT, ''),
        TRUE
    );

    BEGIN
        RETURN QUERY
        SELECT
            session.public_id,
            deployment.installation_public_id,
            principal.public_id,
            subject.public_id,
            workspace.public_id,
            session.authentication_time,
            session.acr,
            session.amr,
            session.version,
            session.principal_authority_generation,
            session.account_session_generation,
            session.provider_generation,
            session.deployment_recovery_epoch,
            session.idle_expires_at,
            session.absolute_expires_at
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
        LEFT JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = session.deployment_id
         AND workspace.id = session.login_workspace_id
        WHERE deployment.installation_public_id = p_expected_deployment_public_id
          AND deployment.recovery_epoch = p_expected_recovery_epoch
          AND session.deployment_recovery_epoch = p_expected_recovery_epoch
          AND session.token_digest_algorithm = p_token_digest_algorithm
          AND session.token_digest_key_id = p_token_digest_key_id
          AND session.token_digest = p_token_digest
          AND session.state = 'active'
          AND session.idle_expires_at > pg_catalog.transaction_timestamp()
          AND session.absolute_expires_at > pg_catalog.transaction_timestamp()
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND principal.state = 'active'
          AND principal.authority_generation = session.principal_authority_generation
          AND account.recovery_state = 'verified'
          AND account.session_generation = session.account_session_generation
          AND subject.state = 'active'
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.current_generation = session.provider_generation
          AND client.state = 'active'
          AND (
              session.login_workspace_id IS NULL
              OR workspace.state = 'active'
          );
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config(
                'mesh.workspace_id',
                COALESCE(previous_workspace_id, ''),
                TRUE
            );
            RAISE;
    END;

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id',
        COALESCE(previous_workspace_id, ''),
        TRUE
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_account_session_v2(
    UUID,
    BIGINT,
    TEXT,
    TEXT,
    BYTEA
) FROM PUBLIC;

REVOKE ALL ON ALL TABLES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh, mesh_ops, mesh_audit FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mesh_ops.resolve_account_session_v2(
    UUID,
    BIGINT,
    TEXT,
    TEXT,
    BYTEA
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
