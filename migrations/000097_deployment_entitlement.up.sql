-- ADR-050 D1/D2: verified Deployment Entitlement authority. Core verifies the
-- signed envelope in Go; PostgreSQL keeps the accepted generations, refuses
-- downgrades and conflicting content, and derives capabilities from the
-- current generation. Profiles share one feature set and differ only in the
-- numeric limits recorded here.

CREATE TABLE mesh.deployment_entitlement (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL REFERENCES mesh.deployment (id),
    generation BIGINT NOT NULL,
    profile TEXT NOT NULL,
    max_active_workspaces BIGINT NOT NULL,
    max_owned_workspaces_per_account BIGINT NOT NULL,
    capabilities TEXT[] NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    grace_seconds BIGINT NOT NULL,
    signer_key_id TEXT NOT NULL,
    content_sha256 BYTEA NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT deployment_entitlement_generation_uidx UNIQUE (deployment_id, generation),
    CONSTRAINT deployment_entitlement_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT deployment_entitlement_generation_check CHECK (generation > 0),
    CONSTRAINT deployment_entitlement_version_check CHECK (version = 1),
    CONSTRAINT deployment_entitlement_profile_check CHECK (profile IN ('cloud', 'self_hosted')),
    CONSTRAINT deployment_entitlement_limits_check CHECK (
        max_active_workspaces BETWEEN 1 AND 1000000
        AND max_owned_workspaces_per_account BETWEEN 1 AND 1000
        AND max_owned_workspaces_per_account <= max_active_workspaces
    ),
    CONSTRAINT deployment_entitlement_capabilities_check CHECK (
        capabilities <@ ARRAY['cloud_billing', 'platform_operations']::TEXT[]
        AND pg_catalog.array_position(capabilities, NULL) IS NULL
        AND pg_catalog.cardinality(capabilities) <= 2
    ),
    CONSTRAINT deployment_entitlement_window_check CHECK (
        issued_at <= not_before + INTERVAL '5 minutes'
        AND expires_at > not_before
        AND expires_at <= not_before + INTERVAL '1098 days'
    ),
    CONSTRAINT deployment_entitlement_grace_check CHECK (grace_seconds BETWEEN 0 AND 7776000),
    CONSTRAINT deployment_entitlement_signer_check CHECK (signer_key_id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    CONSTRAINT deployment_entitlement_digest_check CHECK (pg_catalog.octet_length(content_sha256) = 32)
);

-- Accepted generations are evidence; they are never edited or removed.
CREATE FUNCTION mesh_ops.enforce_deployment_entitlement_immutable_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Deployment entitlement is immutable';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_deployment_entitlement_immutable_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER deployment_entitlement_immutable
BEFORE UPDATE OR DELETE ON mesh.deployment_entitlement
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_deployment_entitlement_immutable_v1();
CREATE TRIGGER deployment_entitlement_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.deployment_entitlement
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'deployment_entitlement', 'public_id'
);

ALTER TABLE mesh.deployment_entitlement ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.deployment_entitlement FORCE ROW LEVEL SECURITY;
CREATE POLICY deployment_entitlement_migrator_policy ON mesh.deployment_entitlement
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.deployment_entitlement
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Records one verified generation. The caller sets mesh.change_public_id and
-- appends audit evidence when outcome = 'recorded'. A replay of the current
-- generation with identical content is 'replayed'; an older generation is
-- 'superseded' and changes nothing. Conflicting content for a recorded
-- generation, a profile that differs from the Deployment, or an inactive
-- Deployment is rejected.
CREATE FUNCTION mesh_ops.record_deployment_entitlement_v1(
    p_deployment_public_id UUID,
    p_entitlement_public_id UUID,
    p_generation BIGINT,
    p_profile TEXT,
    p_max_active_workspaces BIGINT,
    p_max_owned_workspaces_per_account BIGINT,
    p_capabilities TEXT[],
    p_issued_at TIMESTAMPTZ,
    p_not_before TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ,
    p_grace_seconds BIGINT,
    p_signer_key_id TEXT,
    p_content_sha256 BYTEA
)
RETURNS TABLE (
    current_entitlement_public_id UUID,
    current_generation BIGINT,
    outcome TEXT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    target_deployment mesh.deployment%ROWTYPE;
    existing mesh.deployment_entitlement%ROWTYPE;
    latest mesh.deployment_entitlement%ROWTYPE;
BEGIN
    IF p_deployment_public_id IS NULL OR p_entitlement_public_id IS NULL OR p_generation IS NULL
        OR p_content_sha256 IS NULL OR pg_catalog.octet_length(p_content_sha256) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Deployment entitlement input';
    END IF;

    SELECT * INTO target_deployment
    FROM mesh.deployment
    WHERE installation_public_id = p_deployment_public_id
    FOR UPDATE;
    IF NOT FOUND OR target_deployment.state <> 'active' OR target_deployment.deleted_at IS NOT NULL
        OR target_deployment.recovery_state <> 'verified' THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Deployment is unavailable';
    END IF;
    IF target_deployment.profile <> p_profile THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'entitlement profile differs from the Deployment';
    END IF;

    SELECT * INTO existing
    FROM mesh.deployment_entitlement
    WHERE deployment_id = target_deployment.id AND generation = p_generation;
    IF FOUND THEN
        IF existing.content_sha256 <> p_content_sha256 OR existing.public_id <> p_entitlement_public_id THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'entitlement generation conflict';
        END IF;
    END IF;

    SELECT * INTO latest
    FROM mesh.deployment_entitlement
    WHERE deployment_id = target_deployment.id
    ORDER BY generation DESC
    LIMIT 1;
    IF FOUND AND latest.generation > p_generation THEN
        RETURN QUERY SELECT latest.public_id, latest.generation, 'superseded'::TEXT;
        RETURN;
    END IF;
    IF existing.id IS NOT NULL THEN
        RETURN QUERY SELECT existing.public_id, existing.generation, 'replayed'::TEXT;
        RETURN;
    END IF;

    INSERT INTO mesh.deployment_entitlement (
        public_id, deployment_id, generation, profile, max_active_workspaces,
        max_owned_workspaces_per_account, capabilities, issued_at, not_before, expires_at,
        grace_seconds, signer_key_id, content_sha256
    ) VALUES (
        p_entitlement_public_id, target_deployment.id, p_generation, p_profile, p_max_active_workspaces,
        p_max_owned_workspaces_per_account, p_capabilities, p_issued_at, p_not_before, p_expires_at,
        p_grace_seconds, p_signer_key_id, p_content_sha256
    );
    RETURN QUERY SELECT p_entitlement_public_id, p_generation, 'recorded'::TEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.record_deployment_entitlement_v1(
    UUID, UUID, BIGINT, TEXT, BIGINT, BIGINT, TEXT[], TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, BIGINT, TEXT, BYTEA
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_deployment_entitlement_v1(
    UUID, UUID, BIGINT, TEXT, BIGINT, BIGINT, TEXT[], TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, BIGINT, TEXT, BYTEA
) TO mesh_runtime;

-- Capabilities v2 accept every profile. The tuple is derived in Go from the
-- Deployment and its current entitlement; a Deployment without an entitlement
-- reports entitlement NULL and Go keeps the legacy self-host tuple or fails
-- closed for Cloud. Session validation is identical to v1.
CREATE FUNCTION mesh_ops.read_console_deployment_capabilities_v2(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    result JSONB;
    previous_requested_workspace_public_id TEXT;
BEGIN
    previous_requested_workspace_public_id := pg_catalog.current_setting(
        'mesh.requested_workspace_public_id',
        TRUE
    );
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Console Deployment capability input';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );

    WITH authority AS MATERIALIZED (
        SELECT
            deployment.id AS deployment_internal_id,
            deployment.installation_public_id AS deployment_public_id,
            deployment.profile,
            deployment.version
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
         AND workspace.id = session.login_workspace_id
         AND workspace.public_id = p_workspace_public_id
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = session.deployment_id
         AND membership.workspace_id = workspace.id
         AND membership.principal_id = session.principal_id
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
          AND session.authentication_time <= p_evaluated_at
          AND session.idle_expires_at > p_evaluated_at
          AND session.absolute_expires_at > p_evaluated_at
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.recovery_epoch = p_deployment_recovery_epoch
          AND principal.state = 'active'
          AND principal.authority_generation = p_principal_authority_generation
          AND account.recovery_state = 'verified'
          AND account.session_generation = p_account_session_generation
          AND subject.state = 'active'
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.current_generation = p_provider_generation
          AND client.state = 'active'
          AND workspace.state = 'active'
          AND membership.state = 'active'
          AND membership.valid_from <= p_evaluated_at
          AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
        LIMIT 1
    )
    SELECT pg_catalog.jsonb_build_object(
        'deployment_id', authority.deployment_public_id,
        'profile', authority.profile,
        'revision', authority.version,
        'entitlement', (
            SELECT pg_catalog.jsonb_build_object(
                'id', entitlement.public_id,
                'generation', entitlement.generation,
                'max_active_workspaces', entitlement.max_active_workspaces,
                'max_owned_workspaces_per_account', entitlement.max_owned_workspaces_per_account,
                'capabilities', pg_catalog.to_jsonb(entitlement.capabilities),
                'expires_at', entitlement.expires_at,
                'grace_seconds', entitlement.grace_seconds,
                'state', CASE
                    WHEN p_evaluated_at < entitlement.not_before THEN 'not_yet_valid'
                    WHEN p_evaluated_at < entitlement.expires_at THEN 'active'
                    WHEN p_evaluated_at < entitlement.expires_at
                        + pg_catalog.make_interval(secs => entitlement.grace_seconds) THEN 'grace'
                    ELSE 'expired'
                END
            )
            FROM mesh.deployment_entitlement AS entitlement
            WHERE entitlement.deployment_id = authority.deployment_internal_id
              AND entitlement.profile = authority.profile
            ORDER BY entitlement.generation DESC
            LIMIT 1
        )
    )
    INTO result
    FROM authority;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        COALESCE(previous_requested_workspace_public_id, ''),
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
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_console_deployment_capabilities_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_deployment_capabilities_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, TIMESTAMPTZ
) TO mesh_runtime;
