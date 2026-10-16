-- Schema 175: enrollment keys. A key is an enrollment credential that
-- enrolls exactly one Device; whoever creates it (enrollment_credential.issue)
-- chooses how long the key can be used and, separately, how long the Device
-- it enrolls lives: a fixed time from 1 hour to 180 days, or never. The
-- Device belongs to the key's creator. Expiring or revoking a key never
-- touches the Device it enrolled.
--
-- Core generates the secret and its keyed digest; these functions store the
-- digest only, authorize on the transaction clock (no time is taken from the
-- caller) and return documents Core records as audit evidence on the
-- Network's stream. Each Network gets one "Enrollment keys" profile the
-- first time a key is issued. Credentials issued before this schema keep
-- their profile's Device lifetime.
--
-- Errors: 22023 invalid input, 42501 not authorized, P0002 unknown key,
-- MTE01 key already revoked, MTE02 too many usable keys.
--
-- Rollback: older binaries keep lock_registration_credential (v1), which
-- does not read the new columns, so a Device they enroll with a key gets
-- the profile's lifetime.

ALTER TABLE mesh.enrollment_credential
    ADD COLUMN device_lifetime_seconds BIGINT,
    ADD COLUMN device_never_expires BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN description TEXT,
    ADD CONSTRAINT enrollment_credential_device_lifetime_check CHECK (
        NOT (device_never_expires AND device_lifetime_seconds IS NOT NULL)
        AND (device_lifetime_seconds IS NULL OR device_lifetime_seconds BETWEEN 3600 AND 15552000)
    ),
    ADD CONSTRAINT enrollment_credential_description_check CHECK (
        description IS NULL OR (
            pg_catalog.char_length(description) BETWEEN 1 AND 128
            AND description = pg_catalog.btrim(description)
            AND description !~ '[[:cntrl:]]'
        )
    );

-- The usable keys of a profile, so counting and listing them reads only
-- those rows, however many spent keys accumulate.
CREATE INDEX enrollment_credential_usable_idx
    ON mesh.enrollment_credential (workspace_id, network_id, enrollment_profile_id, expires_at)
    WHERE state = 'active' AND deleted_at IS NULL AND use_limit_kind = 'bounded' AND used_count < max_uses;

-- One key profile per Network.
CREATE UNIQUE INDEX enrollment_profile_key_profile_uidx
    ON mesh.enrollment_profile (workspace_id, network_id)
    WHERE name_key = 'enrollment-keys' AND deleted_at IS NULL;

-- lock_registration_credential with the Device lifetime the key chose.
CREATE FUNCTION mesh_ops.lock_registration_credential_v2(p_credential_public_id UUID)
RETURNS TABLE (
    credential_internal_id BIGINT,
    profile_internal_id BIGINT,
    issuer_internal_id BIGINT,
    issuer_public_id TEXT,
    credential_state TEXT,
    use_limit_kind TEXT,
    max_uses BIGINT,
    used_count BIGINT,
    issued_recovery_epoch BIGINT,
    valid_from TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    credential_version BIGINT,
    device_lifetime_seconds BIGINT,
    device_never_expires BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
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
    RETURN QUERY
    SELECT credential.id, credential.enrollment_profile_id, credential.issuer_principal_id,
        principal.public_id::TEXT, credential.state, credential.use_limit_kind, credential.max_uses,
        credential.used_count, credential.issued_recovery_epoch, credential.valid_from,
        credential.expires_at, credential.version, credential.device_lifetime_seconds,
        credential.device_never_expires
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.principal AS principal ON principal.id = credential.issuer_principal_id
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id
    FOR UPDATE OF credential;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'scoped enrollment credential is unavailable';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_registration_credential_v2(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_registration_credential_v2(UUID) TO mesh_runtime;

-- The document of one key, as Core reads and records it. The state is
-- derived on the transaction clock: revoked, used (no uses left), expired,
-- else active. A used key names the Device it registered, created or
-- resumed.
CREATE FUNCTION mesh_ops.enrollment_key_document_internal_v1(p_credential mesh.enrollment_credential)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'key_id', p_credential.public_id,
        'description', p_credential.description,
        'issued_by_principal_id', issuer.public_id,
        'created_at', p_credential.valid_from,
        'expires_at', p_credential.expires_at,
        'revoked_at', p_credential.revoked_at,
        'version', p_credential.version,
        'state', CASE
            WHEN p_credential.state = 'revoked' THEN 'revoked'
            WHEN p_credential.use_limit_kind = 'bounded' AND p_credential.used_count >= p_credential.max_uses
                THEN 'used'
            WHEN p_credential.expires_at <= pg_catalog.transaction_timestamp() THEN 'expired'
            ELSE 'active'
        END,
        'device_lifetime_seconds', p_credential.device_lifetime_seconds,
        'device_never_expires', p_credential.device_never_expires,
        'device_id', used.device_public_id,
        'device_name', used.hostname
    )
    FROM mesh.principal AS issuer
    LEFT JOIN LATERAL (
        SELECT device.public_id AS device_public_id, device.hostname
        FROM mesh.enrollment_credential_use AS credential_use
        JOIN mesh.device AS device
          ON device.workspace_id = credential_use.workspace_id AND device.network_id = credential_use.network_id
         AND device.id = credential_use.device_id
        WHERE credential_use.workspace_id = p_credential.workspace_id
          AND credential_use.network_id = p_credential.network_id
          AND credential_use.enrollment_credential_id = p_credential.id
        ORDER BY credential_use.id
        LIMIT 1
    ) AS used ON TRUE
    WHERE issuer.id = p_credential.issuer_principal_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enrollment_key_document_internal_v1(mesh.enrollment_credential)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The authority a grant carries, for the audit record.
CREATE FUNCTION mesh_ops.enrollment_key_authority_internal_v1(
    p_role_binding_public_id UUID, p_role_definition_public_id UUID, p_binding_generation BIGINT,
    p_membership_generation BIGINT, p_owner_generation BIGINT
)
RETURNS JSONB
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'binding_id', p_role_binding_public_id,
        'role_id', p_role_definition_public_id,
        'binding_generation', COALESCE(p_binding_generation, 0),
        'membership_generation', COALESCE(p_membership_generation, 0),
        'owner_generation', COALESCE(p_owner_generation, 0)
    ))
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enrollment_key_authority_internal_v1(UUID, UUID, BIGINT, BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Issues one key: authorizes enrollment_credential.issue in the Network,
-- refuses a hundred-and-first usable key, creates the Network's key profile
-- the first time, and stores the credential (one use, valid from now for
-- p_key_lifetime_seconds) with the Device lifetime chosen.
CREATE FUNCTION mesh_ops.issue_enrollment_key_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_key_public_id UUID,
    p_digest_key_id TEXT, p_token_digest BYTEA, p_token_fingerprint BYTEA,
    p_key_lifetime_seconds BIGINT, p_device_lifetime_seconds BIGINT, p_device_never_expires BOOLEAN,
    p_description TEXT, p_change_public_id UUID
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
    v_issuer BIGINT;
    v_profile BIGINT;
    v_usable BIGINT;
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_revision BIGINT;
BEGIN
    IF p_key_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_key_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_digest_key_id IS NULL OR p_token_digest IS NULL OR p_token_fingerprint IS NULL
        OR p_key_lifetime_seconds IS NULL OR p_key_lifetime_seconds NOT BETWEEN 300 AND 2592000
        OR p_device_never_expires IS NULL
        OR (p_device_never_expires AND p_device_lifetime_seconds IS NOT NULL)
        OR (NOT p_device_never_expires AND (p_device_lifetime_seconds IS NULL
            OR p_device_lifetime_seconds NOT BETWEEN 3600 AND 15552000))
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'enrollment key request is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enrollment key issue is not authorized: scope';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'enrollment_credential.issue', v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enrollment key issue is not authorized: permission';
    END IF;
    SELECT principal.id INTO v_issuer FROM mesh.principal AS principal
    JOIN mesh.deployment AS deployment ON deployment.id = principal.deployment_id
    WHERE principal.deployment_id = v_scope.deployment_id AND principal.public_id = p_principal_public_id
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND deployment.recovery_epoch = p_deployment_recovery_epoch;
    IF v_issuer IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enrollment key issue is not authorized: issuer';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.enrollment_profile (
        public_id, workspace_id, network_id, created_by_principal_id, display_name, name_key,
        node_lifetime_seconds, ephemeral_mode, credential_use_policy, credential_max_uses, state,
        interactive_authorization_enabled, created_at, updated_at
    ) VALUES (
        pg_catalog.uuidv7(), v_scope.workspace_id, v_scope.network_id, v_issuer, 'Enrollment keys',
        'enrollment-keys', 15552000, 'persistent', 'bounded', 1, 'active', FALSE, v_now, v_now
    )
    ON CONFLICT (workspace_id, network_id) WHERE name_key = 'enrollment-keys' AND deleted_at IS NULL
    DO NOTHING;
    -- Keys of one Network are serialized by their profile's row lock.
    SELECT profile.id INTO v_profile FROM mesh.enrollment_profile AS profile
    WHERE profile.workspace_id = v_scope.workspace_id AND profile.network_id = v_scope.network_id
      AND profile.name_key = 'enrollment-keys' AND profile.deleted_at IS NULL
      AND profile.state = 'active' AND profile.ephemeral_mode = 'persistent'
      AND profile.credential_use_policy = 'bounded' AND profile.credential_max_uses = 1
      AND NOT profile.interactive_authorization_enabled
    FOR UPDATE;
    IF v_profile IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'the Network''s enrollment key profile is not usable';
    END IF;
    SELECT pg_catalog.count(*) INTO v_usable FROM (
        SELECT 1 FROM mesh.enrollment_credential AS credential
        WHERE credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
          AND credential.enrollment_profile_id = v_profile AND credential.state = 'active'
          AND credential.deleted_at IS NULL AND credential.use_limit_kind = 'bounded'
          AND credential.used_count < credential.max_uses AND credential.expires_at > v_now
        LIMIT 100
    ) AS usable;
    IF v_usable >= 100 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTE02', MESSAGE = 'the Network already has 100 usable enrollment keys';
    END IF;

    INSERT INTO mesh.enrollment_credential (
        public_id, workspace_id, network_id, enrollment_profile_id, issuer_principal_id,
        digest_algorithm, digest_key_id, token_digest, token_fingerprint, issued_recovery_epoch,
        use_limit_kind, max_uses, used_count, valid_from, expires_at, state,
        device_lifetime_seconds, device_never_expires, description, created_at, updated_at
    ) VALUES (
        p_key_public_id, v_scope.workspace_id, v_scope.network_id, v_profile, v_issuer,
        'hmac-sha256-v1', p_digest_key_id, p_token_digest, p_token_fingerprint, p_deployment_recovery_epoch,
        'bounded', 1, 0, v_now, v_now + pg_catalog.make_interval(secs => p_key_lifetime_seconds), 'active',
        p_device_lifetime_seconds, p_device_never_expires, NULLIF(p_description, ''), v_now, v_now
    )
    RETURNING * INTO v_credential;
    SELECT revision.network_revision INTO STRICT v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id;

    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', v_revision,
        'key', mesh_ops.enrollment_key_document_internal_v1(v_credential),
        'authority', mesh_ops.enrollment_key_authority_internal_v1(
            v_grant.role_binding_public_id, v_grant.role_definition_public_id,
            v_grant.binding_authority_generation, v_grant.membership_authority_generation,
            v_grant.workspace_owner_authority_generation)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.issue_enrollment_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, BYTEA, BYTEA,
    BIGINT, BIGINT, BOOLEAN, TEXT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.issue_enrollment_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, BYTEA, BYTEA,
    BIGINT, BIGINT, BOOLEAN, TEXT, UUID
) TO mesh_runtime;

-- Lists the Network's keys, at most p_limit: every usable key first, then
-- the newest spent, expired or revoked ones, to a session with
-- enrollment_credential.issue or enrollment_credential.revoke. Never returns
-- digests.
CREATE FUNCTION mesh_ops.list_enrollment_keys_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_profile BIGINT;
    v_keys JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'enrollment key listing is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL OR (
        NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'enrollment_credential.issue', v_now))
        AND NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'enrollment_credential.revoke', v_now))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'enrollment key listing is not authorized';
    END IF;
    -- Every usable key (at most 100), then the newest of the others, so a
    -- usable key can always be found and revoked.
    SELECT profile.id INTO v_profile FROM mesh.enrollment_profile AS profile
    WHERE profile.workspace_id = v_scope.workspace_id AND profile.network_id = v_scope.network_id
      AND profile.name_key = 'enrollment-keys' AND profile.deleted_at IS NULL;
    WITH usable AS (
        SELECT credential.id FROM mesh.enrollment_credential AS credential
        WHERE credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
          AND credential.enrollment_profile_id = v_profile AND credential.state = 'active'
          AND credential.deleted_at IS NULL AND credential.use_limit_kind = 'bounded'
          AND credential.used_count < credential.max_uses AND credential.expires_at > v_now
        ORDER BY credential.valid_from DESC, credential.id DESC
        LIMIT p_limit
    ), others AS (
        SELECT credential.id FROM mesh.enrollment_credential AS credential
        WHERE credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
          AND credential.enrollment_profile_id = v_profile AND credential.deleted_at IS NULL
          AND credential.id NOT IN (SELECT usable.id FROM usable)
        ORDER BY credential.valid_from DESC, credential.id DESC
        LIMIT GREATEST(p_limit - (SELECT pg_catalog.count(*) FROM usable), 0)
    ), listed AS (
        SELECT chosen.id, 0 AS rank FROM usable AS chosen
        UNION ALL
        SELECT chosen.id, 1 AS rank FROM others AS chosen
    )
    SELECT pg_catalog.jsonb_agg(mesh_ops.enrollment_key_document_internal_v1(credential)
               ORDER BY listed.rank, credential.valid_from DESC, credential.id DESC)
    INTO v_keys
    FROM listed
    JOIN mesh.enrollment_credential AS credential
      ON credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
     AND credential.id = listed.id;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'keys', COALESCE(v_keys, '[]'::JSONB)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_enrollment_keys_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_enrollment_keys_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, INTEGER
) TO mesh_runtime;

-- Revokes one key that is not revoked yet, used or not. The Device it
-- enrolled is untouched.
CREATE FUNCTION mesh_ops.revoke_enrollment_key_v1(
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
REVOKE ALL ON FUNCTION mesh_ops.revoke_enrollment_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_enrollment_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
