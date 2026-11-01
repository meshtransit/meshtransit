-- Schema 266: connection logs, Core's part of phase 1a (connection logs
-- design §10, §16b C22–C25).
--
-- A Workspace may log connections only once an operator granted it the
-- connection_logs feature (mesh.workspace_feature; written by the operator
-- command as mesh_migrator, never through the API). Its storage credentials
-- hold an S3 or R2 secret sealed to the connection log receiver's key: Core
-- cannot open them and keeps only the access key's last four characters in
-- clear. A credential names the Networks that may use it. A Network's
-- connection log settings (destination, forwarded traffic, window) are
-- versioned; a change advances the Network revision, so map sessions grant
-- or withdraw FlowTickets. Go appends the events in the same transaction.
--
-- Errors: 22023 invalid input, 42501 not authorized, 40001 stale version,
-- P0002 unknown credential or Network, 55006 a credential in use, 55000 the
-- Workspace lacks the feature or the credential does not allow the Network.
--
-- Rollback: older binaries read none of this; the tables stay empty for them.

INSERT INTO mesh.permission (permission_key, description, risk_class, allowed_scope_kinds, catalog_version)
VALUES
    ('storage_credential.manage',
     'Create, rotate and delete the Workspace''s storage credentials for connection logs',
     'privileged', ARRAY['workspace'], 1),
    ('connection_log.manage',
     'Turn a Network''s connection logs on or off and choose where they go',
     'privileged', ARRAY['network'], 1);

INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT grant_row.role_key, permission.id
FROM (VALUES
    ('admin', 'storage_credential.manage'),
    ('admin', 'connection_log.manage'),
    ('network_admin', 'connection_log.manage')
) AS grant_row(role_key, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key = grant_row.permission_key
ON CONFLICT DO NOTHING;

-- Features an operator granted a Workspace (C22). One row per grant; a
-- revoke deletes it. The audit capture records both.
CREATE TABLE mesh.workspace_feature (
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL REFERENCES mesh.workspace (id) ON DELETE CASCADE,
    feature TEXT NOT NULL CHECK (feature IN ('connection_logs')),
    note TEXT NOT NULL CHECK (pg_catalog.octet_length(note) BETWEEN 1 AND 200 AND note !~ '[[:cntrl:]]'),
    granted_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    PRIMARY KEY (workspace_id, feature)
);
CREATE TRIGGER workspace_feature_authority_capture
AFTER INSERT OR UPDATE OR DELETE ON mesh.workspace_feature
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('workspace_feature', 'public_id');
ALTER TABLE mesh.workspace_feature ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace_feature FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_feature_migrator_policy ON mesh.workspace_feature
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.workspace_feature
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.workspace_has_feature_internal_v1(p_workspace_id BIGINT, p_feature TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (SELECT 1 FROM mesh.workspace_feature AS feature
                   WHERE feature.workspace_id = p_workspace_id AND feature.feature = p_feature)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.workspace_has_feature_internal_v1(BIGINT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- As Go's connectionlog validators (design §10).
CREATE FUNCTION mesh_ops.connection_log_name_is_valid_v1(p_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_name IS NOT NULL AND p_name ~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$'
$function$;

CREATE FUNCTION mesh_ops.connection_log_bucket_is_valid_v1(p_bucket TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_bucket IS NOT NULL AND p_bucket ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'
        AND p_bucket NOT LIKE 'xn--%' AND p_bucket NOT LIKE 'sthree-%' AND p_bucket NOT LIKE '%-s3alias'
        AND p_bucket NOT LIKE '%--ol-s3' AND p_bucket NOT LIKE '%--x-s3'
$function$;

CREATE FUNCTION mesh_ops.connection_log_region_is_valid_v1(p_provider TEXT, p_region TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_region IS NOT NULL AND CASE p_provider
        WHEN 'cloudflare_r2' THEN p_region = 'auto'
        WHEN 'aws_s3' THEN p_region ~ '^(us|eu|ap|sa|ca|me|af|il|mx)-[a-z]{4,10}-[1-9]$'
        ELSE FALSE END
$function$;

CREATE FUNCTION mesh_ops.connection_log_prefix_is_valid_v1(p_prefix TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_prefix IS NOT NULL AND p_prefix ~ '^[a-z0-9_/-]{0,128}$' AND p_prefix NOT LIKE '/%'
        AND p_prefix NOT LIKE '%//%' AND p_prefix NOT LIKE '%..%'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.connection_log_name_is_valid_v1(TEXT),
    mesh_ops.connection_log_bucket_is_valid_v1(TEXT), mesh_ops.connection_log_region_is_valid_v1(TEXT, TEXT),
    mesh_ops.connection_log_prefix_is_valid_v1(TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A Workspace's storage credentials (C24). sealed is HPKE ciphertext of
-- the access key ID and secret to the receiver's credential key named by
-- sealing_key_id; Core never holds the opened secret. The seal binds
-- sealed_version, the row version when the secret was last sealed: a
-- rename or a change of Networks keeps it, so the secret still opens.
CREATE TABLE mesh.storage_credential (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL REFERENCES mesh.workspace (id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (mesh_ops.connection_log_name_is_valid_v1(name)),
    provider TEXT NOT NULL CHECK (provider IN ('aws_s3', 'cloudflare_r2')),
    -- Cloudflare's account ID (32 hex), which names the R2 endpoint.
    account_id TEXT CHECK (account_id ~ '^[0-9a-f]{32}$'),
    access_key_suffix TEXT NOT NULL CHECK (access_key_suffix ~ '^[A-Za-z0-9]{4}$'),
    sealed BYTEA NOT NULL CHECK (pg_catalog.octet_length(sealed) BETWEEN 32 AND 4096),
    sealing_key_id TEXT NOT NULL CHECK (sealing_key_id ~ '^[A-Za-z0-9._-]{1,32}$'),
    sealed_version BIGINT NOT NULL CHECK (sealed_version > 0),
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    created_by_principal_id BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by_principal_id BIGINT NOT NULL,
    CONSTRAINT storage_credential_account_check CHECK ((provider = 'cloudflare_r2') = (account_id IS NOT NULL)),
    CONSTRAINT storage_credential_sealed_version_order_check CHECK (sealed_version <= version),
    CONSTRAINT storage_credential_name_unique UNIQUE (workspace_id, name),
    CONSTRAINT storage_credential_scope_unique UNIQUE (workspace_id, id)
);
CREATE TRIGGER storage_credential_authority_capture
AFTER INSERT OR UPDATE OR DELETE ON mesh.storage_credential
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('storage_credential', 'public_id');
ALTER TABLE mesh.storage_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.storage_credential FORCE ROW LEVEL SECURITY;
CREATE POLICY storage_credential_migrator_policy ON mesh.storage_credential
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.storage_credential
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The Networks that may use a credential.
CREATE TABLE mesh.storage_credential_network (
    workspace_id BIGINT NOT NULL,
    credential_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    PRIMARY KEY (credential_id, network_id),
    CONSTRAINT storage_credential_network_credential_fk FOREIGN KEY (workspace_id, credential_id)
        REFERENCES mesh.storage_credential (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT storage_credential_network_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX storage_credential_network_network_idx ON mesh.storage_credential_network (workspace_id, network_id);
ALTER TABLE mesh.storage_credential_network ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.storage_credential_network FORCE ROW LEVEL SECURITY;
CREATE POLICY storage_credential_network_migrator_policy ON mesh.storage_credential_network
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.storage_credential_network
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A Network's connection log settings (C25): version 0 (absent) is off.
CREATE TABLE mesh.network_connection_log (
    network_id BIGINT PRIMARY KEY,
    -- The Network's public ID: the aggregate its events name.
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    enabled BOOLEAN NOT NULL,
    credential_id BIGINT,
    bucket TEXT NOT NULL CHECK (bucket = '' OR mesh_ops.connection_log_bucket_is_valid_v1(bucket)),
    region TEXT NOT NULL,
    prefix TEXT NOT NULL CHECK (mesh_ops.connection_log_prefix_is_valid_v1(prefix)),
    -- Routers, exit nodes and gateways count what they forward (design §7).
    forwarded BOOLEAN NOT NULL,
    window_s INTEGER NOT NULL CHECK (window_s BETWEEN 60 AND 300),
    -- The AWS account that owns the bucket (C52): S3 refuses a write to a
    -- bucket of another account. NULL: the credential's own account.
    expected_bucket_owner TEXT CHECK (expected_bucket_owner ~ '^[0-9]{12}$'),
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by_principal_id BIGINT NOT NULL,
    CONSTRAINT network_connection_log_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT network_connection_log_credential_fk FOREIGN KEY (workspace_id, credential_id)
        REFERENCES mesh.storage_credential (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_connection_log_destination_check CHECK (
        NOT enabled OR (credential_id IS NOT NULL AND bucket <> '' AND region <> '')),
    CONSTRAINT network_connection_log_owner_check CHECK (expected_bucket_owner IS NULL OR credential_id IS NOT NULL)
);
CREATE INDEX network_connection_log_credential_idx ON mesh.network_connection_log (workspace_id, credential_id);
CREATE TRIGGER network_connection_log_authority_capture
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_connection_log
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_connection_log', 'public_id');
ALTER TABLE mesh.network_connection_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_connection_log FORCE ROW LEVEL SECURITY;
CREATE POLICY network_connection_log_migrator_policy ON mesh.network_connection_log
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_connection_log
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The caller's grant of a Workspace permission: scope, actor and authority.
CREATE FUNCTION mesh_ops.connection_log_workspace_grant_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_permission TEXT
)
RETURNS TABLE (workspace_id BIGINT, actor_id BIGINT, authority JSONB)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_workspace mesh.workspace%ROWTYPE;
    v_scoped BIGINT;
    v_actor BIGINT;
BEGIN
    IF p_permission NOT IN ('workspace.read', 'storage_credential.manage') OR p_workspace_public_id IS NULL
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'storage credential request is invalid';
    END IF;
    -- The Workspace's row scope, as a Workspace rename sets it: the exact
    -- ID selects it, it grants nothing.
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    SELECT workspace.id INTO v_scoped FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id;
    IF v_scoped IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'storage credential action is not authorized: scope';
    END IF;
    IF COALESCE(pg_catalog.current_setting('mesh.workspace_id', TRUE), '') <> ''
        AND mesh_ops.current_workspace_id() <> v_scoped THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Workspace scope cannot be replaced';
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_scoped::TEXT, TRUE);
    SELECT * INTO v_grant FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_permission,
        pg_catalog.transaction_timestamp()) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'storage credential action is not authorized';
    END IF;
    SELECT * INTO v_workspace FROM mesh.workspace AS workspace WHERE workspace.public_id = p_workspace_public_id;
    SELECT principal.id INTO v_actor FROM mesh.principal AS principal
    JOIN mesh.deployment AS deployment ON deployment.id = principal.deployment_id
    WHERE principal.deployment_id = v_workspace.deployment_id AND principal.public_id = p_principal_public_id
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND deployment.recovery_epoch = p_deployment_recovery_epoch;
    IF v_workspace.id IS NULL OR v_actor IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'storage credential action is not authorized: actor';
    END IF;
    RETURN QUERY SELECT v_workspace.id, v_actor,
        mesh_ops.enrollment_key_authority_internal_v1(
            v_grant.role_binding_public_id, v_grant.role_definition_public_id,
            v_grant.binding_authority_generation, v_grant.membership_authority_generation,
            v_grant.workspace_owner_authority_generation);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.connection_log_workspace_grant_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.storage_credential_document_internal_v1(p_credential mesh.storage_credential)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'id', p_credential.public_id,
        'name', p_credential.name,
        'provider', p_credential.provider,
        'account_id', p_credential.account_id,
        'access_key_suffix', p_credential.access_key_suffix,
        'version', p_credential.version,
        'sealed_version', p_credential.sealed_version,
        'created_at', p_credential.created_at,
        'updated_at', p_credential.updated_at,
        'networks', COALESCE((
            SELECT pg_catalog.jsonb_agg(network.public_id ORDER BY network.public_id)
            FROM mesh.storage_credential_network AS allowed
            JOIN mesh.network AS network ON network.workspace_id = allowed.workspace_id AND network.id = allowed.network_id
            WHERE allowed.credential_id = p_credential.id), '[]'::JSONB),
        'used_by', COALESCE((
            SELECT pg_catalog.jsonb_agg(destination.public_id ORDER BY destination.public_id)
            FROM mesh.network_connection_log AS destination
            WHERE destination.workspace_id = p_credential.workspace_id
              AND destination.credential_id = p_credential.id), '[]'::JSONB)
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.storage_credential_document_internal_v1(mesh.storage_credential)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Any reader of the Workspace: its credentials, never their secrets.
CREATE FUNCTION mesh_ops.list_storage_credentials_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID
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
BEGIN
    SELECT * INTO v_grant FROM mesh_ops.connection_log_workspace_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, 'workspace.read');
    RETURN pg_catalog.jsonb_build_object(
        'feature', mesh_ops.workspace_has_feature_internal_v1(v_grant.workspace_id, 'connection_logs'),
        'credentials', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.storage_credential_document_internal_v1(credential)
                ORDER BY credential.name)
            FROM mesh.storage_credential AS credential
            WHERE credential.workspace_id = v_grant.workspace_id), '[]'::JSONB));
END;
$function$;

-- The Networks a credential may name, all of the Workspace; 22023 for an
-- unknown one.
CREATE FUNCTION mesh_ops.storage_credential_networks_internal_v1(p_workspace_id BIGINT, p_networks UUID[])
RETURNS BIGINT[]
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_ids BIGINT[];
BEGIN
    IF p_networks IS NULL OR pg_catalog.cardinality(p_networks) > 1000
        OR pg_catalog.cardinality(p_networks) <> (SELECT pg_catalog.count(DISTINCT network) FROM pg_catalog.unnest(p_networks) AS network) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'storage credential networks are invalid';
    END IF;
    SELECT pg_catalog.array_agg(network.id ORDER BY network.id) INTO v_ids
    FROM mesh.network AS network
    WHERE network.workspace_id = p_workspace_id AND network.public_id = ANY (p_networks);
    IF COALESCE(pg_catalog.cardinality(v_ids), 0) <> pg_catalog.cardinality(p_networks) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'storage credential names an unknown Network';
    END IF;
    RETURN COALESCE(v_ids, ARRAY[]::BIGINT[]);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.storage_credential_networks_internal_v1(BIGINT, UUID[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates, rotates (p_expected_version > 0, same credential) or re-scopes
-- a credential. p_sealed and p_access_key_suffix are NULL when only the
-- Networks change. Removing a Network that sends to the credential is
-- 55006. Returns what Go records as the Workspace's event.
CREATE FUNCTION mesh_ops.put_storage_credential_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_credential_public_id UUID, p_expected_version BIGINT,
    p_name TEXT, p_provider TEXT, p_account_id TEXT, p_access_key_suffix TEXT, p_sealed BYTEA,
    p_sealing_key_id TEXT, p_networks UUID[], p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_grant RECORD;
    v_before mesh.storage_credential%ROWTYPE;
    v_after mesh.storage_credential%ROWTYPE;
    v_networks BIGINT[];
    v_in_use UUID;
BEGIN
    IF p_credential_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 0
        OR p_change_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR NOT COALESCE(mesh_ops.connection_log_name_is_valid_v1(p_name), FALSE)
        OR p_provider NOT IN ('aws_s3', 'cloudflare_r2')
        OR (p_provider = 'cloudflare_r2') <> (p_account_id IS NOT NULL)
        OR (p_sealed IS NULL) <> (p_access_key_suffix IS NULL) OR (p_sealed IS NULL) <> (p_sealing_key_id IS NULL)
        OR (p_expected_version = 0 AND p_sealed IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'storage credential is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.connection_log_workspace_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, 'storage_credential.manage');
    v_networks := mesh_ops.storage_credential_networks_internal_v1(v_grant.workspace_id, p_networks);
    SELECT * INTO v_before FROM mesh.storage_credential AS credential
    WHERE credential.workspace_id = v_grant.workspace_id AND credential.public_id = p_credential_public_id
    FOR UPDATE;
    IF COALESCE(v_before.version, 0) <> p_expected_version THEN
        IF p_expected_version > 0 AND v_before.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown storage credential';
        END IF;
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'storage credential version changed';
    END IF;
    IF v_before.id IS NULL THEN
        -- One creator at a time per Workspace, so the cap holds (M3).
        PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('mesh.storage_credential'),
            pg_catalog.hashtext(v_grant.workspace_id::TEXT));
        IF (SELECT pg_catalog.count(*) FROM mesh.storage_credential AS credential
            WHERE credential.workspace_id = v_grant.workspace_id) >= 50 THEN
            RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'the Workspace has 50 storage credentials';
        END IF;
    END IF;
    IF v_before.id IS NOT NULL AND (v_before.provider <> p_provider
        OR v_before.account_id IS DISTINCT FROM p_account_id) THEN
        -- A credential keeps its provider and account: another is a new one.
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'a storage credential keeps its provider';
    END IF;
    IF v_before.id IS NOT NULL THEN
        SELECT network.public_id INTO v_in_use FROM mesh.network_connection_log AS destination
        JOIN mesh.network AS network ON network.workspace_id = destination.workspace_id
         AND network.id = destination.network_id
        WHERE destination.workspace_id = v_grant.workspace_id AND destination.credential_id = v_before.id
          AND destination.network_id <> ALL (v_networks)
        LIMIT 1;
        IF v_in_use IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55006', MESSAGE = 'a Network sends its connection logs with this credential';
        END IF;
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF v_before.id IS NULL THEN
        INSERT INTO mesh.storage_credential (
            public_id, workspace_id, name, provider, account_id, access_key_suffix, sealed, sealing_key_id,
            sealed_version, version, created_at, created_by_principal_id, updated_at, updated_by_principal_id)
        VALUES (p_credential_public_id, v_grant.workspace_id, p_name, p_provider, p_account_id, p_access_key_suffix,
            p_sealed, p_sealing_key_id, 1, 1, v_now, v_grant.actor_id, v_now, v_grant.actor_id)
        RETURNING * INTO v_after;
    ELSE
        UPDATE mesh.storage_credential AS credential SET
            name = p_name,
            access_key_suffix = COALESCE(p_access_key_suffix, credential.access_key_suffix),
            sealed = COALESCE(p_sealed, credential.sealed),
            sealing_key_id = COALESCE(p_sealing_key_id, credential.sealing_key_id),
            -- Go sealed a new secret to the version this update makes.
            sealed_version = CASE WHEN p_sealed IS NULL THEN credential.sealed_version
                                  ELSE credential.version + 1 END,
            version = credential.version + 1, updated_at = v_now, updated_by_principal_id = v_grant.actor_id
        WHERE credential.id = v_before.id
        RETURNING * INTO v_after;
    END IF;
    DELETE FROM mesh.storage_credential_network AS allowed
    WHERE allowed.credential_id = v_after.id AND allowed.network_id <> ALL (v_networks);
    INSERT INTO mesh.storage_credential_network (workspace_id, credential_id, network_id)
    SELECT v_grant.workspace_id, v_after.id, network_id FROM pg_catalog.unnest(v_networks) AS network_id
    ON CONFLICT DO NOTHING;
    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id,
        'rotated', p_sealed IS NOT NULL AND v_before.id IS NOT NULL,
        'before', CASE WHEN v_before.id IS NULL THEN NULL
                       ELSE mesh_ops.storage_credential_document_internal_v1(v_before) END,
        'credential', mesh_ops.storage_credential_document_internal_v1(v_after),
        'authority', v_grant.authority);
END;
$function$;

-- Deletes a credential no Network sends with (55006 otherwise).
CREATE FUNCTION mesh_ops.delete_storage_credential_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_credential_public_id UUID, p_expected_version BIGINT, p_change_public_id UUID
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
    v_before mesh.storage_credential%ROWTYPE;
BEGIN
    IF p_credential_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_change_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'storage credential deletion is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.connection_log_workspace_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, 'storage_credential.manage');
    SELECT * INTO v_before FROM mesh.storage_credential AS credential
    WHERE credential.workspace_id = v_grant.workspace_id AND credential.public_id = p_credential_public_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown storage credential';
    END IF;
    IF v_before.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'storage credential version changed';
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.network_connection_log AS destination
               WHERE destination.workspace_id = v_grant.workspace_id AND destination.credential_id = v_before.id) THEN
        RAISE EXCEPTION USING ERRCODE = '55006', MESSAGE = 'a Network sends its connection logs with this credential';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    DELETE FROM mesh.storage_credential AS credential WHERE credential.id = v_before.id;
    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id,
        'before', mesh_ops.storage_credential_document_internal_v1(v_before),
        'authority', v_grant.authority);
END;
$function$;

-- The caller's grant of a Network permission (network.read or
-- connection_log.manage): scope, actor, authority.
CREATE FUNCTION mesh_ops.connection_log_network_grant_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT
)
RETURNS TABLE (workspace_id BIGINT, network_id BIGINT, actor_id BIGINT, authority JSONB)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_grant RECORD;
    v_actor BIGINT;
BEGIN
    IF p_permission NOT IN ('network.read', 'connection_log.manage')
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'connection log request is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'connection log action is not authorized: scope';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, pg_catalog.transaction_timestamp()
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'connection log action is not authorized: permission';
    END IF;
    SELECT principal.id INTO v_actor FROM mesh.principal AS principal
    JOIN mesh.deployment AS deployment ON deployment.id = principal.deployment_id
    WHERE principal.deployment_id = v_scope.deployment_id AND principal.public_id = p_principal_public_id
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND deployment.recovery_epoch = p_deployment_recovery_epoch;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'connection log action is not authorized: actor';
    END IF;
    RETURN QUERY SELECT v_scope.workspace_id, v_scope.network_id, v_actor,
        mesh_ops.enrollment_key_authority_internal_v1(
            v_grant.role_binding_public_id, v_grant.role_definition_public_id,
            v_grant.binding_authority_generation, v_grant.membership_authority_generation,
            v_grant.workspace_owner_authority_generation);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.connection_log_network_grant_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.network_connection_log_document_internal_v1(p_settings mesh.network_connection_log)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'enabled', COALESCE(p_settings.enabled, FALSE),
        'credential_id', (SELECT credential.public_id FROM mesh.storage_credential AS credential
                          WHERE credential.workspace_id = p_settings.workspace_id
                            AND credential.id = p_settings.credential_id),
        'bucket', COALESCE(p_settings.bucket, ''),
        'region', COALESCE(p_settings.region, ''),
        'prefix', COALESCE(p_settings.prefix, ''),
        'forwarded', COALESCE(p_settings.forwarded, FALSE),
        'window_seconds', COALESCE(p_settings.window_s, 60),
        'expected_bucket_owner', p_settings.expected_bucket_owner,
        'version', COALESCE(p_settings.version, 0),
        'updated_at', p_settings.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.network_connection_log_document_internal_v1(mesh.network_connection_log)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Any reader of the Network: its settings (version 0 and off until set)
-- and whether its Workspace has the feature.
CREATE FUNCTION mesh_ops.read_network_connection_log_v1(
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
BEGIN
    SELECT * INTO v_grant FROM mesh_ops.connection_log_network_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    SELECT * INTO v_settings FROM mesh.network_connection_log AS settings
    WHERE settings.workspace_id = v_grant.workspace_id AND settings.network_id = v_grant.network_id;
    RETURN pg_catalog.jsonb_build_object(
        'feature', mesh_ops.workspace_has_feature_internal_v1(v_grant.workspace_id, 'connection_logs'),
        'settings', mesh_ops.network_connection_log_document_internal_v1(v_settings));
END;
$function$;

-- Replaces a Network's settings when p_expected_version is current (0
-- before any). Turning logging on needs the feature (55000) and a
-- credential that allows the Network (55000); the same settings change
-- nothing. A change advances the Network revision.
CREATE FUNCTION mesh_ops.replace_network_connection_log_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_expected_version BIGINT,
    p_enabled BOOLEAN, p_credential_public_id UUID, p_bucket TEXT, p_region TEXT, p_prefix TEXT,
    p_forwarded BOOLEAN, p_window_seconds INTEGER, p_expected_bucket_owner TEXT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_grant RECORD;
    v_network mesh.network%ROWTYPE;
    v_credential mesh.storage_credential%ROWTYPE;
    v_before mesh.network_connection_log%ROWTYPE;
    v_after mesh.network_connection_log%ROWTYPE;
    v_network_revision BIGINT;
BEGIN
    IF p_expected_version IS NULL OR p_expected_version < 0 OR p_enabled IS NULL OR p_forwarded IS NULL
        OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 60 AND 300
        OR p_change_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_bucket IS NULL OR p_region IS NULL
        OR NOT COALESCE(mesh_ops.connection_log_prefix_is_valid_v1(p_prefix), FALSE)
        OR (p_credential_public_id IS NULL) <> (p_bucket = '')
        OR (p_enabled AND p_credential_public_id IS NULL)
        OR (p_expected_bucket_owner IS NOT NULL AND (p_expected_bucket_owner !~ '^[0-9]{12}$'
            OR p_credential_public_id IS NULL))
        OR (p_bucket <> '' AND NOT COALESCE(mesh_ops.connection_log_bucket_is_valid_v1(p_bucket), FALSE)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'connection log settings are invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.connection_log_network_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'connection_log.manage');
    IF p_credential_public_id IS NOT NULL THEN
        SELECT * INTO v_credential FROM mesh.storage_credential AS credential
        WHERE credential.workspace_id = v_grant.workspace_id AND credential.public_id = p_credential_public_id
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown storage credential';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM mesh.storage_credential_network AS allowed
                       WHERE allowed.credential_id = v_credential.id AND allowed.network_id = v_grant.network_id) THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'the storage credential does not allow this Network';
        END IF;
        IF NOT COALESCE(mesh_ops.connection_log_region_is_valid_v1(v_credential.provider, p_region), FALSE) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'connection log region is invalid';
        END IF;
        -- Only S3 checks a bucket's owner; R2 cannot (§10.1).
        IF p_expected_bucket_owner IS NOT NULL AND v_credential.provider <> 'aws_s3' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'only an S3 destination names its bucket owner';
        END IF;
    ELSIF p_region <> '' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'connection log region needs a credential';
    END IF;
    -- The grant row is held until commit, so an operator's revoke waits
    -- for this change or this change sees the revoke (review s4a M1).
    IF p_enabled AND NOT EXISTS (SELECT 1 FROM mesh.workspace_feature AS feature
                                 WHERE feature.workspace_id = v_grant.workspace_id
                                   AND feature.feature = 'connection_logs'
                                 FOR KEY SHARE) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'the Workspace does not have connection logs';
    END IF;
    SELECT * INTO v_network FROM mesh.network AS network
    WHERE network.workspace_id = v_grant.workspace_id AND network.id = v_grant.network_id;
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_grant.workspace_id AND revision.network_id = v_grant.network_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'connection log settings scope is unavailable';
    END IF;
    SELECT * INTO v_before FROM mesh.network_connection_log AS settings
    WHERE settings.network_id = v_grant.network_id FOR UPDATE;
    IF COALESCE(v_before.version, 0) <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'connection log settings version changed';
    END IF;
    IF v_before.version IS NOT NULL AND v_before.enabled = p_enabled
        AND v_before.credential_id IS NOT DISTINCT FROM v_credential.id AND v_before.bucket = p_bucket
        AND v_before.region = p_region AND v_before.prefix = p_prefix AND v_before.forwarded = p_forwarded
        AND v_before.window_s = p_window_seconds
        AND v_before.expected_bucket_owner IS NOT DISTINCT FROM p_expected_bucket_owner THEN
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id, 'changed', FALSE,
            'feature', mesh_ops.workspace_has_feature_internal_v1(v_grant.workspace_id, 'connection_logs'),
            'settings', mesh_ops.network_connection_log_document_internal_v1(v_before));
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.network_connection_log AS settings (
        network_id, public_id, workspace_id, enabled, credential_id, bucket, region, prefix, forwarded, window_s,
        expected_bucket_owner,
        version, updated_at, updated_by_principal_id)
    VALUES (v_grant.network_id, v_network.public_id, v_grant.workspace_id, p_enabled, v_credential.id, p_bucket,
        p_region, p_prefix, p_forwarded, p_window_seconds, p_expected_bucket_owner, 1, v_now, v_grant.actor_id)
    ON CONFLICT (network_id) DO UPDATE SET
        enabled = EXCLUDED.enabled, credential_id = EXCLUDED.credential_id, bucket = EXCLUDED.bucket,
        region = EXCLUDED.region, prefix = EXCLUDED.prefix, forwarded = EXCLUDED.forwarded,
        window_s = EXCLUDED.window_s, expected_bucket_owner = EXCLUDED.expected_bucket_owner,
        version = settings.version + 1, updated_at = EXCLUDED.updated_at,
        updated_by_principal_id = EXCLUDED.updated_by_principal_id
    RETURNING * INTO v_after;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1, updated_at = GREATEST(v_now, revision.updated_at)
    WHERE revision.workspace_id = v_grant.workspace_id AND revision.network_id = v_grant.network_id
    RETURNING revision.network_revision INTO v_network_revision;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', v_network_revision,
        'changed', TRUE,
        'feature', mesh_ops.workspace_has_feature_internal_v1(v_grant.workspace_id, 'connection_logs'),
        'before', CASE WHEN v_before.version IS NULL THEN NULL
                       ELSE mesh_ops.network_connection_log_document_internal_v1(v_before) END,
        'settings', mesh_ops.network_connection_log_document_internal_v1(v_after),
        'authority', v_grant.authority);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_storage_credentials_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_storage_credentials_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.put_storage_credential_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, UUID[], UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.put_storage_credential_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, UUID[], UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.delete_storage_credential_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.delete_storage_credential_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_network_connection_log_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_connection_log_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.replace_network_connection_log_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BOOLEAN, UUID, TEXT, TEXT, TEXT, BOOLEAN, INTEGER, TEXT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.replace_network_connection_log_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BOOLEAN, UUID, TEXT, TEXT, TEXT, BOOLEAN, INTEGER, TEXT, UUID
) TO mesh_runtime;
