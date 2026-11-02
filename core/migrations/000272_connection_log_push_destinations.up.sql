-- Connection logs push destinations p1b (push destinations design §5, §6,
-- §12): a storage credential may be an Elasticsearch/OpenSearch, Datadog
-- or Kinesis destination besides S3 and R2, and a Network's settings carry
-- the fields of its credential's type.
--
-- A push credential's non-secret fields (the canonical URL, flavor and
-- custom CA; the Datadog site; the Kinesis stream) sit in config, and the
-- receiver binds them into the sealed secret (shared/flowlog
-- DestinationBinding): Go canonicalises and checks them, these CHECKs only
-- guard their shape. They change only with a new secret, so a new
-- sealed_version: a credential never points its sealed secret somewhere
-- else (S1).
--
-- The v1 functions stay as they were, so Core pods of schema 271 keep
-- working through the rollout; v2 functions return the new fields.

ALTER TABLE mesh.storage_credential DROP CONSTRAINT storage_credential_provider_check;
ALTER TABLE mesh.storage_credential ADD CONSTRAINT storage_credential_provider_check
    CHECK (provider IN ('aws_s3', 'cloudflare_r2', 'elasticsearch', 'datadog', 'kinesis'));
-- "****" when the secret's ID ends in other characters (a user name).
ALTER TABLE mesh.storage_credential DROP CONSTRAINT storage_credential_access_key_suffix_check;
ALTER TABLE mesh.storage_credential ADD CONSTRAINT storage_credential_access_key_suffix_check
    CHECK (access_key_suffix ~ '^([A-Za-z0-9]{4}|\*{4})$');

CREATE FUNCTION mesh_ops.storage_credential_config_is_valid_v1(p_provider TEXT, p_config JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    -- COALESCE: a missing key makes the expression NULL, which a CHECK
    -- would let through (review p1b H1).
    SELECT COALESCE(p_config IS NOT NULL AND pg_catalog.jsonb_typeof(p_config) = 'object' AND CASE p_provider
        WHEN 'aws_s3' THEN p_config = '{}'::JSONB
        WHEN 'cloudflare_r2' THEN p_config = '{}'::JSONB
        WHEN 'elasticsearch' THEN
            (SELECT pg_catalog.array_agg(key ORDER BY key) FROM pg_catalog.jsonb_object_keys(p_config) AS key)
                <@ ARRAY['ca_pem', 'ca_sha256', 'flavor', 'url']
            AND pg_catalog.jsonb_typeof(p_config -> 'url') = 'string'
            AND pg_catalog.octet_length(p_config ->> 'url') <= 512
            AND (p_config ->> 'url') ~ '^https://[a-z0-9.-]{1,253}:(443|9200|9243)(/[A-Za-z0-9_-]+)*$'
            AND pg_catalog.jsonb_typeof(p_config -> 'flavor') = 'string'
            AND (p_config ->> 'flavor') IN ('elasticsearch', 'opensearch')
            AND (p_config ? 'ca_pem') = (p_config ? 'ca_sha256')
            AND (NOT p_config ? 'ca_pem' OR (
                pg_catalog.jsonb_typeof(p_config -> 'ca_pem') = 'string'
                AND pg_catalog.octet_length(p_config ->> 'ca_pem') BETWEEN 1 AND 16384
                AND pg_catalog.jsonb_typeof(p_config -> 'ca_sha256') = 'string'
                AND (p_config ->> 'ca_sha256') ~ '^[0-9a-f]{64}$'))
        WHEN 'datadog' THEN
            (SELECT pg_catalog.array_agg(key) FROM pg_catalog.jsonb_object_keys(p_config) AS key) = ARRAY['site']
            AND pg_catalog.jsonb_typeof(p_config -> 'site') = 'string'
            AND (p_config ->> 'site') IN ('datadoghq.com', 'us3.datadoghq.com', 'us5.datadoghq.com', 'datadoghq.eu',
                'ap1.datadoghq.com', 'ap2.datadoghq.com')
        WHEN 'kinesis' THEN
            (SELECT pg_catalog.array_agg(key ORDER BY key) FROM pg_catalog.jsonb_object_keys(p_config) AS key)
                = ARRAY['region', 'stream_arn']
            AND pg_catalog.jsonb_typeof(p_config -> 'region') = 'string'
            AND pg_catalog.jsonb_typeof(p_config -> 'stream_arn') = 'string'
            AND (p_config ->> 'region') ~ '^(us|eu|ap|sa|ca|me|af|il|mx)-[a-z]{4,10}-[1-9]$'
            AND (p_config ->> 'stream_arn') ~ '^arn:aws:kinesis:[a-z0-9-]+:[0-9]{12}:stream/[A-Za-z0-9_.-]{1,128}$'
            AND pg_catalog.split_part(p_config ->> 'stream_arn', ':', 4) = (p_config ->> 'region')
        ELSE FALSE END, FALSE)
$function$;

ALTER TABLE mesh.storage_credential ADD COLUMN config JSONB NOT NULL DEFAULT '{}'::JSONB;
ALTER TABLE mesh.storage_credential ADD CONSTRAINT storage_credential_config_check
    CHECK (mesh_ops.storage_credential_config_is_valid_v1(provider, config));

REVOKE ALL ON FUNCTION mesh_ops.storage_credential_config_is_valid_v1(TEXT, JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Elasticsearch/OpenSearch data stream or index names (shared/flowlog
-- ValidTarget).
CREATE FUNCTION mesh_ops.connection_log_target_is_valid_v1(p_target TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_target IS NOT NULL AND p_target ~ '^[a-z0-9][a-z0-9._-]{0,254}$'
$function$;

-- A Datadog tag or service: lower case, starting with a letter, no commas.
CREATE FUNCTION mesh_ops.connection_log_datadog_tag_is_valid_v1(p_tag TEXT, p_limit INTEGER)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_tag IS NOT NULL AND pg_catalog.octet_length(p_tag) <= p_limit AND p_tag ~ '^[a-z][a-z0-9_.:/-]*$'
$function$;

CREATE FUNCTION mesh_ops.connection_log_datadog_tags_are_valid_v1(p_tags TEXT[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    -- One dimension, 1 to 20 tags: no tags is NULL, never an empty array.
    SELECT p_tags IS NOT NULL AND pg_catalog.array_ndims(p_tags) = 1
        AND pg_catalog.array_length(p_tags, 1) BETWEEN 1 AND 20
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(p_tags) AS tag
                        WHERE NOT COALESCE(mesh_ops.connection_log_datadog_tag_is_valid_v1(tag, 200), FALSE))
$function$;

REVOKE ALL ON FUNCTION mesh_ops.connection_log_target_is_valid_v1(TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.connection_log_datadog_tag_is_valid_v1(TEXT, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.connection_log_datadog_tags_are_valid_v1(TEXT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

ALTER TABLE mesh.network_connection_log
    ADD COLUMN target TEXT CHECK (target IS NULL OR mesh_ops.connection_log_target_is_valid_v1(target)),
    ADD COLUMN target_kind TEXT CHECK (target_kind IN ('data_stream', 'index')),
    ADD COLUMN service TEXT CHECK (service IS NULL OR mesh_ops.connection_log_datadog_tag_is_valid_v1(service, 100)),
    ADD COLUMN tags TEXT[] CHECK (tags IS NULL OR mesh_ops.connection_log_datadog_tags_are_valid_v1(tags)),
    ADD COLUMN record_format TEXT CHECK (record_format IN ('ndjson_batch', 'json_line')),
    ADD CONSTRAINT network_connection_log_target_pair_check CHECK ((target IS NULL) = (target_kind IS NULL)),
    ADD CONSTRAINT network_connection_log_datadog_check CHECK (tags IS NULL OR service IS NOT NULL),
    -- A push field goes only with a credential and no bucket, region,
    -- prefix or bucket owner, and of one type only: a schema 271 pod's v1
    -- write that would leave them beside an S3 bucket or no credential
    -- fails instead (review p1b H2).
    ADD CONSTRAINT network_connection_log_push_fields_check CHECK (
        (target IS NULL AND service IS NULL AND tags IS NULL AND record_format IS NULL)
        OR (credential_id IS NOT NULL AND bucket = '' AND region = '' AND prefix = ''
            AND expected_bucket_owner IS NULL)),
    ADD CONSTRAINT network_connection_log_one_type_check CHECK (pg_catalog.num_nonnulls(target, service, record_format) <= 1);
-- An enabled destination names a bucket and region (S3, R2) or the field
-- its type requires: a target, a service or a record format.
ALTER TABLE mesh.network_connection_log DROP CONSTRAINT network_connection_log_destination_check;
ALTER TABLE mesh.network_connection_log ADD CONSTRAINT network_connection_log_destination_check CHECK (
    NOT enabled OR (credential_id IS NOT NULL AND ((bucket <> '' AND region <> '')
        OR target IS NOT NULL OR service IS NOT NULL OR record_format IS NOT NULL)));

-- A credential as the API shows it: v1's members and its config without
-- the CA itself (its SHA-256 says which).
CREATE FUNCTION mesh_ops.storage_credential_document_internal_v2(p_credential mesh.storage_credential)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.storage_credential_document_internal_v1(p_credential)
        || pg_catalog.jsonb_build_object('config', p_credential.config - 'ca_pem')
$function$;
REVOKE ALL ON FUNCTION mesh_ops.storage_credential_document_internal_v2(mesh.storage_credential)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.list_storage_credentials_v2(
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
            SELECT pg_catalog.jsonb_agg(mesh_ops.storage_credential_document_internal_v2(credential)
                ORDER BY credential.name)
            FROM mesh.storage_credential AS credential
            WHERE credential.workspace_id = v_grant.workspace_id), '[]'::JSONB));
END;
$function$;

-- As put_storage_credential_v1, with p_config: a push credential's
-- non-secret fields, which change only with a new secret (S1); NULL keeps
-- them (a rename or a change of Networks, which never sees the CA back).
-- A credential keeps its provider.
CREATE FUNCTION mesh_ops.put_storage_credential_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_credential_public_id UUID, p_expected_version BIGINT,
    p_name TEXT, p_provider TEXT, p_account_id TEXT, p_config JSONB, p_access_key_suffix TEXT, p_sealed BYTEA,
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
        OR p_provider IS NULL OR p_provider NOT IN ('aws_s3', 'cloudflare_r2', 'elasticsearch', 'datadog', 'kinesis')
        OR (p_provider = 'cloudflare_r2') <> (p_account_id IS NOT NULL)
        OR (p_config IS NULL AND (p_expected_version = 0 OR p_sealed IS NOT NULL))
        OR (p_config IS NOT NULL AND NOT COALESCE(mesh_ops.storage_credential_config_is_valid_v1(p_provider, p_config),
            FALSE))
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
    IF v_before.id IS NOT NULL AND p_config IS NOT NULL AND v_before.config IS DISTINCT FROM p_config
        AND p_sealed IS NULL THEN
        -- The sealed secret is bound to the config: a new one needs it
        -- sealed again (push destinations design §5 S1).
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'a storage credential changes its endpoint only with its secret';
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
            public_id, workspace_id, name, provider, account_id, config, access_key_suffix, sealed, sealing_key_id,
            sealed_version, version, created_at, created_by_principal_id, updated_at, updated_by_principal_id)
        VALUES (p_credential_public_id, v_grant.workspace_id, p_name, p_provider, p_account_id, p_config,
            p_access_key_suffix, p_sealed, p_sealing_key_id, 1, 1, v_now, v_grant.actor_id, v_now, v_grant.actor_id)
        RETURNING * INTO v_after;
    ELSE
        UPDATE mesh.storage_credential AS credential SET
            name = p_name,
            config = COALESCE(p_config, credential.config),
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
                       ELSE mesh_ops.storage_credential_document_internal_v2(v_before) END,
        'credential', mesh_ops.storage_credential_document_internal_v2(v_after),
        'authority', v_grant.authority);
END;
$function$;

CREATE FUNCTION mesh_ops.network_connection_log_document_internal_v2(p_settings mesh.network_connection_log)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.network_connection_log_document_internal_v1(p_settings) || pg_catalog.jsonb_build_object(
        'target', p_settings.target,
        'target_kind', p_settings.target_kind,
        'service', p_settings.service,
        'tags', COALESCE(pg_catalog.to_jsonb(p_settings.tags), 'null'::JSONB),
        'record_format', p_settings.record_format)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.network_connection_log_document_internal_v2(mesh.network_connection_log)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- As read_network_connection_log_v1 (schema 271), with the v2 settings.
CREATE FUNCTION mesh_ops.read_network_connection_log_v2(
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
        'settings', mesh_ops.network_connection_log_document_internal_v2(v_settings),
        'status', mesh_ops.network_connection_log_status_internal_v1(v_grant.workspace_id, v_grant.network_id, 1)
            || pg_catalog.jsonb_build_object(
                'sealed_version', v_credential.sealed_version,
                'sealing_key_id', v_credential.sealing_key_id));
END;
$function$;

-- As replace_network_connection_log_v1, with the fields of the
-- credential's type: S3/R2 a bucket and region; Elasticsearch a target and
-- its kind; Datadog a service and tags; Kinesis a record format. A field of
-- another type is refused (22023), as is a bucket, region, prefix or bucket
-- owner on a push destination.
CREATE FUNCTION mesh_ops.replace_network_connection_log_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_expected_version BIGINT,
    p_enabled BOOLEAN, p_credential_public_id UUID, p_bucket TEXT, p_region TEXT, p_prefix TEXT,
    p_forwarded BOOLEAN, p_window_seconds INTEGER, p_expected_bucket_owner TEXT,
    p_target TEXT, p_target_kind TEXT, p_service TEXT, p_tags TEXT[], p_record_format TEXT,
    p_change_public_id UUID
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
    v_storage BOOLEAN;
BEGIN
    IF p_expected_version IS NULL OR p_expected_version < 0 OR p_enabled IS NULL OR p_forwarded IS NULL
        OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 60 AND 300
        OR p_change_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_bucket IS NULL OR p_region IS NULL
        OR NOT COALESCE(mesh_ops.connection_log_prefix_is_valid_v1(p_prefix), FALSE)
        OR (p_enabled AND p_credential_public_id IS NULL)
        OR (p_expected_bucket_owner IS NOT NULL AND (p_expected_bucket_owner !~ '^[0-9]{12}$'
            OR p_credential_public_id IS NULL))
        OR (p_bucket <> '' AND NOT COALESCE(mesh_ops.connection_log_bucket_is_valid_v1(p_bucket), FALSE))
        OR (p_target IS NOT NULL AND NOT mesh_ops.connection_log_target_is_valid_v1(p_target))
        OR (p_target IS NULL) <> (p_target_kind IS NULL)
        OR (p_target_kind IS NOT NULL AND p_target_kind NOT IN ('data_stream', 'index'))
        OR (p_service IS NOT NULL AND NOT mesh_ops.connection_log_datadog_tag_is_valid_v1(p_service, 100))
        OR (p_tags IS NOT NULL AND (p_service IS NULL OR NOT mesh_ops.connection_log_datadog_tags_are_valid_v1(p_tags)))
        OR (p_record_format IS NOT NULL AND p_record_format NOT IN ('ndjson_batch', 'json_line'))
        OR (p_credential_public_id IS NULL AND (p_bucket <> '' OR p_region <> '' OR p_target IS NOT NULL
            OR p_service IS NOT NULL OR p_record_format IS NOT NULL)) THEN
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
        v_storage := v_credential.provider IN ('aws_s3', 'cloudflare_r2');
        IF (v_storage AND (p_bucket = '' OR NOT COALESCE(
                mesh_ops.connection_log_region_is_valid_v1(v_credential.provider, p_region), FALSE)
            OR p_target IS NOT NULL OR p_service IS NOT NULL OR p_record_format IS NOT NULL))
            OR (NOT v_storage AND (p_bucket <> '' OR p_region <> '' OR p_prefix <> ''
                OR p_expected_bucket_owner IS NOT NULL))
            OR (v_credential.provider = 'elasticsearch'
                AND (p_target IS NULL OR p_service IS NOT NULL OR p_record_format IS NOT NULL))
            OR (v_credential.provider = 'datadog'
                AND (p_service IS NULL OR p_target IS NOT NULL OR p_record_format IS NOT NULL))
            OR (v_credential.provider = 'kinesis'
                AND (p_record_format IS NULL OR p_target IS NOT NULL OR p_service IS NOT NULL)) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'connection log destination does not fit its credential';
        END IF;
        -- Only S3 checks a bucket's owner; R2 cannot (§10.1).
        IF p_expected_bucket_owner IS NOT NULL AND v_credential.provider <> 'aws_s3' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'only an S3 destination names its bucket owner';
        END IF;
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
        AND v_before.expected_bucket_owner IS NOT DISTINCT FROM p_expected_bucket_owner
        AND v_before.target IS NOT DISTINCT FROM p_target AND v_before.target_kind IS NOT DISTINCT FROM p_target_kind
        AND v_before.service IS NOT DISTINCT FROM p_service AND v_before.tags IS NOT DISTINCT FROM p_tags
        AND v_before.record_format IS NOT DISTINCT FROM p_record_format THEN
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id, 'changed', FALSE,
            'feature', mesh_ops.workspace_has_feature_internal_v1(v_grant.workspace_id, 'connection_logs'),
            'settings', mesh_ops.network_connection_log_document_internal_v2(v_before));
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.network_connection_log AS settings (
        network_id, public_id, workspace_id, enabled, credential_id, bucket, region, prefix, forwarded, window_s,
        expected_bucket_owner, target, target_kind, service, tags, record_format,
        version, updated_at, updated_by_principal_id)
    VALUES (v_grant.network_id, v_network.public_id, v_grant.workspace_id, p_enabled, v_credential.id, p_bucket,
        p_region, p_prefix, p_forwarded, p_window_seconds, p_expected_bucket_owner, p_target, p_target_kind,
        p_service, p_tags, p_record_format, 1, v_now, v_grant.actor_id)
    ON CONFLICT (network_id) DO UPDATE SET
        enabled = EXCLUDED.enabled, credential_id = EXCLUDED.credential_id, bucket = EXCLUDED.bucket,
        region = EXCLUDED.region, prefix = EXCLUDED.prefix, forwarded = EXCLUDED.forwarded,
        window_s = EXCLUDED.window_s, expected_bucket_owner = EXCLUDED.expected_bucket_owner,
        target = EXCLUDED.target, target_kind = EXCLUDED.target_kind, service = EXCLUDED.service,
        tags = EXCLUDED.tags, record_format = EXCLUDED.record_format,
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
                       ELSE mesh_ops.network_connection_log_document_internal_v2(v_before) END,
        'settings', mesh_ops.network_connection_log_document_internal_v2(v_after),
        'authority', v_grant.authority);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_storage_credentials_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_storage_credentials_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.put_storage_credential_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    TEXT, TEXT, TEXT, JSONB, TEXT, BYTEA, TEXT, UUID[], UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.put_storage_credential_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    TEXT, TEXT, TEXT, JSONB, TEXT, BYTEA, TEXT, UUID[], UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_network_connection_log_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_connection_log_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.replace_network_connection_log_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BOOLEAN, UUID, TEXT, TEXT, TEXT, BOOLEAN, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.replace_network_connection_log_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BOOLEAN, UUID, TEXT, TEXT, TEXT, BOOLEAN, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT, UUID
) TO mesh_runtime;
