-- Connection logs push destinations p1c (push destinations design §6,
-- §12): what the receiver needs to write to a push destination, which
-- destination types each receiver writes to, and the ticket gate by type.
--
-- A receiver reports its destination types (none: S3 and R2, a receiver
-- older than push destinations). Core signs a Network's tickets only while
-- every fresh receiver that takes the protocol writes to the Network's
-- type: a node then never posts batches a receiver would have to refuse.
-- Saving a push destination is not gated; the Console status says when no
-- receiver writes to it yet, so the destination can be set before the
-- receivers are upgraded.
--
-- The v1 functions stay for Core pods of schema 272 through the rollout;
-- operator step 273 hands the new ones to their owners.

ALTER TABLE mesh.connection_log_receiver ADD COLUMN destination_types TEXT[] NOT NULL
    DEFAULT ARRAY['aws_s3', 'cloudflare_r2']::TEXT[]
    CHECK (COALESCE(pg_catalog.array_ndims(destination_types), 1) = 1
        AND pg_catalog.cardinality(destination_types) BETWEEN 0 AND 8
        AND destination_types <@ ARRAY['aws_s3', 'cloudflare_r2', 'elasticsearch', 'datadog', 'kinesis']::TEXT[]);

ALTER TABLE mesh.network_connection_log_status ADD COLUMN rejected_24h BIGINT NOT NULL DEFAULT 0
    CHECK (rejected_24h BETWEEN 0 AND 1000000000000);
ALTER TABLE mesh.network_connection_log_status DROP CONSTRAINT network_connection_log_status_delivery_error_check;
ALTER TABLE mesh.network_connection_log_status ADD CONSTRAINT network_connection_log_status_delivery_error_check
    CHECK (delivery_error IN ('unspecified', 'none', 'access_denied', 'no_such_bucket', 'wrong_owner',
        'wrong_region', 'unreachable', 'throttled', 'other', 'event_rejected'));

-- As flowlog_report_status_v1 (schema 270), with the receiver's
-- destination types and each entry's rejected count.
CREATE FUNCTION mesh_ops.flowlog_report_status_v2(p_instance_id BYTEA, p_accepted_versions INTEGER[],
    p_noise_fingerprints BYTEA[], p_sealing_key_ids TEXT[], p_destination_types TEXT[], p_reported_at TIMESTAMPTZ,
    p_entries JSONB)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_fresh INTEGER;
    v_total INTEGER;
    v_matched INTEGER;
    v_written INTEGER;
BEGIN
    IF p_instance_id IS NULL OR p_reported_at IS NULL OR p_entries IS NULL OR p_destination_types IS NULL
        OR pg_catalog.jsonb_typeof(p_entries) <> 'array' OR pg_catalog.jsonb_array_length(p_entries) > 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid connection log receiver report';
    END IF;
    IF p_reported_at > v_now + INTERVAL '2 minutes' THEN
        RETURN pg_catalog.jsonb_build_object('result', 'stale_clock');
    END IF;
    DELETE FROM mesh.connection_log_receiver AS receiver
    WHERE receiver.instance_id IN (SELECT old.instance_id FROM mesh.connection_log_receiver AS old
                                   WHERE old.received_at < v_now - INTERVAL '24 hours' LIMIT 100);
    IF NOT EXISTS (SELECT 1 FROM mesh.connection_log_receiver AS receiver
                   WHERE receiver.instance_id = p_instance_id) THEN
        PERFORM pg_catalog.pg_advisory_xact_lock(7266270270);
        SELECT pg_catalog.count(*) FILTER (WHERE receiver.received_at >= v_now - INTERVAL '10 minutes'),
            pg_catalog.count(*)
        INTO v_fresh, v_total
        FROM mesh.connection_log_receiver AS receiver;
        IF v_fresh >= 64 THEN
            RETURN pg_catalog.jsonb_build_object('result', 'too_many_instances');
        END IF;
        IF v_total >= 1024 THEN
            DELETE FROM mesh.connection_log_receiver AS receiver
            WHERE receiver.instance_id IN (SELECT old.instance_id FROM mesh.connection_log_receiver AS old
                                           WHERE old.received_at < v_now - INTERVAL '10 minutes'
                                           ORDER BY old.received_at LIMIT v_total - 1023);
        END IF;
    END IF;
    INSERT INTO mesh.connection_log_receiver AS receiver (instance_id, accepted_versions, noise_fingerprints,
        sealing_key_ids, destination_types, reported_at, received_at)
    VALUES (p_instance_id, p_accepted_versions, p_noise_fingerprints, p_sealing_key_ids, p_destination_types,
        p_reported_at, v_now)
    ON CONFLICT (instance_id) DO UPDATE SET accepted_versions = excluded.accepted_versions,
        noise_fingerprints = excluded.noise_fingerprints, sealing_key_ids = excluded.sealing_key_ids,
        destination_types = excluded.destination_types,
        reported_at = excluded.reported_at, received_at = excluded.received_at;
    WITH entry AS (
        SELECT *
        FROM pg_catalog.jsonb_to_recordset(p_entries) AS listed(workspace UUID, network UUID, tested_etag TEXT,
            test_result TEXT, tested_at TIMESTAMPTZ, delivered_at TIMESTAMPTZ, delivery_error TEXT, lost BIGINT,
            overflow BIGINT, rejected BIGINT)
    ), matched AS (
        SELECT settings.workspace_id, settings.network_id, entry.*
        FROM entry
        JOIN mesh.workspace AS workspace ON workspace.public_id = entry.workspace
        JOIN mesh.network_connection_log AS settings
          ON settings.public_id = entry.network AND settings.workspace_id = workspace.id
    ), written AS (
        INSERT INTO mesh.network_connection_log_status AS status (network_id, workspace_id, tested_etag,
            test_result, tested_at, last_delivered_at, delivery_error, lost_24h, overflow_24h, rejected_24h,
            reported_at, received_at)
        SELECT matched.network_id, matched.workspace_id, pg_catalog.decode(matched.tested_etag, 'hex'),
            matched.test_result,
            -- Times outside the day before the report are not believed (C69).
            CASE WHEN matched.tested_at BETWEEN p_reported_at - INTERVAL '24 hours' AND p_reported_at
                 THEN matched.tested_at END,
            CASE WHEN matched.delivered_at BETWEEN p_reported_at - INTERVAL '24 hours' AND p_reported_at
                 THEN matched.delivered_at END,
            matched.delivery_error, LEAST(GREATEST(matched.lost, 0), 1000000000000),
            LEAST(GREATEST(matched.overflow, 0), 1000000000000),
            LEAST(GREATEST(COALESCE(matched.rejected, 0), 0), 1000000000000), p_reported_at, v_now
        FROM matched
        ORDER BY matched.network_id
        ON CONFLICT (network_id) DO UPDATE SET tested_etag = excluded.tested_etag,
            test_result = excluded.test_result, tested_at = excluded.tested_at,
            last_delivered_at = excluded.last_delivered_at, delivery_error = excluded.delivery_error,
            lost_24h = excluded.lost_24h, overflow_24h = excluded.overflow_24h,
            rejected_24h = excluded.rejected_24h,
            reported_at = excluded.reported_at, received_at = excluded.received_at
        WHERE (excluded.reported_at, excluded.received_at) > (status.reported_at, status.received_at)
          AND (status.received_at <= v_now - INTERVAL '55 seconds'
               OR excluded.tested_etag IS DISTINCT FROM status.tested_etag
               OR excluded.test_result <> status.test_result)
        RETURNING 1
    )
    SELECT (SELECT pg_catalog.count(*) FROM matched), (SELECT pg_catalog.count(*) FROM written)
    INTO v_matched, v_written;
    RETURN pg_catalog.jsonb_build_object('result', 'ok', 'written', v_written,
        'throttled', v_matched - v_written, 'dropped', pg_catalog.jsonb_array_length(p_entries) - v_matched);
END;
$function$;

-- As flowlog_receiver_gate_v1, with destination_types: the types every
-- fresh receiver that accepts p_version and holds the Noise key of
-- p_fingerprint writes to (at most 64 such receivers, schema 270).
CREATE FUNCTION mesh_ops.flowlog_receiver_gate_v2(p_version INTEGER, p_fingerprint BYTEA)
RETURNS TABLE (fresh INTEGER, accepting INTEGER, newest TIMESTAMPTZ, checked_at TIMESTAMPTZ,
    destination_types TEXT[])
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    WITH accepting AS (
        SELECT receiver.destination_types FROM mesh.connection_log_receiver AS receiver
        WHERE receiver.received_at >= pg_catalog.transaction_timestamp() - INTERVAL '10 minutes'
          AND p_version = ANY (receiver.accepted_versions) AND p_fingerprint = ANY (receiver.noise_fingerprints)
    )
    SELECT pg_catalog.count(*) FILTER (WHERE receiver.received_at >= pg_catalog.transaction_timestamp()
                                                                  - INTERVAL '10 minutes')::INTEGER,
        (SELECT pg_catalog.count(*) FROM accepting)::INTEGER,
        pg_catalog.max(receiver.received_at), pg_catalog.transaction_timestamp(),
        COALESCE((SELECT pg_catalog.array_agg(kind ORDER BY kind)
                  FROM pg_catalog.unnest(ARRAY['aws_s3', 'cloudflare_r2', 'elasticsearch', 'datadog',
                      'kinesis']::TEXT[]) AS kind
                  WHERE EXISTS (SELECT 1 FROM accepting)
                    AND NOT EXISTS (SELECT 1 FROM accepting WHERE kind <> ALL (accepting.destination_types))),
                 ARRAY[]::TEXT[])
    FROM mesh.connection_log_receiver AS receiver
$function$;

-- As flowlog_destination_v1 (schema 268), with the push destination: the
-- credential's config, CA PEM included (the receiver binds it to open the
-- secret), and the settings' fields of its type.
CREATE FUNCTION mesh_ops.flowlog_destination_v2(p_workspace_public_id UUID, p_network_public_id UUID)
RETURNS TABLE (
    reason TEXT, forwarded BOOLEAN, window_s INTEGER, bucket TEXT, region TEXT, prefix TEXT,
    expected_bucket_owner TEXT, settings_version BIGINT, credential_public_id UUID, provider TEXT, account_id TEXT,
    sealed BYTEA, sealed_version BIGINT, sealing_key_id TEXT, config JSONB, target TEXT, target_kind TEXT,
    service TEXT, tags TEXT[], record_format TEXT
)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    -- A deleted Network or Workspace carries none of its destination.
    SELECT found.*, CASE WHEN found.credential_public_id IS NULL THEN NULL ELSE credential.config END,
        CASE WHEN found.credential_public_id IS NULL THEN NULL ELSE settings.target END,
        CASE WHEN found.credential_public_id IS NULL THEN NULL ELSE settings.target_kind END,
        CASE WHEN found.credential_public_id IS NULL THEN NULL ELSE settings.service END,
        CASE WHEN found.credential_public_id IS NULL THEN NULL ELSE settings.tags END,
        CASE WHEN found.credential_public_id IS NULL THEN NULL ELSE settings.record_format END
    FROM mesh_ops.flowlog_destination_v1(p_workspace_public_id, p_network_public_id) AS found
    JOIN mesh.workspace AS workspace ON workspace.public_id = p_workspace_public_id
    JOIN mesh.network_connection_log AS settings
      ON settings.workspace_id = workspace.id AND settings.public_id = p_network_public_id
    JOIN mesh.storage_credential AS credential
      ON credential.workspace_id = settings.workspace_id AND credential.id = settings.credential_id
$function$;

-- A map stream's connection log setting (schema 267) and its credential's
-- type, so the ticket gate holds tickets a receiver could not write.
CREATE FUNCTION mesh_ops.read_connection_log_ticket_v2()
RETURNS TABLE (enabled BOOLEAN, forwarded BOOLEAN, window_s INTEGER, provider TEXT)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT settings.enabled AND mesh_ops.workspace_has_feature_internal_v1(settings.workspace_id, 'connection_logs'),
        settings.forwarded, settings.window_s, credential.provider
    FROM mesh.network_connection_log AS settings
    LEFT JOIN mesh.storage_credential AS credential
      ON credential.workspace_id = settings.workspace_id AND credential.id = settings.credential_id
    WHERE settings.workspace_id = mesh_ops.current_workspace_id()
      AND settings.network_id = mesh_ops.current_network_id()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_connection_log_ticket_v2()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_connection_log_ticket_v2() TO mesh_runtime;

-- As network_connection_log_status_internal_v1 (schema 271), with the
-- rejected count and whether every fresh receiver taking the protocol
-- writes to p_provider. Its owner, the status writer, has no USAGE on
-- mesh_ops, so it repeats v1's reads rather than calling it.
CREATE FUNCTION mesh_ops.network_connection_log_status_internal_v2(
    p_workspace_id BIGINT, p_network_id BIGINT, p_protocol_version INTEGER, p_provider TEXT
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
        'receiver_at', (SELECT pg_catalog.max(receiver.received_at)
                        FROM mesh.connection_log_receiver AS receiver
                        WHERE p_protocol_version = ANY (receiver.accepted_versions)),
        'rejected_24h', (SELECT status.rejected_24h FROM mesh.network_connection_log_status AS status
                         WHERE status.workspace_id = p_workspace_id AND status.network_id = p_network_id),
        -- No fresh receiver lacks the type; whether any is fresh at all is
        -- receiver_at's to say. A soft signal: by protocol version, not
        -- by the Noise key the ticket gate also checks (review p1c L1, L3).
        'receiver_writes_type', p_provider IS NULL OR NOT EXISTS (
            SELECT 1 FROM mesh.connection_log_receiver AS receiver
            WHERE receiver.received_at >= pg_catalog.transaction_timestamp() - INTERVAL '10 minutes'
              AND p_protocol_version = ANY (receiver.accepted_versions)
              AND p_provider <> ALL (receiver.destination_types)))
$function$;

-- The settings read of schema 272 (v2), with the type-aware status: a new
-- version, since schema 272 pods decode v2's status strictly
-- (review p1c H1).
CREATE FUNCTION mesh_ops.read_network_connection_log_v3(
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
        'status', mesh_ops.network_connection_log_status_internal_v2(v_grant.workspace_id, v_grant.network_id, 1,
                v_credential.provider)
            || pg_catalog.jsonb_build_object(
                'sealed_version', v_credential.sealed_version,
                'sealing_key_id', v_credential.sealing_key_id));
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_network_connection_log_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_connection_log_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.flowlog_report_status_v2(BYTEA, INTEGER[], BYTEA[], TEXT[], TEXT[], TIMESTAMPTZ, JSONB),
    mesh_ops.flowlog_receiver_gate_v2(INTEGER, BYTEA), mesh_ops.flowlog_destination_v2(UUID, UUID),
    mesh_ops.network_connection_log_status_internal_v2(BIGINT, BIGINT, INTEGER, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
