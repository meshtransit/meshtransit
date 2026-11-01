-- The connection log receiver's reports (connection logs design §16e,
-- C67–C72, s4c3): which receiver instances run which protocol versions and
-- Noise keys, and each Network's test write and delivery. Operational data,
-- not authority: nothing here moves a Network revision or captures an audit
-- mutation (1b audits status writes). The writer is mesh_flowlog_status_writer
-- (operator steps 270); the ticket gate and later the Console read through
-- mesh_flowlog_reader.

CREATE TABLE mesh.connection_log_receiver (
    instance_id BYTEA PRIMARY KEY CHECK (octet_length(instance_id) = 16),
    accepted_versions INTEGER[] NOT NULL
        CHECK (cardinality(accepted_versions) BETWEEN 1 AND 8 AND 0 < ALL (accepted_versions)),
    noise_fingerprints BYTEA[] NOT NULL CHECK (cardinality(noise_fingerprints) BETWEEN 1 AND 4),
    sealing_key_ids TEXT[] NOT NULL CHECK (cardinality(sealing_key_ids) <= 8),
    reported_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX connection_log_receiver_received_idx ON mesh.connection_log_receiver (received_at);
ALTER TABLE mesh.connection_log_receiver ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.connection_log_receiver FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_log_receiver_migrator_policy ON mesh.connection_log_receiver
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.connection_log_receiver
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh.network_connection_log_status (
    network_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    tested_etag BYTEA CHECK (tested_etag IS NULL OR octet_length(tested_etag) = 16),
    test_result TEXT NOT NULL CHECK (test_result IN ('unspecified', 'ok', 'access_denied', 'no_such_bucket',
        'wrong_owner', 'wrong_region', 'unreachable', 'credential_unopenable', 'other')),
    tested_at TIMESTAMPTZ,
    last_delivered_at TIMESTAMPTZ,
    delivery_error TEXT NOT NULL CHECK (delivery_error IN ('unspecified', 'none', 'access_denied',
        'no_such_bucket', 'wrong_owner', 'wrong_region', 'unreachable', 'throttled', 'other')),
    lost_24h BIGINT NOT NULL CHECK (lost_24h BETWEEN 0 AND 1000000000000),
    overflow_24h BIGINT NOT NULL CHECK (overflow_24h BETWEEN 0 AND 1000000000000),
    reported_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT network_connection_log_status_settings_fk FOREIGN KEY (network_id)
        REFERENCES mesh.network_connection_log (network_id) ON DELETE CASCADE
);
CREATE INDEX network_connection_log_status_workspace_idx ON mesh.network_connection_log_status (workspace_id, network_id);
ALTER TABLE mesh.network_connection_log_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_connection_log_status FORCE ROW LEVEL SECURITY;
CREATE POLICY network_connection_log_status_migrator_policy ON mesh.network_connection_log_status
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_connection_log_status
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The writer: receiver rows, and status rows of Networks with a settings row
-- (C69: a test write comes before the Network logs).
GRANT USAGE ON SCHEMA mesh TO mesh_flowlog_status_writer;
CREATE POLICY connection_log_receiver_status_write ON mesh.connection_log_receiver
    FOR ALL TO mesh_flowlog_status_writer USING (TRUE) WITH CHECK (TRUE);
GRANT SELECT, INSERT, UPDATE, DELETE ON mesh.connection_log_receiver TO mesh_flowlog_status_writer;
CREATE POLICY network_connection_log_status_write ON mesh.network_connection_log_status
    FOR ALL TO mesh_flowlog_status_writer
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged))
    WITH CHECK ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                               FROM mesh.network_connection_log AS logged));
GRANT SELECT, INSERT, UPDATE ON mesh.network_connection_log_status TO mesh_flowlog_status_writer;
-- Only the columns that match a report's IDs (review s4c3 L9).
CREATE POLICY network_connection_log_status_writer_read ON mesh.network_connection_log
    FOR SELECT TO mesh_flowlog_status_writer USING (TRUE);
GRANT SELECT (network_id, public_id, workspace_id) ON mesh.network_connection_log TO mesh_flowlog_status_writer;
CREATE POLICY workspace_status_writer_read ON mesh.workspace
    FOR SELECT TO mesh_flowlog_status_writer
    USING (id IN (SELECT logged.workspace_id FROM mesh.network_connection_log AS logged));
GRANT SELECT (id, public_id) ON mesh.workspace TO mesh_flowlog_status_writer;

-- The reader: every receiver row (no tenant data in it), and status rows of
-- the Networks it already sees.
CREATE POLICY connection_log_receiver_flowlog_read ON mesh.connection_log_receiver
    FOR SELECT TO mesh_flowlog_reader USING (TRUE);
GRANT SELECT ON mesh.connection_log_receiver TO mesh_flowlog_reader;
CREATE POLICY network_connection_log_status_flowlog_read ON mesh.network_connection_log_status
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.network_connection_log_status TO mesh_flowlog_reader;

-- One report of a receiver instance (C67–C69): its versions, keys and
-- sealing key IDs, and the Networks' status entries the API validated and
-- sorted by Network. Answers 'ok' with counts, 'stale_clock' when the
-- report's time is more than 2 minutes ahead of the database's (nothing is
-- written), or 'too_many_instances' when this instance is new and 64 others
-- reported in the last 10 minutes. Instances restart with new IDs, so only
-- fresh ones count (review s4c3 H2); past 1 024 rows a new instance evicts
-- the oldest stale one, and rows age out after 24 hours. New instances
-- take a lock, so replicas never overshoot the bound together (L8). An entry
-- is written only for a (Workspace, Network) pair with a settings row, only
-- when it is newer, and at most once every 55 seconds unless its test write
-- changed (receivers report every minute; M6).
CREATE FUNCTION mesh_ops.flowlog_report_status_v1(p_instance_id BYTEA, p_accepted_versions INTEGER[],
    p_noise_fingerprints BYTEA[], p_sealing_key_ids TEXT[], p_reported_at TIMESTAMPTZ, p_entries JSONB)
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
    IF p_instance_id IS NULL OR p_reported_at IS NULL OR p_entries IS NULL
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
        sealing_key_ids, reported_at, received_at)
    VALUES (p_instance_id, p_accepted_versions, p_noise_fingerprints, p_sealing_key_ids, p_reported_at, v_now)
    ON CONFLICT (instance_id) DO UPDATE SET accepted_versions = excluded.accepted_versions,
        noise_fingerprints = excluded.noise_fingerprints, sealing_key_ids = excluded.sealing_key_ids,
        reported_at = excluded.reported_at, received_at = excluded.received_at;
    WITH entry AS (
        SELECT *
        FROM pg_catalog.jsonb_to_recordset(p_entries) AS listed(workspace UUID, network UUID, tested_etag TEXT,
            test_result TEXT, tested_at TIMESTAMPTZ, delivered_at TIMESTAMPTZ, delivery_error TEXT, lost BIGINT,
            overflow BIGINT)
    ), matched AS (
        SELECT settings.workspace_id, settings.network_id, entry.*
        FROM entry
        JOIN mesh.workspace AS workspace ON workspace.public_id = entry.workspace
        JOIN mesh.network_connection_log AS settings
          ON settings.public_id = entry.network AND settings.workspace_id = workspace.id
    ), written AS (
        INSERT INTO mesh.network_connection_log_status AS status (network_id, workspace_id, tested_etag,
            test_result, tested_at, last_delivered_at, delivery_error, lost_24h, overflow_24h, reported_at,
            received_at)
        SELECT matched.network_id, matched.workspace_id, pg_catalog.decode(matched.tested_etag, 'hex'),
            matched.test_result,
            -- Times outside the day before the report are not believed (C69).
            CASE WHEN matched.tested_at BETWEEN p_reported_at - INTERVAL '24 hours' AND p_reported_at
                 THEN matched.tested_at END,
            CASE WHEN matched.delivered_at BETWEEN p_reported_at - INTERVAL '24 hours' AND p_reported_at
                 THEN matched.delivered_at END,
            matched.delivery_error, LEAST(GREATEST(matched.lost, 0), 1000000000000),
            LEAST(GREATEST(matched.overflow, 0), 1000000000000), p_reported_at, v_now
        FROM matched
        ORDER BY matched.network_id
        ON CONFLICT (network_id) DO UPDATE SET tested_etag = excluded.tested_etag,
            test_result = excluded.test_result, tested_at = excluded.tested_at,
            last_delivered_at = excluded.last_delivered_at, delivery_error = excluded.delivery_error,
            lost_24h = excluded.lost_24h, overflow_24h = excluded.overflow_24h,
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

-- The ticket gate (C71): receiver instances that reported in the last 10
-- minutes on the database's clock, those of them that accept p_version and
-- hold the Noise key of p_fingerprint, and the newest report.
CREATE FUNCTION mesh_ops.flowlog_receiver_gate_v1(p_version INTEGER, p_fingerprint BYTEA)
RETURNS TABLE (fresh INTEGER, accepting INTEGER, newest TIMESTAMPTZ, checked_at TIMESTAMPTZ)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*) FILTER (WHERE receiver.received_at >= pg_catalog.transaction_timestamp()
                                                                  - INTERVAL '10 minutes')::INTEGER,
        pg_catalog.count(*) FILTER (WHERE receiver.received_at >= pg_catalog.transaction_timestamp()
                                                                - INTERVAL '10 minutes'
                                      AND p_version = ANY (receiver.accepted_versions)
                                      AND p_fingerprint = ANY (receiver.noise_fingerprints))::INTEGER,
        pg_catalog.max(receiver.received_at), pg_catalog.transaction_timestamp()
    FROM mesh.connection_log_receiver AS receiver
$function$;

REVOKE ALL ON FUNCTION mesh_ops.flowlog_report_status_v1(BYTEA, INTEGER[], BYTEA[], TEXT[], TIMESTAMPTZ, JSONB),
    mesh_ops.flowlog_receiver_gate_v1(INTEGER, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
