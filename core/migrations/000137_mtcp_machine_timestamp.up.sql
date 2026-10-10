-- Schema 137 (MTCP v1, P4b): durable replay protection for the MTCP
-- handshake. A ClientHello carries a timestamp that must be greater than
-- the last accepted one for the machine key (mtcp-v1 §3, step 3). For a
-- machine key bound to an active Device the last accepted value is kept
-- here, so every control replica sees it; unbound keys rely on a bounded
-- per-replica cache because they have no session to displace.

CREATE TABLE mesh_ops.mtcp_machine_timestamp (
    machine_fingerprint BYTEA PRIMARY KEY
        CHECK (pg_catalog.octet_length(machine_fingerprint) = 32),
    last_timestamp_ms BIGINT NOT NULL CHECK (last_timestamp_ms > 0),
    updated_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE mesh_ops.mtcp_machine_timestamp ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.mtcp_machine_timestamp FORCE ROW LEVEL SECURITY;
CREATE POLICY mtcp_machine_timestamp_migrator_policy ON mesh_ops.mtcp_machine_timestamp
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

-- Returns TRUE when the timestamp is accepted: it is newer than the stored
-- one, or the machine key and node key resolve to no active Device (the
-- caller's per-replica cache then decides). Returns FALSE for a replay.
CREATE FUNCTION mesh_ops.accept_mtcp_timestamp_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_timestamp_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_bound BOOLEAN;
    v_accepted BOOLEAN;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_timestamp_ms IS NULL OR p_timestamp_ms <= 0
        OR (p_node_key IS NOT NULL AND pg_catalog.octet_length(p_node_key) NOT IN (0, 32)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid MTCP timestamp input';
    END IF;
    IF p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) = 0 THEN
        RETURN TRUE;
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_map_session_scope(p_machine_fingerprint, p_node_key)
    ) INTO v_bound;
    IF NOT v_bound THEN
        RETURN TRUE;
    END IF;
    INSERT INTO mesh_ops.mtcp_machine_timestamp AS stored (machine_fingerprint, last_timestamp_ms, updated_at)
    VALUES (p_machine_fingerprint, p_timestamp_ms, pg_catalog.clock_timestamp())
    ON CONFLICT (machine_fingerprint) DO UPDATE
    SET last_timestamp_ms = EXCLUDED.last_timestamp_ms, updated_at = EXCLUDED.updated_at
    WHERE stored.last_timestamp_ms < EXCLUDED.last_timestamp_ms
    RETURNING TRUE INTO v_accepted;
    RETURN COALESCE(v_accepted, FALSE);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.accept_mtcp_timestamp_v1(BYTEA, BYTEA, BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.accept_mtcp_timestamp_v1(BYTEA, BYTEA, BIGINT) TO mesh_runtime;
