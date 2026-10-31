-- Schema 265 (K2h h4c, docs/k8s-k2-access-profile-design.md §33, Q272-Q281):
-- a Kubernetes gateway reports what each group's own RBAC lets it do
-- (gateway.ceiling1, mtcp-v1 §6.12). Core keeps the latest ceiling of each
-- gateway Device for people to read as a lower bound; it never decides
-- access from it, so a write takes no handshake lock.
--
-- Core checks the ceiling against §6.12 and hashes its own encoding before
-- it writes; the table keeps the shape and the bounds whatever the caller.

-- The shape a ceiling body must have (Core checks the rest, and bounds its
-- own encoding to 1 MiB, before it writes): an object with groups, an array
-- of at most 64, and truncated, a boolean. Its text form, with a space after
-- each colon and comma, is bounded to 2 MiB. False, never NULL, otherwise.
CREATE FUNCTION mesh_ops.kubernetes_gateway_ceiling_body_is_valid_v1(p_body JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE(
        pg_catalog.jsonb_typeof(p_body) = 'object'
        AND pg_catalog.jsonb_typeof(p_body -> 'truncated') = 'boolean'
        AND CASE WHEN pg_catalog.jsonb_typeof(p_body -> 'groups') = 'array'
                 THEN pg_catalog.jsonb_array_length(p_body -> 'groups') <= 64 ELSE FALSE END
        AND pg_catalog.octet_length(p_body::TEXT) <= 2097152,
        FALSE)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_ceiling_body_is_valid_v1(JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh_ops.kubernetes_gateway_ceiling (
    device_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    body JSONB NOT NULL,
    -- SHA-256 of Core's encoding of body: replicas that report alike share it.
    content_hash BYTEA NOT NULL CHECK (pg_catalog.octet_length(content_hash) = 32),
    checked_at TIMESTAMPTZ,
    reported_at TIMESTAMPTZ NOT NULL,
    -- When the Core replica that writes it took the ceiling from the
    -- gateway: an older one written later never replaces a newer one.
    received_at TIMESTAMPTZ NOT NULL,
    -- NULL-safe: a missing key fails the check instead of passing it.
    CONSTRAINT kubernetes_gateway_ceiling_body_check CHECK (
        mesh_ops.kubernetes_gateway_ceiling_body_is_valid_v1(body)
    ),
    CONSTRAINT kubernetes_gateway_ceiling_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE,
    CONSTRAINT kubernetes_gateway_ceiling_cluster_fk
        FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE CASCADE
);
CREATE INDEX kubernetes_gateway_ceiling_cluster_idx
    ON mesh_ops.kubernetes_gateway_ceiling (kubernetes_cluster_id);
ALTER TABLE mesh_ops.kubernetes_gateway_ceiling ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_ceiling FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_ceiling_migrator_policy ON mesh_ops.kubernetes_gateway_ceiling
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_ceiling
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Keeps the ceiling of the gateway Device holding the machine key and node
-- key now. Outcomes: stored; older (a newer one is kept); unknown (no such
-- gateway).
CREATE FUNCTION mesh_ops.record_kubernetes_gateway_ceiling_v1(
    p_machine_fingerprint BYTEA,
    p_node_key BYTEA,
    p_body JSONB,
    p_content_hash BYTEA,
    p_checked_at TIMESTAMPTZ,
    p_received_at TIMESTAMPTZ
)
RETURNS TEXT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET lock_timeout = '500ms'
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_device mesh.device%ROWTYPE;
BEGIN
    IF p_received_at IS NULL OR p_received_at > v_now + INTERVAL '5 minutes'
        OR p_received_at < v_now - INTERVAL '1 hour'
        OR p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_content_hash IS NULL OR pg_catalog.octet_length(p_content_hash) <> 32
        OR NOT mesh_ops.kubernetes_gateway_ceiling_body_is_valid_v1(p_body) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway ceiling';
    END IF;
    -- A measurement time far off the database's clock is not shown.
    IF p_checked_at > v_now + INTERVAL '10 minutes' OR p_checked_at < v_now - INTERVAL '31 days' THEN
        p_checked_at := NULL;
    END IF;
    -- The current gateway, as lock_current_kubernetes_gateway_internal_v1
    -- finds it, without its handshake lock: a ceiling decides nothing.
    SELECT device.* INTO v_device
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
     AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
    WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND node_key.public_key = p_node_key AND node_key.state = 'active'
      AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp()
      AND device.kubernetes_cluster_id IS NOT NULL;
    IF v_device.id IS NULL THEN
        RETURN 'unknown';
    END IF;
    INSERT INTO mesh_ops.kubernetes_gateway_ceiling AS kept (
        device_id, workspace_id, network_id, kubernetes_cluster_id, body, content_hash, checked_at,
        reported_at, received_at
    ) VALUES (
        v_device.id, v_device.workspace_id, v_device.network_id, v_device.kubernetes_cluster_id, p_body,
        p_content_hash, p_checked_at, v_now, p_received_at
    )
    ON CONFLICT (device_id) DO UPDATE SET
        -- An unchanged ceiling sent again keeps its stored body, no rewrite;
        -- a stored body that no longer matches is replaced.
        kubernetes_cluster_id = EXCLUDED.kubernetes_cluster_id,
        body = CASE WHEN kept.content_hash = EXCLUDED.content_hash AND kept.body = EXCLUDED.body
                    THEN kept.body ELSE EXCLUDED.body END,
        content_hash = EXCLUDED.content_hash, checked_at = EXCLUDED.checked_at,
        reported_at = EXCLUDED.reported_at, received_at = EXCLUDED.received_at
    WHERE kept.received_at <= EXCLUDED.received_at;
    IF NOT FOUND THEN
        RETURN 'older';
    END IF;
    RETURN 'stored';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_gateway_ceiling_v1(
    BYTEA, BYTEA, JSONB, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_gateway_ceiling_v1(
    BYTEA, BYTEA, JSONB, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;

-- A cluster's active gateway replicas, each with its latest ceiling's
-- times and hash (null: none yet), and the bodies of at most 4 distinct
-- ceilings, the most recently received first; a reader asks for another
-- by its hash (network.read, as the replicas).
CREATE FUNCTION mesh_ops.list_kubernetes_cluster_ceilings_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN pg_catalog.jsonb_build_object(
        'replicas', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'device_id', replica.public_id,
                'received_at', ceiling.received_at,
                'checked_at', ceiling.checked_at,
                'content_hash', pg_catalog.encode(ceiling.content_hash, 'hex'))
                ORDER BY replica.created_at, replica.public_id)
            FROM mesh.device AS replica
            LEFT JOIN mesh_ops.kubernetes_gateway_ceiling AS ceiling ON ceiling.device_id = replica.id
            WHERE replica.workspace_id = v_cluster.workspace_id AND replica.network_id = v_cluster.network_id
              AND replica.kubernetes_cluster_id = v_cluster.id AND replica.kind = 'kubernetes_gateway'
              AND replica.state = 'active' AND replica.deleted_at IS NULL
              AND replica.expires_at > pg_catalog.transaction_timestamp()
        ), '[]'::JSONB),
        'bodies', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'content_hash', pg_catalog.encode(picked.content_hash, 'hex'), 'body', picked.body)
                ORDER BY picked.received_at DESC, picked.content_hash)
            FROM (
                SELECT latest.content_hash, latest.body, latest.received_at
                FROM (
                    SELECT DISTINCT ON (ceiling.content_hash) ceiling.content_hash, ceiling.body,
                        ceiling.received_at
                    FROM mesh_ops.kubernetes_gateway_ceiling AS ceiling
                    JOIN mesh.device AS replica ON replica.id = ceiling.device_id
                    WHERE ceiling.kubernetes_cluster_id = v_cluster.id
                      AND replica.workspace_id = v_cluster.workspace_id
                      AND replica.network_id = v_cluster.network_id
                      AND replica.kubernetes_cluster_id = v_cluster.id AND replica.kind = 'kubernetes_gateway'
                      AND replica.state = 'active' AND replica.deleted_at IS NULL
                      AND replica.expires_at > pg_catalog.transaction_timestamp()
                    ORDER BY ceiling.content_hash, ceiling.received_at DESC
                ) AS latest
                ORDER BY latest.received_at DESC, latest.content_hash
                LIMIT 4
            ) AS picked
        ), '[]'::JSONB)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_cluster_ceilings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_cluster_ceilings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- One ceiling of a cluster's active replicas by its hash; null when none
-- holds it.
CREATE FUNCTION mesh_ops.read_kubernetes_cluster_ceiling_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_content_hash BYTEA
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_content_hash IS NULL OR pg_catalog.octet_length(p_content_hash) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN (
        SELECT pg_catalog.jsonb_build_object(
            'content_hash', pg_catalog.encode(ceiling.content_hash, 'hex'), 'body', ceiling.body)
        FROM mesh_ops.kubernetes_gateway_ceiling AS ceiling
        JOIN mesh.device AS replica ON replica.id = ceiling.device_id
        WHERE ceiling.kubernetes_cluster_id = v_cluster.id AND ceiling.content_hash = p_content_hash
          AND replica.workspace_id = v_cluster.workspace_id AND replica.network_id = v_cluster.network_id
          AND replica.kubernetes_cluster_id = v_cluster.id AND replica.kind = 'kubernetes_gateway'
          AND replica.state = 'active' AND replica.deleted_at IS NULL
          AND replica.expires_at > pg_catalog.transaction_timestamp()
        ORDER BY ceiling.received_at DESC
        LIMIT 1
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_ceiling_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BYTEA
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_ceiling_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BYTEA
) TO mesh_runtime;
