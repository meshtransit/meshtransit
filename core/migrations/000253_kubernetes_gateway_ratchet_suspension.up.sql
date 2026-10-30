-- Schema 253 (K1d d2b, docs/k8s-k1d-console-design.md §4.2, Q165-Q167): an
-- approver suspends a gateway Device's pod token ratchet for at most a day,
-- so a replica that lost its token (a downgraded meshgw, a broken projected
-- volume) can connect while it is fixed. The suspension lives on the
-- Device's proof row and never removes it: first_proven_at stays, and the
-- ratchet holds again when the suspension ends, with or without a new
-- proof. A token proven meanwhile (a session or a join) ends it at once.
--
-- accept_mtcp_timestamp_v4 and commit_mtcp_gateway_timestamp_v3 read the
-- suspension under the Device's advisory lock, by the database's clock: a
-- session without a token accepted while suspended carries the end as a
-- hard deadline, and reads the row again while it runs. Older Core keeps
-- v3 and v2, which ignore the columns and ratchet as before: closed when a
-- replica of an older Core serves the gateway.

ALTER TABLE mesh_ops.kubernetes_gateway_token_proof
    ADD COLUMN ratchet_suspended_until TIMESTAMPTZ,
    ADD COLUMN ratchet_suspended_at TIMESTAMPTZ,
    ADD CONSTRAINT kubernetes_gateway_token_proof_suspension_check CHECK (
        (ratchet_suspended_until IS NULL) = (ratchet_suspended_at IS NULL)
        AND (ratchet_suspended_until IS NULL OR (
            ratchet_suspended_until > ratchet_suspended_at
            AND ratchet_suspended_until <= ratchet_suspended_at + INTERVAL '1 day')
        )
    );

-- Who suspended or resumed which Device when: the hourly bound of a person
-- (Q167) and the cluster's recent history. Why and the change reference go
-- in the audit event.
CREATE TABLE mesh_ops.kubernetes_gateway_ratchet_change (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    actor_principal_id BIGINT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('suspended', 'resumed')),
    suspended_until TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_gateway_ratchet_change_until_check CHECK (
        (action = 'suspended') = (suspended_until IS NOT NULL)
    ),
    CONSTRAINT kubernetes_gateway_ratchet_change_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_gateway_ratchet_change_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE
);
CREATE INDEX kubernetes_gateway_ratchet_change_actor_idx
    ON mesh_ops.kubernetes_gateway_ratchet_change (workspace_id, actor_principal_id, recorded_at);
CREATE INDEX kubernetes_gateway_ratchet_change_device_idx
    ON mesh_ops.kubernetes_gateway_ratchet_change (device_id, recorded_at);
-- Each change is an authority change of its own, with its audit event.
CREATE TRIGGER kubernetes_gateway_ratchet_change_authority_mutation
AFTER INSERT ON mesh_ops.kubernetes_gateway_ratchet_change
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_gateway_ratchet_change', 'public_id');
ALTER TABLE mesh_ops.kubernetes_gateway_ratchet_change ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_ratchet_change FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_ratchet_change_migrator_policy ON mesh_ops.kubernetes_gateway_ratchet_change
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_ratchet_change
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- As v3, and until when the ratchet of the Device holding the machine key
-- is suspended (NULL when it is not, or not ratcheted).
CREATE FUNCTION mesh_ops.accept_mtcp_timestamp_v4(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_timestamp_ms BIGINT
)
RETURNS TABLE (
    accepted BOOLEAN, gateway BOOLEAN, machine_state TEXT, node_current BOOLEAN, token_ratcheted BOOLEAN,
    suspended_until TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_check RECORD;
    v_until TIMESTAMPTZ;
BEGIN
    SELECT * INTO STRICT v_check
    FROM mesh_ops.accept_mtcp_timestamp_v3(p_machine_fingerprint, p_node_key, p_timestamp_ms);
    IF v_check.token_ratcheted THEN
        SELECT proof.ratchet_suspended_until INTO v_until
        FROM mesh.device_machine_key_epoch AS machine
        JOIN mesh.device AS device
          ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
         AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
        JOIN mesh_ops.kubernetes_gateway_token_proof AS proof ON proof.device_id = device.id
        WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
          AND proof.ratchet_suspended_until > pg_catalog.clock_timestamp();
    END IF;
    RETURN QUERY SELECT v_check.accepted, v_check.gateway, v_check.machine_state, v_check.node_current,
        v_check.token_ratcheted, v_until;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.accept_mtcp_timestamp_v4(BYTEA, BYTEA, BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.accept_mtcp_timestamp_v4(BYTEA, BYTEA, BIGINT) TO mesh_runtime;

-- As v2, with the suspension read after the Device's lock: in mode ratchet
-- a session without a token on a ratcheted Device whose ratchet is
-- suspended commits, and suspended_until is its hard deadline. A proven
-- token ends a suspension. suspended_until is NULL otherwise.
CREATE FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v3(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_timestamp_ms BIGINT, p_token_proven BOOLEAN, p_mode TEXT
)
RETURNS TABLE (result TEXT, ratcheted BOOLEAN, suspended_until TIMESTAMPTZ)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
    v_proof mesh_ops.kubernetes_gateway_token_proof%ROWTYPE;
    v_ratcheted BOOLEAN;
    v_suspended BOOLEAN;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_timestamp_ms IS NULL OR p_timestamp_ms <= 0 OR p_token_proven IS NULL
        OR p_mode IS NULL OR p_mode NOT IN ('observe', 'ratchet', 'required') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid MTCP timestamp input';
    END IF;
    v_device := mesh_ops.lock_current_kubernetes_gateway_internal_v1(p_machine_fingerprint, p_node_key);
    IF v_device.id IS NULL THEN
        RETURN QUERY SELECT 'not_committed'::TEXT, FALSE, NULL::TIMESTAMPTZ;
        RETURN;
    END IF;
    -- Read after the lock: a ratchet, a suspension or a resume another
    -- replica committed is seen.
    SELECT * INTO v_proof FROM mesh_ops.kubernetes_gateway_token_proof AS proof
    WHERE proof.device_id = v_device.id;
    v_ratcheted := FOUND;
    -- Never NULL: a Device never suspended has no end, and a NULL here
    -- would let every session without a token through.
    v_suspended := v_ratcheted
        AND COALESCE(v_proof.ratchet_suspended_until > pg_catalog.clock_timestamp(), FALSE);
    IF NOT p_token_proven
        AND (p_mode = 'required' OR (v_ratcheted AND p_mode = 'ratchet' AND NOT v_suspended)) THEN
        RETURN QUERY SELECT 'token_required'::TEXT, v_ratcheted, NULL::TIMESTAMPTZ;
        RETURN;
    END IF;
    IF NOT mesh_ops.commit_mtcp_gateway_timestamp_v1(p_machine_fingerprint, p_node_key, p_timestamp_ms) THEN
        RETURN QUERY SELECT 'not_committed'::TEXT, v_ratcheted, NULL::TIMESTAMPTZ;
        RETURN;
    END IF;
    IF p_token_proven AND NOT v_ratcheted THEN
        INSERT INTO mesh_ops.kubernetes_gateway_token_proof (device_id, workspace_id, network_id, first_proven_at)
        VALUES (v_device.id, v_device.workspace_id, v_device.network_id, pg_catalog.clock_timestamp())
        ON CONFLICT (device_id) DO NOTHING;
        v_ratcheted := TRUE;
    ELSIF p_token_proven AND v_proof.ratchet_suspended_until IS NOT NULL THEN
        -- The gateway is fixed: the door closes now, not at the end.
        UPDATE mesh_ops.kubernetes_gateway_token_proof AS proof
        SET ratchet_suspended_until = NULL, ratchet_suspended_at = NULL
        WHERE proof.device_id = v_device.id;
    END IF;
    RETURN QUERY SELECT 'committed'::TEXT, v_ratcheted,
        CASE WHEN NOT p_token_proven AND v_suspended AND p_mode = 'ratchet'
             THEN v_proof.ratchet_suspended_until END;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v3(BYTEA, BYTEA, BIGINT, BOOLEAN, TEXT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v3(BYTEA, BYTEA, BIGINT, BOOLEAN, TEXT)
    TO mesh_runtime;

-- As schema 246, and a join with a checked pod token ends a suspension.
-- Its parameters do not change: Core 246 to 252 call it as before.
CREATE OR REPLACE FUNCTION mesh_ops.ratchet_kubernetes_gateway_token_v1(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway ratchet input';
    END IF;
    v_device := mesh_ops.lock_current_kubernetes_gateway_internal_v1(p_machine_fingerprint, p_node_key);
    IF v_device.id IS NULL THEN
        RETURN FALSE;
    END IF;
    INSERT INTO mesh_ops.kubernetes_gateway_token_proof AS proof (device_id, workspace_id, network_id, first_proven_at)
    VALUES (v_device.id, v_device.workspace_id, v_device.network_id, pg_catalog.clock_timestamp())
    ON CONFLICT (device_id) DO UPDATE SET ratchet_suspended_until = NULL, ratchet_suspended_at = NULL
    WHERE proof.ratchet_suspended_until IS NOT NULL;
    RETURN TRUE;
END;
$function$;

-- Until when the ratchet of the gateway Device holding both keys now is
-- suspended, NULL when it is not: what a session that relies on the
-- suspension reads again while it runs (Q166). No lock: a reader.
CREATE FUNCTION mesh_ops.read_kubernetes_gateway_ratchet_suspension_v1(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS TIMESTAMPTZ
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT proof.ratchet_suspended_until
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
     AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
    JOIN mesh_ops.kubernetes_gateway_token_proof AS proof ON proof.device_id = device.id
    WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND node_key.public_key = p_node_key AND node_key.state = 'active'
      AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.clock_timestamp()
      AND proof.ratchet_suspended_until > pg_catalog.clock_timestamp()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_gateway_ratchet_suspension_v1(BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_gateway_ratchet_suspension_v1(BYTEA, BYTEA) TO mesh_runtime;

-- The approver's grant, the cluster's replica and its proof row, locked as
-- the handshakes lock it; MTK43 when the Device was never ratcheted.
CREATE FUNCTION mesh_ops.kubernetes_gateway_ratchet_target_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_device_public_id UUID,
    OUT o_grant_actor BIGINT, OUT o_grant_workspace BIGINT, OUT o_grant_network BIGINT, OUT o_authority JSONB,
    OUT o_device mesh.device, OUT o_proof mesh_ops.kubernetes_gateway_token_proof
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
SET lock_timeout = '2s'
AS $function$
DECLARE
    v_grant RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_device_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes gateway ratchet change is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT * INTO o_device FROM mesh.device AS device
    WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
      AND device.kubernetes_cluster_id = v_cluster.id AND device.public_id = p_device_public_id
      AND device.deleted_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes replica';
    END IF;
    -- A person's changes one at a time, then the Device's lock the
    -- handshakes take (always in that order).
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'meshtransit/gateway-ratchet-change/actor/' || v_grant.actor_id::TEXT, 0));
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'meshtransit/gateway-token-proof/' || o_device.public_id::TEXT, 0));
    SELECT * INTO o_proof FROM mesh_ops.kubernetes_gateway_token_proof AS proof
    WHERE proof.device_id = o_device.id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK43', MESSAGE = 'the gateway Device was never ratcheted';
    END IF;
    o_grant_actor := v_grant.actor_id;
    o_grant_workspace := v_grant.workspace_id;
    o_grant_network := v_grant.network_id;
    o_authority := v_grant.authority;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_ratchet_target_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Suspends a replica's ratchet for p_seconds (5 minutes to a day) from now,
-- replacing a suspension it had. Returns what the caller records as the
-- Device's event.
CREATE FUNCTION mesh_ops.suspend_kubernetes_gateway_token_ratchet_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_device_public_id UUID,
    p_seconds INTEGER, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_target RECORD;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_until TIMESTAMPTZ;
    v_recent INTEGER;
BEGIN
    IF p_seconds IS NULL OR p_seconds NOT BETWEEN 300 AND 86400 OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes gateway ratchet change is invalid';
    END IF;
    SELECT * INTO v_target FROM mesh_ops.kubernetes_gateway_ratchet_target_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id, p_device_public_id);
    -- A person's tenth change within the hour, under their own lock: only
    -- a suspension is bounded, a resume closes the door and never is
    -- (review d2b H1), though it counts.
    SELECT pg_catalog.count(*) INTO v_recent FROM (
        SELECT 1 FROM mesh_ops.kubernetes_gateway_ratchet_change AS change
        WHERE change.workspace_id = v_target.o_grant_workspace AND change.actor_principal_id = v_target.o_grant_actor
          AND change.recorded_at > v_now - INTERVAL '1 hour'
        LIMIT 10) AS counted;
    IF v_recent >= 10 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK44', MESSAGE = 'too many ratchet suspensions in the last hour';
    END IF;
    v_until := v_now + pg_catalog.make_interval(secs => p_seconds);
    UPDATE mesh_ops.kubernetes_gateway_token_proof AS proof
    SET ratchet_suspended_until = v_until, ratchet_suspended_at = v_now
    WHERE proof.device_id = (v_target.o_device).id;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh_ops.kubernetes_gateway_ratchet_change (
        public_id, workspace_id, network_id, device_id, actor_principal_id, action, suspended_until, recorded_at)
    VALUES (p_change_public_id, (v_target.o_device).workspace_id, (v_target.o_device).network_id,
        (v_target.o_device).id, v_target.o_grant_actor, 'suspended', v_until, v_now);
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
            v_target.o_grant_workspace, v_target.o_grant_network),
        'cluster_id', p_cluster_public_id,
        'device_id', p_device_public_id,
        'changed', TRUE,
        'suspended_until', v_until,
        'authority', v_target.o_authority
    );
END;
$function$;

-- Ends a replica's suspension now; the same, with nothing suspended, changes
-- nothing (changed false).
CREATE FUNCTION mesh_ops.resume_kubernetes_gateway_token_ratchet_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_device_public_id UUID,
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
    v_target RECORD;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_changed BOOLEAN;
BEGIN
    IF p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes gateway ratchet change is invalid';
    END IF;
    SELECT * INTO v_target FROM mesh_ops.kubernetes_gateway_ratchet_target_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id, p_device_public_id);
    v_changed := COALESCE((v_target.o_proof).ratchet_suspended_until > v_now, FALSE);
    IF v_changed THEN
        UPDATE mesh_ops.kubernetes_gateway_token_proof AS proof
        SET ratchet_suspended_until = NULL, ratchet_suspended_at = NULL
        WHERE proof.device_id = (v_target.o_device).id;
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
        INSERT INTO mesh_ops.kubernetes_gateway_ratchet_change (
            public_id, workspace_id, network_id, device_id, actor_principal_id, action, suspended_until,
            recorded_at)
        VALUES (p_change_public_id, (v_target.o_device).workspace_id, (v_target.o_device).network_id,
            (v_target.o_device).id, v_target.o_grant_actor, 'resumed', NULL, v_now);
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
            v_target.o_grant_workspace, v_target.o_grant_network),
        'cluster_id', p_cluster_public_id,
        'device_id', p_device_public_id,
        'changed', COALESCE(v_changed, FALSE),
        'suspended_until', NULL,
        'authority', v_target.o_authority
    );
END;
$function$;

-- A replica as its v1 document, and until when its ratchet is suspended.
CREATE FUNCTION mesh_ops.kubernetes_cluster_replica_document_internal_v2(p_device mesh.device)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.kubernetes_cluster_replica_document_internal_v1(p_device) || pg_catalog.jsonb_build_object(
        'ratchet_suspended_until', (
            SELECT proof.ratchet_suspended_until FROM mesh_ops.kubernetes_gateway_token_proof AS proof
            WHERE proof.device_id = p_device.id AND proof.workspace_id = p_device.workspace_id
              AND proof.network_id = p_device.network_id
              AND proof.ratchet_suspended_until > pg_catalog.clock_timestamp()))
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_replica_document_internal_v2(mesh.device)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- As v1, with the v2 document.
CREATE FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_after_at TIMESTAMPTZ, p_after_id UUID, p_limit INTEGER
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
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR (p_after_at IS NULL) <> (p_after_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_cluster_replica_document_internal_v2(listed)
            ORDER BY listed.created_at DESC, listed.public_id DESC)
        FROM (
            SELECT device.* FROM mesh.device AS device
            WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
              AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
              AND (p_after_at IS NULL OR (device.created_at, device.public_id) < (p_after_at, p_after_id))
            ORDER BY device.created_at DESC, device.public_id DESC
            LIMIT p_limit + 1
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

CREATE FUNCTION mesh_ops.read_kubernetes_cluster_replica_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_device_public_id UUID
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
    v_document JSONB;
BEGIN
    IF p_device_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT mesh_ops.kubernetes_cluster_replica_document_internal_v2(device) INTO v_document
    FROM mesh.device AS device
    WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
      AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
      AND device.public_id = p_device_public_id;
    IF v_document IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes replica';
    END IF;
    RETURN v_document;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.suspend_kubernetes_gateway_token_ratchet_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.suspend_kubernetes_gateway_token_ratchet_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.resume_kubernetes_gateway_token_ratchet_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resume_kubernetes_gateway_token_ratchet_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_cluster_replicas_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_replica_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_replica_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;
