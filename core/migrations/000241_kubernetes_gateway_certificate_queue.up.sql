-- Schema 241 (K1a4a a3b, docs/k8s-k1a4-a3-signing-design.md §14, review of
-- §13 and §3): the certificate queue made fit for large installations
-- before control starts queueing (MTCP gateway.cert1).
--
-- - A pod token stays in the database only until the worker's first claim:
--   the worker checks it, then records the claims it checked and erases it
--   (R-M1). issue takes the recorded claims.
-- - A request abandoned more than 30 seconds ago no longer counts in flight;
--   a pod's token request supersedes its Device's other unfinished
--   requests (R-M2). A Workspace has at most 200 in flight, and claims take
--   Workspaces in turn (R-M3).
-- - Signing needs the restore tripwire checked within 10 minutes: the
--   lifecycle worker stamps the guard after each comparison (R-M9).
-- - Control reads whether a signer is ready, and refuses at once when none
--   is (R-H3). Results name the Network revision they were issued at (R-M6).
-- - Pruning leaves claimed requests alone (R-L5).

ALTER TABLE mesh_ops.kubernetes_gateway_certificate_request
    ADD COLUMN token_jti TEXT CHECK (pg_catalog.octet_length(token_jti) BETWEEN 1 AND 128 AND token_jti ~ '^[!-~]+$'),
    ADD COLUMN token_expires_at TIMESTAMPTZ,
    ADD COLUMN token_pod_name TEXT CHECK (
        pg_catalog.octet_length(token_pod_name) BETWEEN 1 AND 253 AND token_pod_name ~ '^[a-z0-9.-]+$'),
    ADD COLUMN token_trust_version BIGINT CHECK (token_trust_version >= 1),
    ADD COLUMN network_revision BIGINT CHECK (network_revision >= 1);
ALTER TABLE mesh_ops.kubernetes_gateway_certificate_request
    DROP CONSTRAINT kubernetes_gateway_certificate_request_evidence_check;
-- A token request holds its token, or the claims the worker checked in it,
-- while it is unfinished; never both, and never the token once finished.
ALTER TABLE mesh_ops.kubernetes_gateway_certificate_request
    ADD CONSTRAINT kubernetes_gateway_certificate_request_evidence_v2_check CHECK (
        (token_jti IS NULL) = (token_expires_at IS NULL) AND (token_jti IS NULL) = (token_pod_name IS NULL)
        AND (token_jti IS NULL) = (token_trust_version IS NULL)
        AND (
            (proof = 'token' AND handshake_hash IS NULL AND renewal_certificate_id IS NULL AND renewal_proof IS NULL
                AND (token IS NULL OR token_jti IS NULL)
                AND (state NOT IN ('pending', 'claimed', 'abandoned') OR token IS NOT NULL OR token_jti IS NOT NULL)
                AND (state IN ('pending', 'claimed', 'abandoned') OR token IS NULL))
            OR (proof = 'renewal' AND token IS NULL AND token_jti IS NULL AND handshake_hash IS NOT NULL
                AND renewal_certificate_id IS NOT NULL AND renewal_proof IS NOT NULL)
        )
        AND (network_revision IS NULL OR state = 'issued')
    ) NOT VALID;
ALTER TABLE mesh_ops.kubernetes_gateway_certificate_request
    VALIDATE CONSTRAINT kubernetes_gateway_certificate_request_evidence_v2_check;
CREATE INDEX kubernetes_gateway_certificate_request_workspace_idx
    ON mesh_ops.kubernetes_gateway_certificate_request (workspace_id)
    WHERE state IN ('pending', 'claimed', 'abandoned');

-- When the lifecycle worker last compared the restore marks (or, with no
-- marks configured, last read the guard) for the guard's generation.
ALTER TABLE mesh_ops.kubernetes_ca_guard ADD COLUMN checked_at TIMESTAMPTZ;

-- ---- Queue (control) ----

CREATE OR REPLACE FUNCTION mesh_ops.kubernetes_gateway_certificate_result_internal_v1(p_request_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'outcome', request.state,
        'request_id', request.public_id,
        'device_id', (SELECT device.public_id FROM mesh.device AS device WHERE device.id = request.device_id),
        'reason', request.reason,
        'certificate', pg_catalog.encode(request.certificate, 'hex'),
        'chain', CASE WHEN issued.id IS NULL THEN NULL
            ELSE pg_catalog.jsonb_build_array(pg_catalog.encode(intermediate.certificate, 'hex')) END,
        'issuer_fingerprint', pg_catalog.encode(intermediate.fingerprint, 'hex'),
        'root_fingerprint', pg_catalog.encode(root.fingerprint, 'hex'),
        'not_after', issued.not_after,
        'renew_at', request.renew_at,
        'network_revision', request.network_revision
    )
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    LEFT JOIN mesh.kubernetes_gateway_certificate AS issued ON issued.id = request.certificate_id
    LEFT JOIN mesh.kubernetes_cluster_ca AS intermediate ON intermediate.id = issued.issuer_ca_id
    LEFT JOIN mesh.kubernetes_cluster_ca AS root ON root.id = intermediate.issuer_ca_id
    WHERE request.id = p_request_id
$function$;

-- Requests that hold room in a limit: unfinished, or abandoned within the
-- last 30 seconds (a gateway that sends again soon finds its request).
CREATE FUNCTION mesh_ops.kubernetes_gateway_certificate_in_flight_internal_v1(
    p_state TEXT, p_updated_at TIMESTAMPTZ, p_now TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL SAFE
-- No SET clause and nothing volatile (timestamptz - interval is STABLE), so
-- the planner inlines it.
AS $function$
    SELECT p_state OPERATOR(pg_catalog.=) ANY (ARRAY['pending', 'claimed']::TEXT[])
        OR (p_state OPERATOR(pg_catalog.=) 'abandoned'
            AND p_updated_at OPERATOR(pg_catalog.>) (p_now OPERATOR(pg_catalog.-) INTERVAL '30 seconds'))
$function$;

-- Queues a certificate request of the gateway the session proved, as schema
-- 240 did, with a3 §14:
-- - a token request (a pod that started) refuses the Device's other
--   unfinished requests as 'superseded' (R-M2);
-- - requests abandoned over 30 seconds ago hold no room; one that waits
--   again is counted like a new one (R-M2);
-- - limits: 12 issued per Device and hour, 2 in flight per Device, 20 per
--   cluster, 200 per Workspace (R-M3), 1000 per installation. The last
--   three are soft.
-- Lock order: the Device (FOR UPDATE), the cluster (FOR SHARE), then
-- requests of the Device.
CREATE OR REPLACE FUNCTION mesh_ops.enqueue_kubernetes_gateway_certificate_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_request_public_id UUID, p_request_id BYTEA, p_csr BYTEA,
    p_public_key_sha256 BYTEA, p_token TEXT, p_handshake_hash BYTEA, p_renewal_serial BYTEA, p_renewal_proof BYTEA
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_proof TEXT;
    v_device mesh.device%ROWTYPE;
    v_deployment_id BIGINT;
    v_request mesh_ops.kubernetes_gateway_certificate_request%ROWTYPE;
    v_renewal_id BIGINT;
    v_new_id BIGINT;
    v_oldest TIMESTAMPTZ;
    v_count BIGINT;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    IF p_token IS NOT NULL AND p_handshake_hash IS NULL AND p_renewal_serial IS NULL AND p_renewal_proof IS NULL THEN
        v_proof := 'token';
    ELSIF p_token IS NULL AND p_handshake_hash IS NOT NULL AND p_renewal_serial IS NOT NULL
        AND p_renewal_proof IS NOT NULL THEN
        v_proof := 'renewal';
    END IF;
    IF v_proof IS NULL OR p_request_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR p_request_id IS NULL OR pg_catalog.octet_length(p_request_id) <> 16
        OR p_csr IS NULL OR pg_catalog.octet_length(p_csr) NOT BETWEEN 64 AND 4096
        OR p_public_key_sha256 IS NULL OR pg_catalog.octet_length(p_public_key_sha256) <> 32
        OR pg_catalog.octet_length(p_token) NOT BETWEEN 1 AND 8192
        OR pg_catalog.octet_length(p_handshake_hash) <> 32
        OR pg_catalog.octet_length(p_renewal_serial) <> 16
        OR pg_catalog.octet_length(p_renewal_proof) NOT BETWEEN 8 AND 72 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate request';
    END IF;
    IF NOT mesh_ops.session_proven_node_key_matches_v1(p_machine_fingerprint, p_node_key) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no proven gateway session';
    END IF;
    SELECT device.* INTO v_device
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
    WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND node_key.public_key = p_node_key AND node_key.state = 'active'
      AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > v_now
    FOR UPDATE OF device;
    IF v_device.id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'refused', 'reason', 'revoked');
    END IF;
    PERFORM 1 FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_device.workspace_id AND cluster.network_id = v_device.network_id
      AND cluster.id = v_device.kubernetes_cluster_id AND cluster.state = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'refused', 'reason', 'cluster');
    END IF;

    -- Read without a lock: issue locks the Device before the request, so
    -- this takes no request lock while it holds the Device (review a3a M2).
    SELECT request.* INTO v_request
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    WHERE request.device_id = v_device.id AND request.request_id = p_request_id;
    IF v_request.id IS NOT NULL AND (v_request.public_key_sha256 <> p_public_key_sha256
        OR v_request.proof <> v_proof) THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'conflict');
    END IF;
    -- A request seen before answers as it stands, even once the certificate
    -- it renews has expired (review a3a L3).
    IF v_request.id IS NOT NULL AND v_request.state <> 'abandoned' THEN
        RETURN mesh_ops.kubernetes_gateway_certificate_result_internal_v1(v_request.id);
    END IF;
    IF v_proof = 'renewal' THEN
        SELECT issued.id INTO v_renewal_id
        FROM mesh.kubernetes_gateway_certificate AS issued
        WHERE issued.device_id = v_device.id AND issued.serial = p_renewal_serial AND issued.not_after > v_now;
        IF v_renewal_id IS NULL THEN
            RETURN pg_catalog.jsonb_build_object('outcome', 'refused', 'reason', 'renewal_unknown');
        END IF;
    END IF;

    SELECT pg_catalog.min(issued.issued_at), pg_catalog.count(*) INTO v_oldest, v_count
    FROM mesh.kubernetes_gateway_certificate AS issued
    WHERE issued.device_id = v_device.id AND issued.issued_at > v_now - INTERVAL '1 hour';
    IF v_count >= 12 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'limited',
            'retry_after_ms', GREATEST(1000, (EXTRACT(EPOCH FROM (v_oldest + INTERVAL '1 hour' - v_now)) * 1000)::BIGINT));
    END IF;
    -- A pod that started asks with its token: what an earlier process of
    -- the Device left unfinished is no one's any more (R-M2).
    IF v_proof = 'token' THEN
        -- Locked in id order first, as the claim's lease sweep locks them
        -- (review a3b SQL M3).
        PERFORM 1 FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.device_id = v_device.id AND request.state IN ('pending', 'claimed', 'abandoned')
          AND request.id IS DISTINCT FROM v_request.id
        ORDER BY request.id
        FOR UPDATE;
        UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
        SET state = 'refused', reason = 'superseded', token = NULL, claim_token = NULL, claim_expires_at = NULL,
            updated_at = v_now
        WHERE request.device_id = v_device.id AND request.state IN ('pending', 'claimed', 'abandoned')
          AND request.id IS DISTINCT FROM v_request.id;
    END IF;
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.device_id = v_device.id AND request.state IN ('pending', 'claimed', 'abandoned')
          AND request.id IS DISTINCT FROM v_request.id
          AND mesh_ops.kubernetes_gateway_certificate_in_flight_internal_v1(request.state, request.updated_at, v_now))
        >= 2 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'limited', 'retry_after_ms', 2000);
    END IF;
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.kubernetes_cluster_id = v_device.kubernetes_cluster_id
          AND request.state IN ('pending', 'claimed', 'abandoned') AND request.id IS DISTINCT FROM v_request.id
          AND mesh_ops.kubernetes_gateway_certificate_in_flight_internal_v1(request.state, request.updated_at, v_now))
        >= 20 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'limited', 'retry_after_ms', 2000);
    END IF;
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.workspace_id = v_device.workspace_id
          AND request.state IN ('pending', 'claimed', 'abandoned') AND request.id IS DISTINCT FROM v_request.id
          AND mesh_ops.kubernetes_gateway_certificate_in_flight_internal_v1(request.state, request.updated_at, v_now))
        >= 200 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'limited', 'retry_after_ms', 5000);
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT workspace.deployment_id INTO STRICT v_deployment_id
    FROM mesh.workspace AS workspace WHERE workspace.id = v_device.workspace_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.deployment_id = v_deployment_id
          AND request.state IN ('pending', 'claimed', 'abandoned') AND request.id IS DISTINCT FROM v_request.id
          AND mesh_ops.kubernetes_gateway_certificate_in_flight_internal_v1(request.state, request.updated_at, v_now))
        >= 1000 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'overloaded', 'retry_after_ms', 5000);
    END IF;

    IF v_request.id IS NOT NULL THEN
        -- Waits again with the proof the gateway sent now: a new token
        -- replaces the claims a worker checked in the old one.
        UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
        SET state = 'pending', token = p_token, token_jti = NULL, token_expires_at = NULL, token_pod_name = NULL,
            token_trust_version = NULL, handshake_hash = p_handshake_hash, renewal_certificate_id = v_renewal_id,
            renewal_proof = p_renewal_proof, created_at = v_now, updated_at = v_now
        WHERE request.id = v_request.id AND request.state = 'abandoned';
        RETURN mesh_ops.kubernetes_gateway_certificate_result_internal_v1(v_request.id);
    END IF;
    INSERT INTO mesh_ops.kubernetes_gateway_certificate_request (
        public_id, deployment_id, workspace_id, network_id, kubernetes_cluster_id, device_id, request_id, csr,
        public_key_sha256, machine_fingerprint, proof, token, handshake_hash, renewal_certificate_id, renewal_proof,
        state, created_at, updated_at
    ) VALUES (
        p_request_public_id, v_deployment_id, v_device.workspace_id, v_device.network_id,
        v_device.kubernetes_cluster_id, v_device.id, p_request_id, p_csr, p_public_key_sha256,
        p_machine_fingerprint, v_proof, p_token, p_handshake_hash, v_renewal_id, p_renewal_proof,
        'pending', v_now, v_now
    )
    RETURNING id INTO v_new_id;
    RETURN mesh_ops.kubernetes_gateway_certificate_result_internal_v1(v_new_id);
END;
$function$;

-- Whether a worker can sign now, for control to refuse at once when none
-- can (R-H3): a signer whose heartbeat holds, no restore suspected, and
-- the tripwire checked within 10 minutes. One installation per database
-- (TD-CORE-103): every installation's state is folded together.
CREATE FUNCTION mesh_ops.read_kubernetes_ca_signing_state_v1()
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'signer_ready', EXISTS (
            SELECT 1 FROM mesh_ops.kubernetes_ca_worker_heartbeat AS beat
            WHERE beat.ready_until > pg_catalog.clock_timestamp() AND 'ca.sign1' = ANY (beat.capabilities)),
        'restore_suspected', EXISTS (
            SELECT 1 FROM mesh_ops.kubernetes_ca_guard AS guard WHERE guard.restore_suspected),
        'checked', EXISTS (
            SELECT 1 FROM mesh_ops.kubernetes_ca_guard AS guard
            WHERE NOT guard.restore_suspected AND guard.checked_at > pg_catalog.clock_timestamp() - INTERVAL '10 minutes')
    )
$function$;

-- ---- Signing (worker) ----

-- What the worker signs a claimed request from, as schema 240 gave it, and
-- the claims a worker already checked in its token ('verified').
CREATE OR REPLACE FUNCTION mesh_ops.kubernetes_gateway_certificate_claim_internal_v1(p_request_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'id', request.public_id,
        'claim_token', request.claim_token,
        'request_id', pg_catalog.encode(request.request_id, 'hex'),
        'workspace_id', workspace.public_id,
        'network_id', network.public_id,
        'device_id', device.public_id,
        'cluster_id', cluster.public_id,
        'cluster_name', cluster.name,
        'workspace_code', (SELECT display.display_code FROM mesh_ops.tenant_display_identity AS display
            WHERE display.workspace_public_id = workspace.public_id),
        'network_code', (SELECT display.display_code FROM mesh_ops.tenant_display_identity AS display
            WHERE display.network_public_id = network.public_id),
        'csr', pg_catalog.encode(request.csr, 'hex'),
        'public_key_sha256', pg_catalog.encode(request.public_key_sha256, 'hex'),
        'proof', request.proof,
        'token', request.token,
        'verified', CASE WHEN request.token_jti IS NOT NULL THEN pg_catalog.jsonb_build_object(
            'jti', request.token_jti, 'expires_at', request.token_expires_at, 'pod_name', request.token_pod_name,
            'trust_version', request.token_trust_version) END,
        'handshake_hash', pg_catalog.encode(request.handshake_hash, 'hex'),
        'renewal_proof', pg_catalog.encode(request.renewal_proof, 'hex'),
        'renewal_public_key', pg_catalog.encode(renewed.public_key, 'hex'),
        'renewal_serial', pg_catalog.encode(renewed.serial, 'hex'),
        'renewal_not_after', renewed.not_after,
        'trust', CASE WHEN request.proof = 'token' AND trust.kubernetes_cluster_id IS NOT NULL THEN
            pg_catalog.jsonb_build_object(
                'version', trust.version, 'issuer', trust.issuer,
                'jwks', pg_catalog.encode(trust.jwks, 'base64'),
                'namespace', trust.namespace, 'service_account', trust.service_account,
                'pod_name', (SELECT joined.sa_pod_name FROM mesh.kubernetes_replica_request AS joined
                    WHERE joined.device_id = device.id AND joined.state = 'completed'
                    ORDER BY joined.id DESC LIMIT 1))
            END,
        'intermediate', CASE WHEN intermediate.id IS NOT NULL THEN pg_catalog.jsonb_build_object(
            'id', intermediate.public_id, 'version', intermediate.version,
            'certificate', pg_catalog.encode(intermediate.certificate, 'hex'),
            'sealed_key', pg_catalog.encode(intermediate.private_key_ciphertext, 'hex'),
            'cluster_dns_name', intermediate.cluster_dns_name,
            'not_after', intermediate.not_after,
            'root_id', root.public_id,
            'root_certificate', pg_catalog.encode(root.certificate, 'hex'),
            'data_key', pg_catalog.jsonb_build_object(
                'id', data_key.public_id, 'version', data_key.version, 'active', data_key.state = 'active',
                'custody', wrapping.custody, 'key_id', wrapping.key_id,
                'ciphertext', pg_catalog.encode(wrapping.ciphertext, 'hex'))
        ) END
    )
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    JOIN mesh.device AS device ON device.id = request.device_id
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = request.kubernetes_cluster_id
    JOIN mesh.workspace AS workspace ON workspace.id = request.workspace_id
    JOIN mesh.network AS network ON network.id = request.network_id
    LEFT JOIN mesh.kubernetes_gateway_certificate AS renewed ON renewed.id = request.renewal_certificate_id
    LEFT JOIN mesh.kubernetes_cluster_signing_trust AS trust ON trust.kubernetes_cluster_id = cluster.id
    LEFT JOIN mesh.kubernetes_cluster_ca AS intermediate
      ON intermediate.kubernetes_cluster_id = cluster.id AND intermediate.kind = 'intermediate'
     AND intermediate.state = 'active'
    LEFT JOIN mesh.kubernetes_cluster_ca AS root ON root.id = intermediate.issuer_ca_id
    LEFT JOIN mesh.kubernetes_ca_data_key AS data_key ON data_key.id = intermediate.data_key_id
    LEFT JOIN mesh.kubernetes_ca_data_key_wrapping AS wrapping
      ON wrapping.data_key_id = data_key.id AND wrapping.state = 'active'
    WHERE request.id = p_request_id
$function$;

-- Claims as schema 240 did, with a3 §14: nothing is claimed unless the
-- restore tripwire was checked within 10 minutes ('unchecked', R-M9), and
-- Workspaces take turns: a Workspace's n-th oldest request comes after
-- every Workspace's (n-1)-th (R-M3).
CREATE OR REPLACE FUNCTION mesh_ops.claim_kubernetes_gateway_certificates_v1(
    p_deployment_public_id UUID, p_limit INTEGER, p_lease_seconds INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_claimed BIGINT[];
    v_refused BIGINT;
    v_checked_at TIMESTAMPTZ;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_requests JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 64 OR p_lease_seconds IS NULL
        OR p_lease_seconds NOT BETWEEN 5 AND 120 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate claim';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    -- Leases that ran out end first, even while nothing is signed: their
    -- requests wait again, or are refused after three leases, and no
    -- token or room stays held by a claim no worker holds (review a3b SQL
    -- M1). Locked in id order, skipping rows another transaction holds
    -- (M3).
    WITH expired_rows AS (
        SELECT request.id FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.deployment_id = v_deployment_id AND request.state = 'claimed'
          AND request.claim_expires_at < v_now
        ORDER BY request.id
        FOR UPDATE SKIP LOCKED
    ), expired AS (
        UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
        SET state = CASE WHEN request.attempts >= 3 THEN 'refused' ELSE 'pending' END,
            reason = CASE WHEN request.attempts >= 3 THEN 'attempts' END,
            token = CASE WHEN request.attempts >= 3 THEN NULL ELSE request.token END,
            claim_token = NULL, claim_expires_at = NULL, updated_at = v_now
        FROM expired_rows WHERE request.id = expired_rows.id
        RETURNING request.state
    )
    SELECT pg_catalog.count(*) FILTER (WHERE expired.state = 'refused') INTO v_refused FROM expired;
    IF mesh_ops.kubernetes_ca_guard_suspected_internal_v1(v_deployment_id) THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'suspected', 'now', v_now, 'pending', 0,
            'refused_attempts', v_refused, 'requests', '[]'::JSONB);
    END IF;
    SELECT guard.checked_at INTO v_checked_at
    FROM mesh_ops.kubernetes_ca_guard AS guard WHERE guard.deployment_id = v_deployment_id;
    IF v_checked_at IS NULL OR v_checked_at <= v_now - INTERVAL '10 minutes' THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'unchecked', 'now', v_now, 'pending', 0,
            'refused_attempts', v_refused, 'requests', '[]'::JSONB);
    END IF;
    WITH turns AS (
        SELECT request.id, pg_catalog.row_number() OVER (
            PARTITION BY request.workspace_id ORDER BY request.created_at, request.id) AS turn
        FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.deployment_id = v_deployment_id AND request.state = 'pending'
    ), picked AS (
        SELECT request.id FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        JOIN turns ON turns.id = request.id
        WHERE request.state = 'pending'
        ORDER BY turns.turn, request.created_at, request.id
        LIMIT p_limit
        FOR UPDATE OF request SKIP LOCKED
    ), claimed AS (
        UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
        SET state = 'claimed', claim_token = pg_catalog.gen_random_uuid(),
            claim_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
            attempts = request.attempts + 1, updated_at = v_now
        FROM picked WHERE request.id = picked.id
        RETURNING request.id
    )
    SELECT pg_catalog.array_agg(claimed.id ORDER BY claimed.id) INTO v_claimed FROM claimed;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT COALESCE(pg_catalog.jsonb_agg(
        mesh_ops.kubernetes_gateway_certificate_claim_internal_v1(claimed.id) ORDER BY claimed.id), '[]'::JSONB)
    INTO v_requests
    FROM pg_catalog.unnest(COALESCE(v_claimed, '{}'::BIGINT[])) AS claimed (id);
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'claimed', 'now', v_now, 'refused_attempts', v_refused,
        'pending', (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
            WHERE request.deployment_id = v_deployment_id AND request.state = 'pending'),
        'suffix', (SELECT recorded.suffix FROM mesh_ops.kubernetes_ca_dns_suffix AS recorded
            WHERE recorded.deployment_id = v_deployment_id),
        'requests', v_requests
    );
END;
$function$;

-- The worker checked the pod token of a request it holds: the claims it
-- checked replace the token, so the token leaves the database at the first
-- claim (R-M1). Outcome 'lost' when the claim no longer holds the request.
CREATE FUNCTION mesh_ops.record_kubernetes_gateway_certificate_token_v1(
    p_deployment_public_id UUID, p_request_public_id UUID, p_claim_token UUID, p_jti TEXT,
    p_token_expires_at TIMESTAMPTZ, p_pod_name TEXT, p_trust_version BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_request_id BIGINT;
BEGIN
    IF p_jti IS NULL OR pg_catalog.octet_length(p_jti) NOT BETWEEN 1 AND 128 OR p_jti !~ '^[!-~]+$'
        OR p_token_expires_at IS NULL OR p_pod_name IS NULL
        OR pg_catalog.octet_length(p_pod_name) NOT BETWEEN 1 AND 253 OR p_pod_name !~ '^[a-z0-9.-]+$'
        OR p_trust_version IS NULL OR p_trust_version < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate token claims';
    END IF;
    v_request_id := mesh_ops.kubernetes_gateway_certificate_held_internal_v1(
        p_deployment_public_id, p_request_public_id, p_claim_token);
    IF v_request_id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'lost');
    END IF;
    UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
    SET token = NULL, token_jti = p_jti, token_expires_at = p_token_expires_at, token_pod_name = p_pod_name,
        token_trust_version = p_trust_version, updated_at = pg_catalog.clock_timestamp()
    WHERE request.id = v_request_id AND request.proof = 'token' AND request.token IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'the request holds no token to record';
    END IF;
    RETURN pg_catalog.jsonb_build_object('outcome', 'recorded');
END;
$function$;

-- Issues as schema 240 did, taking the token claims the worker recorded
-- (R-M1), and recording the Network revision in the result (R-M6).
CREATE OR REPLACE FUNCTION mesh_ops.issue_kubernetes_gateway_certificate_v1(
    p_deployment_public_id UUID, p_request_public_id UUID, p_claim_token UUID, p_change_public_id UUID,
    p_certificate_public_id UUID, p_ca_public_id UUID, p_ca_version BIGINT, p_serial BYTEA, p_certificate BYTEA,
    p_public_key BYTEA, p_not_before TIMESTAMPTZ, p_not_after TIMESTAMPTZ, p_renew_at TIMESTAMPTZ, p_jti TEXT,
    p_token_expires_at TIMESTAMPTZ, p_pod_name TEXT, p_trust_version BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_request mesh_ops.kubernetes_gateway_certificate_request%ROWTYPE;
    v_request_id BIGINT;
    v_ca mesh.kubernetes_cluster_ca%ROWTYPE;
    v_stream RECORD;
    v_revision BIGINT;
    v_renewed UUID;
    v_certificate_id BIGINT;
    v_payload JSONB;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    IF p_change_public_id IS NULL OR p_certificate_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_certificate_public_id), 6) >> 4 <> 7
        OR p_change_public_id = p_certificate_public_id OR p_ca_public_id IS NULL
        OR p_ca_version IS NULL OR p_ca_version < 1
        OR p_serial IS NULL OR p_certificate IS NULL OR p_public_key IS NULL
        OR p_not_before IS NULL OR p_not_after IS NULL OR p_renew_at IS NULL
        OR p_renew_at <= p_not_before OR p_renew_at >= p_not_after THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate';
    END IF;
    -- Lock order (review a3a M1, M2): the Network's CA lock shared, so a CA
    -- change of the Network (which takes it alone) waits or finds it busy
    -- instead of deadlocking on the CA and audit stream; then the Device,
    -- then the request, as enqueue locks them.
    SELECT request.* INTO v_request
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    WHERE request.public_id = p_request_public_id
      AND request.deployment_id = mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    IF v_request.id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'lost');
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended(
        'meshtransit/kubernetes-ca/' || (SELECT network.public_id FROM mesh.network AS network
            WHERE network.id = v_request.network_id)::TEXT, 0));
    PERFORM 1 FROM mesh.device AS device WHERE device.id = v_request.device_id FOR SHARE;
    v_request_id := mesh_ops.kubernetes_gateway_certificate_held_internal_v1(
        p_deployment_public_id, p_request_public_id, p_claim_token);
    IF v_request_id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'lost');
    END IF;
    SELECT request.* INTO STRICT v_request
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request WHERE request.id = v_request_id;
    IF mesh_ops.kubernetes_ca_guard_suspected_internal_v1(v_request.deployment_id) THEN
        PERFORM mesh_ops.release_kubernetes_gateway_certificate_v1(
            p_deployment_public_id, p_request_public_id, p_claim_token);
        RETURN pg_catalog.jsonb_build_object('outcome', 'suspected');
    END IF;
    PERFORM 1 FROM mesh.device AS device
    WHERE device.id = v_request.device_id AND device.kind = 'kubernetes_gateway' AND device.state = 'active'
      AND device.deleted_at IS NULL AND device.expires_at > v_now
      AND device.kubernetes_cluster_id = v_request.kubernetes_cluster_id;
    IF NOT FOUND THEN
        RETURN mesh_ops.refuse_kubernetes_gateway_certificate_v1(
            p_deployment_public_id, p_request_public_id, p_claim_token, 'revoked');
    END IF;
    PERFORM 1 FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.id = v_request.kubernetes_cluster_id AND cluster.state = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN mesh_ops.refuse_kubernetes_gateway_certificate_v1(
            p_deployment_public_id, p_request_public_id, p_claim_token, 'cluster');
    END IF;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_request.workspace_id AND stream.network_id = v_request.network_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    SELECT ca.* INTO v_ca
    FROM mesh.kubernetes_cluster_ca AS ca
    WHERE ca.public_id = p_ca_public_id AND ca.kubernetes_cluster_id = v_request.kubernetes_cluster_id
    FOR SHARE;
    IF v_ca.id IS NULL OR v_ca.kind <> 'intermediate' OR v_ca.state <> 'active' OR v_ca.version <> p_ca_version THEN
        PERFORM mesh_ops.release_kubernetes_gateway_certificate_v1(
            p_deployment_public_id, p_request_public_id, p_claim_token);
        RETURN pg_catalog.jsonb_build_object('outcome', 'requeued');
    END IF;
    IF pg_catalog.sha256(p_public_key) <> v_request.public_key_sha256
        OR p_not_before < v_ca.not_before OR p_not_after > v_ca.not_after THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'the certificate is not the one requested';
    END IF;
    IF v_request.proof = 'token' THEN
        IF p_jti IS NULL OR p_pod_name IS NULL OR p_token_expires_at IS NULL OR p_trust_version IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate token';
        END IF;
        -- The worker recorded the token's claims at its first claim and
        -- erased the token (a3 §14 R-M1): it issues those claims.
        IF v_request.token IS NOT NULL OR v_request.token_jti IS NULL OR p_jti <> v_request.token_jti
            OR p_token_expires_at <> v_request.token_expires_at OR p_pod_name <> v_request.token_pod_name
            OR p_trust_version <> v_request.token_trust_version THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'the token claims are not the ones recorded';
        END IF;
        -- Keys replaced after a compromise since the claim refuse the token
        -- (review a3a L2).
        PERFORM 1 FROM mesh.kubernetes_cluster_signing_trust AS trust
        WHERE trust.kubernetes_cluster_id = v_request.kubernetes_cluster_id AND trust.version = p_trust_version
        FOR SHARE;
        IF NOT FOUND THEN
            RETURN mesh_ops.refuse_kubernetes_gateway_certificate_v1(
                p_deployment_public_id, p_request_public_id, p_claim_token, 'trust_missing');
        END IF;
        -- The worker checked the token by its own clock; the database checks
        -- again by its own (as for rotations, schema 232).
        IF p_token_expires_at <= v_now OR p_token_expires_at > v_now + INTERVAL '15 minutes 30 seconds' THEN
            RETURN mesh_ops.refuse_kubernetes_gateway_certificate_v1(
                p_deployment_public_id, p_request_public_id, p_claim_token, 'token_expired');
        END IF;
        -- One certificate per pod token, whatever key asks: a captured
        -- token does not mint certificates for many keys (review a3a M4).
        -- The key column holds no key for this purpose.
        INSERT INTO mesh_ops.kubernetes_gateway_token_use (
            kubernetes_cluster_id, jti, purpose, replaced_key, device_id, expires_at, xact_id, used_at
        ) VALUES (
            v_request.kubernetes_cluster_id, p_jti, 'cert', pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
            v_request.device_id, p_token_expires_at, pg_catalog.pg_current_xact_id(), v_now
        )
        ON CONFLICT DO NOTHING;
        IF NOT FOUND THEN
            RETURN mesh_ops.refuse_kubernetes_gateway_certificate_v1(
                p_deployment_public_id, p_request_public_id, p_claim_token, 'token_used');
        END IF;
    ELSE
        IF p_jti IS NOT NULL OR p_pod_name IS NOT NULL OR p_token_expires_at IS NOT NULL
            OR p_trust_version IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate renewal';
        END IF;
        SELECT renewed.public_id INTO v_renewed
        FROM mesh.kubernetes_gateway_certificate AS renewed
        WHERE renewed.id = v_request.renewal_certificate_id AND renewed.not_after > v_now;
        IF v_renewed IS NULL THEN
            RETURN mesh_ops.refuse_kubernetes_gateway_certificate_v1(
                p_deployment_public_id, p_request_public_id, p_claim_token, 'renewal_expired');
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.kubernetes_gateway_certificate (
        public_id, workspace_id, network_id, kubernetes_cluster_id, device_id, issuer_ca_id, serial, public_key,
        public_key_sha256, certificate_sha256, not_before, not_after, issued_at, request_public_id, proof,
        machine_fingerprint, pod_name, jti, renewed_certificate_public_id
    ) VALUES (
        p_certificate_public_id, v_request.workspace_id, v_request.network_id, v_request.kubernetes_cluster_id,
        v_request.device_id, v_ca.id, p_serial, p_public_key, pg_catalog.sha256(p_public_key),
        pg_catalog.sha256(p_certificate), p_not_before, p_not_after, v_now, v_request.public_id, v_request.proof,
        v_request.machine_fingerprint, p_pod_name, p_jti, v_renewed
    )
    RETURNING id INTO v_certificate_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_request.workspace_id AND revision.network_id = v_request.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;
    -- The result names the revision: a gateway map at or past it shows the
    -- CAs as they were when this certificate was issued (a3 §14 R-M6).
    UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
    SET state = 'issued', token = NULL, claim_token = NULL, claim_expires_at = NULL,
        certificate_id = v_certificate_id, certificate = p_certificate, renew_at = p_renew_at,
        network_revision = v_revision, updated_at = v_now
    WHERE request.id = v_request.id;
    v_payload := mesh_ops.kubernetes_gateway_certificate_payload_internal_v1(v_certificate_id);
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'changed',
        'aggregate', 'kubernetes_gateway_certificate',
        'action', 'kubernetes_gateway.certificate_issued',
        'permission', 'system.reconcile',
        'row_id', p_certificate_public_id,
        'version', 1,
        'network_revision', v_revision,
        'semantic_hash', pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_payload::TEXT, 'UTF8')), 'hex'),
        'stream_id', v_stream.id,
        'sequence', v_stream.next_sequence,
        'previous_hash', pg_catalog.encode(v_stream.latest_event_hash, 'hex'),
        'payload', v_payload::TEXT
    );
END;
$function$;

-- Removes requests that ended (issued, refused), were abandoned, or waited
-- over 10 minutes unclaimed, and ledger rows past 13 months. A claimed
-- request stays while a worker may still settle it (R-L5): until a minute
-- past its lease.
CREATE OR REPLACE FUNCTION mesh_ops.prune_kubernetes_gateway_certificates_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_requests INTEGER;
    v_certificates INTEGER;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate retention input';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    WITH doomed AS (
        SELECT request.id FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.deployment_id = v_deployment_id AND request.created_at < v_now - INTERVAL '10 minutes'
          AND (request.state <> 'claimed' OR request.claim_expires_at < v_now - INTERVAL '1 minute')
        ORDER BY request.created_at
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    USING doomed WHERE request.id = doomed.id;
    GET DIAGNOSTICS v_requests = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    WITH doomed AS (
        SELECT issued.id FROM mesh.kubernetes_gateway_certificate AS issued
        JOIN mesh.workspace AS workspace ON workspace.id = issued.workspace_id
        WHERE workspace.deployment_id = v_deployment_id AND issued.issued_at < v_now - INTERVAL '13 months 1 day'
        ORDER BY issued.issued_at
        LIMIT p_limit
    )
    DELETE FROM mesh.kubernetes_gateway_certificate AS issued
    USING doomed WHERE issued.id = doomed.id
      AND NOT EXISTS (SELECT 1 FROM mesh_ops.kubernetes_gateway_certificate_request AS request
                      WHERE request.certificate_id = issued.id OR request.renewal_certificate_id = issued.id);
    GET DIAGNOSTICS v_certificates = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object('requests', v_requests, 'certificates', v_certificates);
END;
$function$;

-- ---- Restore guard ----

-- The guard as schema 240 read it, with when the tripwire was last checked.
CREATE OR REPLACE FUNCTION mesh_ops.read_kubernetes_ca_guard_v1(p_deployment_public_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_deployment_id BIGINT := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_guard mesh_ops.kubernetes_ca_guard%ROWTYPE;
    v_certificate_mark BIGINT;
    v_ca_mark BIGINT;
    v_finished TIMESTAMPTZ;
BEGIN
    SELECT guard.* INTO v_guard FROM mesh_ops.kubernetes_ca_guard AS guard WHERE guard.deployment_id = v_deployment_id;
    -- The newest certificate: exact for committed rows (a restored
    -- sequence may be logged ahead by up to 32, review a3a M5). Pruning
    -- removes the oldest only; an empty ledger falls back to the sequence.
    v_certificate_mark := COALESCE((SELECT pg_catalog.max(issued.id) FROM mesh.kubernetes_gateway_certificate AS issued),
        pg_catalog.pg_sequence_last_value(
            pg_catalog.pg_get_serial_sequence('mesh.kubernetes_gateway_certificate', 'id')::REGCLASS), 0);
    SELECT COALESCE((SELECT pg_catalog.sum(ca.version) FROM mesh.kubernetes_cluster_ca AS ca), 0)
        + COALESCE((SELECT pg_catalog.sum(data_key.version) FROM mesh.kubernetes_ca_data_key AS data_key), 0)
    INTO v_ca_mark;
    v_finished := pg_catalog.clock_timestamp();
    RETURN pg_catalog.jsonb_build_object(
        'suspected', COALESCE(v_guard.restore_suspected, FALSE),
        'generation', COALESCE(v_guard.generation, 1),
        'marked_at', v_guard.marked_at,
        'checked_at', v_guard.checked_at,
        'certificate_mark', v_certificate_mark,
        'ca_mark', v_ca_mark,
        'started_at', v_now,
        'finished_at', v_finished
    );
END;
$function$;

-- The lifecycle worker compared the marks for p_generation and found no
-- restore (or has no marks to compare): signing may go on for 10 minutes
-- (R-M9). Outcome 'stale' when the generation moved or a restore is
-- suspected.
CREATE FUNCTION mesh_ops.stamp_kubernetes_ca_guard_v1(p_deployment_public_id UUID, p_generation BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    IF p_generation IS NULL OR p_generation < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA guard stamp';
    END IF;
    INSERT INTO mesh_ops.kubernetes_ca_guard AS guard (
        deployment_id, generation, restore_suspected, checked_at, updated_at
    )
    SELECT v_deployment_id, 1, FALSE, v_now, v_now WHERE p_generation = 1
    ON CONFLICT (deployment_id) DO UPDATE
    SET checked_at = EXCLUDED.checked_at
    WHERE guard.generation = p_generation AND NOT guard.restore_suspected;
    IF FOUND THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stamped');
    END IF;
    UPDATE mesh_ops.kubernetes_ca_guard AS guard
    SET checked_at = v_now
    WHERE guard.deployment_id = v_deployment_id AND guard.generation = p_generation AND NOT guard.restore_suspected;
    IF FOUND THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stamped');
    END IF;
    RETURN pg_catalog.jsonb_build_object('outcome', 'stale');
END;
$function$;

-- Resumes CA work as schema 240 did; signing waits for the lifecycle
-- worker's next comparison of the marks of the new generation (review a3b
-- SQL L6).
CREATE OR REPLACE FUNCTION mesh_ops.clear_kubernetes_ca_restore_v1(
    p_deployment_public_id UUID, p_generation BIGINT, p_actor TEXT, p_change_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_guard mesh_ops.kubernetes_ca_guard%ROWTYPE;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_active BOOLEAN;
BEGIN
    IF p_generation IS NULL OR p_actor IS NULL OR p_change_ref IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA restore clearance';
    END IF;
    SELECT guard.* INTO v_guard FROM mesh_ops.kubernetes_ca_guard AS guard
    WHERE guard.deployment_id = v_deployment_id FOR UPDATE;
    IF v_guard.deployment_id IS NULL OR NOT v_guard.restore_suspected THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'clear');
    END IF;
    IF v_guard.generation <> p_generation THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stale');
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT EXISTS (
        SELECT 1 FROM mesh.kubernetes_cluster_ca AS ca
        JOIN mesh.workspace AS workspace ON workspace.id = ca.workspace_id
        WHERE workspace.deployment_id = v_deployment_id AND ca.kind = 'intermediate' AND ca.state = 'active'
    ) INTO v_active;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_active THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'intermediates_active');
    END IF;
    UPDATE mesh_ops.kubernetes_ca_guard AS guard
    SET restore_suspected = FALSE,
        generation = GREATEST(guard.generation + 1,
            (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
        cleared_at = pg_catalog.clock_timestamp(),
        cleared_by = p_actor, cleared_ref = p_change_ref, checked_at = NULL,
        updated_at = pg_catalog.clock_timestamp()
    WHERE guard.deployment_id = v_deployment_id;
    RETURN pg_catalog.jsonb_build_object('outcome', 'cleared', 'generation', (
        SELECT guard.generation FROM mesh_ops.kubernetes_ca_guard AS guard WHERE guard.deployment_id = v_deployment_id));
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_certificate_in_flight_internal_v1(TEXT, TIMESTAMPTZ, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_ca_signing_state_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_gateway_certificate_token_v1(
    UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TEXT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.stamp_kubernetes_ca_guard_v1(UUID, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Control reads whether anyone signs; only the worker records token claims
-- and stamps the guard.
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_ca_signing_state_v1() TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_gateway_certificate_token_v1(
    UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TEXT, BIGINT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.stamp_kubernetes_ca_guard_v1(UUID, BIGINT) TO mesh_worker;
