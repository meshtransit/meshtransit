-- Schema 240 (K1a4a a3a, docs/k8s-k1a4-a3-signing-design.md v2, owner
-- decisions Q29–Q35): Kubernetes gateways get 24-hour replica certificates
-- that the worker signs with their cluster's intermediate.
--
-- - Control queues a gateway's request (mesh_runtime) for the keys its
--   session proved; the worker claims it with a 30-second lease, checks
--   the pod token or the renewal signature itself, signs outside any
--   transaction, and issues it in one transaction that checks again the
--   Device, cluster and CA, uses the token once for that key, writes the
--   certificate ledger and its sealed audit event.
-- - The ledger keeps what was issued (no key material, no certificate) for
--   13 months; requests live 10 minutes.
-- - A guard per installation stops all CA work once the database looks
--   restored, until an operator reconciles (§5). The worker compares the
--   marks below with ones it keeps outside the database.
-- - A worker change that touches a CA advances the Network revision once,
--   so gateway maps learn the CAs that sign.

-- A token is used also for a certificate: once per cluster and jti, for
-- whatever key (replaced_key is zero for this purpose).
ALTER TABLE mesh_ops.kubernetes_gateway_token_use
    ADD CONSTRAINT kubernetes_gateway_token_use_purpose_v2_check
        CHECK (purpose IN ('machine_key', 'node_key', 'cert')) NOT VALID;
ALTER TABLE mesh_ops.kubernetes_gateway_token_use
    VALIDATE CONSTRAINT kubernetes_gateway_token_use_purpose_v2_check;
ALTER TABLE mesh_ops.kubernetes_gateway_token_use DROP CONSTRAINT kubernetes_gateway_token_use_purpose_check;

-- Each replica certificate issued. Rows are never changed; they are removed
-- 13 months after issue.
CREATE TABLE mesh.kubernetes_gateway_certificate (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    issuer_ca_id BIGINT NOT NULL,
    -- 127 bits: 126 random below a set top bit.
    serial BYTEA NOT NULL UNIQUE CHECK (pg_catalog.octet_length(serial) = 16),
    public_key BYTEA NOT NULL CHECK (pg_catalog.octet_length(public_key) BETWEEN 64 AND 128),
    public_key_sha256 BYTEA NOT NULL CHECK (public_key_sha256 = pg_catalog.sha256(public_key)),
    certificate_sha256 BYTEA NOT NULL CHECK (pg_catalog.octet_length(certificate_sha256) = 32),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    request_public_id UUID NOT NULL,
    proof TEXT NOT NULL CHECK (proof IN ('token', 'renewal')),
    machine_fingerprint BYTEA NOT NULL CHECK (pg_catalog.octet_length(machine_fingerprint) = 32),
    pod_name TEXT CHECK (pg_catalog.octet_length(pod_name) BETWEEN 1 AND 253 AND pod_name ~ '^[a-z0-9.-]+$'),
    jti TEXT CHECK (pg_catalog.octet_length(jti) BETWEEN 1 AND 128 AND jti ~ '^[!-~]+$'),
    renewed_certificate_public_id UUID,
    CONSTRAINT kubernetes_gateway_certificate_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_gateway_certificate_validity_check CHECK (
        not_after > not_before AND not_after <= not_before + INTERVAL '25 hours'
    ),
    CONSTRAINT kubernetes_gateway_certificate_evidence_check CHECK (
        (proof = 'token' AND jti IS NOT NULL AND pod_name IS NOT NULL AND renewed_certificate_public_id IS NULL)
        OR (proof = 'renewal' AND jti IS NULL AND pod_name IS NULL AND renewed_certificate_public_id IS NOT NULL)
    ),
    CONSTRAINT kubernetes_gateway_certificate_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_gateway_certificate_issuer_fk
        FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id, issuer_ca_id)
        REFERENCES mesh.kubernetes_cluster_ca (workspace_id, network_id, kubernetes_cluster_id, id) ON DELETE RESTRICT
);
CREATE INDEX kubernetes_gateway_certificate_device_idx
    ON mesh.kubernetes_gateway_certificate (device_id, issued_at DESC);
CREATE INDEX kubernetes_gateway_certificate_issued_idx ON mesh.kubernetes_gateway_certificate (issued_at);
CREATE INDEX kubernetes_gateway_certificate_issuer_idx ON mesh.kubernetes_gateway_certificate (issuer_ca_id);

-- A gateway's request for a certificate, from control's queue to the
-- worker's result. One per Device and gateway-chosen request id.
CREATE TABLE mesh_ops.kubernetes_gateway_certificate_request (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    request_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(request_id) = 16),
    csr BYTEA NOT NULL CHECK (pg_catalog.octet_length(csr) BETWEEN 64 AND 4096),
    public_key_sha256 BYTEA NOT NULL CHECK (pg_catalog.octet_length(public_key_sha256) = 32),
    machine_fingerprint BYTEA NOT NULL CHECK (pg_catalog.octet_length(machine_fingerprint) = 32),
    proof TEXT NOT NULL CHECK (proof IN ('token', 'renewal')),
    -- The pod token, kept until the request ends; never logged.
    token TEXT CHECK (pg_catalog.octet_length(token) BETWEEN 1 AND 8192),
    handshake_hash BYTEA CHECK (pg_catalog.octet_length(handshake_hash) = 32),
    renewal_certificate_id BIGINT REFERENCES mesh.kubernetes_gateway_certificate (id) ON DELETE CASCADE,
    renewal_proof BYTEA CHECK (pg_catalog.octet_length(renewal_proof) BETWEEN 8 AND 72),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'issued', 'refused', 'abandoned')),
    reason TEXT CHECK (reason ~ '^[a-z][a-z_]{0,31}$'),
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 16),
    certificate_id BIGINT REFERENCES mesh.kubernetes_gateway_certificate (id) ON DELETE CASCADE,
    certificate BYTEA CHECK (pg_catalog.octet_length(certificate) BETWEEN 64 AND 4096),
    renew_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (device_id, request_id),
    CONSTRAINT kubernetes_gateway_certificate_request_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_gateway_certificate_request_evidence_check CHECK (
        (proof = 'token' AND handshake_hash IS NULL AND renewal_certificate_id IS NULL AND renewal_proof IS NULL
            AND (token IS NOT NULL) = (state IN ('pending', 'claimed', 'abandoned')))
        OR (proof = 'renewal' AND token IS NULL AND handshake_hash IS NOT NULL AND renewal_certificate_id IS NOT NULL
            AND renewal_proof IS NOT NULL)
    ),
    CONSTRAINT kubernetes_gateway_certificate_request_lifecycle_check CHECK (
        (state IN ('pending', 'abandoned') AND claim_token IS NULL AND claim_expires_at IS NULL AND reason IS NULL
            AND certificate_id IS NULL AND certificate IS NULL AND renew_at IS NULL)
        OR (state = 'claimed' AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL AND reason IS NULL
            AND certificate_id IS NULL AND certificate IS NULL AND renew_at IS NULL)
        OR (state = 'issued' AND claim_token IS NULL AND claim_expires_at IS NULL AND reason IS NULL
            AND certificate_id IS NOT NULL AND certificate IS NOT NULL AND renew_at IS NOT NULL)
        OR (state = 'refused' AND claim_token IS NULL AND claim_expires_at IS NULL AND reason IS NOT NULL
            AND certificate_id IS NULL AND certificate IS NULL AND renew_at IS NULL)
    ),
    CONSTRAINT kubernetes_gateway_certificate_request_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT
);
CREATE INDEX kubernetes_gateway_certificate_request_pending_idx
    ON mesh_ops.kubernetes_gateway_certificate_request (deployment_id, created_at, id) WHERE state = 'pending';
CREATE INDEX kubernetes_gateway_certificate_request_claimed_idx
    ON mesh_ops.kubernetes_gateway_certificate_request (deployment_id, claim_expires_at) WHERE state = 'claimed';
CREATE INDEX kubernetes_gateway_certificate_request_cluster_idx
    ON mesh_ops.kubernetes_gateway_certificate_request (kubernetes_cluster_id)
    WHERE state IN ('pending', 'claimed', 'abandoned');
CREATE INDEX kubernetes_gateway_certificate_request_created_idx
    ON mesh_ops.kubernetes_gateway_certificate_request (created_at);
CREATE INDEX kubernetes_gateway_certificate_request_renewal_idx
    ON mesh_ops.kubernetes_gateway_certificate_request (renewal_certificate_id) WHERE renewal_certificate_id IS NOT NULL;
CREATE INDEX kubernetes_gateway_certificate_request_certificate_idx
    ON mesh_ops.kubernetes_gateway_certificate_request (certificate_id) WHERE certificate_id IS NOT NULL;

-- Whether an installation's CA work is stopped because its database looks
-- restored (§5). generation moves forward each time an operator reconciles,
-- so the worker's outside marks restart from the database then.
CREATE TABLE mesh_ops.kubernetes_ca_guard (
    deployment_id BIGINT PRIMARY KEY REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    generation BIGINT NOT NULL CHECK (generation >= 1),
    restore_suspected BOOLEAN NOT NULL,
    marked_at TIMESTAMPTZ,
    marked_by TEXT CHECK (pg_catalog.octet_length(marked_by) BETWEEN 1 AND 128 AND marked_by ~ '^[ -~]+$'),
    marked_ref TEXT CHECK (pg_catalog.octet_length(marked_ref) BETWEEN 1 AND 128 AND marked_ref ~ '^[ -~]+$'),
    cleared_at TIMESTAMPTZ,
    cleared_by TEXT CHECK (pg_catalog.octet_length(cleared_by) BETWEEN 1 AND 128 AND cleared_by ~ '^[ -~]+$'),
    cleared_ref TEXT CHECK (pg_catalog.octet_length(cleared_ref) BETWEEN 1 AND 128 AND cleared_ref ~ '^[ -~]+$'),
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_ca_guard_marked_check CHECK (
        (marked_at IS NULL) = (marked_by IS NULL) AND (marked_by IS NULL) = (marked_ref IS NULL)
        AND (NOT restore_suspected OR marked_at IS NOT NULL)
    ),
    CONSTRAINT kubernetes_ca_guard_cleared_check CHECK (
        (cleared_at IS NULL) = (cleared_by IS NULL) AND (cleared_by IS NULL) = (cleared_ref IS NULL)
    )
);

ALTER TABLE mesh.kubernetes_gateway_certificate ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_gateway_certificate FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_certificate_migrator_policy ON mesh.kubernetes_gateway_certificate
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.kubernetes_gateway_certificate_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_certificate_request FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_certificate_request_migrator_policy
    ON mesh_ops.kubernetes_gateway_certificate_request TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.kubernetes_ca_guard ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_ca_guard FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_ca_guard_migrator_policy ON mesh_ops.kubernetes_ca_guard
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_gateway_certificate, mesh_ops.kubernetes_gateway_certificate_request,
    mesh_ops.kubernetes_ca_guard
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Only an issue is authority; removal after 13 months is retention.
CREATE TRIGGER kubernetes_gateway_certificate_authority_mutation
AFTER INSERT ON mesh.kubernetes_gateway_certificate
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_gateway_certificate', 'public_id');

CREATE FUNCTION mesh_ops.guard_kubernetes_gateway_certificate_row_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.issued_at < pg_catalog.clock_timestamp() - INTERVAL '13 months' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Kubernetes gateway certificates are kept as issued';
END;
$function$;
CREATE TRIGGER kubernetes_gateway_certificate_guard
BEFORE UPDATE OR DELETE ON mesh.kubernetes_gateway_certificate
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_kubernetes_gateway_certificate_row_v1();
REVOKE ALL ON FUNCTION mesh_ops.guard_kubernetes_gateway_certificate_row_v1() FROM PUBLIC;

-- While a restore is suspected the worker changes no CA or data key: only
-- an operator's change (with changed_by, as reconcile-after-restore's
-- retirements) goes through, whatever a worker pass read before the mark
-- (review a3a M3).
CREATE FUNCTION mesh_ops.refuse_kubernetes_ca_change_while_restored_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_suspected BOOLEAN;
BEGIN
    IF NEW.changed_by IS NOT NULL THEN
        RETURN NEW;
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT COALESCE(guard.restore_suspected, FALSE) INTO v_suspected
    FROM mesh.workspace AS workspace
    LEFT JOIN mesh_ops.kubernetes_ca_guard AS guard ON guard.deployment_id = workspace.deployment_id
    WHERE workspace.id = NEW.workspace_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_suspected THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK30', MESSAGE = 'Kubernetes CA work is stopped: a database restore is suspected';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.refuse_kubernetes_ca_change_while_restored_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER kubernetes_cluster_ca_restore_guard
BEFORE INSERT OR UPDATE ON mesh.kubernetes_cluster_ca
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_ca_change_while_restored_v1();
CREATE TRIGGER kubernetes_ca_data_key_restore_guard
BEFORE INSERT OR UPDATE ON mesh.kubernetes_ca_data_key
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_ca_change_while_restored_v1();

-- Schema 239's proof, plus: the first CA change of a transaction advances
-- the Network revision, once, before its audit event binds to it, so
-- gateway maps learn which CAs sign (a3 §3). A data key change alone moves
-- nothing a map shows.
CREATE OR REPLACE FUNCTION mesh_ops.kubernetes_ca_proof_internal_v1(p_aggregate TEXT, p_row_id BIGINT, p_operation TEXT)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_row RECORD;
    v_revision BIGINT;
    v_stream RECORD;
    v_payload JSONB;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_transaction TEXT := pg_catalog.pg_current_xact_id()::TEXT;
    v_scope_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    v_scope_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
    v_advanced INTEGER;
BEGIN
    IF p_aggregate = 'kubernetes_cluster_ca' THEN
        SELECT ca.public_id, ca.version, ca.workspace_id, ca.network_id, ca.changed_by INTO STRICT v_row
        FROM mesh.kubernetes_cluster_ca AS ca WHERE ca.id = p_row_id;
    ELSE
        SELECT data_key.public_id, data_key.version, data_key.workspace_id, data_key.network_id,
            data_key.changed_by INTO STRICT v_row
        FROM mesh.kubernetes_ca_data_key AS data_key WHERE data_key.id = p_row_id;
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    -- The first CA change of the Network in this transaction advances it:
    -- told by the transaction's own CA mutations, which a caller cannot
    -- forge (review a3a L6).
    IF p_aggregate = 'kubernetes_cluster_ca' AND (
        SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
        JOIN mesh.kubernetes_cluster_ca AS ca ON ca.public_id = mutation.row_public_id
        WHERE mutation.transaction_id = v_transaction::BIGINT AND mutation.aggregate_kind = 'kubernetes_cluster_ca'
          AND ca.workspace_id = v_row.workspace_id AND ca.network_id = v_row.network_id
    ) = 1 THEN
        -- The owner updates a revision only in the Network scope it names
        -- (schema 9's policy); a filtered update would advance nothing.
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_row.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_row.network_id::TEXT, TRUE);
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1, updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = v_row.workspace_id AND revision.network_id = v_row.network_id;
        GET DIAGNOSTICS v_advanced = ROW_COUNT;
        PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_scope_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_scope_network, ''), TRUE);
        IF v_advanced <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
        END IF;
    END IF;
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_row.workspace_id AND revision.network_id = v_row.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_row.workspace_id AND stream.network_id = v_row.network_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    v_payload := mesh_ops.kubernetes_ca_payload_internal_v1(p_aggregate, p_row_id);
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'changed',
        'aggregate', p_aggregate,
        'action', mesh_ops.kubernetes_ca_action_internal_v1(p_aggregate, p_operation, p_row_id),
        'permission', CASE WHEN v_row.changed_by IS NULL THEN 'system.reconcile' ELSE 'system.operator' END,
        'row_id', v_row.public_id,
        'version', v_row.version,
        'network_revision', v_revision,
        'semantic_hash', pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_payload::TEXT, 'UTF8')), 'hex'),
        'stream_id', v_stream.id,
        'sequence', v_stream.next_sequence,
        'previous_hash', pg_catalog.encode(v_stream.latest_event_hash, 'hex'),
        'payload', v_payload::TEXT
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_proof_internal_v1(TEXT, BIGINT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- ---- Requests (control) ----

-- What a request's gateway receives: the state, a refusal's reason, or the
-- certificate with the intermediate that signed it, the fingerprints of
-- that intermediate and its root, and when to renew.
CREATE FUNCTION mesh_ops.kubernetes_gateway_certificate_result_internal_v1(p_request_id BIGINT)
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
        'reason', request.reason,
        'certificate', pg_catalog.encode(request.certificate, 'hex'),
        'chain', CASE WHEN issued.id IS NULL THEN NULL
            ELSE pg_catalog.jsonb_build_array(pg_catalog.encode(intermediate.certificate, 'hex')) END,
        'issuer_fingerprint', pg_catalog.encode(intermediate.fingerprint, 'hex'),
        'root_fingerprint', pg_catalog.encode(root.fingerprint, 'hex'),
        'not_after', issued.not_after,
        'renew_at', request.renew_at
    )
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    LEFT JOIN mesh.kubernetes_gateway_certificate AS issued ON issued.id = request.certificate_id
    LEFT JOIN mesh.kubernetes_cluster_ca AS intermediate ON intermediate.id = issued.issuer_ca_id
    LEFT JOIN mesh.kubernetes_cluster_ca AS root ON root.id = intermediate.issuer_ca_id
    WHERE request.id = p_request_id
$function$;

-- Queues a certificate request of the gateway the session proved (schema
-- 226's mark, in this transaction), with either its pod token or a renewal
-- signature by the key of a certificate it still holds (the serial names
-- it). Control checked both already; the worker checks again. A request
-- id seen before returns that request: still waiting, issued (its result),
-- refused, or waiting again if it was abandoned; with another key or proof,
-- 'conflict'. Limits (Q31): 12 issued per Device and hour, 2 in flight per
-- Device, 20 per cluster, 1000 per installation; over one, 'limited' with
-- when to try again. Lock order: the Device (FOR UPDATE), the cluster (FOR
-- SHARE), the request.
CREATE FUNCTION mesh_ops.enqueue_kubernetes_gateway_certificate_v1(
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

    -- Limits, for a new request and for an abandoned one that waits again
    -- (review a3a M3). An abandoned request counts as in flight until it is
    -- removed, so abandoning requests does not make room for more. The
    -- cluster and installation limits are soft: requests of other Devices
    -- queued at the same moment may pass them by a few.
    SELECT pg_catalog.min(issued.issued_at), pg_catalog.count(*) INTO v_oldest, v_count
    FROM mesh.kubernetes_gateway_certificate AS issued
    WHERE issued.device_id = v_device.id AND issued.issued_at > v_now - INTERVAL '1 hour';
    IF v_count >= 12 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'limited',
            'retry_after_ms', GREATEST(1000, (EXTRACT(EPOCH FROM (v_oldest + INTERVAL '1 hour' - v_now)) * 1000)::BIGINT));
    END IF;
    IF v_request.id IS NOT NULL THEN
        -- Waits again with the proof the gateway sent now; it was counted
        -- in flight all along.
        UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
        SET state = 'pending', token = p_token, handshake_hash = p_handshake_hash,
            renewal_certificate_id = v_renewal_id, renewal_proof = p_renewal_proof, updated_at = v_now
        WHERE request.id = v_request.id AND request.state = 'abandoned';
        RETURN mesh_ops.kubernetes_gateway_certificate_result_internal_v1(v_request.id);
    END IF;
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.device_id = v_device.id AND request.state IN ('pending', 'claimed', 'abandoned')) >= 2 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'limited', 'retry_after_ms', 2000);
    END IF;
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.kubernetes_cluster_id = v_device.kubernetes_cluster_id
          AND request.state IN ('pending', 'claimed', 'abandoned')) >= 20 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'limited', 'retry_after_ms', 2000);
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT workspace.deployment_id INTO STRICT v_deployment_id
    FROM mesh.workspace AS workspace WHERE workspace.id = v_device.workspace_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF (SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.deployment_id = v_deployment_id AND request.state IN ('pending', 'claimed', 'abandoned'))
        >= 1000 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'limited', 'reason', 'overloaded', 'retry_after_ms', 2000);
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

-- Reads a request of a Device, as enqueue returns it; NULL when there is
-- none (it was removed after 10 minutes).
CREATE FUNCTION mesh_ops.read_kubernetes_gateway_certificate_v1(p_device_public_id UUID, p_request_public_id UUID)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.kubernetes_gateway_certificate_result_internal_v1(request.id)
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    JOIN mesh.device AS device ON device.id = request.device_id
    WHERE device.public_id = p_device_public_id AND request.public_id = p_request_public_id
$function$;

-- Control stopped waiting: a request no worker claimed yet is abandoned (a
-- claimed one is still signed). Returns the request as read.
CREATE FUNCTION mesh_ops.abandon_kubernetes_gateway_certificate_v1(p_device_public_id UUID, p_request_public_id UUID)
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
    SELECT request.id INTO v_request_id
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    JOIN mesh.device AS device ON device.id = request.device_id
    WHERE device.public_id = p_device_public_id AND request.public_id = p_request_public_id
    FOR UPDATE OF request;
    IF v_request_id IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
    SET state = 'abandoned', updated_at = pg_catalog.clock_timestamp()
    WHERE request.id = v_request_id AND request.state = 'pending';
    RETURN mesh_ops.kubernetes_gateway_certificate_result_internal_v1(v_request_id);
END;
$function$;

-- ---- Signing (worker) ----

-- Whether a restore is suspected in the installation.
CREATE FUNCTION mesh_ops.kubernetes_ca_guard_suspected_internal_v1(p_deployment_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE((SELECT guard.restore_suspected FROM mesh_ops.kubernetes_ca_guard AS guard
        WHERE guard.deployment_id = p_deployment_id), FALSE)
$function$;

-- What the worker signs a claimed request from: the request, its Device,
-- cluster and tenant codes, the cluster's signing trust and the pod its join
-- named (a token request), the key of the certificate it renews (a renewal),
-- and the cluster's active intermediate with its root and data key. Never
-- in a log.
CREATE FUNCTION mesh_ops.kubernetes_gateway_certificate_claim_internal_v1(p_request_id BIGINT)
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
        'handshake_hash', pg_catalog.encode(request.handshake_hash, 'hex'),
        'renewal_proof', pg_catalog.encode(request.renewal_proof, 'hex'),
        'renewal_public_key', pg_catalog.encode(renewed.public_key, 'hex'),
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

-- Claims up to p_limit pending requests of the installation, oldest first,
-- for p_lease_seconds: a request whose lease ran out waits again, or after
-- three leases is refused (H5). Nothing is claimed while a restore is
-- suspected. Several workers claim apart (SKIP LOCKED).
CREATE FUNCTION mesh_ops.claim_kubernetes_gateway_certificates_v1(
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
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_requests JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 64 OR p_lease_seconds IS NULL
        OR p_lease_seconds NOT BETWEEN 5 AND 120 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate claim';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    IF mesh_ops.kubernetes_ca_guard_suspected_internal_v1(v_deployment_id) THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'suspected', 'now', v_now, 'pending', 0,
            'refused_attempts', 0, 'requests', '[]'::JSONB);
    END IF;
    WITH expired AS (
        UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
        SET state = CASE WHEN request.attempts >= 3 THEN 'refused' ELSE 'pending' END,
            reason = CASE WHEN request.attempts >= 3 THEN 'attempts' END,
            token = CASE WHEN request.attempts >= 3 THEN NULL ELSE request.token END,
            claim_token = NULL, claim_expires_at = NULL, updated_at = v_now
        WHERE request.deployment_id = v_deployment_id AND request.state = 'claimed'
          AND request.claim_expires_at < v_now
        RETURNING request.state
    )
    SELECT pg_catalog.count(*) FILTER (WHERE expired.state = 'refused') INTO v_refused FROM expired;
    WITH picked AS (
        SELECT request.id FROM mesh_ops.kubernetes_gateway_certificate_request AS request
        WHERE request.deployment_id = v_deployment_id AND request.state = 'pending'
        ORDER BY request.created_at, request.id
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
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

-- A claimed request of the installation, locked, if p_claim_token still
-- holds it.
CREATE FUNCTION mesh_ops.kubernetes_gateway_certificate_held_internal_v1(
    p_deployment_public_id UUID, p_request_public_id UUID, p_claim_token UUID
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_request_id BIGINT;
BEGIN
    SELECT request.id INTO v_request_id
    FROM mesh_ops.kubernetes_gateway_certificate_request AS request
    WHERE request.public_id = p_request_public_id
      AND request.deployment_id = mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id)
      AND request.state = 'claimed' AND request.claim_token = p_claim_token
    FOR UPDATE;
    RETURN v_request_id;
END;
$function$;

-- Ends a held request as refused; outcome 'lost' when the claim no longer
-- holds it.
CREATE FUNCTION mesh_ops.refuse_kubernetes_gateway_certificate_v1(
    p_deployment_public_id UUID, p_request_public_id UUID, p_claim_token UUID, p_reason TEXT
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
    IF p_reason IS NULL OR p_reason !~ '^[a-z][a-z_]{0,31}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway certificate refusal';
    END IF;
    v_request_id := mesh_ops.kubernetes_gateway_certificate_held_internal_v1(
        p_deployment_public_id, p_request_public_id, p_claim_token);
    IF v_request_id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'lost');
    END IF;
    UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
    SET state = 'refused', reason = p_reason, token = NULL, claim_token = NULL, claim_expires_at = NULL,
        updated_at = pg_catalog.clock_timestamp()
    WHERE request.id = v_request_id;
    RETURN pg_catalog.jsonb_build_object('outcome', 'refused', 'reason', p_reason);
END;
$function$;

-- Gives a held request back to wait again (a worker stopping, or a CA that
-- changed while it signed), without counting the claim as an attempt;
-- outcome 'lost' when the claim no longer holds it.
CREATE FUNCTION mesh_ops.release_kubernetes_gateway_certificate_v1(
    p_deployment_public_id UUID, p_request_public_id UUID, p_claim_token UUID
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
    v_request_id := mesh_ops.kubernetes_gateway_certificate_held_internal_v1(
        p_deployment_public_id, p_request_public_id, p_claim_token);
    IF v_request_id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'lost');
    END IF;
    UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
    SET state = 'pending', claim_token = NULL, claim_expires_at = NULL, attempts = request.attempts - 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE request.id = v_request_id;
    RETURN pg_catalog.jsonb_build_object('outcome', 'released');
END;
$function$;

-- What a certificate's audit event says: never key material or the
-- certificate.
CREATE FUNCTION mesh_ops.kubernetes_gateway_certificate_payload_internal_v1(p_certificate_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'format', 'kubernetes-gateway-certificate/v1',
        'certificate_id', issued.public_id,
        'device_id', device.public_id,
        'cluster_id', cluster.public_id,
        'issuer_id', issuer.public_id,
        'serial', pg_catalog.encode(issued.serial, 'hex'),
        'public_key_sha256', pg_catalog.encode(issued.public_key_sha256, 'hex'),
        'certificate_sha256', pg_catalog.encode(issued.certificate_sha256, 'hex'),
        'not_before', issued.not_before,
        'not_after', issued.not_after,
        'proof', issued.proof,
        'machine_fingerprint', pg_catalog.encode(issued.machine_fingerprint, 'hex'),
        'pod_name', issued.pod_name,
        'jti', issued.jti,
        'renewed_certificate_id', issued.renewed_certificate_public_id,
        'request_id', issued.request_public_id
    )
    FROM mesh.kubernetes_gateway_certificate AS issued
    JOIN mesh.device AS device ON device.id = issued.device_id
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = issued.kubernetes_cluster_id
    JOIN mesh.kubernetes_cluster_ca AS issuer ON issuer.id = issued.issuer_ca_id
    WHERE issued.id = p_certificate_id
$function$;

-- Issues a held request with the certificate the worker signed, in one
-- transaction (H2): the Device still an active gateway of the cluster, the
-- cluster active, the intermediate still active at p_ca_version, no restore
-- suspected; a pod token used once for this key (purpose 'cert'), or the
-- renewed certificate still valid. Then the ledger row, the request's
-- result and the proof for the audit event (permission system.reconcile,
-- not bound to a revision: Q32). Outcomes: 'issued' (the proof), 'refused'
-- (with its reason), 'requeued' (the CA changed: signed again later),
-- 'suspected' (given back), 'lost' (the claim ran out). A pod token's
-- trust must still be at the version the worker checked it against.
CREATE FUNCTION mesh_ops.issue_kubernetes_gateway_certificate_v1(
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
    UPDATE mesh_ops.kubernetes_gateway_certificate_request AS request
    SET state = 'issued', token = NULL, claim_token = NULL, claim_expires_at = NULL,
        certificate_id = v_certificate_id, certificate = p_certificate, renew_at = p_renew_at, updated_at = v_now
    WHERE request.id = v_request.id;

    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_request.workspace_id AND revision.network_id = v_request.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;
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

-- Appends the audit event of the certificate this transaction issued, at
-- the Network revision issue read and the worker hashed (Q32: not bound to
-- the current one, which may have moved since; review a3a H1).
CREATE FUNCTION mesh_ops.append_kubernetes_gateway_certificate_evidence_v1(
    p_certificate_public_id UUID,
    p_stream_id BIGINT,
    p_sequence BIGINT,
    p_previous_hash BYTEA,
    p_event_hash BYTEA,
    p_audit_event_public_id UUID,
    p_outbox_public_id UUID,
    p_payload JSONB,
    p_network_revision BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    v_change UUID;
    v_transaction BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    v_row RECORD;
    v_revision BIGINT;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    BEGIN
        v_change := NULLIF(pg_catalog.current_setting('mesh.change_public_id', TRUE), '')::UUID;
    EXCEPTION WHEN invalid_text_representation THEN
        v_change := NULL;
    END;
    IF v_change IS NULL OR p_certificate_public_id IS NULL OR p_stream_id IS NULL
        OR p_sequence IS NULL OR p_sequence <= 0
        OR p_previous_hash IS NULL OR pg_catalog.octet_length(p_previous_hash) <> 32
        OR p_event_hash IS NULL OR pg_catalog.octet_length(p_event_hash) <> 32
        OR p_audit_event_public_id IS NULL OR p_outbox_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_audit_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_outbox_public_id), 6) >> 4 <> 7
        OR p_audit_event_public_id = p_outbox_public_id
        OR p_audit_event_public_id IN (v_change, p_certificate_public_id)
        OR p_outbox_public_id IN (v_change, p_certificate_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes gateway certificate evidence';
    END IF;
    SELECT issued.id, issued.public_id, issued.workspace_id, issued.network_id INTO v_row
    FROM mesh.kubernetes_gateway_certificate AS issued WHERE issued.public_id = p_certificate_public_id;
    IF v_row.id IS NULL
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
              AND mutation.aggregate_kind = 'kubernetes_gateway_certificate'
              AND mutation.row_public_id = p_certificate_public_id AND mutation.operation = 'insert')
        OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.audit_stream AS stream
            WHERE stream.id = p_stream_id AND stream.scope_kind = 'network'
              AND stream.workspace_id = v_row.workspace_id AND stream.network_id = v_row.network_id)
        OR p_payload IS DISTINCT FROM mesh_ops.kubernetes_gateway_certificate_payload_internal_v1(v_row.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes gateway certificate evidence';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT revision.network_revision INTO STRICT v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_row.workspace_id AND revision.network_id = v_row.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF p_network_revision IS NULL OR p_network_revision < 1 OR p_network_revision > v_revision THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes gateway certificate evidence';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_audit_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'kubernetes_gateway_certificate', v_row.public_id, 1, p_network_revision, NULL::UUID,
        'kubernetes_gateway.certificate_issued', 'system.reconcile', NULL::UUID, NULL::BYTEA,
        pg_catalog.sha256(pg_catalog.convert_to(p_payload::TEXT, 'UTF8')),
        p_payload, 'kubernetes_gateway.certificate_issued', p_payload
    );
END;
$function$;

-- Removes requests older than 10 minutes and ledger rows older than 13
-- months of the installation, oldest first, at most p_limit of each.
CREATE FUNCTION mesh_ops.prune_kubernetes_gateway_certificates_v1(p_deployment_public_id UUID, p_limit INTEGER)
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

-- ---- Restore guard (§5) ----

-- The installation's guard and the marks the worker compares with its own
-- outside the database: the newest certificate, and the sum of the versions of every CA and data key (rows
-- never deleted). Both only grow, unless the database goes back.
-- started_at is read before the marks and finished_at after, so the worker
-- can tell a read that began after another one ended (review a3a M2).
CREATE FUNCTION mesh_ops.read_kubernetes_ca_guard_v1(p_deployment_public_id UUID)
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
        'certificate_mark', v_certificate_mark,
        'ca_mark', v_ca_mark,
        'started_at', v_now,
        'finished_at', v_finished
    );
END;
$function$;

-- Stops the installation's CA work: an operator after a restore (the
-- runbook's mandatory step), or the worker when its marks show one.
CREATE FUNCTION mesh_ops.mark_kubernetes_ca_restored_v1(p_deployment_public_id UUID, p_actor TEXT, p_change_ref TEXT)
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
    v_generation BIGINT;
BEGIN
    IF p_actor IS NULL OR p_change_ref IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA restore mark';
    END IF;
    INSERT INTO mesh_ops.kubernetes_ca_guard AS guard (
        deployment_id, generation, restore_suspected, marked_at, marked_by, marked_ref, updated_at
    ) VALUES (v_deployment_id, 1, TRUE, v_now, p_actor, p_change_ref, v_now)
    ON CONFLICT (deployment_id) DO UPDATE
    SET restore_suspected = TRUE,
        marked_at = CASE WHEN guard.restore_suspected THEN guard.marked_at ELSE EXCLUDED.marked_at END,
        marked_by = CASE WHEN guard.restore_suspected THEN guard.marked_by ELSE EXCLUDED.marked_by END,
        marked_ref = CASE WHEN guard.restore_suspected THEN guard.marked_ref ELSE EXCLUDED.marked_ref END,
        updated_at = EXCLUDED.updated_at
    RETURNING guard.generation INTO v_generation;
    RETURN pg_catalog.jsonb_build_object('outcome', 'suspected', 'generation', v_generation);
END;
$function$;

-- Resumes the installation's CA work after an operator reconciled: only
-- once no intermediate is active (reconcile retired them all, §5), and only
-- for the generation the operator read. The next generation tells the
-- worker to take the database's marks as its own again; it is at least the
-- clock in ms, so it is above any generation the worker saw before a
-- restore brought an older one back (review a3a M1).
CREATE FUNCTION mesh_ops.clear_kubernetes_ca_restore_v1(
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
        cleared_by = p_actor, cleared_ref = p_change_ref, updated_at = pg_catalog.clock_timestamp()
    WHERE guard.deployment_id = v_deployment_id;
    RETURN pg_catalog.jsonb_build_object('outcome', 'cleared', 'generation', (
        SELECT guard.generation FROM mesh_ops.kubernetes_ca_guard AS guard WHERE guard.deployment_id = v_deployment_id));
END;
$function$;

-- The installation's active intermediates, at most p_limit, with the
-- version each is at, for reconcile-after-restore to retire them.
CREATE FUNCTION mesh_ops.list_kubernetes_ca_active_intermediates_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_intermediates JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA intermediate listing';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'workspace_id', listed.workspace_public_id, 'network_id', listed.network_public_id,
        'cluster_id', listed.cluster_public_id, 'ca_id', listed.ca_public_id, 'version', listed.version)
        ORDER BY listed.id), '[]'::JSONB)
    INTO v_intermediates
    FROM (
        SELECT ca.id, ca.public_id AS ca_public_id, ca.version, workspace.public_id AS workspace_public_id,
            network.public_id AS network_public_id, cluster.public_id AS cluster_public_id
        FROM mesh.kubernetes_cluster_ca AS ca
        JOIN mesh.workspace AS workspace ON workspace.id = ca.workspace_id
        JOIN mesh.network AS network ON network.id = ca.network_id
        JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = ca.kubernetes_cluster_id
        WHERE workspace.deployment_id = v_deployment_id AND ca.kind = 'intermediate' AND ca.state = 'active'
        ORDER BY ca.id
        LIMIT p_limit
    ) AS listed;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object('intermediates', v_intermediates);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_certificate_result_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_guard_suspected_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_certificate_claim_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_certificate_held_internal_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_gateway_certificate_payload_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enqueue_kubernetes_gateway_certificate_v1(
    BYTEA, BYTEA, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_gateway_certificate_v1(UUID, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.abandon_kubernetes_gateway_certificate_v1(UUID, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.claim_kubernetes_gateway_certificates_v1(UUID, INTEGER, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.refuse_kubernetes_gateway_certificate_v1(UUID, UUID, UUID, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.release_kubernetes_gateway_certificate_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.issue_kubernetes_gateway_certificate_v1(
    UUID, UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, TEXT,
    TIMESTAMPTZ, TEXT, BIGINT
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.append_kubernetes_gateway_certificate_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB, BIGINT
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prune_kubernetes_gateway_certificates_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_ca_guard_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.mark_kubernetes_ca_restored_v1(UUID, TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.clear_kubernetes_ca_restore_v1(UUID, BIGINT, TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_ca_active_intermediates_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Control queues and reads; only the worker claims, signs and issues.
GRANT EXECUTE ON FUNCTION mesh_ops.enqueue_kubernetes_gateway_certificate_v1(
    BYTEA, BYTEA, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, BYTEA, BYTEA) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_gateway_certificate_v1(UUID, UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.abandon_kubernetes_gateway_certificate_v1(UUID, UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.claim_kubernetes_gateway_certificates_v1(UUID, INTEGER, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.refuse_kubernetes_gateway_certificate_v1(UUID, UUID, UUID, TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.release_kubernetes_gateway_certificate_v1(UUID, UUID, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.issue_kubernetes_gateway_certificate_v1(
    UUID, UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, TEXT,
    TIMESTAMPTZ, TEXT, BIGINT
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.append_kubernetes_gateway_certificate_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB, BIGINT
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_kubernetes_gateway_certificates_v1(UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_ca_guard_v1(UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.mark_kubernetes_ca_restored_v1(UUID, TEXT, TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.clear_kubernetes_ca_restore_v1(UUID, BIGINT, TEXT, TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_ca_active_intermediates_v1(UUID, INTEGER) TO mesh_worker;
