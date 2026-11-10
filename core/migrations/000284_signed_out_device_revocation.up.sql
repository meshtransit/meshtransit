-- Schema 284: a Device signed out for 30 days is removed
-- (docs/device-logout-design.md §3.5, S1b). A signed-out Device keeps its
-- addresses and name; once its owner has not signed in again for the hold,
-- the worker revokes it, as an administrator would: its addresses go
-- through quarantine and its name is released. One Device a step, with one
-- device.revoked evidence record (reason signed_out_expired) under the
-- system actor, on its Network's stream, so the Device's own history shows
-- it. The step re-checks the sign-out under the Device's row lock, so an
-- owner signing in at the same moment wins or loses cleanly.

-- The worker finds due Devices across the installation: Workspaces are
-- readable by the function owner only while mesh.signed_out_device_scan is
-- on, and only in a worker's or the migration's session (as schema 277's
-- summary scan). The step itself runs in the Device's exact scope.
CREATE POLICY workspace_signed_out_device_scan ON mesh.workspace
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.signed_out_device_scan', TRUE) = 'on'
        AND (pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
             OR pg_catalog.pg_has_role(SESSION_USER, 'mesh_migrator', 'MEMBER')));

-- Due Devices without the revoked ones that keep their signed_out_at, so
-- the scan does not step over history (schema 283's index does).
CREATE INDEX device_signed_out_due_idx ON mesh.device (signed_out_at, id)
    WHERE signed_out_at IS NOT NULL AND deleted_at IS NULL AND state IN ('active', 'suspended', 'expired');

-- A Device whose step failed waits before it is tried again, so a few
-- that always fail do not hold the others back; the last SQLSTATE shows
-- why. Only the migrator reaches it.
CREATE TABLE mesh_ops.signed_out_revocation_backoff (
    device_id BIGINT PRIMARY KEY,
    not_before TIMESTAMPTZ NOT NULL,
    failures INTEGER NOT NULL CHECK (failures > 0),
    last_sqlstate TEXT NOT NULL
);
ALTER TABLE mesh_ops.signed_out_revocation_backoff ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.signed_out_revocation_backoff FORCE ROW LEVEL SECURITY;
CREATE POLICY signed_out_revocation_backoff_migrator_policy ON mesh_ops.signed_out_revocation_backoff
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.signed_out_revocation_backoff
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- How long a signed-out Device is kept for its owner to sign in again.
CREATE FUNCTION mesh_ops.signed_out_device_hold_v1()
RETURNS INTERVAL
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$ SELECT INTERVAL '30 days' $function$;

-- The evidence a step described, for finalize in the same transaction.
-- Only the migrator reaches it, so a worker session cannot swap it.
CREATE TABLE mesh_ops.signed_out_revocation_proof (
    transaction_id BIGINT PRIMARY KEY,
    change_public_id UUID NOT NULL,
    proof JSONB NOT NULL
);
ALTER TABLE mesh_ops.signed_out_revocation_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.signed_out_revocation_proof FORCE ROW LEVEL SECURITY;
CREATE POLICY signed_out_revocation_proof_migrator_policy ON mesh_ops.signed_out_revocation_proof
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.signed_out_revocation_proof
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Revokes one Device past the hold, its Network's revision then its row
-- locked as every writer of the Network does. MTL05 when the revision or
-- the Device is held by another writer, the Device no longer qualifies or
-- its Network is being deleted (the deletion worker revokes it): the
-- caller rolls back to its savepoint, which gives every lock back.
CREATE FUNCTION mesh_ops.signed_out_revocation_step_internal_v1(
    p_workspace BIGINT, p_network BIGINT, p_device BIGINT, p_change UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_device mesh.device%ROWTYPE;
    v_network UUID;
    v_signed_out_at TIMESTAMPTZ;
    v_advanced JSONB;
    v_head RECORD;
    v_audit JSONB;
    v_outbox JSONB;
BEGIN
    PERFORM pg_catalog.set_config('mesh.workspace_id', p_workspace::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', p_network::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_workspace AND revision.network_id = p_network
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL05', MESSAGE = 'the Network is busy';
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.network AS network
               WHERE network.workspace_id = p_workspace AND network.id = p_network
                 AND network.state = 'deleted') THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL05', MESSAGE = 'the Network is being deleted';
    END IF;
    SELECT device.* INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = p_workspace AND device.network_id = p_network AND device.id = p_device
      AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
      AND device.signed_out_at <= v_now - mesh_ops.signed_out_device_hold_v1()
    FOR UPDATE SKIP LOCKED;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL05', MESSAGE = 'the Device is busy or no longer due';
    END IF;
    v_signed_out_at := v_device.signed_out_at;
    PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'signed out for 30 days', v_now);
    SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_device.id;
    SELECT network.public_id INTO STRICT v_network FROM mesh.network AS network
    WHERE network.workspace_id = p_workspace AND network.id = p_network;
    -- Peers lose the Device and groups their member: every projection moves.
    v_advanced := mesh_ops.advance_member_networks_internal_v1(p_workspace, ARRAY[p_network]);
    SELECT * INTO STRICT v_head FROM mesh_audit.lock_network_stream_head();
    v_audit := pg_catalog.jsonb_build_object(
        'network_id', v_network,
        'device_id', v_device.public_id,
        'display_name', v_device.hostname,
        'reason', 'signed_out_expired',
        'signed_out_at', v_signed_out_at,
        'initiator', 'system');
    v_outbox := pg_catalog.jsonb_build_object(
        'network_id', v_network, 'aggregate_kind', 'device', 'aggregate_id', v_device.public_id,
        'network_revision', (v_advanced -> 0 ->> 'network_revision')::BIGINT,
        'group_revision', (v_advanced -> 0 ->> 'group_revision')::BIGINT);
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE,
        'change_id', p_change,
        'device_id', v_device.public_id,
        'aggregate_version', v_device.version,
        'action', 'device.revoked',
        'stream_id', v_head.stream_internal_id,
        'sequence', v_head.next_sequence,
        'previous_hash', pg_catalog.encode(v_head.latest_event_hash, 'hex'),
        'network_revision', (v_advanced -> 0 ->> 'network_revision')::BIGINT,
        'audit_payload', v_audit::TEXT,
        'outbox_payload', v_outbox::TEXT);
END;
$function$;

-- One step: tries this Deployment's Devices past the hold, longest signed
-- out first, and returns the evidence of the first it revokes. A busy one
-- (MTL05) is skipped. A Device whose step fails is rolled back to a
-- savepoint, counted, and left alone for ten minutes, doubling up to six
-- hours; the next is tried, so
-- one does not hold the others back. The lag still counts it.
CREATE FUNCTION mesh_ops.prepare_signed_out_revocation_step_v1(p_deployment UUID, p_change UUID)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment BIGINT;
    v_candidate RECORD;
    v_due JSONB;
    v_sqlstate TEXT;
    v_proof JSONB;
    v_failed INTEGER := 0;
BEGIN
    IF NOT pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
        OR p_deployment IS NULL OR p_change IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'signed-out Device revocation step is invalid';
    END IF;
    SELECT deployment.id INTO v_deployment FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment;
    IF v_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'signed-out Device revocation step is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.signed_out_device_scan', 'on', TRUE);
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        due.workspace_id, due.network_id, due.id) ORDER BY due.signed_out_at, due.id), '[]'::JSONB)
    INTO v_due
    FROM (
        SELECT device.workspace_id, device.network_id, device.id, device.signed_out_at
        FROM mesh.device AS device
        JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
        WHERE workspace.deployment_id = v_deployment
          AND device.signed_out_at <= pg_catalog.transaction_timestamp() - mesh_ops.signed_out_device_hold_v1()
          AND device.signed_out_at IS NOT NULL AND device.state IN ('active', 'suspended', 'expired')
          AND device.deleted_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM mesh_ops.signed_out_revocation_backoff AS backoff
                          WHERE backoff.device_id = device.id
                            AND backoff.not_before > pg_catalog.transaction_timestamp())
        ORDER BY device.signed_out_at, device.id
        LIMIT 16
    ) AS due;
    PERFORM pg_catalog.set_config('mesh.signed_out_device_scan', '', TRUE);
    FOR v_candidate IN
        SELECT (item.value ->> 0)::BIGINT AS workspace_id, (item.value ->> 1)::BIGINT AS network_id,
               (item.value ->> 2)::BIGINT AS id
        FROM pg_catalog.jsonb_array_elements(v_due) WITH ORDINALITY AS item (value, position)
        ORDER BY item.position
    LOOP
        v_proof := NULL;
        BEGIN
            v_proof := mesh_ops.signed_out_revocation_step_internal_v1(v_candidate.workspace_id,
                v_candidate.network_id, v_candidate.id, p_change);
        EXCEPTION
            WHEN SQLSTATE 'MTL05' THEN
                NULL;
            WHEN OTHERS THEN
                v_failed := v_failed + 1;
                v_sqlstate := SQLSTATE;
                INSERT INTO mesh_ops.signed_out_revocation_backoff AS backoff
                    (device_id, not_before, failures, last_sqlstate)
                VALUES (v_candidate.id, pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 1, v_sqlstate)
                ON CONFLICT (device_id) DO UPDATE
                -- Doubling with each failure, at most six hours apart.
                SET not_before = pg_catalog.transaction_timestamp() + LEAST(
                        INTERVAL '10 minutes' * pg_catalog.power(2, LEAST(backoff.failures, 6)),
                        INTERVAL '6 hours'),
                    failures = backoff.failures + 1, last_sqlstate = EXCLUDED.last_sqlstate;
        END;
        IF v_proof IS NOT NULL THEN
            v_proof := v_proof || pg_catalog.jsonb_build_object('failed', v_failed);
            INSERT INTO mesh_ops.signed_out_revocation_proof (transaction_id, change_public_id, proof)
            VALUES ((pg_catalog.pg_current_xact_id()::TEXT)::BIGINT, p_change, v_proof);
            DELETE FROM mesh_ops.signed_out_revocation_backoff AS backoff WHERE backoff.device_id = v_candidate.id;
            RETURN v_proof;
        END IF;
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('changed', FALSE, 'failed', v_failed);
END;
$function$;

-- Appends the one event prepare_signed_out_revocation_step_v1 kept for this
-- transaction, with the hash the worker computed, as the system actor.
CREATE FUNCTION mesh_ops.finalize_signed_out_revocation_step_v1(p_change UUID, p_event JSONB)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_proof JSONB;
    v_sequence BIGINT;
BEGIN
    DELETE FROM mesh_ops.signed_out_revocation_proof AS kept
    WHERE kept.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      AND kept.change_public_id = p_change
    RETURNING kept.proof INTO v_proof;
    IF NOT pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
        OR v_proof IS NULL OR p_change IS NULL OR p_event IS NULL
        OR pg_catalog.jsonb_typeof(p_event) <> 'object'
        OR v_proof ->> 'change_id' IS DISTINCT FROM p_change::TEXT
        OR p_event ->> 'stream_id' IS DISTINCT FROM v_proof ->> 'stream_id'
        OR p_event ->> 'sequence' IS DISTINCT FROM v_proof ->> 'sequence'
        OR p_event ->> 'previous_hash' IS DISTINCT FROM v_proof ->> 'previous_hash'
        OR p_event ->> 'audit_payload' IS DISTINCT FROM v_proof ->> 'audit_payload'
        OR p_event ->> 'outbox_payload' IS DISTINCT FROM v_proof ->> 'outbox_payload'
        OR p_event ->> 'event_id' IS NULL OR p_event ->> 'outbox_id' IS NULL
        OR p_event ->> 'event_hash' !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'signed-out Device revocation evidence mismatch';
    END IF;
    v_sequence := mesh_audit.append_authority_evidence(
        (v_proof ->> 'stream_id')::BIGINT,
        (p_event ->> 'event_id')::UUID,
        (p_event ->> 'outbox_id')::UUID,
        (v_proof ->> 'sequence')::BIGINT,
        pg_catalog.decode(v_proof ->> 'previous_hash', 'hex'),
        pg_catalog.decode(p_event ->> 'event_hash', 'hex'),
        'device',
        (v_proof ->> 'device_id')::UUID,
        (v_proof ->> 'aggregate_version')::BIGINT,
        (v_proof ->> 'network_revision')::BIGINT,
        NULL::UUID,
        v_proof ->> 'action',
        'system.reconcile',
        NULL::UUID,
        NULL::BYTEA,
        NULL::BYTEA,
        (v_proof ->> 'audit_payload')::JSONB,
        'network.revision.advanced',
        (v_proof ->> 'outbox_payload')::JSONB
    );
    IF v_sequence <> (v_proof ->> 'sequence')::BIGINT THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'signed-out Device revocation evidence changed';
    END IF;
    RETURN v_sequence;
END;
$function$;

-- How many Devices are past the hold, and since when, for the metrics.
CREATE FUNCTION mesh_ops.signed_out_revocation_lag_v1(p_deployment UUID)
RETURNS TABLE (pending BIGINT, oldest_due_at TIMESTAMPTZ)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NOT pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER') THEN
        RETURN QUERY SELECT 0::BIGINT, NULL::TIMESTAMPTZ;
        RETURN;
    END IF;
    PERFORM pg_catalog.set_config('mesh.signed_out_device_scan', 'on', TRUE);
    RETURN QUERY
    SELECT pg_catalog.count(*), pg_catalog.min(device.signed_out_at + mesh_ops.signed_out_device_hold_v1())
    FROM mesh.device AS device
    JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE deployment.installation_public_id = p_deployment
      AND device.signed_out_at <= pg_catalog.transaction_timestamp() - mesh_ops.signed_out_device_hold_v1()
      AND device.signed_out_at IS NOT NULL AND device.state IN ('active', 'suspended', 'expired')
      AND device.deleted_at IS NULL;
    PERFORM pg_catalog.set_config('mesh.signed_out_device_scan', '', TRUE);
END;
$function$;

REVOKE ALL ON FUNCTION
    mesh_ops.signed_out_device_hold_v1(),
    mesh_ops.signed_out_revocation_step_internal_v1(BIGINT, BIGINT, BIGINT, UUID),
    mesh_ops.prepare_signed_out_revocation_step_v1(UUID, UUID),
    mesh_ops.finalize_signed_out_revocation_step_v1(UUID, JSONB),
    mesh_ops.signed_out_revocation_lag_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION
    mesh_ops.prepare_signed_out_revocation_step_v1(UUID, UUID),
    mesh_ops.finalize_signed_out_revocation_step_v1(UUID, JSONB),
    mesh_ops.signed_out_revocation_lag_v1(UUID)
TO mesh_worker;
