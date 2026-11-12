-- Schema 290: a browser sign-in moves its machine (docs/sign-in-moves-machine-design.md, approved 2026-11-12).
--
-- When the person approves a Network other than the one where the machine
-- key holds their own Device, the completion revokes that Device (reason
-- 'moved', like "Remove this device") and creates the new one, in one
-- transaction. The approval page shows the Device and the person ticks "Move
-- this computer here"; the approval records that acknowledgement, and the
-- completion moves only the acknowledged Device.
--
-- Functions:
--   lookup_browser_move_source_v1        what the approval page tells about the machine
--   acknowledge_browser_move_v1          the approval records the confirmed source Device
--   lock_browser_move_revisions_v1       locks both Networks' revisions in ascending order
--   move_out_browser_device_v1           revokes the source Device, keeps its evidence proof
--   finalize_browser_move_v1             appends that evidence in the source Network's stream
-- and issue_browser_registration_intent_v1 now also ends a pending approval of
-- the same machine key whose node key differs (a meshd that starts a new
-- sign-in with a new key).
--
-- Every function derives its authority from the intent token digest and the
-- Noise-proven machine key, saves and restores the scope settings it changes
-- (also on error), and refuses everything but the person's own member
-- Device: never a Workspace's, a suspended one, one in handover, or one in
-- another state. A source Network being deleted is a temporary refusal
-- (MTL05): the deletion worker revokes the Device.

CREATE TABLE mesh_ops.browser_move_acknowledgement (
    intent_id BIGINT PRIMARY KEY REFERENCES mesh.browser_registration_intent (id) ON DELETE CASCADE,
    source_device_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
ALTER TABLE mesh_ops.browser_move_acknowledgement ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.browser_move_acknowledgement FORCE ROW LEVEL SECURITY;
CREATE POLICY browser_move_acknowledgement_migrator_policy ON mesh_ops.browser_move_acknowledgement
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.browser_move_acknowledgement
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The Devices a move revoked (review H3): only move_out_browser_device_v1
-- writes here, so an administrator's free-text revocation reason can never
-- let a revoked machine come back as a fresh Device.
CREATE TABLE mesh_ops.browser_move_record (
    device_id BIGINT PRIMARY KEY,
    moved_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
ALTER TABLE mesh_ops.browser_move_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.browser_move_record FORCE ROW LEVEL SECURITY;
CREATE POLICY browser_move_record_migrator_policy ON mesh_ops.browser_move_record
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.browser_move_record
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether a move revoked this Device; the completion's resume lookup asks.
CREATE FUNCTION mesh_ops.browser_device_moved_v1(p_device_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (SELECT 1 FROM mesh_ops.browser_move_record AS record WHERE record.device_id = p_device_id)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.browser_device_moved_v1(BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.browser_device_moved_v1(BIGINT) TO mesh_runtime;

-- One proof per transaction and change, consumed by finalize (as schema 284).
CREATE TABLE mesh_ops.browser_move_proof (
    transaction_id BIGINT NOT NULL,
    change_public_id UUID NOT NULL,
    proof JSONB NOT NULL,
    PRIMARY KEY (transaction_id, change_public_id)
);
ALTER TABLE mesh_ops.browser_move_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.browser_move_proof FORCE ROW LEVEL SECURITY;
CREATE POLICY browser_move_proof_migrator_policy ON mesh_ops.browser_move_proof
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.browser_move_proof
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The movable source of an approved or pending intent's machine: the
-- person's own active member Device holding the machine key, outside the
-- given (target) scope. NULL target compares against nothing.
CREATE FUNCTION mesh_ops.browser_move_source_internal_v1(
    p_machine_key BYTEA, p_principal BIGINT, p_target_workspace BIGINT, p_target_network BIGINT
)
RETURNS TABLE (device_id BIGINT, workspace_id BIGINT, network_id BIGINT, movable BOOLEAN, owned BOOLEAN,
               resumable BOOLEAN)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT device.id, device.workspace_id, device.network_id,
           device.owner_principal_id = p_principal
           AND device.custodian_principal_id = p_principal
           AND device.ownership = 'member'
           AND device.kind = 'standard'
           AND device.state = 'active'
           AND device.deleted_at IS NULL,
           device.owner_principal_id = p_principal,
           -- What a sign-in into that same Network resumes: the person's own
           -- Device, or one handed over to them (review H1).
           device.deleted_at IS NULL AND (device.owner_principal_id = p_principal
               OR (device.state = 'suspended' AND device.suspended_reason = 'handover'
                   AND device.handover_principal_id = p_principal))
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device ON device.workspace_id = machine.workspace_id
     AND device.network_id = machine.network_id AND device.id = machine.device_id
    WHERE machine.public_key = p_machine_key AND machine.state = 'active'
      AND (machine.workspace_id, machine.network_id)
          IS DISTINCT FROM (p_target_workspace, p_target_network)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.browser_move_source_internal_v1(BYTEA, BIGINT, BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- What the approval page tells the signed-in person about the machine of a
-- pending intent: 'new' (no Device holds its key), 'own' (their movable
-- member Device, with its name and Network), 'resume' (one they can only sign
-- back in to in its own Network: handed over to them, or theirs but not
-- movable) or 'other' (anyone else's), without names.
CREATE FUNCTION mesh_ops.lookup_browser_move_source_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT, p_session_digest BYTEA, p_intent_token_digest BYTEA
)
RETURNS TABLE (
    kind TEXT, device_public_id UUID, device_hostname TEXT,
    workspace_public_id UUID, network_public_id UUID, network_display_name TEXT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
-- Session reads follow their written join order (as every session authority).
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_intent mesh.browser_registration_intent%ROWTYPE;
    v_principal BIGINT;
    v_source RECORD;
    v_device mesh.device%ROWTYPE;
    v_saved_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    v_saved_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_session_digest_key_id IS NULL OR p_session_digest IS NULL
        OR pg_catalog.octet_length(p_session_digest) <> 32
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser move lookup';
    END IF;
    SELECT session.principal_id INTO v_principal
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.recovery_epoch = p_recovery_epoch
      AND session.token_digest_key_id = p_session_digest_key_id
      AND session.token_digest = p_session_digest
      AND session.state = 'active' AND session.ended_at IS NULL
      AND session.idle_expires_at > pg_catalog.clock_timestamp()
      AND session.absolute_expires_at > pg_catalog.clock_timestamp();
    IF v_principal IS NULL THEN
        RETURN;
    END IF;
    SELECT intent.* INTO v_intent
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.state = 'pending'
      AND intent.expires_at > pg_catalog.clock_timestamp();
    IF v_intent.id IS NULL THEN
        RETURN;
    END IF;
    SELECT * INTO v_source
    FROM mesh_ops.browser_move_source_internal_v1(v_intent.machine_key, v_principal, NULL, NULL);
    IF v_source.device_id IS NULL THEN
        kind := 'new';
        RETURN NEXT;
        RETURN;
    END IF;
    IF NOT v_source.movable AND NOT v_source.resumable THEN
        kind := 'other';
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT device.* INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_source.device_id;
    BEGIN
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_source.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_source.network_id::TEXT, TRUE);
        SELECT CASE WHEN v_source.movable THEN 'own' ELSE 'resume' END,
               v_device.public_id, v_device.hostname, workspace.public_id, network.public_id,
               network.display_name
        INTO kind, device_public_id, device_hostname, workspace_public_id, network_public_id,
             network_display_name
        FROM mesh.network AS network
        JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
        WHERE network.workspace_id = v_source.workspace_id AND network.id = v_source.network_id;
        PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
            PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
            RAISE;
    END;
    IF kind IS NULL THEN
        kind := 'other';
        device_public_id := NULL;
    END IF;
    RETURN NEXT;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lookup_browser_move_source_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lookup_browser_move_source_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA)
    TO mesh_runtime;

-- Called in the approval transaction, after the approval is recorded: keeps
-- the source Device the page showed and the person confirmed. The session
-- must be the approving one, and the source the person's movable Device
-- that holds the intent's machine key outside the approved Network.
CREATE FUNCTION mesh_ops.acknowledge_browser_move_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT, p_session_digest BYTEA, p_intent_token_digest BYTEA,
    p_source_device_public_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
-- Session reads follow their written join order (as every session authority).
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_intent mesh.browser_registration_intent%ROWTYPE;
    v_registration mesh.pending_registration%ROWTYPE;
    v_source RECORD;
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_session_digest_key_id IS NULL OR p_session_digest IS NULL
        OR pg_catalog.octet_length(p_session_digest) <> 32
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_source_device_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser move acknowledgement';
    END IF;
    SELECT intent.* INTO v_intent
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    JOIN mesh.account_session AS session ON session.public_id = intent.approved_session_public_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.state = 'approved'
      AND session.token_digest_key_id = p_session_digest_key_id
      AND session.token_digest = p_session_digest
    FOR UPDATE OF intent;
    IF v_intent.id IS NULL THEN
        RETURN FALSE;
    END IF;
    SELECT registration.* INTO v_registration
    FROM mesh.pending_registration AS registration
    WHERE registration.public_id = v_intent.pending_registration_public_id
      AND registration.state = 'authorized' AND registration.authorization_kind = 'interactive';
    IF v_registration.id IS NULL THEN
        RETURN FALSE;
    END IF;
    SELECT source.* INTO v_source
    FROM mesh_ops.browser_move_source_internal_v1(v_intent.machine_key, v_registration.authorized_principal_id,
        v_registration.workspace_id, v_registration.network_id) AS source
    JOIN mesh.device AS device ON device.id = source.device_id
    WHERE device.public_id = p_source_device_public_id AND source.movable;
    IF v_source.device_id IS NULL THEN
        RETURN FALSE;
    END IF;
    INSERT INTO mesh_ops.browser_move_acknowledgement (intent_id, source_device_id, principal_id)
    VALUES (v_intent.id, v_source.device_id, v_registration.authorized_principal_id)
    ON CONFLICT (intent_id) DO UPDATE
    SET source_device_id = EXCLUDED.source_device_id, principal_id = EXCLUDED.principal_id,
        created_at = pg_catalog.clock_timestamp();
    RETURN TRUE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.acknowledge_browser_move_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.acknowledge_browser_move_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID)
    TO mesh_runtime;

-- Before the completion authority: finds whether the approved intent's
-- machine key holds a Device in another Network and, if so, locks both
-- Networks' revisions in ascending (Workspace, Network) order, the order
-- every multi-Network writer uses. No row when there is nothing to move.
-- The scope settings are only borrowed: the caller's are restored.
CREATE FUNCTION mesh_ops.lock_browser_move_revisions_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_intent_token_digest BYTEA, p_machine_key BYTEA, p_machine_key_fingerprint BYTEA,
    p_requested_node_key BYTEA
)
RETURNS TABLE (source_workspace_id BIGINT, source_network_id BIGINT, source_device_id BIGINT,
               movable BOOLEAN, owned BOOLEAN, acknowledged BOOLEAN, same_node_key BOOLEAN)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_intent mesh.browser_registration_intent%ROWTYPE;
    v_registration mesh.pending_registration%ROWTYPE;
    v_source RECORD;
    v_scope RECORD;
    v_saved_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    v_saved_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_machine_key IS NULL OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_machine_key_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_requested_node_key IS NULL OR pg_catalog.octet_length(p_requested_node_key) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser move lock';
    END IF;
    SELECT intent.* INTO v_intent
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.machine_key = p_machine_key
      AND intent.machine_key_fingerprint = p_machine_key_fingerprint
      AND intent.requested_node_key = p_requested_node_key
      AND intent.state = 'approved';
    IF v_intent.id IS NULL THEN
        RETURN;
    END IF;
    SELECT registration.* INTO v_registration
    FROM mesh.pending_registration AS registration
    WHERE registration.public_id = v_intent.pending_registration_public_id;
    IF v_registration.id IS NULL THEN
        RETURN;
    END IF;
    SELECT * INTO v_source
    FROM mesh_ops.browser_move_source_internal_v1(p_machine_key, v_registration.authorized_principal_id,
        v_registration.workspace_id, v_registration.network_id);
    IF v_source.device_id IS NULL THEN
        RETURN;
    END IF;
    BEGIN
        FOR v_scope IN
            SELECT scope.workspace_id, scope.network_id
            FROM (VALUES (v_source.workspace_id, v_source.network_id),
                         (v_registration.workspace_id, v_registration.network_id))
                 AS scope (workspace_id, network_id)
            ORDER BY scope.workspace_id, scope.network_id
        LOOP
            PERFORM pg_catalog.set_config('mesh.workspace_id', v_scope.workspace_id::TEXT, TRUE);
            PERFORM pg_catalog.set_config('mesh.network_id', v_scope.network_id::TEXT, TRUE);
            PERFORM 1 FROM mesh_ops.network_revision AS revision
            WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser move revision is not visible';
            END IF;
        END LOOP;
        PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
            PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
            RAISE;
    END;
    source_workspace_id := v_source.workspace_id;
    source_network_id := v_source.network_id;
    source_device_id := v_source.device_id;
    movable := v_source.movable;
    owned := v_source.owned;
    -- An older meshd signs in with the Device's own node key, which can never
    -- be reused: it must update before the machine can move.
    same_node_key := EXISTS (
        SELECT 1 FROM mesh.device_node_key_epoch AS node_key
        WHERE node_key.device_id = v_source.device_id AND node_key.public_key = p_requested_node_key);
    acknowledged := EXISTS (
        SELECT 1 FROM mesh_ops.browser_move_acknowledgement AS ack
        WHERE ack.intent_id = v_intent.id AND ack.source_device_id = v_source.device_id
          AND ack.principal_id = v_registration.authorized_principal_id);
    RETURN NEXT;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_browser_move_revisions_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_browser_move_revisions_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA)
    TO mesh_runtime;

-- Inside the completion transaction, after its authority and before the new
-- Device: revokes the acknowledged source Device in its own Network under
-- change p_change, advances that Network's projections, and keeps the proof
-- finalize_browser_move_v1 needs to append its evidence. Rechecks every
-- condition itself; MTL05 when the source Network is being deleted.
CREATE FUNCTION mesh_ops.move_out_browser_device_v1(
    p_change UUID, p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_intent_token_digest BYTEA, p_machine_key BYTEA, p_machine_key_fingerprint BYTEA,
    p_registration_public_id UUID
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
    v_intent mesh.browser_registration_intent%ROWTYPE;
    v_registration mesh.pending_registration%ROWTYPE;
    v_ack mesh_ops.browser_move_acknowledgement%ROWTYPE;
    v_source RECORD;
    v_device mesh.device%ROWTYPE;
    v_principal UUID;
    v_source_network UUID;
    v_target_network UUID;
    v_advanced JSONB;
    v_head RECORD;
    v_audit JSONB;
    v_outbox JSONB;
    v_proof JSONB;
    v_saved_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    v_saved_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
    v_saved_change TEXT := pg_catalog.current_setting('mesh.change_public_id', TRUE);
BEGIN
    IF p_change IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7
        OR p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_machine_key IS NULL OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_machine_key_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_registration_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser move';
    END IF;
    SELECT intent.* INTO v_intent
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.machine_key = p_machine_key
      AND intent.machine_key_fingerprint = p_machine_key_fingerprint
      AND intent.pending_registration_public_id = p_registration_public_id
      AND intent.state = 'approved'
    FOR UPDATE OF intent;
    SELECT registration.* INTO v_registration
    FROM mesh.pending_registration AS registration
    WHERE registration.public_id = p_registration_public_id AND registration.state = 'authorized'
      AND registration.authorization_kind = 'interactive'
      AND registration.browser_authorization_public_id = v_intent.public_id;
    IF v_intent.id IS NULL OR v_registration.id IS NULL
        OR v_registration.workspace_id::TEXT IS DISTINCT FROM v_saved_workspace
        OR v_registration.network_id::TEXT IS DISTINCT FROM v_saved_network THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser move authority mismatch';
    END IF;
    SELECT ack.* INTO v_ack FROM mesh_ops.browser_move_acknowledgement AS ack
    WHERE ack.intent_id = v_intent.id AND ack.principal_id = v_registration.authorized_principal_id;
    SELECT source.* INTO v_source
    FROM mesh_ops.browser_move_source_internal_v1(p_machine_key, v_registration.authorized_principal_id,
        v_registration.workspace_id, v_registration.network_id) AS source;
    IF v_source.device_id IS NULL OR NOT v_source.movable OR v_ack.intent_id IS NULL
        OR v_ack.source_device_id <> v_source.device_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'the machine is not movable here';
    END IF;
    SELECT principal.public_id INTO STRICT v_principal FROM mesh.principal AS principal
    WHERE principal.id = v_registration.authorized_principal_id;
    SELECT network.public_id INTO STRICT v_target_network FROM mesh.network AS network
    WHERE network.workspace_id = v_registration.workspace_id AND network.id = v_registration.network_id;
    BEGIN
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_source.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_source.network_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
        -- The caller locked this revision (lock_browser_move_revisions_v1).
        PERFORM 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = v_source.workspace_id AND revision.network_id = v_source.network_id
        FOR UPDATE;
        IF EXISTS (SELECT 1 FROM mesh.network AS network
                   WHERE network.workspace_id = v_source.workspace_id AND network.id = v_source.network_id
                     AND network.state = 'deleted') THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL05', MESSAGE = 'the source Network is being deleted';
        END IF;
        SELECT device.* INTO v_device FROM mesh.device AS device
        WHERE device.id = v_source.device_id AND device.workspace_id = v_source.workspace_id
          AND device.network_id = v_source.network_id
          AND device.owner_principal_id = v_registration.authorized_principal_id
          AND device.custodian_principal_id = v_registration.authorized_principal_id
          AND device.ownership = 'member' AND device.kind = 'standard'
          AND device.state = 'active' AND device.deleted_at IS NULL
        FOR UPDATE;
        IF v_device.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'the machine is not movable here';
        END IF;
        PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'moved', v_now);
        INSERT INTO mesh_ops.browser_move_record (device_id) VALUES (v_device.id);
        SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_device.id;
        SELECT network.public_id INTO STRICT v_source_network FROM mesh.network AS network
        WHERE network.workspace_id = v_source.workspace_id AND network.id = v_source.network_id;
        -- Peers lose the Device and groups their member: every projection moves.
        v_advanced := mesh_ops.advance_member_networks_internal_v1(v_source.workspace_id,
            ARRAY[v_source.network_id]);
        SELECT * INTO STRICT v_head FROM mesh_audit.lock_network_stream_head();
        -- Another Workspace's ids never reach this one's audit.
        IF v_source.workspace_id = v_registration.workspace_id THEN
            v_audit := pg_catalog.jsonb_build_object(
                'network_id', v_source_network, 'device_id', v_device.public_id,
                'display_name', v_device.hostname, 'reason', 'moved',
                'moved_to_network', v_target_network, 'initiator', 'owner');
        ELSE
            v_audit := pg_catalog.jsonb_build_object(
                'network_id', v_source_network, 'device_id', v_device.public_id,
                'display_name', v_device.hostname, 'reason', 'moved',
                'moved_by_owner', TRUE, 'initiator', 'owner');
        END IF;
        v_outbox := pg_catalog.jsonb_build_object(
            'network_id', v_source_network, 'aggregate_kind', 'device', 'aggregate_id', v_device.public_id,
            'network_revision', (v_advanced -> 0 ->> 'network_revision')::BIGINT,
            'group_revision', (v_advanced -> 0 ->> 'group_revision')::BIGINT);
        v_proof := pg_catalog.jsonb_build_object(
            'change_id', p_change,
            'workspace_internal_id', v_source.workspace_id,
            'network_internal_id', v_source.network_id,
            'same_workspace', v_source.workspace_id = v_registration.workspace_id,
            'device_id', v_device.public_id,
            'aggregate_version', v_device.version,
            'principal_id', v_principal,
            'action', 'device.moved_out',
            'stream_id', v_head.stream_internal_id,
            'sequence', v_head.next_sequence,
            'previous_hash', pg_catalog.encode(v_head.latest_event_hash, 'hex'),
            'network_revision', (v_advanced -> 0 ->> 'network_revision')::BIGINT,
            'audit_payload', v_audit::TEXT,
            'outbox_payload', v_outbox::TEXT);
        INSERT INTO mesh_ops.browser_move_proof (transaction_id, change_public_id, proof)
        VALUES ((pg_catalog.pg_current_xact_id()::TEXT)::BIGINT, p_change, v_proof);
        DELETE FROM mesh_ops.browser_move_acknowledgement AS ack WHERE ack.intent_id = v_intent.id;
        PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', COALESCE(v_saved_change, ''), TRUE);
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
            PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
            PERFORM pg_catalog.set_config('mesh.change_public_id', COALESCE(v_saved_change, ''), TRUE);
            RAISE;
    END;
    RETURN v_proof;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.move_out_browser_device_v1(UUID, UUID, BIGINT, BYTEA, BYTEA, BYTEA, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.move_out_browser_device_v1(UUID, UUID, BIGINT, BYTEA, BYTEA, BYTEA, UUID)
    TO mesh_runtime;

-- Appends the one event move_out_browser_device_v1 kept for this
-- transaction, with the hash Core computed, in the source Network's stream
-- and under its change; restores the caller's scope and change.
CREATE FUNCTION mesh_ops.finalize_browser_move_v1(p_change UUID, p_event JSONB)
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
    v_saved_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    v_saved_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
    v_saved_change TEXT := pg_catalog.current_setting('mesh.change_public_id', TRUE);
BEGIN
    DELETE FROM mesh_ops.browser_move_proof AS kept
    WHERE kept.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      AND kept.change_public_id = p_change
    RETURNING kept.proof INTO v_proof;
    IF v_proof IS NULL OR p_change IS NULL OR p_event IS NULL
        OR pg_catalog.jsonb_typeof(p_event) <> 'object'
        OR v_proof ->> 'change_id' IS DISTINCT FROM p_change::TEXT
        OR p_event ->> 'stream_id' IS DISTINCT FROM v_proof ->> 'stream_id'
        OR p_event ->> 'sequence' IS DISTINCT FROM v_proof ->> 'sequence'
        OR p_event ->> 'previous_hash' IS DISTINCT FROM v_proof ->> 'previous_hash'
        OR p_event ->> 'audit_payload' IS DISTINCT FROM v_proof ->> 'audit_payload'
        OR p_event ->> 'outbox_payload' IS DISTINCT FROM v_proof ->> 'outbox_payload'
        OR p_event ->> 'event_id' IS NULL OR p_event ->> 'outbox_id' IS NULL
        OR p_event ->> 'event_hash' !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser move evidence mismatch';
    END IF;
    BEGIN
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_proof ->> 'workspace_internal_id', TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_proof ->> 'network_internal_id', TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
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
            (v_proof ->> 'principal_id')::UUID,
            v_proof ->> 'action',
            'device.register',
            NULL::UUID,
            NULL::BYTEA,
            NULL::BYTEA,
            (v_proof ->> 'audit_payload')::JSONB,
            'network.revision.advanced',
            (v_proof ->> 'outbox_payload')::JSONB
        );
        IF v_sequence <> (v_proof ->> 'sequence')::BIGINT THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'browser move evidence changed';
        END IF;
        PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.change_public_id', COALESCE(v_saved_change, ''), TRUE);
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
            PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
            PERFORM pg_catalog.set_config('mesh.change_public_id', COALESCE(v_saved_change, ''), TRUE);
            RAISE;
    END;
    RETURN v_sequence;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.finalize_browser_move_v1(UUID, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_browser_move_v1(UUID, JSONB) TO mesh_runtime;

-- issue_browser_registration_intent_v1 (schema 289 plus one rule): a pending
-- intent of the same machine key with another node key ends, so a meshd that
-- starts a new sign-in with a fresh key gets a new approval instead of a
-- conflict until the old one expires (review H3). Approved intents keep the
-- schema 289 rules, except that an approval with a confirmed move (schema 290)
-- can complete and is not ended.
CREATE OR REPLACE FUNCTION mesh_ops.issue_browser_registration_intent_v1(
    p_deployment_public_id UUID,
    p_recovery_epoch BIGINT,
    p_intent_public_id UUID,
    p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA,
    p_requested_node_key BYTEA,
    p_requested_hostname TEXT,
    p_token_nonce BYTEA,
    p_token_key_id TEXT,
    p_token_digest BYTEA,
    p_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    intent_public_id UUID,
    issued_recovery_epoch BIGINT,
    token_nonce BYTEA,
    token_key_id TEXT,
    token_digest BYTEA,
    intent_state TEXT,
    intent_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    deployment_internal_id BIGINT;
    current_intent mesh.browser_registration_intent%ROWTYPE;
    previous_change_public_id TEXT;
    held_elsewhere BOOLEAN := FALSE;
    intent_found BOOLEAN;
BEGIN
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_intent_public_id), 6) >> 4 <> 7
        OR p_machine_key IS NULL OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_machine_key = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_requested_node_key IS NULL
        OR pg_catalog.octet_length(p_requested_node_key) <> 32
        OR p_requested_node_key = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_requested_hostname IS NULL
        OR pg_catalog.char_length(p_requested_hostname) NOT BETWEEN 1 AND 253
        OR p_requested_hostname <> pg_catalog.btrim(p_requested_hostname)
        OR p_token_nonce IS NULL OR pg_catalog.octet_length(p_token_nonce) <> 32
        OR p_token_nonce = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_token_key_id IS NULL
        OR pg_catalog.char_length(p_token_key_id) NOT BETWEEN 1 AND 128
        OR p_token_key_id <> pg_catalog.btrim(p_token_key_id)
        OR p_token_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_token_digest = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_expires_at IS NULL
        OR p_expires_at <= pg_catalog.transaction_timestamp() + INTERVAL '1 minute'
        OR p_expires_at > pg_catalog.transaction_timestamp() + INTERVAL '15 minutes' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid browser registration intent input';
    END IF;

    SELECT deployment.id INTO deployment_internal_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.recovery_epoch = p_recovery_epoch
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
    FOR SHARE;
    IF deployment_internal_id IS NULL THEN
        RETURN;
    END IF;

    previous_change_public_id := pg_catalog.current_setting('mesh.change_public_id', TRUE);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_intent_public_id::TEXT, TRUE);

    SELECT * INTO current_intent
    FROM mesh.browser_registration_intent AS intent
    WHERE intent.deployment_id = deployment_internal_id
      AND intent.machine_key_fingerprint = p_machine_key_fingerprint
      AND intent.state IN ('pending', 'approved')
    FOR UPDATE;
    intent_found := FOUND;
    -- An approval for another Network or Workspace than the one where this
    -- machine key already holds an active Device can never complete: the key
    -- indexes are global (TD-CORE-150). A new sign-in ends it instead of
    -- handing the node the same approved URL until it expires.
    IF intent_found AND current_intent.state = 'approved'
        AND current_intent.expires_at > pg_catalog.transaction_timestamp()
        AND current_intent.issued_recovery_epoch = p_recovery_epoch THEN
        SELECT EXISTS (
            SELECT 1
            FROM mesh.pending_registration AS registration
            JOIN mesh.device_machine_key_epoch AS machine
              ON machine.public_key = current_intent.machine_key
             AND machine.state = 'active'
            WHERE registration.public_id = current_intent.pending_registration_public_id
              AND (machine.workspace_id, machine.network_id)
                  IS DISTINCT FROM (registration.workspace_id, registration.network_id)
              -- Schema 290: a move the person confirmed can complete, while the
              -- same sign-in (same node key) asks again; another key ends it.
              AND NOT (current_intent.requested_node_key = p_requested_node_key
                       AND EXISTS (SELECT 1 FROM mesh_ops.browser_move_acknowledgement AS ack
                                   WHERE ack.intent_id = current_intent.id))
        ) INTO held_elsewhere;
    END IF;
    IF intent_found AND (
        current_intent.expires_at <= pg_catalog.transaction_timestamp()
        OR current_intent.issued_recovery_epoch <> p_recovery_epoch
        OR held_elsewhere
        -- Schema 290: the same Noise-proven machine starts a new sign-in with
        -- a new node key; its pending one (nobody approved it yet) ends.
        OR (current_intent.state = 'pending'
            AND current_intent.machine_key = p_machine_key
            AND current_intent.requested_node_key <> p_requested_node_key)
    ) THEN
        UPDATE mesh.browser_registration_intent AS intent
        SET state = 'expired',
            version = intent.version + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE intent.id = current_intent.id;
        -- Its authorized registration ends with it, or a new approval for the
        -- same Network would meet it on the active machine index.
        IF held_elsewhere THEN
            UPDATE mesh.pending_registration AS registration
            SET state = 'expired',
                version = registration.version + 1,
                updated_at = pg_catalog.clock_timestamp()
            WHERE registration.public_id = current_intent.pending_registration_public_id
              AND registration.state = 'authorized'
              AND registration.device_id IS NULL;
        END IF;
        current_intent.id := NULL;
    END IF;

    IF current_intent.id IS NULL THEN
        INSERT INTO mesh.browser_registration_intent (
            public_id, deployment_id, issued_recovery_epoch,
            machine_key, machine_key_fingerprint,
            requested_node_key, requested_hostname,
            token_nonce, token_key_id, token_digest_algorithm, token_digest,
            state, expires_at
        ) VALUES (
            p_intent_public_id, deployment_internal_id, p_recovery_epoch,
            p_machine_key, p_machine_key_fingerprint,
            p_requested_node_key, p_requested_hostname,
            p_token_nonce, p_token_key_id, 'sha256-domain-v1', p_token_digest,
            'pending', p_expires_at
        ) ON CONFLICT DO NOTHING
        RETURNING * INTO current_intent;

        IF current_intent.id IS NULL THEN
            SELECT * INTO current_intent
            FROM mesh.browser_registration_intent AS intent
            WHERE intent.deployment_id = deployment_internal_id
              AND intent.machine_key_fingerprint = p_machine_key_fingerprint
              AND intent.state IN ('pending', 'approved')
            FOR UPDATE;
        END IF;
    END IF;

    IF current_intent.id IS NULL
        OR current_intent.expires_at <= pg_catalog.transaction_timestamp()
        OR current_intent.issued_recovery_epoch <> p_recovery_epoch
        OR current_intent.machine_key <> p_machine_key
        OR current_intent.requested_node_key <> p_requested_node_key
        OR current_intent.requested_hostname <> p_requested_hostname THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'browser registration intent conflict';
    END IF;

    RETURN QUERY SELECT
        current_intent.public_id,
        current_intent.issued_recovery_epoch,
        current_intent.token_nonce,
        current_intent.token_key_id,
        current_intent.token_digest,
        current_intent.state,
        current_intent.expires_at;
    PERFORM pg_catalog.set_config(
        'mesh.change_public_id', COALESCE(previous_change_public_id, ''), TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.change_public_id', COALESCE(previous_change_public_id, ''), TRUE
        );
        RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.issue_browser_registration_intent_v1(
    UUID, BIGINT, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, TEXT, BYTEA, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.issue_browser_registration_intent_v1(
    UUID, BIGINT, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, TEXT, BYTEA, TIMESTAMPTZ
) TO mesh_runtime;
