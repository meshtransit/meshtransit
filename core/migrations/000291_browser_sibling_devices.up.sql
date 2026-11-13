-- Schema 291: one Device per person and Network on one machine (docs/duplicate-device-design.md 2.1, approved
-- 2026-11-13).
--
-- Each meshd profile has its own machine key, so Core could not tell that two profiles share a machine. A browser
-- sign-in now lists the machine's other profiles' machine keys (siblings), each proven in the Noise session
-- (register.siblings1). When the approving person picks a Network where a sibling key holds their own Device, Core
-- makes no Device: the page offers "Use that account", which ends the sign-in ('rejected') with a joined record,
-- and the completion answers already_in_network with that sibling's machine key.
--
-- Functions:
--   sibling_device_internal_v1          the one rule (design §2): the person's Device a sibling key holds in a Network
--   record_browser_intent_siblings_v1   a pending sign-in's proven sibling keys (replaced while pending)
--   lookup_browser_sibling_devices_v1   what the approval page tells: the person's Devices on this machine
--   minimize_browser_intent_siblings_v1 at approval: keeps only keys of the person's Devices or of no Device
--   join_browser_existing_device_v1     "Use that account": ends the sign-in with a joined record
--   browser_sibling_conflict_v1         at completion, under the revision lock: refuses a second Device
--   lookup_browser_joined_v1            the completion's answer for a joined sign-in (also its replay)
--   clear_browser_intent_siblings_v1    drops a sign-in's sibling keys when it ends
--
-- Sibling keys are kept only while the sign-in lives and are never in audit or the Console. Intents are retained
-- (never deleted), so the explicit deletes here, and the sweep in record_browser_intent_siblings_v1, are the only
-- cleanup; ON DELETE CASCADE is a backstop.

CREATE TABLE mesh_ops.browser_intent_sibling (
    intent_id BIGINT NOT NULL REFERENCES mesh.browser_registration_intent (id) ON DELETE CASCADE,
    machine_key BYTEA NOT NULL,
    PRIMARY KEY (intent_id, machine_key),
    CONSTRAINT browser_intent_sibling_key_check CHECK (
        pg_catalog.octet_length(machine_key) = 32
        AND machine_key <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    )
);
ALTER TABLE mesh_ops.browser_intent_sibling ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.browser_intent_sibling FORCE ROW LEVEL SECURITY;
CREATE POLICY browser_intent_sibling_migrator_policy ON mesh_ops.browser_intent_sibling
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.browser_intent_sibling
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh_ops.browser_intent_joined (
    intent_id BIGINT PRIMARY KEY REFERENCES mesh.browser_registration_intent (id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
ALTER TABLE mesh_ops.browser_intent_joined ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.browser_intent_joined FORCE ROW LEVEL SECURITY;
CREATE POLICY browser_intent_joined_migrator_policy ON mesh_ops.browser_intent_joined
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.browser_intent_joined
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The rule (design §2, §6.4): the Device one of p_keys holds through its active machine-key epoch, in the given
-- Network (any Network when NULL), that is the person's own standard member Device (owner and custodian) or one
-- handed over to them, not deleted, in any other state. Its state: 'active', 'signed_out', 'expired' or
-- 'suspended' (suspended for any reason, handover included).
CREATE FUNCTION mesh_ops.sibling_device_internal_v1(
    p_keys BYTEA[], p_principal BIGINT, p_workspace BIGINT, p_network BIGINT
)
RETURNS TABLE (device_id BIGINT, workspace_id BIGINT, network_id BIGINT, machine_key BYTEA, device_state TEXT)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT device.id, device.workspace_id, device.network_id, machine.public_key,
           CASE
               WHEN device.state = 'suspended' THEN 'suspended'
               WHEN device.signed_out_at IS NOT NULL THEN 'signed_out'
               WHEN device.state = 'expired' THEN 'expired'
               WHEN device.expires_at IS NOT NULL AND device.expires_at <= pg_catalog.clock_timestamp() THEN 'expired'
               ELSE 'active'
           END
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device ON device.workspace_id = machine.workspace_id
     AND device.network_id = machine.network_id AND device.id = machine.device_id
    WHERE machine.public_key = ANY (p_keys) AND machine.state = 'active'
      AND (p_network IS NULL OR (machine.workspace_id = p_workspace AND machine.network_id = p_network))
      AND device.kind = 'standard' AND device.ownership = 'member' AND device.deleted_at IS NULL
      AND device.state IN ('active', 'expired', 'suspended')
      AND ((device.owner_principal_id = p_principal AND device.custodian_principal_id = p_principal)
           OR (device.state = 'suspended' AND device.suspended_reason = 'handover'
               AND device.handover_principal_id = p_principal))
    ORDER BY device.id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.sibling_device_internal_v1(BYTEA[], BIGINT, BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The pending intent this machine (Noise-proven key) holds, by its token digest: its id, or NULL.
CREATE FUNCTION mesh_ops.browser_sibling_intent_internal_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_intent_token_digest BYTEA, p_machine_key BYTEA
)
RETURNS BIGINT
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT intent.id
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.machine_key = p_machine_key
      AND intent.state = 'pending'
      AND intent.expires_at > pg_catalog.clock_timestamp()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.browser_sibling_intent_internal_v1(UUID, BIGINT, BYTEA, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Records a pending sign-in's sibling keys, already proven by the caller in the machine's Noise session. Replaces
-- the list while the intent is pending; does nothing once it is approved (the list is frozen). At most 16 keys of
-- 32 bytes, none the intent's own. Also sweeps the sibling keys of intents that ended by time (design §6.3).
CREATE FUNCTION mesh_ops.record_browser_intent_siblings_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_intent_token_digest BYTEA, p_machine_key BYTEA,
    p_keys BYTEA[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_intent BIGINT;
    v_count INTEGER;
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_machine_key IS NULL OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_keys IS NULL OR pg_catalog.cardinality(p_keys) > 16
        OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_keys) AS entry
                   WHERE entry IS NULL OR pg_catalog.octet_length(entry) <> 32 OR entry = p_machine_key
                      OR entry = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser sign-in siblings';
    END IF;
    -- Intents that ended by time keep no sibling keys (bounded per call).
    DELETE FROM mesh_ops.browser_intent_sibling AS sibling
    WHERE sibling.intent_id IN (
        SELECT intent.id FROM mesh.browser_registration_intent AS intent
        WHERE intent.expires_at <= pg_catalog.clock_timestamp()
          AND intent.id IN (SELECT DISTINCT stale.intent_id FROM mesh_ops.browser_intent_sibling AS stale)
        LIMIT 32);
    v_intent := mesh_ops.browser_sibling_intent_internal_v1(p_deployment_public_id, p_recovery_epoch,
        p_intent_token_digest, p_machine_key);
    IF v_intent IS NULL THEN
        RETURN 0;
    END IF;
    -- Pending again under the lock: an approval that committed meanwhile froze the list (review L1).
    PERFORM 1 FROM mesh.browser_registration_intent AS intent
    WHERE intent.id = v_intent AND intent.state = 'pending' FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    DELETE FROM mesh_ops.browser_intent_sibling AS sibling WHERE sibling.intent_id = v_intent;
    INSERT INTO mesh_ops.browser_intent_sibling (intent_id, machine_key)
    SELECT DISTINCT v_intent, entry FROM pg_catalog.unnest(p_keys) AS entry;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.record_browser_intent_siblings_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA[])
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_browser_intent_siblings_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA[])
    TO mesh_runtime;

-- The signed-in person of an active session, or NULL (as lookup_browser_move_source_v1).
CREATE FUNCTION mesh_ops.browser_session_principal_internal_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_session_digest_key_id TEXT, p_session_digest BYTEA
)
RETURNS BIGINT
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT session.principal_id
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.recovery_epoch = p_recovery_epoch
      AND session.token_digest_key_id = p_session_digest_key_id
      AND session.token_digest = p_session_digest
      AND session.state = 'active' AND session.ended_at IS NULL
      AND session.idle_expires_at > pg_catalog.clock_timestamp()
      AND session.absolute_expires_at > pg_catalog.clock_timestamp()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.browser_session_principal_internal_v1(UUID, BIGINT, TEXT, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The pending intent of a page by its token digest, or NULL.
CREATE FUNCTION mesh_ops.browser_page_intent_internal_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_intent_token_digest BYTEA
)
RETURNS BIGINT
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT intent.id
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.state = 'pending'
      AND intent.expires_at > pg_catalog.clock_timestamp()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.browser_page_intent_internal_v1(UUID, BIGINT, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- What the approval page tells the signed-in person (design §7): their Devices on this machine (through the
-- pending sign-in's sibling keys), with name, Network and state. Nothing about anyone else's.
CREATE FUNCTION mesh_ops.lookup_browser_sibling_devices_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT, p_session_digest BYTEA, p_intent_token_digest BYTEA
)
RETURNS TABLE (
    device_public_id UUID, device_hostname TEXT, device_state TEXT,
    workspace_public_id UUID, network_public_id UUID, network_display_name TEXT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_principal BIGINT;
    v_intent BIGINT;
    v_keys BYTEA[];
    v_row RECORD;
    v_saved_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    v_saved_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_session_digest_key_id IS NULL OR p_session_digest IS NULL
        OR pg_catalog.octet_length(p_session_digest) <> 32
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser sibling lookup';
    END IF;
    v_principal := mesh_ops.browser_session_principal_internal_v1(p_deployment_public_id, p_recovery_epoch,
        p_session_digest_key_id, p_session_digest);
    v_intent := mesh_ops.browser_page_intent_internal_v1(p_deployment_public_id, p_recovery_epoch,
        p_intent_token_digest);
    IF v_principal IS NULL OR v_intent IS NULL THEN
        RETURN;
    END IF;
    SELECT pg_catalog.array_agg(sibling.machine_key) INTO v_keys
    FROM mesh_ops.browser_intent_sibling AS sibling WHERE sibling.intent_id = v_intent;
    IF v_keys IS NULL THEN
        RETURN;
    END IF;
    FOR v_row IN SELECT * FROM mesh_ops.sibling_device_internal_v1(v_keys, v_principal, NULL, NULL) LOOP
        BEGIN
            PERFORM pg_catalog.set_config('mesh.workspace_id', v_row.workspace_id::TEXT, TRUE);
            PERFORM pg_catalog.set_config('mesh.network_id', v_row.network_id::TEXT, TRUE);
            SELECT device.public_id, device.hostname, v_row.device_state, workspace.public_id, network.public_id,
                   network.display_name
            INTO device_public_id, device_hostname, device_state, workspace_public_id, network_public_id,
                 network_display_name
            FROM mesh.device AS device
            JOIN mesh.network AS network ON network.workspace_id = device.workspace_id
             AND network.id = device.network_id
            JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
            WHERE device.id = v_row.device_id;
            PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
            PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
        EXCEPTION
            WHEN OTHERS THEN
                PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(v_saved_workspace, ''), TRUE);
                PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(v_saved_network, ''), TRUE);
                RAISE;
        END;
        IF device_public_id IS NOT NULL THEN
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lookup_browser_sibling_devices_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lookup_browser_sibling_devices_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA)
    TO mesh_runtime;

-- Called in the approval transaction (design §6.2, §19 N2): from then on the sign-in keeps only sibling keys that
-- hold one of the approver's Devices, or no active Device at all (one may get a Device while the sign-in waits).
CREATE FUNCTION mesh_ops.minimize_browser_intent_siblings_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_intent_token_digest BYTEA, p_principal_public_id UUID
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_intent BIGINT;
    v_principal BIGINT;
    v_count INTEGER;
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_principal_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser sibling minimization';
    END IF;
    SELECT intent.id INTO v_intent
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.state = 'approved';
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;
    IF v_intent IS NULL OR v_principal IS NULL THEN
        RETURN 0;
    END IF;
    DELETE FROM mesh_ops.browser_intent_sibling AS sibling
    WHERE sibling.intent_id = v_intent
      AND EXISTS (
          SELECT 1 FROM mesh.device_machine_key_epoch AS machine
          WHERE machine.public_key = sibling.machine_key AND machine.state = 'active')
      AND NOT EXISTS (
          SELECT 1 FROM mesh_ops.sibling_device_internal_v1(ARRAY[sibling.machine_key], v_principal, NULL, NULL));
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.minimize_browser_intent_siblings_v1(UUID, BIGINT, BYTEA, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.minimize_browser_intent_siblings_v1(UUID, BIGINT, BYTEA, UUID)
    TO mesh_runtime;

-- "Use that account" (design §8.2, §19 N1): the person chose the Device a sibling key of this pending sign-in holds.
-- "Use that account" (design §8.2). Locks the sign-in, then the Network's revision (approval's order), checks the
-- rule, then ends the sign-in ('rejected', no registration) with a joined record and drops its sibling keys. The
-- change is p_change_public_id; the row returned is what the caller's audit evidence needs, in this transaction
-- (whose Network scope settings stay set). No row, with nothing changed, when anything does not hold; never says
-- whether the Device exists. Refused for a suspended Device (Q1: the page offers no button for it).
CREATE FUNCTION mesh_ops.join_browser_existing_device_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT,
    p_session_digest_key_id TEXT, p_session_digest BYTEA, p_intent_token_digest BYTEA,
    p_device_public_id UUID, p_change_public_id UUID
)
RETURNS TABLE (
    joined_intent_public_id UUID, joined_intent_version BIGINT, joined_principal_public_id UUID,
    joined_workspace_public_id UUID, joined_network_public_id UUID, joined_network_revision BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_principal BIGINT;
    v_intent mesh.browser_registration_intent%ROWTYPE;
    v_intent_id BIGINT;
    v_keys BYTEA[];
    v_device mesh.device%ROWTYPE;
    v_row RECORD;
    v_revision BIGINT;
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_session_digest_key_id IS NULL OR p_session_digest IS NULL
        OR pg_catalog.octet_length(p_session_digest) <> 32
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR p_device_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser existing-device choice';
    END IF;
    v_principal := mesh_ops.browser_session_principal_internal_v1(p_deployment_public_id, p_recovery_epoch,
        p_session_digest_key_id, p_session_digest);
    v_intent_id := mesh_ops.browser_page_intent_internal_v1(p_deployment_public_id, p_recovery_epoch,
        p_intent_token_digest);
    IF v_principal IS NULL OR v_intent_id IS NULL THEN
        RETURN;
    END IF;
    -- The sign-in first, as an approval locks it (review L2).
    SELECT * INTO v_intent FROM mesh.browser_registration_intent AS intent
    WHERE intent.id = v_intent_id AND intent.state = 'pending' FOR UPDATE;
    IF v_intent.id IS NULL THEN
        RETURN;
    END IF;
    SELECT pg_catalog.array_agg(sibling.machine_key) INTO v_keys
    FROM mesh_ops.browser_intent_sibling AS sibling WHERE sibling.intent_id = v_intent.id;
    IF v_keys IS NULL THEN
        RETURN;
    END IF;
    -- The person's Device through a sibling key, any Network, before any lock is taken on its Network: a public
    -- id alone never makes a pending sign-in lock another Network (review re-check L1).
    SELECT device.* INTO v_device FROM mesh.device AS device
    WHERE device.public_id = p_device_public_id
      AND device.id IN (SELECT sibling.device_id
                        FROM mesh_ops.sibling_device_internal_v1(v_keys, v_principal, NULL, NULL) AS sibling);
    IF v_device.id IS NULL THEN
        RETURN;
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_device.workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', v_device.network_id::TEXT, TRUE);
    SELECT revision.network_revision INTO v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_device.workspace_id AND revision.network_id = v_device.network_id
    FOR UPDATE;
    IF v_revision IS NULL THEN
        RETURN;
    END IF;
    -- Resume comes first (design §8.1): this sign-in signs its own Device in that Network back in instead.
    IF EXISTS (SELECT 1 FROM mesh_ops.sibling_device_internal_v1(ARRAY[v_intent.machine_key], v_principal,
                                                                 v_device.workspace_id, v_device.network_id)) THEN
        RETURN;
    END IF;
    -- Again under the lock.
    SELECT * INTO v_row FROM mesh_ops.sibling_device_internal_v1(v_keys, v_principal,
        v_device.workspace_id, v_device.network_id) AS sibling
    WHERE sibling.device_id = v_device.id AND sibling.device_state <> 'suspended';
    IF v_row.device_id IS NULL THEN
        RETURN;
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.browser_registration_intent AS intent
    SET state = 'rejected', version = intent.version + 1, updated_at = pg_catalog.clock_timestamp()
    WHERE intent.id = v_intent.id AND intent.state = 'pending';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'browser sign-in changed while joining';
    END IF;
    INSERT INTO mesh_ops.browser_intent_joined (intent_id, device_id, principal_id)
    VALUES (v_intent.id, v_device.id, v_principal);
    DELETE FROM mesh_ops.browser_intent_sibling AS sibling WHERE sibling.intent_id = v_intent.id;
    RETURN QUERY
    SELECT v_intent.public_id, v_intent.version + 1, principal.public_id, workspace.public_id, network.public_id,
           v_revision
    FROM mesh.principal AS principal, mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    WHERE principal.id = v_principal AND network.workspace_id = v_device.workspace_id
      AND network.id = v_device.network_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser existing-device scope is not visible';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.join_browser_existing_device_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.join_browser_existing_device_v1(UUID, BIGINT, TEXT, BYTEA, BYTEA, UUID, UUID)
    TO mesh_runtime;

-- At approval and at completion, under the target Network's revision lock and before any move or Device limit
-- (design §8.3, §8.4, §19 N2): whether a sibling key (stored, or proven again in the completing session) holds the
-- approver's Device in that Network. Returns that Device's id, or NULL. The approval passes no machine key (it has
-- none); the completion passes the Noise-proven one.
CREATE FUNCTION mesh_ops.browser_sibling_conflict_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_intent_token_digest BYTEA, p_machine_key BYTEA,
    p_session_keys BYTEA[], p_principal_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_intent BIGINT;
    v_principal BIGINT;
    v_workspace BIGINT;
    v_network BIGINT;
    v_keys BYTEA[];
    v_device BIGINT;
    v_own_key BYTEA;
BEGIN
    IF p_deployment_public_id IS NULL OR p_recovery_epoch IS NULL OR p_recovery_epoch <= 0
        OR p_intent_token_digest IS NULL OR pg_catalog.octet_length(p_intent_token_digest) <> 32
        OR (p_machine_key IS NOT NULL AND pg_catalog.octet_length(p_machine_key) <> 32)
        OR pg_catalog.cardinality(COALESCE(p_session_keys, ARRAY[]::BYTEA[])) > 16
        OR p_principal_public_id IS NULL OR p_workspace_public_id IS NULL OR p_network_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid browser sibling check';
    END IF;
    SELECT intent.id, intent.machine_key INTO v_intent, v_own_key
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND (p_machine_key IS NULL OR intent.machine_key = p_machine_key);
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;
    SELECT network.workspace_id, network.id INTO v_workspace, v_network
    FROM mesh.network AS network JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    WHERE workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id;
    -- Fail closed (review M2): a caller always holds this sign-in, person and Network.
    IF v_intent IS NULL OR v_principal IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'browser sibling check scope is not visible';
    END IF;
    -- Resume comes first (design §8.1): the sign-in's own key already holding the person's Device in this Network
    -- signs that Device back in, even beside an older duplicate (§11).
    IF EXISTS (SELECT 1 FROM mesh_ops.sibling_device_internal_v1(ARRAY[v_own_key], v_principal, v_workspace,
                                                                 v_network)) THEN
        RETURN NULL;
    END IF;
    SELECT pg_catalog.array_agg(DISTINCT entry) INTO v_keys
    FROM (SELECT sibling.machine_key AS entry FROM mesh_ops.browser_intent_sibling AS sibling
          WHERE sibling.intent_id = v_intent
          UNION SELECT session_key FROM pg_catalog.unnest(COALESCE(p_session_keys, ARRAY[]::BYTEA[])) AS session_key
          WHERE pg_catalog.octet_length(session_key) = 32
            AND session_key IS DISTINCT FROM p_machine_key) AS keys;
    IF v_keys IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT sibling.device_id INTO v_device
    FROM mesh_ops.sibling_device_internal_v1(v_keys, v_principal, v_workspace, v_network) AS sibling
    LIMIT 1;
    RETURN v_device;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.browser_sibling_conflict_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA[], UUID, UUID, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.browser_sibling_conflict_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA[], UUID, UUID, UUID)
    TO mesh_runtime;

-- The completion's answer for a sign-in the person ended with "Use that account" (also its replay, design §19 N3):
-- the machine key the joined Device holds now, through its active epoch. No row for any other sign-in, or when
-- that Device no longer holds an active key (the node signs in again).
CREATE FUNCTION mesh_ops.lookup_browser_joined_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_intent_token_digest BYTEA,
    p_machine_key BYTEA, p_machine_key_fingerprint BYTEA, p_requested_node_key BYTEA
)
RETURNS TABLE (sibling_machine_key BYTEA)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT machine.public_key
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    JOIN mesh_ops.browser_intent_joined AS joined ON joined.intent_id = intent.id
    JOIN mesh.device_machine_key_epoch AS machine ON machine.device_id = joined.device_id
     AND machine.state = 'active'
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest
      AND intent.machine_key = p_machine_key
      AND intent.machine_key_fingerprint = p_machine_key_fingerprint
      AND intent.requested_node_key = p_requested_node_key
      AND intent.state = 'rejected'
      AND intent.expires_at + INTERVAL '10 minutes' > pg_catalog.clock_timestamp()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lookup_browser_joined_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lookup_browser_joined_v1(UUID, BIGINT, BYTEA, BYTEA, BYTEA, BYTEA)
    TO mesh_runtime;

-- Drops a sign-in's sibling keys when it ends (completion; design §6.3).
CREATE FUNCTION mesh_ops.clear_browser_intent_siblings_v1(
    p_deployment_public_id UUID, p_recovery_epoch BIGINT, p_intent_token_digest BYTEA
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count INTEGER;
BEGIN
    DELETE FROM mesh_ops.browser_intent_sibling AS sibling
    USING mesh.browser_registration_intent AS intent, mesh.deployment AS deployment
    WHERE sibling.intent_id = intent.id AND deployment.id = intent.deployment_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND intent.issued_recovery_epoch = p_recovery_epoch
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_intent_token_digest;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.clear_browser_intent_siblings_v1(UUID, BIGINT, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.clear_browser_intent_siblings_v1(UUID, BIGINT, BYTEA) TO mesh_runtime;
