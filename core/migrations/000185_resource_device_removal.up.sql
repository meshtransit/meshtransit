-- Retires the Device Resource of a removed Device. Traffic already stops when
-- the Device leaves (map readers require an active Device), but the Resource
-- stayed active: it kept its name, so the Device enrolled again under the
-- same hostname could not be shared, and it was still offered for sharing.
-- Retiring moves the Resource to deleted and its Device target to superseded
-- and advances the Network, so the name and the Device can be used again. A
-- suspended or expired Device can come back and keeps its Resource.
--
-- Removing a Device queues its Resource through a trigger, whichever path
-- removed it; the migration queues the Resources of Devices already removed.
-- The worker role calls bounded entry points, as for shares of removed
-- Devices (schema 178): prepare changes the rows and returns the evidence to
-- hash, finalize records it and drops the queue row in the same transaction.
-- A Resource still in use waits, looked at again every five minutes: an open
-- share of it ends first (schema 178), and a Resource an active policy
-- release or a current Resource Group names stays until that rule or member
-- is removed, since publication resolves those destinations only while they
-- are active (schema 165) and retiring one would fail every later
-- publication of the Network. An export or an undecided offer of a retired
-- Resource is left as it is: accepting it fails closed, as for a Resource
-- deleted by hand.

-- A hint, not authority: no foreign key, so queueing never locks a Resource
-- row inside the transaction that removes the Device.
CREATE TABLE mesh_ops.resource_device_removal (
    resource_id BIGINT PRIMARY KEY,
    resource_public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    -- A Resource still in use is looked at again only after this instant.
    next_attempt_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX resource_device_removal_order_idx
    ON mesh_ops.resource_device_removal (deployment_id, requested_at, resource_public_id);

-- Only the definer functions below, owned by the migrator, read or write it.
ALTER TABLE mesh_ops.resource_device_removal ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.resource_device_removal FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_device_removal_migrator ON mesh_ops.resource_device_removal
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.resource_device_removal
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Queues the Resource bound to the Device's active target. A Device has at
-- most one active target (resource_device_target_active_device_uidx).
CREATE FUNCTION mesh_ops.queue_resource_device_removal_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    INSERT INTO mesh_ops.resource_device_removal (
        resource_id, resource_public_id, deployment_id, workspace_id, network_id, requested_at, next_attempt_at
    )
    SELECT resource.id, resource.public_id, resource.deployment_id,
        resource.workspace_id, resource.network_id, pg_catalog.transaction_timestamp(),
        pg_catalog.transaction_timestamp()
    FROM mesh.resource_device_target AS target
    JOIN mesh.resource AS resource
      ON resource.workspace_id = target.workspace_id
     AND resource.network_id = target.network_id
     AND resource.id = target.resource_id
     AND resource.target_generation = target.target_generation
    WHERE target.workspace_id = NEW.workspace_id
      AND target.network_id = NEW.network_id
      AND target.device_id = NEW.id
      AND target.state = 'active'
      AND resource.state <> 'deleted'
    ON CONFLICT (resource_id) DO NOTHING;
    RETURN NULL;
END;
$function$;

CREATE TRIGGER device_removal_retires_resource
AFTER UPDATE OF state ON mesh.device
FOR EACH ROW
WHEN (NEW.state IN ('revoked', 'deleted') AND OLD.state NOT IN ('revoked', 'deleted'))
EXECUTE FUNCTION mesh_ops.queue_resource_device_removal_v1();

-- Resources whose Device is already gone.
INSERT INTO mesh_ops.resource_device_removal (
    resource_id, resource_public_id, deployment_id, workspace_id, network_id, requested_at, next_attempt_at
)
SELECT resource.id, resource.public_id, resource.deployment_id,
    resource.workspace_id, resource.network_id, pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp()
FROM mesh.resource AS resource
JOIN mesh.resource_device_target AS target
  ON target.workspace_id = resource.workspace_id
 AND target.network_id = resource.network_id
 AND target.resource_id = resource.id
 AND target.target_generation = resource.target_generation
 AND target.state = 'active'
JOIN mesh.device AS device
  ON device.workspace_id = target.workspace_id
 AND device.network_id = target.network_id
 AND device.id = target.device_id
WHERE resource.state <> 'deleted'
  AND device.state IN ('revoked', 'deleted')
ON CONFLICT (resource_id) DO NOTHING;

-- Whether the Resource is still in use: an open share, a destination of an
-- active policy release in its own Network or, through a share, in another,
-- or a member of a current Resource Group definition. Only the provider
-- Network is locked: a consumer release can add an imported destination only
-- for an activating or active contract, which this check already counts, and
-- a new contract needs the provider Network's revision lock.
CREATE FUNCTION mesh_ops.resource_retirement_blocked_internal_v1(p_resource_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh.resource AS resource
        WHERE resource.id = p_resource_id AND (
            EXISTS (
                SELECT 1 FROM mesh.trust_contract AS contract
                WHERE contract.provider_workspace_id = resource.workspace_id
                  AND contract.provider_network_id = resource.network_id
                  AND contract.resource_id = resource.id
                  AND contract.state IN ('activating', 'active')
            )
            OR EXISTS (
                SELECT 1 FROM mesh.compiled_policy_resource_destination AS destination
                JOIN mesh.compiled_policy_rule AS rule ON rule.id = destination.compiled_policy_rule_id
                JOIN mesh.policy_release AS release
                  ON release.id = rule.policy_release_id AND release.state = 'active'
                WHERE destination.workspace_id = resource.workspace_id
                  AND destination.network_id = resource.network_id
                  AND destination.destination_resource_id = resource.id
            )
            OR EXISTS (
                SELECT 1 FROM mesh.compiled_policy_resource_group_destination AS destination
                JOIN mesh.compiled_policy_rule AS rule ON rule.id = destination.compiled_policy_rule_id
                JOIN mesh.policy_release AS release
                  ON release.id = rule.policy_release_id AND release.state = 'active'
                WHERE destination.workspace_id = resource.workspace_id
                  AND destination.network_id = resource.network_id
                  AND destination.destination_resource_id = resource.id
            )
            OR EXISTS (
                SELECT 1 FROM mesh.compiled_policy_imported_resource_destination AS destination
                JOIN mesh.policy_release AS release
                  ON release.id = destination.policy_release_id AND release.state = 'active'
                WHERE destination.provider_workspace_id = resource.workspace_id
                  AND destination.provider_network_id = resource.network_id
                  AND destination.destination_resource_id = resource.id
            )
            OR EXISTS (
                SELECT 1 FROM mesh.resource_group_version_member AS member
                JOIN mesh.resource_group_version AS definition ON definition.id = member.resource_group_version_id
                JOIN mesh.resource_group AS resource_group
                  ON resource_group.id = definition.resource_group_id
                 AND resource_group.state <> 'deleted'
                 AND resource_group.active_definition_version = definition.definition_version
                WHERE member.workspace_id = resource.workspace_id
                  AND member.network_id = resource.network_id
                  AND member.resource_id = resource.id
            )
        )
    )
$function$;

-- The installation the worker serves, or an error.
CREATE FUNCTION mesh_ops.resource_device_removal_deployment_internal_v1(p_deployment UUID)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
BEGIN
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment AND deployment.deleted_at IS NULL;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource retirement installation is unavailable';
    END IF;
    RETURN v_deployment_id;
END;
$function$;

-- Lists at most p_limit queued Resources in (requested_at, resource) order.
-- The result is a discovery hint; prepare rechecks everything under locks.
CREATE FUNCTION mesh_ops.list_resource_device_removals_v1(
    p_deployment UUID,
    p_after_requested_at TIMESTAMPTZ,
    p_after_resource UUID,
    p_limit INTEGER
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
    v_items JSONB;
    v_count INTEGER;
BEGIN
    IF p_deployment IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 128
        OR (p_after_requested_at IS NULL) <> (p_after_resource IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource retirement page';
    END IF;
    v_deployment_id := mesh_ops.resource_device_removal_deployment_internal_v1(p_deployment);
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'resource_id', page.resource_public_id, 'requested_at', page.requested_at
        ) ORDER BY page.requested_at, page.resource_public_id), '[]'::JSONB),
        pg_catalog.count(*)
    INTO v_items, v_count
    FROM (
        SELECT removal.resource_public_id, removal.requested_at
        FROM mesh_ops.resource_device_removal AS removal
        WHERE removal.deployment_id = v_deployment_id
          AND removal.next_attempt_at <= pg_catalog.transaction_timestamp()
          AND (
              p_after_requested_at IS NULL
              OR (removal.requested_at, removal.resource_public_id) > (p_after_requested_at, p_after_resource)
          )
        ORDER BY removal.requested_at, removal.resource_public_id
        LIMIT p_limit + 1
    ) AS page;
    IF v_count > p_limit THEN
        v_items := v_items - p_limit;
    END IF;
    RETURN pg_catalog.jsonb_build_object('items', v_items, 'done', v_count <= p_limit);
END;
$function$;

-- Retires one queued Resource of a removed Device and returns the evidence
-- to hash. A Resource already deleted, rebound, or whose Device was not
-- removed only drops its queue row; one locked by a concurrent writer or
-- still in use keeps it for a later sweep. Lock order: the Network revision,
-- the Resource (skipping a concurrent writer), its target, then the audit
-- head.
CREATE FUNCTION mesh_ops.prepare_resource_device_removal_v1(
    p_deployment UUID,
    p_resource UUID,
    p_change UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_unchanged CONSTANT JSONB := '{"changed":false,"events":[]}'::JSONB;
    v_deployment_id BIGINT;
    v_queued mesh_ops.resource_device_removal%ROWTYPE;
    v_resource mesh.resource%ROWTYPE;
    v_target mesh.resource_device_target%ROWTYPE;
    v_device_public_id UUID;
    v_device_state TEXT;
    v_now TIMESTAMPTZ;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_head RECORD;
    v_scope RECORD;
    v_audit JSONB;
    v_outbox JSONB;
BEGIN
    IF p_resource IS NULL OR p_change IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource retirement';
    END IF;
    v_deployment_id := mesh_ops.resource_device_removal_deployment_internal_v1(p_deployment);
    SELECT * INTO v_queued FROM mesh_ops.resource_device_removal AS removal
    WHERE removal.resource_public_id = p_resource AND removal.deployment_id = v_deployment_id;
    IF v_queued.resource_id IS NULL THEN
        RETURN v_unchanged;
    END IF;
    -- A Resource in use costs one read, then waits five minutes; the locked
    -- check decides.
    IF mesh_ops.resource_retirement_blocked_internal_v1(v_queued.resource_id) THEN
        UPDATE mesh_ops.resource_device_removal AS removal
        SET next_attempt_at = pg_catalog.transaction_timestamp() + INTERVAL '5 minutes'
        WHERE removal.resource_id = v_queued.resource_id;
        RETURN v_unchanged;
    END IF;
    -- The Network's exact scope, which the row policies of its revision,
    -- Workspace and Network require; this transaction serves no other.
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_queued.workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', v_queued.network_id::TEXT, TRUE);
    SELECT workspace.public_id AS workspace_public_id, network.public_id AS network_public_id INTO v_scope
    FROM mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    WHERE network.workspace_id = v_queued.workspace_id AND network.id = v_queued.network_id;
    IF v_scope.network_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Resource retirement scope is unavailable';
    END IF;

    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_queued.workspace_id AND revision.network_id = v_queued.network_id
    FOR UPDATE;
    SELECT * INTO v_resource FROM mesh.resource AS resource
    WHERE resource.workspace_id = v_queued.workspace_id AND resource.network_id = v_queued.network_id
      AND resource.id = v_queued.resource_id
    FOR UPDATE SKIP LOCKED;
    IF v_resource.id IS NULL THEN
        -- A concurrent writer holds it; the next sweep retries.
        RETURN v_unchanged;
    END IF;
    SELECT target.* INTO v_target FROM mesh.resource_device_target AS target
    WHERE target.workspace_id = v_resource.workspace_id AND target.network_id = v_resource.network_id
      AND target.resource_id = v_resource.id AND target.target_generation = v_resource.target_generation
      AND target.state = 'active'
    FOR UPDATE;
    SELECT device.public_id, device.state INTO v_device_public_id, v_device_state
    FROM mesh.device AS device
    WHERE device.workspace_id = v_target.workspace_id AND device.network_id = v_target.network_id
      AND device.id = v_target.device_id;
    IF v_resource.state = 'deleted' OR v_target.id IS NULL
        OR v_device_state IS NULL OR v_device_state NOT IN ('revoked', 'deleted') THEN
        -- Deleted or rebound another way, or the Device was never removed.
        DELETE FROM mesh_ops.resource_device_removal AS removal WHERE removal.resource_id = v_resource.id;
        RETURN v_unchanged;
    END IF;
    IF mesh_ops.resource_retirement_blocked_internal_v1(v_resource.id) THEN
        -- Still in use; keep the queue row for a later attempt.
        UPDATE mesh_ops.resource_device_removal AS removal
        SET next_attempt_at = pg_catalog.transaction_timestamp() + INTERVAL '5 minutes'
        WHERE removal.resource_id = v_resource.id;
        RETURN v_unchanged;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    v_now := GREATEST(pg_catalog.transaction_timestamp(), v_resource.updated_at, v_target.updated_at);
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        updated_at = GREATEST(v_now, revision.updated_at)
    WHERE revision.workspace_id = v_resource.workspace_id AND revision.network_id = v_resource.network_id
    RETURNING revision.network_revision, revision.inventory_revision
    INTO v_network_revision, v_inventory_revision;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Resource retirement scope is unavailable';
    END IF;
    UPDATE mesh.resource_device_target AS target
    SET state = 'superseded', version = target.version + 1, updated_at = v_now
    WHERE target.id = v_target.id;
    UPDATE mesh.resource AS resource
    SET state = 'deleted', activated_network_revision = v_network_revision,
        inventory_revision = v_inventory_revision, version = resource.version + 1,
        updated_at = v_now, deleted_at = v_now
    WHERE resource.id = v_resource.id
    RETURNING * INTO v_resource;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_resource.workspace_id AND stream.network_id = v_resource.network_id
    FOR UPDATE;
    v_audit := pg_catalog.jsonb_build_object(
        'resource_public_id', v_resource.public_id,
        'device_public_id', v_device_public_id,
        'reason', 'device_removed',
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision
    );
    v_outbox := pg_catalog.jsonb_build_object(
        'network_revision', v_network_revision,
        'subsystem', 'inventory',
        'subsystem_revision', v_inventory_revision
    );
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE,
        'transaction_id', (pg_catalog.pg_current_xact_id()::TEXT),
        'change_id', p_change,
        'resource_id', v_resource.public_id,
        'aggregate_version', v_resource.version,
        'event', pg_catalog.jsonb_build_object(
            'workspace_id', v_scope.workspace_public_id,
            'network_id', v_scope.network_public_id,
            'stream_id', v_head.id,
            'sequence', v_head.next_sequence,
            'previous_hash', pg_catalog.encode(v_head.latest_event_hash, 'hex'),
            'network_revision', v_network_revision,
            'audit_payload', v_audit::TEXT,
            'outbox_payload', v_outbox::TEXT
        )
    );
END;
$function$;

-- Records the evidence prepare returned, once MeshCore has hashed it, and
-- drops the queue row. Everything it appends is recomputed here and must
-- match, so only the ids and hash come from the caller.
CREATE FUNCTION mesh_ops.finalize_resource_device_removal_v1(
    p_deployment UUID,
    p_resource UUID,
    p_change UUID,
    p_event JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_resource mesh.resource%ROWTYPE;
    v_head RECORD;
    v_sequence BIGINT;
    v_rows INTEGER;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_device_public_id UUID;
    v_audit JSONB;
    v_outbox JSONB;
BEGIN
    IF p_resource IS NULL OR p_change IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7
        OR p_event IS NULL OR pg_catalog.jsonb_typeof(p_event) <> 'object'
        OR pg_catalog.octet_length(p_event::TEXT) > 16384 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource retirement evidence';
    END IF;
    IF pg_catalog.current_setting('mesh.change_public_id', TRUE) IS DISTINCT FROM p_change::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource retirement was not prepared in this transaction';
    END IF;
    v_deployment_id := mesh_ops.resource_device_removal_deployment_internal_v1(p_deployment);
    SELECT resource.* INTO v_resource
    FROM mesh_ops.resource_device_removal AS removal
    JOIN mesh.resource AS resource ON resource.id = removal.resource_id
    WHERE removal.resource_public_id = p_resource AND removal.deployment_id = v_deployment_id;
    IF v_resource.id IS NULL OR v_resource.state <> 'deleted' OR NOT EXISTS (
        SELECT 1 FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
          AND mutation.change_public_id = p_change
          AND mutation.aggregate_kind = 'resource'
          AND mutation.row_public_id = v_resource.public_id
          AND mutation.after_version = v_resource.version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource retirement mutation missing';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision INTO v_network_revision, v_inventory_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_resource.workspace_id AND revision.network_id = v_resource.network_id;
    SELECT device.public_id INTO v_device_public_id
    FROM mesh.resource_device_target AS target
    JOIN mesh.device AS device
      ON device.workspace_id = target.workspace_id AND device.network_id = target.network_id
     AND device.id = target.device_id
    WHERE target.workspace_id = v_resource.workspace_id AND target.network_id = v_resource.network_id
      AND target.resource_id = v_resource.id AND target.target_generation = v_resource.target_generation;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_resource.workspace_id AND stream.network_id = v_resource.network_id
    FOR UPDATE;
    v_audit := pg_catalog.jsonb_build_object(
        'resource_public_id', v_resource.public_id,
        'device_public_id', v_device_public_id,
        'reason', 'device_removed',
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision
    );
    v_outbox := pg_catalog.jsonb_build_object(
        'network_revision', v_network_revision,
        'subsystem', 'inventory',
        'subsystem_revision', v_inventory_revision
    );
    IF (p_event ->> 'stream_id')::BIGINT IS DISTINCT FROM v_head.id
        OR (p_event ->> 'sequence')::BIGINT IS DISTINCT FROM v_head.next_sequence
        OR p_event ->> 'previous_hash' IS DISTINCT FROM pg_catalog.encode(v_head.latest_event_hash, 'hex')
        OR (p_event ->> 'network_revision')::BIGINT IS DISTINCT FROM v_network_revision
        OR p_event ->> 'audit_payload' IS DISTINCT FROM v_audit::TEXT
        OR p_event ->> 'outbox_payload' IS DISTINCT FROM v_outbox::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource retirement evidence mismatch';
    END IF;
    v_sequence := mesh_audit.append_authority_evidence(
        v_head.id,
        (p_event ->> 'event_id')::UUID,
        (p_event ->> 'outbox_id')::UUID,
        v_head.next_sequence,
        v_head.latest_event_hash,
        pg_catalog.decode(p_event ->> 'event_hash', 'hex'),
        'resource',
        v_resource.public_id,
        v_resource.version,
        v_network_revision,
        NULL::UUID,
        'resource.retired',
        'system.reconcile',
        NULL::UUID,
        NULL::BYTEA,
        NULL::BYTEA,
        v_audit,
        'network.revision.advanced',
        v_outbox
    );
    IF v_sequence <> v_head.next_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Resource retirement evidence changed';
    END IF;
    DELETE FROM mesh_ops.resource_device_removal AS removal WHERE removal.resource_id = v_resource.id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Resource retirement queue changed';
    END IF;
    RETURN 1;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.queue_resource_device_removal_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.resource_device_removal_deployment_internal_v1(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.resource_retirement_blocked_internal_v1(BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.list_resource_device_removals_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_resource_device_removal_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.finalize_resource_device_removal_v1(UUID, UUID, UUID, JSONB)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Only the worker role retires Resources of removed Devices.
GRANT EXECUTE ON FUNCTION mesh_ops.list_resource_device_removals_v1(UUID, TIMESTAMPTZ, UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_resource_device_removal_v1(UUID, UUID, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_resource_device_removal_v1(UUID, UUID, UUID, JSONB) TO mesh_worker;
