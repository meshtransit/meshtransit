-- Deleting a Resource supersedes its Device target.
--
-- transition_resource_lifecycle_v1 moved a deleted Resource to deleted but
-- left its Device target active, and a Device has at most one active target
-- (resource_device_target_active_device_uidx), so that Device could never
-- get a new Resource: creating one answered device_resource_exists. A
-- Resource retired because its Device left (schema 185) already supersedes
-- its target; a Resource deleted by hand now does the same, in the same
-- transaction and under the same change. Targets left active by earlier
-- deletions keep their state.
--
-- The body is the schema 39 definition with that one step added; CREATE OR
-- REPLACE keeps the owner and grants.
--
-- A deleted Resource's current target is now superseded, so read_resource_v2
-- and list_resources_v1 accept that target for a deleted Resource and still
-- return it, under GET and list?state=deleted. Access paths (maps, policy,
-- shares) keep requiring an active target.
--
-- prepare_resource_device_removal_v1 (schema 185) also says when a Resource
-- waits because it is still in use, so the worker can count those apart from
-- failures; otherwise it is unchanged.

CREATE OR REPLACE FUNCTION mesh_ops.transition_resource_lifecycle_v1(p_resource_public_id uuid, p_expected_resource_version bigint, p_target_state text, p_actor_principal_public_id uuid, p_occurred_at timestamp with time zone)
 RETURNS TABLE(network_revision bigint, inventory_revision bigint, resource_version bigint, resource_state text, semantic_hash bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    actor_principal_id BIGINT;
    current_network_revision BIGINT;
    current_inventory_revision BIGINT;
    current_resource_id BIGINT;
    current_resource_version BIGINT;
    current_resource_state TEXT;
    current_semantic_hash BYTEA;
    advanced_network_revision BIGINT;
    advanced_inventory_revision BIGINT;
    advanced_resource_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_resource_version IS NULL OR p_expected_resource_version <= 0
        OR p_target_state IS NULL OR p_target_state NOT IN ('active', 'suspended', 'deleted')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource lifecycle input';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision
    INTO current_network_revision, current_inventory_revision
    FROM mesh_ops.lock_network_revision() AS revision;

    SELECT principal.id INTO actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= p_occurred_at
     AND (membership.expires_at IS NULL OR membership.expires_at > p_occurred_at)
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource lifecycle authority is unavailable';
    END IF;

    SELECT resource.id, resource.version, resource.state, resource.semantic_hash
    INTO current_resource_id, current_resource_version, current_resource_state, current_semantic_hash
    FROM mesh.resource AS resource
    WHERE resource.workspace_id = scoped_workspace_id
      AND resource.network_id = scoped_network_id
      AND resource.public_id = p_resource_public_id
    FOR UPDATE;
    IF current_resource_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource is unavailable';
    END IF;
    IF current_resource_version <> p_expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;
    IF current_resource_state = 'deleted'
        OR (p_target_state = 'active' AND current_resource_state <> 'suspended')
        OR (p_target_state = 'suspended' AND current_resource_state <> 'active')
        OR p_target_state = current_resource_state THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'invalid Resource lifecycle transition';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.inventory_revision = current_inventory_revision
    RETURNING revision.network_revision, revision.inventory_revision
    INTO advanced_network_revision, advanced_inventory_revision;
    IF advanced_network_revision IS NULL OR advanced_inventory_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource inventory revision changed';
    END IF;

    UPDATE mesh.resource AS resource
    SET state = p_target_state,
        activated_network_revision = advanced_network_revision,
        inventory_revision = advanced_inventory_revision,
        version = resource.version + 1,
        updated_at = p_occurred_at,
        deleted_at = CASE WHEN p_target_state = 'deleted' THEN p_occurred_at ELSE NULL END
    WHERE resource.id = current_resource_id
      AND resource.version = current_resource_version
    RETURNING resource.version INTO advanced_resource_version;
    IF advanced_resource_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;

    -- A deleted Resource frees its Device for a new Resource.
    IF p_target_state = 'deleted' THEN
        UPDATE mesh.resource_device_target AS target
        SET state = 'superseded', version = target.version + 1,
            updated_at = GREATEST(p_occurred_at, target.updated_at)
        WHERE target.workspace_id = scoped_workspace_id
          AND target.network_id = scoped_network_id
          AND target.resource_id = current_resource_id
          AND target.state = 'active';
    END IF;

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    resource_version := advanced_resource_version;
    resource_state := p_target_state;
    semantic_hash := current_semantic_hash;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.prepare_resource_device_removal_v1(
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
    v_blocked CONSTANT JSONB := '{"changed":false,"blocked":true,"events":[]}'::JSONB;
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
        RETURN v_blocked;
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
        RETURN v_blocked;
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

CREATE OR REPLACE FUNCTION mesh_ops.read_resource_v2(p_resource_public_id uuid)
 RETURNS TABLE(resource_public_id uuid, display_name text, owner_principal_public_id uuid, custodian_principal_public_id uuid, device_public_id uuid, resource_state text, resource_kind text, provenance_kind text, resource_version bigint, target_generation bigint, semantic_hash bytea, activated_network_revision bigint, inventory_revision bigint, created_at timestamp with time zone, updated_at timestamp with time zone)
 LANGUAGE sql
 STABLE PARALLEL SAFE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
    SELECT
        resource.public_id,
        resource.display_name,
        owner.public_id,
        custodian.public_id,
        device.public_id,
        resource.state,
        resource.kind,
        resource.provenance_kind,
        resource.version,
        resource.target_generation,
        resource.semantic_hash,
        resource.activated_network_revision,
        resource.inventory_revision,
        resource.created_at,
        resource.updated_at
    FROM mesh.resource AS resource
    JOIN mesh.principal AS owner ON owner.id = resource.owner_principal_id
    JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = resource.target_generation
     AND (target.state = 'active' OR resource.state = 'deleted')
    JOIN mesh.device AS device
      ON device.workspace_id = target.workspace_id
     AND device.network_id = target.network_id
     AND device.id = target.device_id
    WHERE resource.workspace_id = mesh_ops.current_workspace_id()
      AND resource.network_id = mesh_ops.current_network_id()
      AND resource.public_id = p_resource_public_id
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.list_resources_v1(p_after_public_id uuid, p_state text, p_limit integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE PARALLEL SAFE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    result JSONB;
BEGIN
    IF p_limit < 1 OR p_limit > 101 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource page limit';
    END IF;
    IF p_state IS NOT NULL AND p_state NOT IN ('active', 'suspended', 'deleted') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource state filter';
    END IF;

    SELECT COALESCE(
        pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.public_id),
        '[]'::JSONB
    ) INTO result
    FROM (
        SELECT
            resource.public_id,
            pg_catalog.jsonb_build_object(
                'resource_public_id', resource.public_id,
                'display_name', resource.display_name,
                'owner_principal_public_id', owner.public_id,
                'custodian_principal_public_id', custodian.public_id,
                'device_public_id', device.public_id,
                'state', resource.state,
                'kind', resource.kind,
                'provenance_kind', resource.provenance_kind,
                'version', resource.version,
                'target_generation', resource.target_generation,
                'semantic_hash', pg_catalog.encode(resource.semantic_hash, 'hex'),
                'activated_network_revision', resource.activated_network_revision,
                'inventory_revision', resource.inventory_revision,
                'created_at', resource.created_at,
                'updated_at', resource.updated_at
            ) AS payload
        FROM mesh.resource AS resource
        JOIN mesh.principal AS owner ON owner.id = resource.owner_principal_id
        JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND (target.state = 'active' OR resource.state = 'deleted')
        JOIN mesh.device AS device
          ON device.workspace_id = target.workspace_id
         AND device.network_id = target.network_id
         AND device.id = target.device_id
        WHERE resource.workspace_id = mesh_ops.current_workspace_id()
          AND resource.network_id = mesh_ops.current_network_id()
          AND (p_after_public_id IS NULL OR resource.public_id > p_after_public_id)
          AND (p_state IS NULL OR resource.state = p_state)
        ORDER BY resource.public_id
        LIMIT p_limit
    ) AS candidate;
    RETURN result;
END;
$function$;
