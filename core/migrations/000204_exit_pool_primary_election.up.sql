-- Schema 204: Core elects each Exit Pool's primary exit node (exit node
-- design §9, step E1c), as it elects Sites' primary routers (schema 193).
--
-- The worker reads, page by page, the facts of every active pool with exit
-- nodes (priority, state, whether each exit node's Device is live,
-- Workspace-owned and offers to be an exit node, and the current primary),
-- adds what Redis holds of the exit nodes' health, and decides in Go with
-- the election Sites use. A change is written by prepare and finalize in one
-- transaction: prepare checks the generation the decision was made on,
-- records the new primary, advances the Network and route revisions and
-- returns the evidence; Go hashes it; finalize appends the audit event
-- exit_pool.primary_changed (system.reconcile, no actor) with the revision
-- wakeup that rebuilds the Network's maps. A pool's read carries its
-- primary, and its primary changes read back from the audit history.

CREATE TABLE mesh.exit_pool_primary (
    pool_id BIGINT PRIMARY KEY,
    -- The pool's public ID, which names the aggregate in the audit stream.
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    -- NULL: no exit node can serve the pool. previous_device_id is the
    -- primary this election replaced, for its evidence.
    device_id BIGINT,
    previous_device_id BIGINT,
    generation BIGINT NOT NULL CHECK (generation > 0),
    reason TEXT NOT NULL CHECK (reason ~ '^[a-z_]{1,32}$'),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    elected_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT exit_pool_primary_pool_fk FOREIGN KEY (workspace_id, network_id, pool_id)
        REFERENCES mesh.network_exit_pool (workspace_id, network_id, id) ON DELETE CASCADE,
    CONSTRAINT exit_pool_primary_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE SET NULL (device_id),
    CONSTRAINT exit_pool_primary_previous_device_fk FOREIGN KEY (workspace_id, network_id, previous_device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE SET NULL (previous_device_id)
);

CREATE INDEX exit_pool_primary_device_idx ON mesh.exit_pool_primary (device_id) WHERE device_id IS NOT NULL;

CREATE TRIGGER exit_pool_primary_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.exit_pool_primary
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('exit_pool_primary', 'public_id');

ALTER TABLE mesh.exit_pool_primary ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.exit_pool_primary FORCE ROW LEVEL SECURITY;
CREATE POLICY exit_pool_primary_migrator_policy ON mesh.exit_pool_primary
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.exit_pool_primary FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
    mesh_share_writer;

-- One page of active Exit Pools with exit nodes, in pool order after
-- p_after_pool: each pool's failback setting, its current primary and
-- generation (none before its first election) and its exit nodes with the
-- facts that decide whether they can serve. A discovery read: prepare checks
-- again under locks.
CREATE FUNCTION mesh_ops.list_exit_pool_elections_v1(p_deployment UUID, p_after_pool UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_pool RECORD;
    v_items JSONB := '[]'::JSONB;
    v_count INTEGER := 0;
BEGIN
    IF p_deployment IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 64 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Exit Pool election page';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    FOR v_pool IN
        SELECT exit_pool.id, exit_pool.public_id, exit_pool.workspace_id, exit_pool.network_id,
               exit_pool.failback, pool_primary.device_id AS primary_id,
               COALESCE(pool_primary.generation, 0) AS generation
        FROM mesh.network_exit_pool AS exit_pool
        LEFT JOIN mesh.exit_pool_primary AS pool_primary ON pool_primary.pool_id = exit_pool.id
        WHERE exit_pool.deployment_id = v_deployment_id AND exit_pool.state = 'active'
          AND (p_after_pool IS NULL OR exit_pool.public_id > p_after_pool)
          AND EXISTS (SELECT 1 FROM mesh.network_exit_node AS any_node WHERE any_node.pool_id = exit_pool.id)
        ORDER BY exit_pool.public_id
        LIMIT p_limit + 1
    LOOP
        v_count := v_count + 1;
        EXIT WHEN v_count > p_limit;
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_pool.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_pool.network_id::TEXT, TRUE);
        v_items := v_items || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'pool_id', v_pool.public_id,
            'workspace_id', (SELECT workspace.public_id FROM mesh.workspace AS workspace
                             WHERE workspace.id = v_pool.workspace_id),
            'network_id', (SELECT network.public_id FROM mesh.network AS network
                           WHERE network.workspace_id = v_pool.workspace_id AND network.id = v_pool.network_id),
            'failback', v_pool.failback,
            'primary_device_id', (SELECT device.public_id FROM mesh.device AS device
                                  WHERE device.workspace_id = v_pool.workspace_id
                                    AND device.network_id = v_pool.network_id AND device.id = v_pool.primary_id),
            'generation', v_pool.generation,
            'nodes', (
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'device_id', device.public_id,
                    'priority', exit_node.priority,
                    'state', exit_node.state,
                    'live', device.state = 'active' AND device.expires_at > pg_catalog.transaction_timestamp(),
                    'workspace_owned', device.ownership = 'workspace',
                    'offered', COALESCE(offer.offered, FALSE)
                ) ORDER BY exit_node.priority, device.public_id)
                FROM mesh.network_exit_node AS exit_node
                JOIN mesh.device AS device
                  ON device.workspace_id = exit_node.workspace_id AND device.network_id = exit_node.network_id
                 AND device.id = exit_node.device_id
                LEFT JOIN mesh.device_exit_offer AS offer ON offer.device_id = exit_node.device_id
                WHERE exit_node.pool_id = v_pool.id
            )
        ));
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('items', v_items, 'done', v_count <= p_limit);
END;
$function$;

-- The audit and outbox payloads of a primary change, as prepare returns and
-- finalize recomputes them.
CREATE FUNCTION mesh_ops.exit_pool_primary_payloads_internal_v1(
    p_pool UUID, p_device UUID, p_previous UUID, p_reason TEXT, p_generation BIGINT,
    p_network_revision BIGINT, p_route_revision BIGINT
)
RETURNS TABLE (audit_payload JSONB, outbox_payload JSONB)
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
               'exit_pool_public_id', p_pool, 'device_public_id', p_device,
               'previous_device_public_id', p_previous, 'reason', p_reason, 'generation', p_generation,
               'network_revision', p_network_revision, 'route_revision', p_route_revision),
           pg_catalog.jsonb_build_object(
               'network_revision', p_network_revision, 'subsystem', 'routes',
               'subsystem_revision', p_route_revision)
$function$;

-- Makes p_device (NULL: none) the primary of p_pool when its generation is
-- still p_expected_generation (0: never elected) and the Device is still one
-- of its exit nodes that can serve, and returns the evidence to hash;
-- otherwise changes nothing.
CREATE FUNCTION mesh_ops.prepare_exit_pool_primary_v1(
    p_deployment UUID, p_pool UUID, p_expected_generation BIGINT, p_device UUID, p_reason TEXT, p_change UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_unchanged CONSTANT JSONB := '{"changed":false}'::JSONB;
    v_deployment_id BIGINT;
    v_pool mesh.network_exit_pool%ROWTYPE;
    v_scope RECORD;
    v_current mesh.exit_pool_primary%ROWTYPE;
    v_device_id BIGINT;
    v_previous UUID;
    v_revisions RECORD;
    v_head RECORD;
    v_generation BIGINT;
    v_version BIGINT;
    v_payloads RECORD;
BEGIN
    IF p_pool IS NULL OR p_change IS NULL OR p_expected_generation IS NULL OR p_expected_generation < 0
        OR p_reason IS NULL OR p_reason !~ '^[a-z_]{1,32}$'
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_pool), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Exit Pool election';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    SELECT * INTO v_pool FROM mesh.network_exit_pool AS exit_pool
    WHERE exit_pool.public_id = p_pool AND exit_pool.deployment_id = v_deployment_id
      AND exit_pool.state = 'active';
    IF v_pool.id IS NULL THEN
        RETURN v_unchanged;
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_pool.workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', v_pool.network_id::TEXT, TRUE);
    SELECT workspace.public_id AS workspace_public_id, network.public_id AS network_public_id INTO v_scope
    FROM mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    WHERE network.workspace_id = v_pool.workspace_id AND network.id = v_pool.network_id;
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_pool.workspace_id, v_pool.network_id);

    SELECT * INTO v_current FROM mesh.exit_pool_primary AS pool_primary
    WHERE pool_primary.pool_id = v_pool.id FOR UPDATE;
    IF COALESCE(v_current.generation, 0) <> p_expected_generation THEN
        RETURN v_unchanged; -- decided on an older state
    END IF;
    IF p_device IS NOT NULL THEN
        -- Still an exit node of the pool that can serve it: the facts the
        -- decision was made on may have changed since the list.
        SELECT device.id INTO v_device_id
        FROM mesh.network_exit_node AS exit_node
        JOIN mesh.device AS device
          ON device.workspace_id = exit_node.workspace_id AND device.network_id = exit_node.network_id
         AND device.id = exit_node.device_id
        JOIN mesh.device_exit_offer AS offer ON offer.device_id = exit_node.device_id AND offer.offered
        WHERE exit_node.pool_id = v_pool.id AND device.public_id = p_device
          AND device.state = 'active' AND device.expires_at > pg_catalog.transaction_timestamp()
          AND device.ownership = 'workspace';
        IF v_device_id IS NULL THEN
            RETURN v_unchanged; -- no longer an exit node of the pool that can serve it
        END IF;
    END IF;
    IF v_current.pool_id IS NOT NULL AND v_current.device_id IS NOT DISTINCT FROM v_device_id THEN
        RETURN v_unchanged;
    END IF;
    SELECT device.public_id INTO v_previous FROM mesh.device AS device
    WHERE device.workspace_id = v_pool.workspace_id AND device.network_id = v_pool.network_id
      AND device.id = v_current.device_id;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(v_pool.workspace_id,
        v_pool.network_id);
    INSERT INTO mesh.exit_pool_primary AS pool_primary
        (pool_id, public_id, workspace_id, network_id, device_id, previous_device_id, generation, reason, elected_at)
    VALUES (v_pool.id, v_pool.public_id, v_pool.workspace_id, v_pool.network_id, v_device_id, NULL, 1, p_reason,
        pg_catalog.transaction_timestamp())
    ON CONFLICT (pool_id) DO UPDATE
    SET device_id = EXCLUDED.device_id, previous_device_id = pool_primary.device_id,
        generation = pool_primary.generation + 1, reason = EXCLUDED.reason,
        version = pool_primary.version + 1, elected_at = EXCLUDED.elected_at
    RETURNING pool_primary.generation, pool_primary.version INTO v_generation, v_version;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_pool.workspace_id AND stream.network_id = v_pool.network_id
    FOR UPDATE;
    SELECT * INTO STRICT v_payloads FROM mesh_ops.exit_pool_primary_payloads_internal_v1(p_pool, p_device, v_previous,
        p_reason, v_generation, v_revisions.network_revision, v_revisions.route_revision);
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE,
        'transaction_id', (pg_catalog.pg_current_xact_id()::TEXT),
        'change_id', p_change,
        'pool_id', p_pool,
        'generation', v_generation,
        'aggregate_version', v_version,
        'event', pg_catalog.jsonb_build_object(
            'workspace_id', v_scope.workspace_public_id,
            'network_id', v_scope.network_public_id,
            'stream_id', v_head.id,
            'sequence', v_head.next_sequence,
            'previous_hash', pg_catalog.encode(v_head.latest_event_hash, 'hex'),
            'network_revision', v_revisions.network_revision,
            'audit_payload', v_payloads.audit_payload::TEXT,
            'outbox_payload', v_payloads.outbox_payload::TEXT
        )
    );
END;
$function$;

-- Records the evidence prepare returned, once MeshCore has hashed it.
-- Everything appended is recomputed here and must match, so only the ids
-- and hash come from the caller.
CREATE FUNCTION mesh_ops.finalize_exit_pool_primary_v1(
    p_deployment UUID, p_pool UUID, p_change UUID, p_reason TEXT, p_event JSONB
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
    v_primary mesh.exit_pool_primary%ROWTYPE;
    v_device UUID;
    v_previous UUID;
    v_revisions RECORD;
    v_head RECORD;
    v_payloads RECORD;
    v_sequence BIGINT;
BEGIN
    IF p_pool IS NULL OR p_change IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z_]{1,32}$'
        OR p_event IS NULL OR pg_catalog.jsonb_typeof(p_event) <> 'object'
        OR pg_catalog.octet_length(p_event::TEXT) > 16384 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Exit Pool election evidence';
    END IF;
    IF pg_catalog.current_setting('mesh.change_public_id', TRUE) IS DISTINCT FROM p_change::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Exit Pool election was not prepared in this transaction';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    SELECT pool_primary.* INTO v_primary
    FROM mesh.exit_pool_primary AS pool_primary
    JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = pool_primary.pool_id
    WHERE pool_primary.public_id = p_pool AND exit_pool.deployment_id = v_deployment_id;
    IF v_primary.pool_id IS NULL OR v_primary.reason <> p_reason OR NOT EXISTS (
        SELECT 1 FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
          AND mutation.change_public_id = p_change
          AND mutation.aggregate_kind = 'exit_pool_primary'
          AND mutation.row_public_id = v_primary.public_id
          AND mutation.after_version = v_primary.version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Exit Pool election mutation missing';
    END IF;
    SELECT device.public_id INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_primary.workspace_id AND device.network_id = v_primary.network_id
      AND device.id = v_primary.device_id;
    SELECT device.public_id INTO v_previous FROM mesh.device AS device
    WHERE device.workspace_id = v_primary.workspace_id AND device.network_id = v_primary.network_id
      AND device.id = v_primary.previous_device_id;
    SELECT revision.network_revision, revision.route_revision INTO STRICT v_revisions
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_primary.workspace_id AND revision.network_id = v_primary.network_id;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_primary.workspace_id AND stream.network_id = v_primary.network_id
    FOR UPDATE;
    SELECT * INTO STRICT v_payloads FROM mesh_ops.exit_pool_primary_payloads_internal_v1(p_pool, v_device, v_previous,
        p_reason, v_primary.generation, v_revisions.network_revision, v_revisions.route_revision);
    IF (p_event ->> 'stream_id')::BIGINT IS DISTINCT FROM v_head.id
        OR (p_event ->> 'sequence')::BIGINT IS DISTINCT FROM v_head.next_sequence
        OR p_event ->> 'previous_hash' IS DISTINCT FROM pg_catalog.encode(v_head.latest_event_hash, 'hex')
        OR (p_event ->> 'network_revision')::BIGINT IS DISTINCT FROM v_revisions.network_revision
        OR p_event ->> 'audit_payload' IS DISTINCT FROM v_payloads.audit_payload::TEXT
        OR p_event ->> 'outbox_payload' IS DISTINCT FROM v_payloads.outbox_payload::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Exit Pool election evidence mismatch';
    END IF;
    v_sequence := mesh_audit.append_authority_evidence(
        v_head.id,
        (p_event ->> 'event_id')::UUID,
        (p_event ->> 'outbox_id')::UUID,
        v_head.next_sequence,
        v_head.latest_event_hash,
        pg_catalog.decode(p_event ->> 'event_hash', 'hex'),
        'exit_pool_primary',
        v_primary.public_id,
        v_primary.version,
        v_revisions.network_revision,
        NULL::UUID,
        'exit_pool.primary_changed',
        'system.reconcile',
        NULL::UUID,
        NULL::BYTEA,
        NULL::BYTEA,
        v_payloads.audit_payload,
        'network.revision.advanced',
        v_payloads.outbox_payload
    );
    IF v_sequence <> v_head.next_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Exit Pool election evidence changed';
    END IF;
    RETURN 1;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.exit_pool_primary_payloads_internal_v1(UUID, UUID, UUID, TEXT, BIGINT, BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_exit_pool_elections_v1(UUID, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_exit_pool_primary_v1(UUID, UUID, BIGINT, UUID, TEXT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.finalize_exit_pool_primary_v1(UUID, UUID, UUID, TEXT, JSONB)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Only the worker role elects primaries.
GRANT EXECUTE ON FUNCTION mesh_ops.list_exit_pool_elections_v1(UUID, UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_exit_pool_primary_v1(UUID, UUID, BIGINT, UUID, TEXT, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_exit_pool_primary_v1(UUID, UUID, UUID, TEXT, JSONB) TO mesh_worker;

-- One active Exit Pool (route.read), as read_exit_pool_v1, with its elected
-- primary: NULL before the first election; device_id NULL when no exit node
-- can serve.
CREATE FUNCTION mesh_ops.read_exit_pool_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_pool_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_reading JSONB;
    v_primary JSONB;
BEGIN
    v_reading := mesh_ops.read_exit_pool_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_pool_public_id);
    SELECT pg_catalog.jsonb_build_object(
               'device_id', device.public_id,
               'generation', pool_primary.generation,
               'reason', pool_primary.reason,
               'elected_at', pool_primary.elected_at)
    INTO v_primary
    FROM mesh.exit_pool_primary AS pool_primary
    JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = pool_primary.pool_id
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = pool_primary.workspace_id AND device.network_id = pool_primary.network_id
     AND device.id = pool_primary.device_id
    WHERE pool_primary.public_id = p_pool_public_id
      AND exit_pool.workspace_id = mesh_ops.current_workspace_id()
      AND exit_pool.network_id = mesh_ops.current_network_id();
    RETURN v_reading || pg_catalog.jsonb_build_object('primary', v_primary);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_exit_pool_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_exit_pool_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- One page of an Exit Pool's primary changes (route.read), newest first, after the
-- change p_after_event_public_id when given: each the audit event Core
-- recorded with the pool's primary election. A bounded read on the audit
-- index of (Workspace, target, time).
CREATE FUNCTION mesh_ops.list_exit_pool_primary_changes_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_pool_public_id UUID,
    p_after_event_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_after_at TIMESTAMPTZ;
    v_page JSONB;
    v_count INTEGER;
BEGIN
    IF p_pool_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool primary history page is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    IF NOT EXISTS (SELECT 1 FROM mesh.network_exit_pool AS exit_pool
                   WHERE exit_pool.workspace_id = v_scope.workspace_id
                     AND exit_pool.network_id = v_scope.network_id
                     AND exit_pool.public_id = p_pool_public_id AND exit_pool.state = 'active') THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Exit Pool is unavailable';
    END IF;
    IF p_after_event_public_id IS NOT NULL THEN
        SELECT event.occurred_at INTO v_after_at
        FROM mesh_audit.audit_event_identity AS identity
        JOIN mesh_audit.audit_event AS event
          ON event.event_identity_id = identity.id AND event.occurred_at = identity.occurred_at
        WHERE identity.public_id = p_after_event_public_id
          AND event.workspace_id = v_scope.workspace_id AND event.network_id = v_scope.network_id
          AND event.target_public_id = p_pool_public_id AND event.target_kind = 'exit_pool_primary'
          AND event.action = 'exit_pool.primary_changed';
        IF v_after_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool primary history cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'event_id', page.event_public_id,
               'occurred_at', page.occurred_at,
               'device_id', page.payload -> 'device_public_id',
               'previous_device_id', page.payload -> 'previous_device_public_id',
               'reason', page.payload -> 'reason',
               'generation', page.payload -> 'generation'
           ) ORDER BY page.occurred_at DESC, page.event_public_id DESC),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT event.occurred_at, event.payload, identity.public_id AS event_public_id
        FROM mesh_audit.audit_event AS event
        JOIN mesh_audit.audit_event_identity AS identity
          ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
        WHERE event.workspace_id = v_scope.workspace_id AND event.target_public_id = p_pool_public_id
          AND event.network_id = v_scope.network_id
          AND event.target_kind = 'exit_pool_primary' AND event.action = 'exit_pool.primary_changed'
          AND (v_after_at IS NULL
               OR (event.occurred_at, identity.public_id) < (v_after_at, p_after_event_public_id))
        ORDER BY event.occurred_at DESC, identity.public_id DESC
        LIMIT p_limit + 1
    ) AS page;
    RETURN pg_catalog.jsonb_build_object(
        'changes', CASE WHEN v_count > p_limit THEN v_page - p_limit ELSE COALESCE(v_page, '[]'::JSONB) END,
        'has_more', v_count > p_limit
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_exit_pool_primary_changes_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_exit_pool_primary_changes_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;
