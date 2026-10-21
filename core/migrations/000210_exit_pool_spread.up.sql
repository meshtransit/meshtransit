-- Schema 210: Exit Pools that spread their consumers over their exit nodes
-- (exit node design §16). A pool's mode is failover (every consumer through
-- the elected primary, as before) or spread: the worker elects a serving
-- set of exit nodes, and maps give each consumer its own exit node of that
-- set by rendezvous hashing, keyed by the pool's secret salt.
--
-- The worker keeps electing every pool's primary as before, so a Core
-- without this schema's readers, or a pool back in failover mode, is right
-- at once. A serving set change is written by prepare and finalize in one
-- transaction, as a primary change is (schema 204): audit action
-- exit_pool.serving_changed (system.reconcile, no actor) with the revision
-- wakeup that rebuilds the Network's maps. Earlier functions stay for older
-- Cores during a rollout or a rollback.

ALTER TABLE mesh.network_exit_pool
    ADD COLUMN mode TEXT NOT NULL DEFAULT 'failover',
    ADD COLUMN assignment_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN spread_salt BYTEA,
    ADD CONSTRAINT network_exit_pool_mode_check CHECK (mode IN ('failover', 'spread')),
    ADD CONSTRAINT network_exit_pool_assignment_version_check CHECK (assignment_version BETWEEN 1 AND 32767),
    ADD CONSTRAINT network_exit_pool_spread_salt_check CHECK (
        (spread_salt IS NULL OR pg_catalog.octet_length(spread_salt) = 16)
        AND (mode <> 'spread' OR spread_salt IS NOT NULL)
    );

-- The serving set of a spread pool: the exit nodes consumers are assigned
-- to. previous_device_ids is the set this election replaced, for its
-- evidence. Devices are internal IDs in increasing order; a Device that
-- leaves the Network is dropped by the next election, and maps keep only
-- active exit nodes of the pool.
CREATE TABLE mesh.exit_pool_serving (
    pool_id BIGINT PRIMARY KEY,
    -- The pool's public ID, which names the aggregate in the audit stream.
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_ids BIGINT[] NOT NULL,
    previous_device_ids BIGINT[] NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    reason TEXT NOT NULL CHECK (reason ~ '^[a-z_]{1,32}$'),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    changed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT exit_pool_serving_devices_check CHECK (
        pg_catalog.cardinality(device_ids) <= 16 AND pg_catalog.cardinality(previous_device_ids) <= 16
        AND pg_catalog.array_position(device_ids, NULL) IS NULL
        AND pg_catalog.array_position(previous_device_ids, NULL) IS NULL
    ),
    CONSTRAINT exit_pool_serving_pool_fk FOREIGN KEY (workspace_id, network_id, pool_id)
        REFERENCES mesh.network_exit_pool (workspace_id, network_id, id) ON DELETE CASCADE
);

CREATE TRIGGER exit_pool_serving_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.exit_pool_serving
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('exit_pool_serving', 'public_id');

ALTER TABLE mesh.exit_pool_serving ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.exit_pool_serving FORCE ROW LEVEL SECURITY;
CREATE POLICY exit_pool_serving_migrator_policy ON mesh.exit_pool_serving
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.exit_pool_serving FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
    mesh_share_writer;

-- The public IDs of the Devices of a set that are still Devices of the
-- pool's Network, in public ID order.
CREATE FUNCTION mesh_ops.exit_pool_device_public_ids_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_device_ids BIGINT[]
)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE(pg_catalog.jsonb_agg(device.public_id ORDER BY device.public_id), '[]'::JSONB)
    FROM mesh.device AS device
    WHERE device.workspace_id = p_workspace_id AND device.network_id = p_network_id
      AND device.id = ANY (p_device_ids)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.exit_pool_device_public_ids_internal_v1(BIGINT, BIGINT, BIGINT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates, changes or deletes a pool as change_exit_pool_v1 of schema 202
-- does (a pool that active rules name is never deleted, MTX06), with its
-- mode; an update without a mode (NULL, from a Console that does not know
-- modes) keeps the stored one. p_spread_salt (16 random bytes from Go) becomes the pool's salt the
-- first time it is spread and is never replaced, so assignments stay put
-- across mode changes. Changing the mode empties the serving set, its
-- generation going on: the worker elects a new one for a spread pool. The result adds the mode before and
-- after the change; the salt never leaves the database.
CREATE FUNCTION mesh_ops.change_exit_pool_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_pool_public_id UUID, p_expected_version BIGINT, p_name TEXT, p_failback BOOLEAN,
    p_smtp_allowed BOOLEAN, p_conntrack_per_consumer INTEGER, p_dns_upstreams INET[], p_probes JSONB,
    p_mode TEXT, p_spread_salt BYTEA, p_pool_limit INTEGER, p_change_public_id UUID
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
    v_pool mesh.network_exit_pool%ROWTYPE;
    v_before JSONB;
    v_previous_mode TEXT;
    v_mode TEXT;
    v_revisions RECORD;
    v_constraint TEXT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_pool_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_pool_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_failback IS NULL OR p_smtp_allowed IS NULL
            OR p_conntrack_per_consumer IS NULL OR p_dns_upstreams IS NULL OR p_probes IS NULL
            OR p_mode NOT IN ('failover', 'spread')
            OR p_spread_salt IS NULL OR pg_catalog.octet_length(p_spread_salt) <> 16))
        OR (p_operation = 'create' AND (p_pool_limit IS NULL OR p_pool_limit NOT BETWEEN 1 AND 64
            OR p_mode IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id,
        CASE WHEN p_operation = 'delete' THEN 'route.withdraw' ELSE 'route.approve' END
    );
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_scope.workspace_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.network_exit_pool AS exit_pool
            WHERE exit_pool.workspace_id = v_scope.workspace_id
              AND exit_pool.network_id = v_scope.network_id
              AND exit_pool.state = 'active') >= p_pool_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTX02', MESSAGE = 'Network already has the maximum Exit Pools';
        END IF;
        BEGIN
            INSERT INTO mesh.network_exit_pool (
                public_id, deployment_id, workspace_id, network_id, name, name_key, failback, smtp_allowed,
                conntrack_per_consumer, dns_upstreams, probes, mode, spread_salt, created_at, updated_at
            ) VALUES (
                p_pool_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_failback, p_smtp_allowed, p_conntrack_per_consumer,
                p_dns_upstreams, p_probes, p_mode, CASE WHEN p_mode = 'spread' THEN p_spread_salt END, v_now, v_now
            ) RETURNING * INTO v_pool;
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_exit_pool_active_name_uidx' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTX01', MESSAGE = 'Exit Pool name is taken';
            END IF;
            RAISE;
        END;
    ELSE
        SELECT * INTO v_pool FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
          AND exit_pool.public_id = p_pool_public_id AND exit_pool.state = 'active'
        FOR UPDATE;
        IF v_pool.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Exit Pool is unavailable';
        END IF;
        IF v_pool.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Exit Pool version changed';
        END IF;
        v_before := mesh_ops.exit_pool_document_internal_v1(v_pool);
        v_previous_mode := v_pool.mode;
        v_mode := COALESCE(p_mode, v_pool.mode);
        IF p_operation = 'update' AND v_pool.name = p_name AND v_pool.failback = p_failback
            AND v_pool.smtp_allowed = p_smtp_allowed AND v_pool.conntrack_per_consumer = p_conntrack_per_consumer
            AND v_pool.dns_upstreams = p_dns_upstreams AND v_pool.probes = p_probes AND v_pool.mode = v_mode THEN
            RETURN pg_catalog.jsonb_build_object(
                'pool', v_before, 'previous', v_before, 'changed', FALSE,
                'mode', v_pool.mode, 'previous_mode', v_pool.mode,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        IF p_operation = 'update' THEN
            IF v_pool.mode <> v_mode THEN
                -- A new mode starts from an empty set; its generation goes on.
                UPDATE mesh.exit_pool_serving
                SET previous_device_ids = device_ids, device_ids = '{}'::BIGINT[], generation = generation + 1,
                    reason = 'none', version = version + 1, changed_at = v_now
                WHERE pool_id = v_pool.id AND pg_catalog.cardinality(device_ids) > 0;
            END IF;
            BEGIN
                UPDATE mesh.network_exit_pool
                SET name = p_name, name_key = pg_catalog.lower(p_name), failback = p_failback,
                    smtp_allowed = p_smtp_allowed, conntrack_per_consumer = p_conntrack_per_consumer,
                    dns_upstreams = p_dns_upstreams, probes = p_probes, mode = v_mode,
                    spread_salt = CASE WHEN v_mode = 'spread' THEN COALESCE(spread_salt, p_spread_salt)
                                       ELSE spread_salt END,
                    version = version + 1, updated_at = GREATEST(v_now, updated_at)
                WHERE id = v_pool.id
                RETURNING * INTO v_pool;
            EXCEPTION WHEN unique_violation THEN
                GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
                IF v_constraint = 'network_exit_pool_active_name_uidx' THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTX01', MESSAGE = 'Exit Pool name is taken';
                END IF;
                RAISE;
            END;
        ELSE
            IF mesh_ops.exit_pool_rule_count_internal_v1(v_pool.id) > 0 THEN
                RAISE EXCEPTION USING ERRCODE = 'MTX06', MESSAGE = 'Exit Pool is named by active rules';
            END IF;
            DELETE FROM mesh.network_exit_node WHERE pool_id = v_pool.id;
            UPDATE mesh.network_exit_pool
            SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at),
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_pool.id
            RETURNING * INTO v_pool;
        END IF;
    END IF;
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(
        v_scope.workspace_id, v_scope.network_id);
    RETURN pg_catalog.jsonb_build_object(
        'pool', mesh_ops.exit_pool_document_internal_v1(v_pool), 'previous', v_before, 'changed', TRUE,
        'mode', v_pool.mode, 'previous_mode', v_previous_mode,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_exit_pool_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, TEXT, BYTEA, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_exit_pool_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, TEXT, BYTEA, INTEGER, UUID
) TO mesh_runtime;

-- Changes an exit node as change_exit_node_v1 does; the result adds the
-- pool's mode.
CREATE FUNCTION mesh_ops.change_exit_node_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_pool_public_id UUID, p_expected_version BIGINT, p_device_public_id UUID,
    p_priority INTEGER, p_state TEXT, p_node_limit INTEGER, p_node_public_id UUID,
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
    v_result JSONB;
BEGIN
    v_result := mesh_ops.change_exit_node_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_operation, p_pool_public_id, p_expected_version,
        p_device_public_id, p_priority, p_state, p_node_limit, p_node_public_id, p_change_public_id);
    RETURN v_result || pg_catalog.jsonb_build_object('mode', (
        SELECT exit_pool.mode FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = mesh_ops.current_workspace_id()
          AND exit_pool.network_id = mesh_ops.current_network_id()
          AND exit_pool.public_id = p_pool_public_id));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_exit_node_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_exit_node_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) TO mesh_runtime;

-- One page of pools as list_exit_pools_v1, with each listed pool's mode by
-- pool ID.
CREATE FUNCTION mesh_ops.list_exit_pools_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_pool_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_page JSONB;
BEGIN
    v_page := mesh_ops.list_exit_pools_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_after_pool_public_id, p_limit);
    RETURN v_page || pg_catalog.jsonb_build_object('modes', COALESCE((
        SELECT pg_catalog.jsonb_object_agg(exit_pool.public_id::TEXT, exit_pool.mode)
        FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = mesh_ops.current_workspace_id()
          AND exit_pool.network_id = mesh_ops.current_network_id()
          AND exit_pool.public_id IN (
              SELECT (listed.item ->> 'pool_id')::UUID
              FROM pg_catalog.jsonb_array_elements(v_page -> 'pools') AS listed(item))
    ), '{}'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_exit_pools_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_exit_pools_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;

-- One pool as read_exit_pool_v2, with its mode and, for a spread pool, its
-- serving set (NULL before the first election) as Device public IDs.
CREATE FUNCTION mesh_ops.read_exit_pool_v3(
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
    v_pool mesh.network_exit_pool%ROWTYPE;
    v_serving JSONB;
BEGIN
    v_reading := mesh_ops.read_exit_pool_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_pool_public_id);
    SELECT * INTO STRICT v_pool FROM mesh.network_exit_pool AS exit_pool
    WHERE exit_pool.workspace_id = mesh_ops.current_workspace_id()
      AND exit_pool.network_id = mesh_ops.current_network_id()
      AND exit_pool.public_id = p_pool_public_id;
    IF v_pool.mode = 'spread' THEN
        SELECT pg_catalog.jsonb_build_object(
                   'device_ids', mesh_ops.exit_pool_device_public_ids_internal_v1(
                       serving.workspace_id, serving.network_id, serving.device_ids),
                   'generation', serving.generation,
                   'reason', serving.reason,
                   'changed_at', serving.changed_at)
        INTO v_serving
        FROM mesh.exit_pool_serving AS serving
        WHERE serving.pool_id = v_pool.id;
    END IF;
    RETURN v_reading || pg_catalog.jsonb_build_object('mode', v_pool.mode, 'serving', v_serving);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_exit_pool_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_exit_pool_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- One page of pools to elect for, as list_exit_pool_elections_v1, adding
-- whether each is spread and its serving set (Device public IDs), the set's
-- generation (0 before the first), when and why it last changed and the set
-- before that change.
CREATE FUNCTION mesh_ops.list_exit_pool_elections_v2(p_deployment UUID, p_after_pool UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_page JSONB;
    v_items JSONB := '[]'::JSONB;
    v_item JSONB;
    v_pool RECORD;
BEGIN
    v_page := mesh_ops.list_exit_pool_elections_v1(p_deployment, p_after_pool, p_limit);
    FOR v_item IN SELECT listed.item FROM pg_catalog.jsonb_array_elements(v_page -> 'items') AS listed(item)
    LOOP
        SELECT exit_pool.mode, serving.workspace_id, serving.network_id, serving.device_ids,
               serving.previous_device_ids, serving.reason,
               COALESCE(serving.generation, 0) AS generation, serving.changed_at
        INTO STRICT v_pool
        FROM mesh.network_exit_pool AS exit_pool
        LEFT JOIN mesh.exit_pool_serving AS serving ON serving.pool_id = exit_pool.id
        WHERE exit_pool.public_id = (v_item ->> 'pool_id')::UUID;
        v_items := v_items || pg_catalog.jsonb_build_array(v_item || pg_catalog.jsonb_build_object(
            'spread', v_pool.mode = 'spread',
            'serving', CASE WHEN v_pool.device_ids IS NULL THEN '[]'::JSONB
                            ELSE mesh_ops.exit_pool_device_public_ids_internal_v1(
                                v_pool.workspace_id, v_pool.network_id, v_pool.device_ids) END,
            'serving_generation', v_pool.generation,
            'serving_changed_at', v_pool.changed_at,
            -- The last change, so every worker replica holds back exit nodes
            -- that left overloaded until RecoveredAfter has passed.
            'serving_reason', v_pool.reason,
            'serving_previous', CASE WHEN v_pool.previous_device_ids IS NULL THEN '[]'::JSONB
                                     ELSE mesh_ops.exit_pool_device_public_ids_internal_v1(
                                         v_pool.workspace_id, v_pool.network_id, v_pool.previous_device_ids) END));
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('items', v_items, 'done', v_page -> 'done');
END;
$function$;

-- The audit and outbox payloads of a serving set change, as prepare returns
-- and finalize recomputes them.
CREATE FUNCTION mesh_ops.exit_pool_serving_payloads_internal_v1(
    p_pool UUID, p_devices JSONB, p_previous JSONB, p_reason TEXT, p_generation BIGINT,
    p_network_revision BIGINT, p_route_revision BIGINT
)
RETURNS TABLE (audit_payload JSONB, outbox_payload JSONB)
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
               'exit_pool_public_id', p_pool, 'device_public_ids', p_devices,
               'previous_device_public_ids', p_previous, 'reason', p_reason, 'generation', p_generation,
               'network_revision', p_network_revision, 'route_revision', p_route_revision),
           pg_catalog.jsonb_build_object(
               'network_revision', p_network_revision, 'subsystem', 'routes',
               'subsystem_revision', p_route_revision)
$function$;

-- Makes p_devices the serving set of the spread pool p_pool when its set's
-- generation is still p_expected_generation (0: never elected) and every
-- Device is still one of its exit nodes that can serve, and returns the
-- evidence to hash; otherwise changes nothing.
CREATE FUNCTION mesh_ops.prepare_exit_pool_serving_v1(
    p_deployment UUID, p_pool UUID, p_expected_generation BIGINT, p_devices UUID[], p_reason TEXT, p_change UUID
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
    v_current mesh.exit_pool_serving%ROWTYPE;
    v_device_ids BIGINT[];
    v_previous_ids BIGINT[];
    v_revisions RECORD;
    v_head RECORD;
    v_generation BIGINT;
    v_version BIGINT;
    v_payloads RECORD;
BEGIN
    IF p_pool IS NULL OR p_change IS NULL OR p_expected_generation IS NULL OR p_expected_generation < 0
        OR p_devices IS NULL OR pg_catalog.cardinality(p_devices) > 16
        OR pg_catalog.array_position(p_devices, NULL) IS NOT NULL
        OR p_reason IS NULL OR p_reason !~ '^[a-z_]{1,32}$'
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_pool), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Exit Pool serving election';
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
    -- The mode is read again under the lock: a pool back in failover mode
    -- has no serving set.
    SELECT * INTO v_pool FROM mesh.network_exit_pool AS exit_pool WHERE exit_pool.id = v_pool.id;
    IF v_pool.state <> 'active' OR v_pool.mode <> 'spread' THEN
        RETURN v_unchanged;
    END IF;

    SELECT * INTO v_current FROM mesh.exit_pool_serving AS serving
    WHERE serving.pool_id = v_pool.id FOR UPDATE;
    IF COALESCE(v_current.generation, 0) <> p_expected_generation THEN
        RETURN v_unchanged; -- decided on an older state
    END IF;
    -- Every Device is still an exit node of the pool that can serve it: the
    -- facts the decision was made on may have changed since the list.
    SELECT pg_catalog.array_agg(device.id ORDER BY device.id) INTO v_device_ids
    FROM mesh.network_exit_node AS exit_node
    JOIN mesh.device AS device
      ON device.workspace_id = exit_node.workspace_id AND device.network_id = exit_node.network_id
     AND device.id = exit_node.device_id
    JOIN mesh.device_exit_offer AS offer ON offer.device_id = exit_node.device_id AND offer.offered
    WHERE exit_node.pool_id = v_pool.id AND device.public_id = ANY (p_devices)
      AND exit_node.state = 'active'
      AND device.state = 'active' AND device.expires_at > pg_catalog.transaction_timestamp()
      AND device.ownership = 'workspace';
    v_device_ids := COALESCE(v_device_ids, '{}'::BIGINT[]);
    IF pg_catalog.cardinality(v_device_ids) <> pg_catalog.cardinality(
        ARRAY(SELECT DISTINCT listed FROM pg_catalog.unnest(p_devices) AS listed)) THEN
        RETURN v_unchanged; -- a Device can no longer serve the pool
    END IF;
    v_previous_ids := COALESCE(v_current.device_ids, '{}'::BIGINT[]);
    IF v_current.pool_id IS NOT NULL AND v_previous_ids = v_device_ids THEN
        RETURN v_unchanged;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(v_pool.workspace_id,
        v_pool.network_id);
    INSERT INTO mesh.exit_pool_serving AS serving
        (pool_id, public_id, workspace_id, network_id, device_ids, previous_device_ids, generation, reason,
         changed_at)
    VALUES (v_pool.id, v_pool.public_id, v_pool.workspace_id, v_pool.network_id, v_device_ids, '{}'::BIGINT[], 1,
        p_reason, pg_catalog.transaction_timestamp())
    ON CONFLICT (pool_id) DO UPDATE
    SET device_ids = EXCLUDED.device_ids, previous_device_ids = serving.device_ids,
        generation = serving.generation + 1, reason = EXCLUDED.reason,
        version = serving.version + 1, changed_at = EXCLUDED.changed_at
    RETURNING serving.generation, serving.version INTO v_generation, v_version;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_pool.workspace_id AND stream.network_id = v_pool.network_id
    FOR UPDATE;
    SELECT * INTO STRICT v_payloads FROM mesh_ops.exit_pool_serving_payloads_internal_v1(p_pool,
        mesh_ops.exit_pool_device_public_ids_internal_v1(v_pool.workspace_id, v_pool.network_id, v_device_ids),
        mesh_ops.exit_pool_device_public_ids_internal_v1(v_pool.workspace_id, v_pool.network_id, v_previous_ids),
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
CREATE FUNCTION mesh_ops.finalize_exit_pool_serving_v1(
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
    v_serving mesh.exit_pool_serving%ROWTYPE;
    v_revisions RECORD;
    v_head RECORD;
    v_payloads RECORD;
    v_sequence BIGINT;
BEGIN
    IF p_pool IS NULL OR p_change IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z_]{1,32}$'
        OR p_event IS NULL OR pg_catalog.jsonb_typeof(p_event) <> 'object'
        OR pg_catalog.octet_length(p_event::TEXT) > 16384 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Exit Pool serving evidence';
    END IF;
    IF pg_catalog.current_setting('mesh.change_public_id', TRUE) IS DISTINCT FROM p_change::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Exit Pool serving election was not prepared in this transaction';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    SELECT serving.* INTO v_serving
    FROM mesh.exit_pool_serving AS serving
    JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = serving.pool_id
    WHERE serving.public_id = p_pool AND exit_pool.deployment_id = v_deployment_id;
    IF v_serving.pool_id IS NULL OR v_serving.reason <> p_reason OR NOT EXISTS (
        SELECT 1 FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
          AND mutation.change_public_id = p_change
          AND mutation.aggregate_kind = 'exit_pool_serving'
          AND mutation.row_public_id = v_serving.public_id
          AND mutation.after_version = v_serving.version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Exit Pool serving mutation missing';
    END IF;
    SELECT revision.network_revision, revision.route_revision INTO STRICT v_revisions
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_serving.workspace_id AND revision.network_id = v_serving.network_id;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_serving.workspace_id AND stream.network_id = v_serving.network_id
    FOR UPDATE;
    SELECT * INTO STRICT v_payloads FROM mesh_ops.exit_pool_serving_payloads_internal_v1(p_pool,
        mesh_ops.exit_pool_device_public_ids_internal_v1(v_serving.workspace_id, v_serving.network_id,
            v_serving.device_ids),
        mesh_ops.exit_pool_device_public_ids_internal_v1(v_serving.workspace_id, v_serving.network_id,
            v_serving.previous_device_ids),
        p_reason, v_serving.generation, v_revisions.network_revision, v_revisions.route_revision);
    IF (p_event ->> 'stream_id')::BIGINT IS DISTINCT FROM v_head.id
        OR (p_event ->> 'sequence')::BIGINT IS DISTINCT FROM v_head.next_sequence
        OR p_event ->> 'previous_hash' IS DISTINCT FROM pg_catalog.encode(v_head.latest_event_hash, 'hex')
        OR (p_event ->> 'network_revision')::BIGINT IS DISTINCT FROM v_revisions.network_revision
        OR p_event ->> 'audit_payload' IS DISTINCT FROM v_payloads.audit_payload::TEXT
        OR p_event ->> 'outbox_payload' IS DISTINCT FROM v_payloads.outbox_payload::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Exit Pool serving evidence mismatch';
    END IF;
    v_sequence := mesh_audit.append_authority_evidence(
        v_head.id,
        (p_event ->> 'event_id')::UUID,
        (p_event ->> 'outbox_id')::UUID,
        v_head.next_sequence,
        v_head.latest_event_hash,
        pg_catalog.decode(p_event ->> 'event_hash', 'hex'),
        'exit_pool_serving',
        v_serving.public_id,
        v_serving.version,
        v_revisions.network_revision,
        NULL::UUID,
        'exit_pool.serving_changed',
        'system.reconcile',
        NULL::UUID,
        NULL::BYTEA,
        NULL::BYTEA,
        v_payloads.audit_payload,
        'network.revision.advanced',
        v_payloads.outbox_payload
    );
    IF v_sequence <> v_head.next_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Exit Pool serving evidence changed';
    END IF;
    RETURN 1;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.exit_pool_serving_payloads_internal_v1(UUID, JSONB, JSONB, TEXT, BIGINT, BIGINT,
    BIGINT) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_exit_pool_elections_v2(UUID, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_exit_pool_serving_v1(UUID, UUID, BIGINT, UUID[], TEXT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.finalize_exit_pool_serving_v1(UUID, UUID, UUID, TEXT, JSONB)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Only the worker role elects serving sets.
GRANT EXECUTE ON FUNCTION mesh_ops.list_exit_pool_elections_v2(UUID, UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_exit_pool_serving_v1(UUID, UUID, BIGINT, UUID[], TEXT, UUID)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_exit_pool_serving_v1(UUID, UUID, UUID, TEXT, JSONB) TO mesh_worker;

-- One page of a spread pool's serving set changes (route.read), newest
-- first, after the change p_after_event_public_id when given: each the
-- audit event Core recorded with the set's election.
CREATE FUNCTION mesh_ops.list_exit_pool_serving_changes_v1(
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool serving history page is invalid';
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
          AND event.target_public_id = p_pool_public_id AND event.target_kind = 'exit_pool_serving'
          AND event.action = 'exit_pool.serving_changed';
        IF v_after_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool serving history cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'event_id', page.event_public_id,
               'occurred_at', page.occurred_at,
               'device_ids', page.payload -> 'device_public_ids',
               'previous_device_ids', page.payload -> 'previous_device_public_ids',
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
          AND event.target_kind = 'exit_pool_serving' AND event.action = 'exit_pool.serving_changed'
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
REVOKE ALL ON FUNCTION mesh_ops.list_exit_pool_serving_changes_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_exit_pool_serving_changes_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;

-- The Network's active pools for maps, as load_map_network_exit_pools_v1,
-- with each pool's mode, assignment version, salt and serving set. The salt
-- reaches only the map builder, which hashes with it.
CREATE FUNCTION mesh_ops.load_map_network_exit_pools_v2(p_limit INTEGER)
RETURNS TABLE (
    pool_id BIGINT,
    pool_public_id UUID,
    pool_name TEXT,
    smtp_allowed BOOLEAN,
    conntrack_per_consumer INTEGER,
    dns_upstreams INET[],
    probe_addresses INET[],
    probe_ports INTEGER[],
    elected BOOLEAN,
    primary_device_id BIGINT,
    spread BOOLEAN,
    assignment_version SMALLINT,
    spread_salt BYTEA,
    serving_device_ids BIGINT[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    RETURN QUERY
    SELECT loaded.pool_id, loaded.pool_public_id, loaded.pool_name, loaded.smtp_allowed,
           loaded.conntrack_per_consumer, loaded.dns_upstreams, loaded.probe_addresses, loaded.probe_ports,
           loaded.elected, loaded.primary_device_id,
           exit_pool.mode = 'spread', exit_pool.assignment_version,
           CASE WHEN exit_pool.mode = 'spread' THEN exit_pool.spread_salt END,
           COALESCE(serving.device_ids, '{}'::BIGINT[])
    FROM mesh_ops.load_map_network_exit_pools_v1(p_limit) AS loaded
    JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = loaded.pool_id
    LEFT JOIN mesh.exit_pool_serving AS serving
      ON serving.pool_id = exit_pool.id AND exit_pool.mode = 'spread'
    ORDER BY loaded.pool_public_id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_pools_v2(INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_exit_pools_v2(INTEGER) TO mesh_runtime;
