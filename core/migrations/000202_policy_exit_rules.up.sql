-- Access Rules whose destination is an Exit Pool (exit node design §4.2,
-- step E1b).
--
-- An exit rule names a source selector (Device, Device Group, Identity Group
-- or tag) and an Exit Pool: its source may reach the Internet, as
-- shared/internet defines it, through the pool's exit nodes, on the rule's
-- protocol and ports. It never names addresses. Rules stay at selector
-- level, like route rules: maps resolve sources from the membership current
-- at each Network revision.
--
-- attach_policy_exit_rules_v1 stores the exit rules of a release in the
-- transaction that publishes it, after its route rules. An Exit Pool that
-- active rules name cannot be deleted (MTX06), and the rule counts of Device
-- Groups, Identity Groups and tags count exit rules too. The simulation
-- baseline (v6) and the active policy (v4) carry them, the latter with
-- selector_kind 'exit_pool'.

CREATE TABLE mesh.compiled_policy_exit_rule (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    access_rule_public_id UUID NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    policy_release_id BIGINT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    source_device_id BIGINT,
    source_device_group_id BIGINT,
    source_identity_group_id BIGINT,
    source_device_tag_id BIGINT,
    destination_exit_pool_id BIGINT NOT NULL,
    protocol TEXT NOT NULL,
    destination_ports INT4MULTIRANGE NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT compiled_policy_exit_rule_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_exit_rule_access_rule_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(access_rule_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_exit_rule_source_check CHECK (
        pg_catalog.num_nonnulls(source_device_id, source_device_group_id,
            source_identity_group_id, source_device_tag_id) = 1
    ),
    CONSTRAINT compiled_policy_exit_rule_protocol_check CHECK (protocol IN ('tcp', 'udp', 'icmp')),
    CONSTRAINT compiled_policy_exit_rule_port_shape_check CHECK (
        (protocol = 'icmp' AND destination_ports = '{}'::INT4MULTIRANGE)
        OR (
            protocol IN ('tcp', 'udp')
            AND NOT pg_catalog.isempty(destination_ports)
            AND destination_ports <@ '{[1,65536)}'::INT4MULTIRANGE
            AND mesh_ops.int4multirange_count(destination_ports) BETWEEN 1 AND 64
        )
    ),
    CONSTRAINT compiled_policy_exit_rule_release_fk FOREIGN KEY (
        workspace_id, network_id, policy_release_id, policy_revision
    ) REFERENCES mesh.policy_release (workspace_id, network_id, id, policy_revision) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_exit_rule_source_device_fk FOREIGN KEY (workspace_id, network_id, source_device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_exit_rule_source_group_fk FOREIGN KEY (
        workspace_id, network_id, source_device_group_id
    ) REFERENCES mesh.device_group (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_exit_rule_source_identity_group_fk FOREIGN KEY (
        workspace_id, source_identity_group_id
    ) REFERENCES mesh.identity_group (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_exit_rule_source_tag_fk FOREIGN KEY (workspace_id, source_device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_exit_rule_pool_fk FOREIGN KEY (workspace_id, network_id, destination_exit_pool_id)
        REFERENCES mesh.network_exit_pool (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (policy_release_id, access_rule_public_id)
);

CREATE INDEX compiled_policy_exit_rule_release_idx
    ON mesh.compiled_policy_exit_rule (workspace_id, network_id, policy_revision, access_rule_public_id);
CREATE INDEX compiled_policy_exit_rule_pool_idx ON mesh.compiled_policy_exit_rule (destination_exit_pool_id);
CREATE INDEX compiled_policy_exit_rule_source_group_idx
    ON mesh.compiled_policy_exit_rule (source_device_group_id) WHERE source_device_group_id IS NOT NULL;
CREATE INDEX compiled_policy_exit_rule_source_identity_group_idx
    ON mesh.compiled_policy_exit_rule (source_identity_group_id) WHERE source_identity_group_id IS NOT NULL;
CREATE INDEX compiled_policy_exit_rule_source_tag_idx
    ON mesh.compiled_policy_exit_rule (source_device_tag_id) WHERE source_device_tag_id IS NOT NULL;
CREATE INDEX compiled_policy_exit_rule_source_device_idx
    ON mesh.compiled_policy_exit_rule (source_device_id) WHERE source_device_id IS NOT NULL;

CREATE TRIGGER compiled_policy_exit_rule_immutable
BEFORE UPDATE OR DELETE ON mesh.compiled_policy_exit_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER compiled_policy_exit_rule_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.compiled_policy_exit_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('compiled_policy_exit_rule', 'public_id');

ALTER TABLE mesh.compiled_policy_exit_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.compiled_policy_exit_rule FORCE ROW LEVEL SECURITY;
CREATE POLICY compiled_policy_exit_rule_migrator_policy ON mesh.compiled_policy_exit_rule
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.compiled_policy_exit_rule
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The rule counts of schema 189 now count exit rules too: a group, Identity
-- Group or tag that an exit rule selects cannot be deleted, its membership
-- changes wake maps, and the Console shows the rule count.
CREATE OR REPLACE FUNCTION mesh_ops.device_group_rule_count_internal_v1(p_device_group_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_group_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active'
          AND (rule.source_device_group_id = p_device_group_id
               OR rule.destination_device_group_id = p_device_group_id)
    )::INTEGER + (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_route_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active' AND rule.source_device_group_id = p_device_group_id
    )::INTEGER + (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_exit_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active' AND rule.source_device_group_id = p_device_group_id
    )::INTEGER
$function$;
CREATE OR REPLACE FUNCTION mesh_ops.identity_group_rule_count_internal_v1(p_identity_group_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_group_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active' AND rule.source_identity_group_id = p_identity_group_id
    )::INTEGER + (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_route_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active' AND rule.source_identity_group_id = p_identity_group_id
    )::INTEGER + (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_exit_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active' AND rule.source_identity_group_id = p_identity_group_id
    )::INTEGER
$function$;
CREATE OR REPLACE FUNCTION mesh_ops.device_tag_rule_count_internal_v1(p_device_tag_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_group_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active'
          AND (rule.source_device_tag_id = p_device_tag_id OR rule.destination_device_tag_id = p_device_tag_id)
    )::INTEGER + (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_route_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active' AND rule.source_device_tag_id = p_device_tag_id
    )::INTEGER + (
        SELECT pg_catalog.count(*)
        FROM mesh.compiled_policy_exit_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
        WHERE release.state = 'active' AND rule.source_device_tag_id = p_device_tag_id
    )::INTEGER
$function$;

-- How many rules of the active release name the Exit Pool.
CREATE FUNCTION mesh_ops.exit_pool_rule_count_internal_v1(p_pool_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*)::INTEGER
    FROM mesh.compiled_policy_exit_rule AS rule
    JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
    WHERE release.state = 'active' AND rule.destination_exit_pool_id = p_pool_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.exit_pool_rule_count_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Stores the exit rules of a release published in this transaction, after
-- its route rules. Every source must exist (a removed Device only when the
-- replaced release held the same rule unchanged), every Exit Pool must be
-- active in this Network, and no other rule of the release may hold the same
-- Access Rule identity.
CREATE FUNCTION mesh_ops.attach_policy_exit_rules_v1(
    p_release_public_id UUID, p_created_at TIMESTAMPTZ, p_rules JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_release mesh.policy_release%ROWTYPE;
    v_previous_release BIGINT;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy exit rule input is invalid';
    END IF;
    SELECT * INTO v_release FROM mesh.policy_release AS release
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.public_id = p_release_public_id AND release.state = 'active'
      AND EXISTS (
          SELECT 1 FROM mesh_audit.authority_mutation AS mutation
          WHERE mutation.aggregate_kind = 'policy_release' AND mutation.operation = 'insert'
            AND mutation.row_public_id = p_release_public_id
            AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      )
      AND NOT EXISTS (
          SELECT 1 FROM mesh.compiled_policy_exit_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy exit rules need the release published now';
    END IF;
    -- Publication holds the Network scope lock that change_exit_pool_v1
    -- takes, so the pools read below cannot be deleted before commit.
    SELECT previous.id INTO v_previous_release FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = v_workspace AND previous.network_id = v_network
      AND previous.policy_revision = v_release.policy_revision - 1
      AND previous.state = 'superseded';
    v_expected := pg_catalog.jsonb_array_length(p_rules);

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID, access_rule_public_id UUID,
            source_node_public_id UUID, source_device_group_public_id UUID,
            source_identity_group_public_id UUID, source_device_tag_public_id UUID,
            exit_pool_public_id UUID,
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[]
        )
    ),
    valid_rule AS (
        SELECT rule.* FROM input_rule AS rule
        WHERE rule.projection_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.projection_public_id), 6) >> 4 = 7
          AND rule.access_rule_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.access_rule_public_id), 6) >> 4 = 7
          AND pg_catalog.num_nonnulls(rule.source_node_public_id, rule.source_device_group_public_id,
                                      rule.source_identity_group_public_id, rule.source_device_tag_public_id) = 1
          AND rule.exit_pool_public_id IS NOT NULL
          AND rule.protocol IN ('tcp', 'udp', 'icmp')
          AND rule.port_range_first IS NOT NULL AND rule.port_range_last IS NOT NULL
          AND pg_catalog.cardinality(rule.port_range_first) = pg_catalog.cardinality(rule.port_range_last)
          AND pg_catalog.cardinality(rule.port_range_first) <= 64
          AND ((rule.protocol = 'icmp' AND pg_catalog.cardinality(rule.port_range_first) = 0)
               OR (rule.protocol IN ('tcp', 'udp') AND pg_catalog.cardinality(rule.port_range_first) > 0))
          AND NOT EXISTS (
              SELECT 1 FROM ROWS FROM (
                  pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
              ) AS port_range(first_port, last_port)
              WHERE port_range.first_port < 1 OR port_range.last_port < port_range.first_port
                 OR port_range.last_port > 65535
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_rule AS device_rule
              WHERE device_rule.policy_release_id = v_release.id
                AND device_rule.access_rule_public_id = rule.access_rule_public_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_group_rule AS group_rule
              WHERE group_rule.policy_release_id = v_release.id
                AND group_rule.access_rule_public_id = rule.access_rule_public_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_route_rule AS route_rule
              WHERE route_rule.policy_release_id = v_release.id
                AND route_rule.access_rule_public_id = rule.access_rule_public_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_imported_resource_destination AS imported_rule
              WHERE imported_rule.policy_release_id = v_release.id
                AND imported_rule.access_rule_public_id = rule.access_rule_public_id
          )
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               exit_pool.id AS destination_exit_pool_id, ports.destination_ports
        FROM valid_rule AS rule
        JOIN mesh.network_exit_pool AS exit_pool
          ON exit_pool.workspace_id = v_workspace AND exit_pool.network_id = v_network
         AND exit_pool.public_id = rule.exit_pool_public_id AND exit_pool.state = 'active'
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        CROSS JOIN LATERAL (
            SELECT COALESCE(pg_catalog.range_agg(
                pg_catalog.int4range(port_range.first_port, port_range.last_port + 1, '[)')
            ), '{}'::INT4MULTIRANGE) AS destination_ports
            FROM ROWS FROM (
                pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
            ) AS port_range(first_port, last_port)
        ) AS ports
        WHERE (rule.source_node_public_id IS NULL OR source_device.id IS NOT NULL)
          AND (rule.source_device_group_public_id IS NULL OR source_group.id IS NOT NULL)
          AND (rule.source_identity_group_public_id IS NULL OR source_identity.id IS NOT NULL)
          AND (rule.source_device_tag_public_id IS NULL OR source_tag.id IS NOT NULL)
          -- A revoked or deleted source Device only for a rule the replaced
          -- release held unchanged.
          AND (source_device.id IS NULL OR source_device.state IN ('active', 'expired', 'suspended')
               OR EXISTS (
                   SELECT 1 FROM mesh.compiled_policy_exit_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id = source_device.id
                     AND carried.destination_exit_pool_id = exit_pool.id
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_exit_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_exit_pool_id, protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_exit_pool_id,
           rule.protocol, rule.destination_ports, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001',
            MESSAGE = 'an Exit Pool, Device, group or tag changed during publication';
    END IF;
    RETURN v_inserted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_exit_rules_v1(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_exit_rules_v1(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;

-- The active Exit Pools of the scope with the given IDs (route.read), for
-- the policy compiler. Unknown or deleted pools are absent.
CREATE FUNCTION mesh_ops.read_policy_exit_pools_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_pool_public_ids UUID[]
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
BEGIN
    IF p_pool_public_ids IS NULL OR pg_catalog.cardinality(p_pool_public_ids) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool read is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    RETURN pg_catalog.jsonb_build_object('pools', COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.exit_pool_document_internal_v1(exit_pool)
            ORDER BY exit_pool.public_id)
        FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
          AND exit_pool.state = 'active' AND exit_pool.public_id = ANY (p_pool_public_ids)
    ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_exit_pools_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID[]
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_exit_pools_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID[]
) TO mesh_runtime;

-- change_exit_pool_v1 of schema 201, refusing to delete a pool that rules
-- of the active release name (MTX06): change those rules first. Otherwise
-- every later publication, which resends the active rules, would fail. The
-- Network scope lock is the one publication takes, so no rule can be
-- published in between.
--
-- Creates or changes a pool (route.approve) or deletes it (route.withdraw).
-- p_pool_limit is the Workspace's plan limit, already bounded by Go. An
-- update that changes nothing writes nothing and returns changed = false.
-- Deleting a pool removes its exit nodes. Changes serialize on the Network's
-- revision row and advance the Network and route revisions, as Site changes
-- do (schema 188).
CREATE OR REPLACE FUNCTION mesh_ops.change_exit_pool_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_pool_public_id UUID, p_expected_version BIGINT, p_name TEXT, p_failback BOOLEAN,
    p_smtp_allowed BOOLEAN, p_conntrack_per_consumer INTEGER, p_dns_upstreams INET[], p_probes JSONB,
    p_pool_limit INTEGER, p_change_public_id UUID
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
            OR p_conntrack_per_consumer IS NULL OR p_dns_upstreams IS NULL OR p_probes IS NULL))
        OR (p_operation = 'create' AND (p_pool_limit IS NULL OR p_pool_limit NOT BETWEEN 1 AND 64)) THEN
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
                conntrack_per_consumer, dns_upstreams, probes, created_at, updated_at
            ) VALUES (
                p_pool_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_failback, p_smtp_allowed, p_conntrack_per_consumer,
                p_dns_upstreams, p_probes, v_now, v_now
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
        IF p_operation = 'update' AND v_pool.name = p_name AND v_pool.failback = p_failback
            AND v_pool.smtp_allowed = p_smtp_allowed AND v_pool.conntrack_per_consumer = p_conntrack_per_consumer
            AND v_pool.dns_upstreams = p_dns_upstreams AND v_pool.probes = p_probes THEN
            RETURN pg_catalog.jsonb_build_object(
                'pool', v_before, 'previous', v_before, 'changed', FALSE,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        IF p_operation = 'update' THEN
            BEGIN
                UPDATE mesh.network_exit_pool
                SET name = p_name, name_key = pg_catalog.lower(p_name), failback = p_failback,
                    smtp_allowed = p_smtp_allowed, conntrack_per_consumer = p_conntrack_per_consumer,
                    dns_upstreams = p_dns_upstreams, probes = p_probes,
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
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_exit_pool_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_exit_pool_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, INTEGER, UUID
) TO mesh_runtime;

-- The simulation baseline of schema 189 with the exit rules of the active
-- release, so the compiled baseline rebuilds to the stored semantic hash.
CREATE FUNCTION mesh_ops.read_policy_simulation_baseline_v6(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_rule_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT, inventory_revision BIGINT, group_revision BIGINT,
    policy_revision BIGINT, dns_revision BIGINT, route_revision BIGINT,
    sharing_revision BIGINT, isolation_generation BIGINT,
    has_active_release BOOLEAN, release_public_id UUID,
    compiler_format_version INTEGER, release_semantic_hash BYTEA, rules JSONB,
    group_rules JSONB, selector_members JSONB, route_rules JSONB, exit_rules JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    baseline RECORD;
    v_exit_rules JSONB;
BEGIN
    SELECT value.* INTO baseline
    FROM mesh_ops.read_policy_simulation_baseline_v5(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_evaluated_at, p_rule_limit
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Policy simulation baseline is unavailable';
    END IF;
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
               'projection_public_id', rule.public_id,
               'access_rule_public_id', rule.access_rule_public_id,
               'source_node_public_id', source_device.public_id,
               'source_device_group_public_id', source_group.public_id,
               'source_identity_group_public_id', source_identity.public_id,
               'source_device_tag_public_id', source_tag.public_id,
               'exit_pool_public_id', exit_pool.public_id,
               'protocol', rule.protocol,
               'port_range_first', ARRAY(
                   SELECT pg_catalog.lower(port_range)::INTEGER
                   FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                   ORDER BY pg_catalog.lower(port_range)),
               'port_range_last', ARRAY(
                   SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                   FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                   ORDER BY pg_catalog.lower(port_range))
           )) ORDER BY rule.access_rule_public_id), '[]'::JSONB)
    INTO v_exit_rules
    FROM mesh.policy_release AS release
    JOIN mesh.compiled_policy_exit_rule AS rule ON rule.policy_release_id = release.id
    JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = rule.destination_exit_pool_id
    LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
    LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
    LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
    LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
    WHERE baseline.has_active_release AND release.public_id = baseline.release_public_id
      AND release.workspace_id = mesh_ops.current_workspace_id()
      AND release.network_id = mesh_ops.current_network_id();
    RETURN QUERY SELECT baseline.network_revision, baseline.inventory_revision, baseline.group_revision,
        baseline.policy_revision, baseline.dns_revision, baseline.route_revision, baseline.sharing_revision,
        baseline.isolation_generation, baseline.has_active_release, baseline.release_public_id,
        baseline.compiler_format_version, baseline.release_semantic_hash, baseline.rules, baseline.group_rules,
        baseline.selector_members, baseline.route_rules, v_exit_rules;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_simulation_baseline_v6(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_simulation_baseline_v6(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;

-- The active policy of schema 189 with exit rules: selector_kind
-- 'exit_pool' and the Exit Pool as destination_selector_id, without
-- prefixes. Authoring reads it, so republishing keeps them.
CREATE FUNCTION mesh_ops.read_active_policy_v4(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_network_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    current_revision BIGINT;
    current_release_id BIGINT;
    current_hash BYTEA;
    row_count BIGINT;
    only_devices BOOLEAN;
    result_rows JSONB;
BEGIN
    IF p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Invalid active policy read';
    END IF;
    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'policy.read', p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN RETURN NULL; END IF;

    SELECT revision.policy_revision INTO current_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = mesh_ops.current_workspace_id()
      AND revision.network_id = mesh_ops.current_network_id()
    FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;

    SELECT release.id, release.semantic_hash
    INTO current_release_id, current_hash
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = mesh_ops.current_workspace_id()
      AND release.network_id = mesh_ops.current_network_id()
      AND release.policy_revision = current_revision AND release.state = 'active';
    IF current_revision > 1 AND current_release_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Active policy is unavailable';
    END IF;

    WITH local_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source.public_id AS source_id, destination.public_id AS destination_id,
            rule.protocol, rule.destination_ports,
            CASE WHEN group_provenance.id IS NOT NULL THEN 'resource_group'
                 WHEN resource_provenance.id IS NOT NULL THEN 'resource'
                 ELSE 'device' END AS selector_kind,
            COALESCE(resource_group.public_id, resource.public_id, destination.public_id) AS selector_id,
            'device'::TEXT AS source_kind, source.public_id AS source_selector_id,
            NULL::CIDR[] AS prefixes
        FROM mesh.compiled_policy_rule AS rule
        JOIN mesh.device AS source ON source.workspace_id = rule.workspace_id
            AND source.network_id = rule.network_id AND source.id = rule.source_device_id
        JOIN mesh.device AS destination ON destination.workspace_id = rule.workspace_id
            AND destination.network_id = rule.network_id AND destination.id = rule.destination_device_id
        LEFT JOIN mesh.compiled_policy_resource_destination AS resource_provenance
            ON resource_provenance.workspace_id = rule.workspace_id
            AND resource_provenance.network_id = rule.network_id
            AND resource_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource AS resource ON resource.workspace_id = rule.workspace_id
            AND resource.network_id = rule.network_id AND resource.id = resource_provenance.destination_resource_id
        LEFT JOIN mesh.compiled_policy_resource_group_destination AS group_provenance
            ON group_provenance.workspace_id = rule.workspace_id
            AND group_provenance.network_id = rule.network_id
            AND group_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource_group AS resource_group ON resource_group.workspace_id = rule.workspace_id
            AND resource_group.network_id = rule.network_id AND resource_group.id = group_provenance.destination_resource_group_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), imported_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source.public_id AS source_id, NULL::UUID AS destination_id,
            rule.protocol, rule.destination_ports, 'imported_resource'::TEXT AS selector_kind,
            imported.public_id AS selector_id,
            'device'::TEXT AS source_kind, source.public_id AS source_selector_id,
            NULL::CIDR[] AS prefixes
        FROM mesh.compiled_policy_imported_resource_destination AS rule
        JOIN mesh.device AS source ON source.workspace_id = rule.workspace_id
            AND source.network_id = rule.network_id AND source.id = rule.source_device_id
        JOIN mesh.imported_resource AS imported ON imported.workspace_id = rule.workspace_id
            AND imported.network_id = rule.network_id AND imported.id = rule.imported_resource_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), group_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source_device.public_id AS source_id, destination_device.public_id AS destination_id,
            rule.protocol, rule.destination_ports,
            CASE WHEN rule.destination_device_group_id IS NOT NULL THEN 'device_group'
                 WHEN rule.destination_device_tag_id IS NOT NULL THEN 'device_tag'
                 ELSE 'device' END AS selector_kind,
            COALESCE(destination_group.public_id, destination_tag.public_id, destination_device.public_id)
                AS selector_id,
            CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                 WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                 WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                 ELSE 'device' END AS source_kind,
            COALESCE(source_group.public_id, source_identity.public_id, source_tag.public_id,
                     source_device.public_id) AS source_selector_id,
            NULL::CIDR[] AS prefixes
        FROM mesh.compiled_policy_group_rule AS rule
        LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
        LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
        LEFT JOIN mesh.device AS destination_device ON destination_device.id = rule.destination_device_id
        LEFT JOIN mesh.device_group AS destination_group ON destination_group.id = rule.destination_device_group_id
        LEFT JOIN mesh.device_tag AS destination_tag ON destination_tag.id = rule.destination_device_tag_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), route_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source_device.public_id AS source_id, NULL::UUID AS destination_id,
            rule.protocol, rule.destination_ports, 'site'::TEXT AS selector_kind,
            network_site.public_id AS selector_id,
            CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                 WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                 WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                 ELSE 'device' END AS source_kind,
            COALESCE(source_group.public_id, source_identity.public_id, source_tag.public_id,
                     source_device.public_id) AS source_selector_id,
            rule.prefixes
        FROM mesh.compiled_policy_route_rule AS rule
        JOIN mesh.network_site AS network_site ON network_site.id = rule.destination_site_id
        LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
        LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), exit_rule AS (
        SELECT rule.access_rule_public_id AS id, rule.public_id AS projection_id,
            source_device.public_id AS source_id, NULL::UUID AS destination_id,
            rule.protocol, rule.destination_ports, 'exit_pool'::TEXT AS selector_kind,
            exit_pool.public_id AS selector_id,
            CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                 WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                 WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                 ELSE 'device' END AS source_kind,
            COALESCE(source_group.public_id, source_identity.public_id, source_tag.public_id,
                     source_device.public_id) AS source_selector_id,
            NULL::CIDR[] AS prefixes
        FROM mesh.compiled_policy_exit_rule AS rule
        JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = rule.destination_exit_pool_id
        LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
        LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
        WHERE rule.workspace_id = mesh_ops.current_workspace_id()
            AND rule.network_id = mesh_ops.current_network_id()
            AND rule.policy_release_id = current_release_id AND rule.policy_revision = current_revision
    ), all_rule AS (
        SELECT * FROM local_rule UNION ALL SELECT * FROM imported_rule UNION ALL SELECT * FROM group_rule
        UNION ALL SELECT * FROM route_rule UNION ALL SELECT * FROM exit_rule
    ),
    bounded AS (
        SELECT * FROM all_rule ORDER BY id, source_id, destination_id, projection_id LIMIT 1000
    )
    SELECT (SELECT count(*) FROM all_rule),
        NOT EXISTS (SELECT 1 FROM all_rule WHERE selector_kind NOT IN ('device', 'device_group', 'device_tag')),
        COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'id', bounded.id, 'source_device_id', COALESCE(bounded.source_id::TEXT, ''),
            'source_kind', bounded.source_kind, 'source_selector_id', bounded.source_selector_id,
            'destination_device_id', COALESCE(bounded.destination_id::TEXT, ''),
            'protocol', bounded.protocol, 'selector_kind', bounded.selector_kind,
            'destination_selector_id', bounded.selector_id,
            'destination_prefixes', COALESCE((SELECT jsonb_agg(prefix::TEXT ORDER BY ordinal)
                FROM unnest(bounded.prefixes) WITH ORDINALITY AS item(prefix, ordinal)), '[]'::JSONB),
            'destination_port_ranges', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                'first', lower(port)::INTEGER, 'last', (upper(port)-1)::INTEGER
            ) ORDER BY lower(port)) FROM unnest(bounded.destination_ports) AS port), '[]'::JSONB)
        ) ORDER BY bounded.id, bounded.source_id, bounded.destination_id, bounded.projection_id)
        FROM bounded), '[]'::JSONB)
    INTO row_count, only_devices, result_rows;
    RETURN jsonb_build_object('workspace_id', p_workspace_public_id,
        'network_id', p_network_public_id, 'policy_revision', current_revision,
        'semantic_hash', encode(current_hash, 'hex'), 'rule_count', row_count,
        'device_rules_only', only_devices, 'rules', result_rows);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_active_policy_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_active_policy_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;

-- change_identity_group_members_v1 of schema 181, advancing every Network
-- whose active rules take the group as source: rules to Sites (schema 189)
-- and to Exit Pools as well as group rules. Before, a membership change did
-- not rebuild the maps of a Network whose only rules naming the group were
-- rules to Sites.
CREATE OR REPLACE FUNCTION mesh_ops.change_identity_group_members_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_group_public_id uuid, p_expected_version bigint, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_group mesh.identity_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_requested INTEGER;
    v_eligible INTEGER;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_count INTEGER;
    v_networks BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_group_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_add IS NULL OR pg_catalog.jsonb_typeof(p_add) <> 'array'
        OR pg_catalog.jsonb_array_length(p_add) > 150
        OR p_remove IS NULL OR pg_catalog.cardinality(p_remove) > 150
        OR pg_catalog.jsonb_array_length(p_add) + pg_catalog.cardinality(p_remove) = 0
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_add) AS entry(value)
            WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
               OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(entry.value)) <> 2
               OR NOT entry.value ? 'principal_id' OR NOT entry.value ? 'member_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
            WHERE item.principal_id IS NULL OR item.member_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.member_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.principal_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
            WHERE item.principal_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Identity Group membership change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'identity_group.manage', pg_catalog.transaction_timestamp()
    );
    SELECT * INTO v_group FROM mesh.identity_group AS identity_group
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = p_group_public_id
      AND identity_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Identity Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Identity Group version changed';
    END IF;
    v_before := mesh_ops.identity_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.identity_group_member_hash_internal_v1(v_group.id);

    v_requested := pg_catalog.jsonb_array_length(p_add);
    IF v_requested > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_eligible
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = item.principal_id
         AND principal.state = 'active' AND principal.deleted_at IS NULL
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > v_now);
        IF v_eligible <> v_requested THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI01', MESSAGE = 'a principal is not an active member of this Workspace';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.identity_group_member AS member
        USING mesh.principal AS principal
        WHERE member.identity_group_id = v_group.id AND principal.id = member.principal_id
          AND principal.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF v_requested > 0 THEN
        INSERT INTO mesh.identity_group_member (public_id, workspace_id, identity_group_id, principal_id, created_at)
        SELECT item.member_id, v_scope.workspace_id, v_group.id, principal.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = item.principal_id
        ORDER BY principal.id
        ON CONFLICT (identity_group_id, principal_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;

    IF v_added + v_removed > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_count
        FROM mesh.identity_group_member AS member WHERE member.identity_group_id = v_group.id;
        IF v_count > 10000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI03', MESSAGE = 'Identity Group would exceed 10000 members';
        END IF;
        UPDATE mesh.identity_group
        SET member_count = v_count, version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
        -- Every Network whose active rules take the group as source, whatever
        -- the rule's destination: Devices, Sites or Exit Pools.
        SELECT pg_catalog.array_agg(DISTINCT selected.network_id ORDER BY selected.network_id) INTO v_networks
        FROM (
            SELECT rule.network_id FROM mesh.compiled_policy_group_rule AS rule
            JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
            WHERE rule.workspace_id = v_scope.workspace_id AND rule.source_identity_group_id = v_group.id
            UNION
            SELECT rule.network_id FROM mesh.compiled_policy_route_rule AS rule
            JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
            WHERE rule.workspace_id = v_scope.workspace_id AND rule.source_identity_group_id = v_group.id
            UNION
            SELECT rule.network_id FROM mesh.compiled_policy_exit_rule AS rule
            JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
            WHERE rule.workspace_id = v_scope.workspace_id AND rule.source_identity_group_id = v_group.id
        ) AS selected;
        IF v_networks IS NOT NULL THEN
            v_advanced := mesh_ops.advance_identity_networks_internal_v1(v_scope.workspace_id, v_networks);
            IF v_added > 0 AND mesh_ops.identity_networks_over_edge_budget_internal_v1(
                    v_scope.workspace_id, v_networks) THEN
                RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
            END IF;
        END IF;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.identity_group_document_internal_v1(v_group),
        'previous', v_before,
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.identity_group_member_hash_internal_v1(v_group.id), 'hex'),
        'networks', v_advanced,
        'authority', v_scope.authority
    );
END;
$function$
;
