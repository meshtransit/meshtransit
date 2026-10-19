-- Access Rules whose destination is a Site (subnet routes, R1.3).
--
-- A route rule names a source selector (Device, Device Group, Identity Group
-- or tag) and a Site with the prefixes the rule grants, as compiled: the
-- prefixes asked for, or the whole Site, each inside the Site when the
-- release is published. Rules stay at selector level, like group rules:
-- maps resolve sources from the membership current at each Network revision
-- and intersect the granted prefixes with the Site's current ones, so a
-- later Site change never widens what a rule grants. A Site cannot drop
-- address space that active rules grant (MTS08).
--
-- attach_policy_route_rules_v1 stores the rules of a release in the same
-- transaction that publishes it. It refuses rules of different Sites whose
-- granted prefixes overlap (MTS07), whatever their sources: memberships
-- change without a new release. A Site that active rules name cannot be
-- deleted (MTS06), like a Device Group. read_policy_sites_v1 lets the
-- compiler resolve Sites in one read.

CREATE TABLE mesh.compiled_policy_route_rule (
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
    destination_site_id BIGINT NOT NULL,
    prefixes CIDR[] NOT NULL,
    protocol TEXT NOT NULL,
    destination_ports INT4MULTIRANGE NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT compiled_policy_route_rule_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_route_rule_access_rule_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(access_rule_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_route_rule_source_check CHECK (
        pg_catalog.num_nonnulls(source_device_id, source_device_group_id,
            source_identity_group_id, source_device_tag_id) = 1
    ),
    CONSTRAINT compiled_policy_route_rule_prefixes_check CHECK (
        mesh_ops.site_prefixes_valid_internal_v1(prefixes)
    ),
    CONSTRAINT compiled_policy_route_rule_protocol_check CHECK (protocol IN ('tcp', 'udp', 'icmp')),
    CONSTRAINT compiled_policy_route_rule_port_shape_check CHECK (
        (protocol = 'icmp' AND destination_ports = '{}'::INT4MULTIRANGE)
        OR (
            protocol IN ('tcp', 'udp')
            AND NOT pg_catalog.isempty(destination_ports)
            AND destination_ports <@ '{[1,65536)}'::INT4MULTIRANGE
            AND mesh_ops.int4multirange_count(destination_ports) BETWEEN 1 AND 64
        )
    ),
    CONSTRAINT compiled_policy_route_rule_release_fk FOREIGN KEY (
        workspace_id, network_id, policy_release_id, policy_revision
    ) REFERENCES mesh.policy_release (workspace_id, network_id, id, policy_revision) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_route_rule_source_device_fk FOREIGN KEY (workspace_id, network_id, source_device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_route_rule_source_group_fk FOREIGN KEY (
        workspace_id, network_id, source_device_group_id
    ) REFERENCES mesh.device_group (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_route_rule_source_identity_group_fk FOREIGN KEY (
        workspace_id, source_identity_group_id
    ) REFERENCES mesh.identity_group (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_route_rule_source_tag_fk FOREIGN KEY (workspace_id, source_device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_route_rule_site_fk FOREIGN KEY (workspace_id, network_id, destination_site_id)
        REFERENCES mesh.network_site (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (policy_release_id, access_rule_public_id)
);

CREATE INDEX compiled_policy_route_rule_release_idx
    ON mesh.compiled_policy_route_rule (workspace_id, network_id, policy_revision, access_rule_public_id);
CREATE INDEX compiled_policy_route_rule_site_idx ON mesh.compiled_policy_route_rule (destination_site_id);
CREATE INDEX compiled_policy_route_rule_source_group_idx
    ON mesh.compiled_policy_route_rule (source_device_group_id) WHERE source_device_group_id IS NOT NULL;
CREATE INDEX compiled_policy_route_rule_source_identity_group_idx
    ON mesh.compiled_policy_route_rule (source_identity_group_id) WHERE source_identity_group_id IS NOT NULL;
CREATE INDEX compiled_policy_route_rule_source_tag_idx
    ON mesh.compiled_policy_route_rule (source_device_tag_id) WHERE source_device_tag_id IS NOT NULL;
CREATE INDEX compiled_policy_route_rule_source_device_idx
    ON mesh.compiled_policy_route_rule (source_device_id) WHERE source_device_id IS NOT NULL;

CREATE TRIGGER compiled_policy_route_rule_immutable
BEFORE UPDATE OR DELETE ON mesh.compiled_policy_route_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER compiled_policy_route_rule_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.compiled_policy_route_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('compiled_policy_route_rule', 'public_id');

ALTER TABLE mesh.compiled_policy_route_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.compiled_policy_route_rule FORCE ROW LEVEL SECURITY;
CREATE POLICY compiled_policy_route_rule_migrator_policy ON mesh.compiled_policy_route_rule
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.compiled_policy_route_rule
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The rule counts of schema 120 and 121 now count route rules too: a group,
-- Identity Group or tag that a route rule selects cannot be deleted, its
-- membership changes wake maps, and the Console shows the rule count.
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
    )::INTEGER
$function$;

-- How many rules of the active release name the Site.
CREATE FUNCTION mesh_ops.site_rule_count_internal_v1(p_site_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*)::INTEGER
    FROM mesh.compiled_policy_route_rule AS rule
    JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
    WHERE release.state = 'active' AND rule.destination_site_id = p_site_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.site_rule_count_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether two route rules of different Sites of the release grant
-- overlapping prefixes. Two prefixes are either disjoint or nested, and
-- sorted as inet a prefix comes right after the prefixes that contain it. A
-- stack of open containers then finds every overlap in one pass, in
-- O(n log n) for the n granted prefixes (at most 16384 per release); only
-- the innermost container needs checking, since an outer one of a third Site
-- would already have overlapped it.
CREATE FUNCTION mesh_ops.release_route_overlap_internal_v1(p_release_id BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_item RECORD;
    v_prefixes CIDR[] := ARRAY[]::CIDR[];
    v_sites BIGINT[] := ARRAY[]::BIGINT[];
    v_depth INTEGER := 0;
BEGIN
    FOR v_item IN
        SELECT rule.destination_site_id AS site_id, granted.prefix
        FROM mesh.compiled_policy_route_rule AS rule,
             pg_catalog.unnest(rule.prefixes) AS granted(prefix)
        WHERE rule.policy_release_id = p_release_id
        ORDER BY granted.prefix, rule.destination_site_id
    LOOP
        WHILE v_depth > 0 AND NOT (v_prefixes[v_depth] >>= v_item.prefix) LOOP
            v_depth := v_depth - 1;
        END LOOP;
        IF v_depth > 0 AND v_sites[v_depth] <> v_item.site_id THEN
            RETURN TRUE;
        END IF;
        v_depth := v_depth + 1;
        v_prefixes[v_depth] := v_item.prefix;
        v_sites[v_depth] := v_item.site_id;
    END LOOP;
    RETURN FALSE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.release_route_overlap_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Stores the route rules of a release published in this transaction. Every
-- source must exist (a removed Device only when the replaced release held
-- the same rule unchanged), every Site must be active in this Network, and
-- every granted prefix must lie inside its Site.
CREATE FUNCTION mesh_ops.attach_policy_route_rules_v1(
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
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy route rule input is invalid';
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
          SELECT 1 FROM mesh.compiled_policy_route_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy route rules need the release published now';
    END IF;
    -- Publication holds the Network scope lock that change_site_v1 takes, so
    -- the Sites read below cannot change or be deleted before commit.
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
            site_public_id UUID, prefixes CIDR[],
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
          AND rule.site_public_id IS NOT NULL
          AND rule.prefixes IS NOT NULL AND mesh_ops.site_prefixes_valid_internal_v1(rule.prefixes)
          -- IPv4-mapped IPv6 prefixes would alias IPv4 space.
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(rule.prefixes) AS mapped(prefix)
                          WHERE pg_catalog.family(mapped.prefix) = 6
                            AND mapped.prefix <<= '::ffff:0:0/96'::CIDR)
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
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               network_site.id AS destination_site_id, ports.destination_ports
        FROM valid_rule AS rule
        JOIN mesh.network_site AS network_site
          ON network_site.workspace_id = v_workspace AND network_site.network_id = v_network
         AND network_site.public_id = rule.site_public_id AND network_site.state = 'active'
         -- Every granted prefix lies inside one prefix of the Site.
         AND NOT EXISTS (
             SELECT 1 FROM pg_catalog.unnest(rule.prefixes) AS granted
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(network_site.prefixes) AS owned
                               WHERE granted <<= owned))
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
                   SELECT 1 FROM mesh.compiled_policy_route_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id = source_device.id
                     AND carried.destination_site_id = network_site.id
                     AND carried.prefixes = rule.prefixes
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_route_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_site_id, prefixes, protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_site_id,
           rule.prefixes, rule.protocol, rule.destination_ports, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001',
            MESSAGE = 'a Site, Device, group or tag changed during publication';
    END IF;
    IF (SELECT pg_catalog.sum(pg_catalog.cardinality(rule.prefixes)) FROM mesh.compiled_policy_route_rule AS rule
        WHERE rule.policy_release_id = v_release.id) > 16384 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'a release grants more than 16384 route prefixes';
    END IF;
    IF mesh_ops.release_route_overlap_internal_v1(v_release.id) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTS07', MESSAGE = 'route rules of different Sites overlap';
    END IF;
    RETURN v_inserted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_route_rules_v1(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_route_rules_v1(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;

-- The active Sites of the scope with the given IDs (route.read), for the
-- policy compiler. Unknown or deleted Sites are absent.
CREATE FUNCTION mesh_ops.read_policy_sites_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_site_public_ids UUID[]
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
    IF p_site_public_ids IS NULL OR pg_catalog.cardinality(p_site_public_ids) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site read is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_site_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    RETURN pg_catalog.jsonb_build_object('sites', COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.site_document_internal_v1(network_site)
            ORDER BY network_site.public_id)
        FROM mesh.network_site AS network_site
        WHERE network_site.workspace_id = v_scope.workspace_id AND network_site.network_id = v_scope.network_id
          AND network_site.state = 'active' AND network_site.public_id = ANY (p_site_public_ids)
    ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_sites_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID[]
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_sites_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID[]
) TO mesh_runtime;

-- change_site_v1 of schema 188, refusing to delete a Site that rules of the
-- active release name (MTS06), or to drop address space they grant (MTS08):
-- change those rules first. Otherwise every later publication, which resends
-- the active rules, would fail. The Network scope lock is the one
-- publication takes, so no rule can be published in between.
CREATE OR REPLACE FUNCTION mesh_ops.change_site_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_site_public_id UUID, p_expected_version BIGINT, p_name TEXT, p_prefixes CIDR[],
    p_masquerade BOOLEAN, p_failback BOOLEAN, p_probes JSONB, p_site_limit INTEGER,
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
    v_scope RECORD;
    v_site mesh.network_site%ROWTYPE;
    v_before JSONB;
    v_revisions RECORD;
    v_constraint TEXT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_site_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_site_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_prefixes IS NULL OR p_masquerade IS NULL
            OR p_failback IS NULL OR p_probes IS NULL))
        OR (p_operation = 'create' AND (p_site_limit IS NULL OR p_site_limit NOT BETWEEN 1 AND 1024)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_site_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id,
        CASE WHEN p_operation = 'delete' THEN 'route.withdraw' ELSE 'route.approve' END
    );
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_scope.workspace_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.network_site AS network_site
            WHERE network_site.workspace_id = v_scope.workspace_id
              AND network_site.network_id = v_scope.network_id
              AND network_site.state = 'active') >= p_site_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTS02', MESSAGE = 'Network already has the maximum Sites';
        END IF;
        BEGIN
            INSERT INTO mesh.network_site (
                public_id, deployment_id, workspace_id, network_id, name, name_key, prefixes,
                masquerade, failback, probes, created_at, updated_at
            ) VALUES (
                p_site_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_prefixes, p_masquerade, p_failback, p_probes, v_now, v_now
            ) RETURNING * INTO v_site;
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_site_active_name_uidx' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTS01', MESSAGE = 'Site name is taken';
            END IF;
            RAISE;
        END;
    ELSE
        SELECT * INTO v_site FROM mesh.network_site AS network_site
        WHERE network_site.workspace_id = v_scope.workspace_id AND network_site.network_id = v_scope.network_id
          AND network_site.public_id = p_site_public_id AND network_site.state = 'active'
        FOR UPDATE;
        IF v_site.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Site is unavailable';
        END IF;
        IF v_site.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Site version changed';
        END IF;
        v_before := mesh_ops.site_document_internal_v1(v_site);
        IF p_operation = 'update' AND v_site.name = p_name AND v_site.prefixes = p_prefixes
            AND v_site.masquerade = p_masquerade AND v_site.failback = p_failback AND v_site.probes = p_probes THEN
            RETURN pg_catalog.jsonb_build_object(
                'site', v_before, 'previous', v_before, 'changed', FALSE,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        IF p_operation = 'update' AND v_site.prefixes <> p_prefixes AND EXISTS (
            SELECT 1
            FROM mesh.compiled_policy_route_rule AS rule
            JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
            CROSS JOIN LATERAL pg_catalog.unnest(rule.prefixes) AS granted(prefix)
            WHERE release.state = 'active' AND rule.destination_site_id = v_site.id
              AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(p_prefixes) AS owned(prefix)
                              WHERE granted.prefix <<= owned.prefix)
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTS08', MESSAGE = 'Site prefixes are granted by active rules';
        END IF;
        IF p_operation = 'update' THEN
            BEGIN
                UPDATE mesh.network_site
                SET name = p_name, name_key = pg_catalog.lower(p_name), prefixes = p_prefixes,
                    masquerade = p_masquerade, failback = p_failback, probes = p_probes,
                    version = version + 1, updated_at = GREATEST(v_now, updated_at)
                WHERE id = v_site.id
                RETURNING * INTO v_site;
            EXCEPTION WHEN unique_violation THEN
                GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
                IF v_constraint = 'network_site_active_name_uidx' THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTS01', MESSAGE = 'Site name is taken';
                END IF;
                RAISE;
            END;
        ELSE
            IF mesh_ops.site_rule_count_internal_v1(v_site.id) > 0 THEN
                RAISE EXCEPTION USING ERRCODE = 'MTS06', MESSAGE = 'Site is named by active rules';
            END IF;
            DELETE FROM mesh.network_site_router WHERE site_id = v_site.id;
            UPDATE mesh.network_site
            SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at),
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_site.id
            RETURNING * INTO v_site;
        END IF;
    END IF;
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(
        v_scope.workspace_id, v_scope.network_id);
    RETURN pg_catalog.jsonb_build_object(
        'site', mesh_ops.site_document_internal_v1(v_site), 'previous', v_before, 'changed', TRUE,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;

-- The simulation baseline of schema 122 with the route rules of the active
-- release, so the compiled baseline rebuilds to the stored semantic hash.
CREATE FUNCTION mesh_ops.read_policy_simulation_baseline_v5(
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
    group_rules JSONB, selector_members JSONB, route_rules JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    baseline RECORD;
    v_route_rules JSONB;
BEGIN
    SELECT value.* INTO baseline
    FROM mesh_ops.read_policy_simulation_baseline_v4(
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
               'site_public_id', network_site.public_id,
               'prefixes', (SELECT pg_catalog.jsonb_agg(prefix::TEXT ORDER BY ordinal)
                            FROM pg_catalog.unnest(rule.prefixes) WITH ORDINALITY AS item(prefix, ordinal)),
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
    INTO v_route_rules
    FROM mesh.policy_release AS release
    JOIN mesh.compiled_policy_route_rule AS rule ON rule.policy_release_id = release.id
    JOIN mesh.network_site AS network_site ON network_site.id = rule.destination_site_id
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
        baseline.selector_members, v_route_rules;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_simulation_baseline_v5(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_simulation_baseline_v5(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;

-- The active policy of schema 122 with route rules: selector_kind 'site',
-- the Site as destination_selector_id and the granted destination_prefixes
-- (empty for other rules). Authoring reads it, so republishing keeps them.
CREATE FUNCTION mesh_ops.read_active_policy_v3(
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
    ), all_rule AS (
        SELECT * FROM local_rule UNION ALL SELECT * FROM imported_rule UNION ALL SELECT * FROM group_rule
        UNION ALL SELECT * FROM route_rule
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
REVOKE ALL ON FUNCTION mesh_ops.read_active_policy_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_active_policy_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
