-- Schema 258 (K2d d1, K2 design §24): Kubernetes access profiles in a
-- policy release, and what keeps a Core before K2 from widening them.
--
-- A profile narrows the Kubernetes groups a rule to a cluster grants. Its
-- content is the Network's and never changes; a release names the profiles
-- it holds and pins each rule's profile by content hash. Only a writer that
-- hashes profiles (attach_policy_group_rules_v4, schema 259 and later)
-- sets them: it turns mesh.kubernetes_profiles_aware on for its
-- transaction.
--
-- A Core before K2 never reads profiles:
-- - its map reader loses every rule that holds one, so its gateways grant
--   nothing there (never the whole group);
-- - republishing a rule unchanged keeps its profile (with the rest of the
--   release's profiles); changing such a rule is refused, and removing it is
--   always possible, so revocations never stop.
--
-- Errors: MTP07 a rule's Kubernetes access would change unseen.

-- A rule's namespaces: every one ('*' alone) or 1 to 64 DNS labels, strictly
-- sorted as Go sorts strings.
CREATE FUNCTION mesh_ops.kubernetes_namespaces_are_valid_v1(p_namespaces TEXT[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_namespaces IS NULL OR (
        pg_catalog.array_ndims(p_namespaces) = 1 AND pg_catalog.array_lower(p_namespaces, 1) = 1
        AND pg_catalog.array_position(p_namespaces, NULL) IS NULL
        AND (
            p_namespaces = ARRAY['*']::TEXT[]
            OR (
                pg_catalog.cardinality(p_namespaces) BETWEEN 1 AND 64
                AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.unnest(p_namespaces) AS namespace(name)
                    WHERE namespace.name !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
                )
                AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.generate_subscripts(p_namespaces, 1) AS position(index)
                    WHERE position.index > 1
                      AND NOT (p_namespaces[position.index - 1] COLLATE "C" < p_namespaces[position.index] COLLATE "C")
                )
            )
        )
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_namespaces_are_valid_v1(TEXT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A profile's content, by its hash (shared/kubeprofile ContentHash): the
-- Network's own, never shared across Networks, never changed or deleted.
CREATE TABLE mesh.kubernetes_access_profile_content (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    content_hash BYTEA NOT NULL,
    name TEXT NOT NULL,
    rules JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_access_profile_content_hash_check CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT kubernetes_access_profile_content_name_check
        CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT kubernetes_access_profile_content_rules_check CHECK (
        pg_catalog.jsonb_typeof(rules) = 'object' AND pg_catalog.octet_length(rules::TEXT) <= 32768
    ),
    CONSTRAINT kubernetes_access_profile_content_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_access_profile_content_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_access_profile_content_uidx UNIQUE (workspace_id, network_id, content_hash)
);
CREATE TRIGGER kubernetes_access_profile_content_immutable
BEFORE UPDATE OR DELETE ON mesh.kubernetes_access_profile_content
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

-- The profiles a release holds: each by the ID people know it by and the
-- content it had in that release. A rule pins its profile here.
CREATE TABLE mesh.policy_release_kubernetes_profile (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    policy_release_id BIGINT NOT NULL,
    policy_revision BIGINT NOT NULL,
    profile_public_id UUID NOT NULL,
    content_hash BYTEA NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT policy_release_kubernetes_profile_public_id_check
        CHECK (pg_catalog.get_byte(pg_catalog.uuid_send(profile_public_id), 6) >> 4 = 7),
    CONSTRAINT policy_release_kubernetes_profile_description_check
        CHECK (pg_catalog.char_length(description) <= 512),
    CONSTRAINT policy_release_kubernetes_profile_release_fk FOREIGN KEY (
        workspace_id, network_id, policy_release_id, policy_revision
    ) REFERENCES mesh.policy_release (workspace_id, network_id, id, policy_revision) ON DELETE RESTRICT,
    CONSTRAINT policy_release_kubernetes_profile_content_fk FOREIGN KEY (workspace_id, network_id, content_hash)
        REFERENCES mesh.kubernetes_access_profile_content (workspace_id, network_id, content_hash) ON DELETE RESTRICT,
    CONSTRAINT policy_release_kubernetes_profile_uidx UNIQUE (policy_release_id, profile_public_id),
    CONSTRAINT policy_release_kubernetes_profile_pin_uidx
        UNIQUE (policy_release_id, profile_public_id, content_hash)
);
CREATE INDEX policy_release_kubernetes_profile_content_idx
    ON mesh.policy_release_kubernetes_profile (workspace_id, network_id, content_hash);
CREATE TRIGGER policy_release_kubernetes_profile_immutable
BEFORE UPDATE OR DELETE ON mesh.policy_release_kubernetes_profile
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

ALTER TABLE mesh.kubernetes_access_profile_content ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_access_profile_content FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_access_profile_content_migrator_policy ON mesh.kubernetes_access_profile_content
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.policy_release_kubernetes_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.policy_release_kubernetes_profile FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_release_kubernetes_profile_migrator_policy ON mesh.policy_release_kubernetes_profile
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_access_profile_content, mesh.policy_release_kubernetes_profile
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A rule's profile, as the release pins it: its namespaces, whether its
-- cluster part applies, its mode and, reporting, until when. Whether the
-- release's hash covers them, as kubernetes_groups_hashed does the groups.
ALTER TABLE mesh.compiled_policy_group_rule
    ADD COLUMN kubernetes_profile_public_id UUID,
    ADD COLUMN kubernetes_profile_hash BYTEA,
    ADD COLUMN kubernetes_namespaces TEXT[],
    ADD COLUMN kubernetes_cluster_part BOOLEAN,
    ADD COLUMN kubernetes_mode TEXT,
    ADD COLUMN kubernetes_report_until TIMESTAMPTZ,
    ADD COLUMN kubernetes_profile_hashed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mesh.compiled_policy_group_rule
    ADD CONSTRAINT compiled_policy_group_rule_kubernetes_profile_check CHECK (
        (kubernetes_profile_public_id IS NULL AND kubernetes_profile_hash IS NULL AND kubernetes_namespaces IS NULL
         AND kubernetes_cluster_part IS NULL AND kubernetes_mode IS NULL AND kubernetes_report_until IS NULL
         AND NOT kubernetes_profile_hashed)
        OR (
            kubernetes_profile_public_id IS NOT NULL AND kubernetes_groups IS NOT NULL
            AND kubernetes_profile_hash IS NOT NULL AND kubernetes_mode IS NOT NULL
            AND pg_catalog.octet_length(kubernetes_profile_hash) = 32
            AND kubernetes_namespaces IS NOT NULL
            AND mesh_ops.kubernetes_namespaces_are_valid_v1(kubernetes_namespaces)
            AND kubernetes_cluster_part IS NOT NULL
            AND kubernetes_mode IN ('enforce', 'report')
            AND (kubernetes_mode = 'report') = (kubernetes_report_until IS NOT NULL)
            AND (kubernetes_report_until IS NULL OR kubernetes_report_until <= created_at + INTERVAL '14 days')
        )
    ) NOT VALID,
    ADD CONSTRAINT compiled_policy_group_rule_kubernetes_profile_fk FOREIGN KEY (
        policy_release_id, kubernetes_profile_public_id, kubernetes_profile_hash
    ) REFERENCES mesh.policy_release_kubernetes_profile (policy_release_id, profile_public_id, content_hash)
        ON DELETE RESTRICT NOT VALID;
-- Not validated here: every existing row has the new columns NULL, the
-- constraints hold for every row written from now on, and scanning every
-- rule of every release under this migration's lock would stop publishes.

-- carry_kubernetes_rule_groups_v1 of schema 236, then a rule's profile.
-- Same trigger name, so it still runs after compiled_policy_group_rule_kubernetes.
CREATE FUNCTION mesh_ops.carry_kubernetes_rule_access_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_aware BOOLEAN := COALESCE(pg_catalog.current_setting('mesh.kubernetes_groups_aware', TRUE), '') = 'on';
    v_profiles_aware BOOLEAN :=
        COALESCE(pg_catalog.current_setting('mesh.kubernetes_profiles_aware', TRUE), '') = 'on';
    v_cluster BOOLEAN;
    v_previous mesh.compiled_policy_group_rule%ROWTYPE;
    v_unchanged BOOLEAN;
BEGIN
    v_cluster := NEW.destination_device_group_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM mesh.device_group AS device_group
        WHERE device_group.id = NEW.destination_device_group_id AND device_group.kind = 'kubernetes_cluster'
    );
    IF NEW.kubernetes_groups IS NOT NULL AND NOT (v_cluster AND v_aware) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP07',
            MESSAGE = 'only a rule to a Kubernetes cluster, attached by a Core that hashes them, names Kubernetes groups',
            DETAIL = NEW.access_rule_public_id::TEXT;
    END IF;
    IF (NEW.kubernetes_profile_public_id IS NOT NULL OR NEW.kubernetes_profile_hash IS NOT NULL
        OR NEW.kubernetes_namespaces IS NOT NULL OR NEW.kubernetes_cluster_part IS NOT NULL
        OR NEW.kubernetes_mode IS NOT NULL OR NEW.kubernetes_report_until IS NOT NULL)
        AND NOT (v_cluster AND v_profiles_aware) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP07',
            MESSAGE = 'only a rule to a Kubernetes cluster, attached by a Core that hashes them, names an access profile',
            DETAIL = NEW.access_rule_public_id::TEXT;
    END IF;
    NEW.kubernetes_groups_hashed := v_aware AND NEW.kubernetes_groups IS NOT NULL;
    NEW.kubernetes_profile_hashed := v_profiles_aware AND NEW.kubernetes_profile_public_id IS NOT NULL;
    -- A writer that does not hash profiles keeps every profile of the
    -- release it replaces, used or not, from its first rule on. (A release
    -- with no group rule at all keeps none: the next profile writer sends
    -- them again.)
    IF NOT v_profiles_aware AND NOT EXISTS (
        SELECT 1 FROM mesh.policy_release_kubernetes_profile AS held
        WHERE held.policy_release_id = NEW.policy_release_id
    ) THEN
        INSERT INTO mesh.policy_release_kubernetes_profile (
            workspace_id, network_id, policy_release_id, policy_revision, profile_public_id, content_hash,
            description, created_at
        )
        SELECT NEW.workspace_id, NEW.network_id, NEW.policy_release_id, NEW.policy_revision,
               held.profile_public_id, held.content_hash, held.description, NEW.created_at
        FROM mesh.policy_release_kubernetes_profile AS held
        JOIN mesh.policy_release AS previous ON previous.id = held.policy_release_id
        WHERE previous.workspace_id = NEW.workspace_id AND previous.network_id = NEW.network_id
          AND previous.policy_revision = NEW.policy_revision - 1 AND previous.state = 'superseded'
        ON CONFLICT (policy_release_id, profile_public_id) DO NOTHING;
    END IF;
    IF NOT v_cluster THEN
        RETURN NEW;
    END IF;
    SELECT carried.* INTO v_previous
    FROM mesh.compiled_policy_group_rule AS carried
    JOIN mesh.policy_release AS previous ON previous.id = carried.policy_release_id
    WHERE previous.workspace_id = NEW.workspace_id AND previous.network_id = NEW.network_id
      AND previous.policy_revision = NEW.policy_revision - 1 AND previous.state = 'superseded'
      AND carried.access_rule_public_id = NEW.access_rule_public_id;
    v_unchanged := v_previous.id IS NOT NULL
        AND v_previous.source_device_id IS NOT DISTINCT FROM NEW.source_device_id
        AND v_previous.source_device_group_id IS NOT DISTINCT FROM NEW.source_device_group_id
        AND v_previous.source_identity_group_id IS NOT DISTINCT FROM NEW.source_identity_group_id
        AND v_previous.source_device_tag_id IS NOT DISTINCT FROM NEW.source_device_tag_id
        AND v_previous.destination_device_id IS NOT DISTINCT FROM NEW.destination_device_id
        AND v_previous.destination_device_group_id IS NOT DISTINCT FROM NEW.destination_device_group_id
        AND v_previous.destination_device_tag_id IS NOT DISTINCT FROM NEW.destination_device_tag_id
        AND v_previous.protocol = NEW.protocol
        AND v_previous.destination_ports = NEW.destination_ports;
    -- The groups, as schema 236 carries them.
    IF NEW.kubernetes_groups IS NULL AND v_previous.id IS NOT NULL AND v_previous.kubernetes_groups IS NOT NULL THEN
        -- A Core before K1a3 republishing the rule unchanged keeps its groups.
        IF v_aware OR NOT v_unchanged THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP07',
                MESSAGE = 'a rule to a Kubernetes cluster would lose its Kubernetes groups',
                DETAIL = NEW.access_rule_public_id::TEXT;
        END IF;
        NEW.kubernetes_groups := v_previous.kubernetes_groups;
    END IF;
    -- The profile: a Core that does not hash profiles keeps a rule's profile
    -- only by republishing the rule unchanged, groups included; it never
    -- turns it into the whole groups.
    IF NOT v_profiles_aware AND v_previous.kubernetes_profile_public_id IS NOT NULL THEN
        IF NOT v_unchanged OR NEW.kubernetes_groups IS DISTINCT FROM v_previous.kubernetes_groups THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP07',
                MESSAGE = 'a rule to a Kubernetes cluster would lose its access profile',
                DETAIL = NEW.access_rule_public_id::TEXT;
        END IF;
        NEW.kubernetes_profile_public_id := v_previous.kubernetes_profile_public_id;
        NEW.kubernetes_profile_hash := v_previous.kubernetes_profile_hash;
        NEW.kubernetes_namespaces := v_previous.kubernetes_namespaces;
        NEW.kubernetes_cluster_part := v_previous.kubernetes_cluster_part;
        NEW.kubernetes_mode := v_previous.kubernetes_mode;
        NEW.kubernetes_report_until := v_previous.kubernetes_report_until;
        -- The release's hash, written by such a Core, does not cover it.
        NEW.kubernetes_profile_hashed := FALSE;
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.carry_kubernetes_rule_access_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
DROP TRIGGER compiled_policy_group_rule_kubernetes_groups ON mesh.compiled_policy_group_rule;
CREATE TRIGGER compiled_policy_group_rule_kubernetes_groups
BEFORE INSERT ON mesh.compiled_policy_group_rule
FOR EACH ROW EXECUTE FUNCTION mesh_ops.carry_kubernetes_rule_access_v1();

-- A Core before K2 reads the groups of the rules that name no profile: a
-- rule that names one grants nothing through it, never its whole groups.
CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_kubernetes_rule_groups_v1(p_policy_revision BIGINT)
RETURNS TABLE (access_rule_public_id UUID, kubernetes_groups TEXT[])
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace_id BIGINT := mesh_ops.current_workspace_id();
    v_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_policy_revision IS NULL OR p_policy_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map Kubernetes groups request is invalid';
    END IF;
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT rule.access_rule_public_id, rule.kubernetes_groups
    FROM mesh.policy_release AS release
    JOIN mesh.compiled_policy_group_rule AS rule ON rule.policy_release_id = release.id
    WHERE release.workspace_id = v_workspace_id AND release.network_id = v_network_id
      AND release.policy_revision = p_policy_revision AND release.state = 'active'
      AND rule.kubernetes_groups IS NOT NULL AND rule.kubernetes_profile_public_id IS NULL
    ORDER BY rule.access_rule_public_id;
END;
$function$;

-- The writers of schemas 228 and 236, unchanged but for turning
-- mesh.kubernetes_profiles_aware off first (review d1 M2).
CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_group_rules_v2(
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
    -- Never a writer that hashes profiles (schema 258): a flag left on
    -- earlier in the transaction must not drop a rule's profile.
    PERFORM pg_catalog.set_config('mesh.kubernetes_profiles_aware', 'off', TRUE);
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rule input is invalid';
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
          SELECT 1 FROM mesh.compiled_policy_group_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rules need the release published now';
    END IF;
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
            destination_node_public_id UUID, destination_device_group_public_id UUID,
            destination_device_tag_public_id UUID,
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
          AND pg_catalog.num_nonnulls(rule.destination_node_public_id, rule.destination_device_group_public_id,
                                      rule.destination_device_tag_public_id) = 1
          AND (rule.source_node_public_id IS NULL OR rule.destination_node_public_id IS NULL)
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
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               destination_device.id AS destination_device_id,
               destination_group.id AS destination_device_group_id, destination_tag.id AS destination_device_tag_id,
               ports.destination_ports
        FROM valid_rule AS rule
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace AND source_identity.network_id = v_network
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace AND source_tag.network_id = v_network
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        LEFT JOIN mesh.device AS destination_device
          ON destination_device.workspace_id = v_workspace AND destination_device.network_id = v_network
         AND destination_device.public_id = rule.destination_node_public_id
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.workspace_id = v_workspace AND destination_group.network_id = v_network
         AND destination_group.public_id = rule.destination_device_group_public_id
         AND destination_group.state = 'active'
        LEFT JOIN mesh.device_tag AS destination_tag
          ON destination_tag.workspace_id = v_workspace AND destination_tag.network_id = v_network
         AND destination_tag.public_id = rule.destination_device_tag_public_id AND destination_tag.state = 'active'
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
          AND (rule.destination_node_public_id IS NULL OR destination_device.id IS NOT NULL)
          AND (rule.destination_device_group_public_id IS NULL OR destination_group.id IS NOT NULL)
          AND (rule.destination_device_tag_public_id IS NULL OR destination_tag.id IS NOT NULL)
          -- A revoked or deleted Device side only for a rule the replaced
          -- release held unchanged: same sides, protocol and ports.
          AND ((source_device.id IS NULL OR source_device.state IN ('active', 'expired', 'suspended'))
               AND (destination_device.id IS NULL OR destination_device.state IN ('active', 'expired', 'suspended'))
               OR EXISTS (
                   SELECT 1 FROM mesh.compiled_policy_group_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id IS NOT DISTINCT FROM source_device.id
                     AND carried.source_device_group_id IS NOT DISTINCT FROM source_group.id
                     AND carried.source_identity_group_id IS NOT DISTINCT FROM source_identity.id
                     AND carried.source_device_tag_id IS NOT DISTINCT FROM source_tag.id
                     AND carried.destination_device_id IS NOT DISTINCT FROM destination_device.id
                     AND carried.destination_device_group_id IS NOT DISTINCT FROM destination_group.id
                     AND carried.destination_device_tag_id IS NOT DISTINCT FROM destination_tag.id
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_group_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_device_id, destination_device_group_id, destination_device_tag_id,
        protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_device_id,
           rule.destination_device_group_id, rule.destination_device_tag_id, rule.protocol,
           rule.destination_ports, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        -- A rule left out that names a Device not in this Network, or one
        -- that is gone, is new or changed: refuse it as such.
        IF EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID, source_node_public_id UUID, destination_node_public_id UUID
            )
            CROSS JOIN LATERAL (VALUES
                (rule.source_node_public_id), (rule.destination_node_public_id)
            ) AS side(node_public_id)
            WHERE side.node_public_id IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.compiled_policy_group_rule AS attached
                  WHERE attached.public_id = rule.projection_public_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.device AS device
                  WHERE device.workspace_id = v_workspace AND device.network_id = v_network
                    AND device.public_id = side.node_public_id AND device.state IN ('active', 'expired', 'suspended')
              )
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'a Device, group or tag changed during publication';
    END IF;
    IF mesh_ops.max_device_policy_edges_internal_v1(v_workspace, v_network) > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
    END IF;
    RETURN v_inserted;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_group_rules_v3(
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
    -- Never a writer that hashes profiles (schema 258): a flag left on
    -- earlier in the transaction must not drop a rule's profile.
    PERFORM pg_catalog.set_config('mesh.kubernetes_profiles_aware', 'off', TRUE);
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    -- The caller hashed the release with each cluster rule's Kubernetes
    -- groups: the groups trigger refuses a rule that would lose them instead
    -- of carrying them. Transaction-local, so it never leaks to a pooled
    -- connection a Core before K1a3 uses next.
    PERFORM pg_catalog.set_config('mesh.kubernetes_groups_aware', 'on', TRUE);
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rule input is invalid';
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
          SELECT 1 FROM mesh.compiled_policy_group_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rules need the release published now';
    END IF;
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
            destination_node_public_id UUID, destination_device_group_public_id UUID,
            destination_device_tag_public_id UUID,
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[],
            kubernetes_groups TEXT[]
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
          AND pg_catalog.num_nonnulls(rule.destination_node_public_id, rule.destination_device_group_public_id,
                                      rule.destination_device_tag_public_id) = 1
          AND (rule.source_node_public_id IS NULL OR rule.destination_node_public_id IS NULL)
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
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               destination_device.id AS destination_device_id,
               destination_group.id AS destination_device_group_id, destination_tag.id AS destination_device_tag_id,
               ports.destination_ports
        FROM valid_rule AS rule
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace AND source_identity.network_id = v_network
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace AND source_tag.network_id = v_network
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        LEFT JOIN mesh.device AS destination_device
          ON destination_device.workspace_id = v_workspace AND destination_device.network_id = v_network
         AND destination_device.public_id = rule.destination_node_public_id
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.workspace_id = v_workspace AND destination_group.network_id = v_network
         AND destination_group.public_id = rule.destination_device_group_public_id
         AND destination_group.state = 'active'
        LEFT JOIN mesh.device_tag AS destination_tag
          ON destination_tag.workspace_id = v_workspace AND destination_tag.network_id = v_network
         AND destination_tag.public_id = rule.destination_device_tag_public_id AND destination_tag.state = 'active'
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
          AND (rule.destination_node_public_id IS NULL OR destination_device.id IS NOT NULL)
          AND (rule.destination_device_group_public_id IS NULL OR destination_group.id IS NOT NULL)
          AND (rule.destination_device_tag_public_id IS NULL OR destination_tag.id IS NOT NULL)
          -- A revoked or deleted Device side only for a rule the replaced
          -- release held unchanged: same sides, protocol and ports.
          AND ((source_device.id IS NULL OR source_device.state IN ('active', 'expired', 'suspended'))
               AND (destination_device.id IS NULL OR destination_device.state IN ('active', 'expired', 'suspended'))
               OR EXISTS (
                   SELECT 1 FROM mesh.compiled_policy_group_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id IS NOT DISTINCT FROM source_device.id
                     AND carried.source_device_group_id IS NOT DISTINCT FROM source_group.id
                     AND carried.source_identity_group_id IS NOT DISTINCT FROM source_identity.id
                     AND carried.source_device_tag_id IS NOT DISTINCT FROM source_tag.id
                     AND carried.destination_device_id IS NOT DISTINCT FROM destination_device.id
                     AND carried.destination_device_group_id IS NOT DISTINCT FROM destination_group.id
                     AND carried.destination_device_tag_id IS NOT DISTINCT FROM destination_tag.id
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_group_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_device_id, destination_device_group_id, destination_device_tag_id,
        protocol, destination_ports, kubernetes_groups, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_device_id,
           rule.destination_device_group_id, rule.destination_device_tag_id, rule.protocol,
           rule.destination_ports, rule.kubernetes_groups, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        -- A rule left out that names a Device not in this Network, or one
        -- that is gone, is new or changed: refuse it as such.
        IF EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID, source_node_public_id UUID, destination_node_public_id UUID
            )
            CROSS JOIN LATERAL (VALUES
                (rule.source_node_public_id), (rule.destination_node_public_id)
            ) AS side(node_public_id)
            WHERE side.node_public_id IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.compiled_policy_group_rule AS attached
                  WHERE attached.public_id = rule.projection_public_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.device AS device
                  WHERE device.workspace_id = v_workspace AND device.network_id = v_network
                    AND device.public_id = side.node_public_id AND device.state IN ('active', 'expired', 'suspended')
              )
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'a Device, group or tag changed during publication';
    END IF;
    IF mesh_ops.max_device_policy_edges_internal_v1(v_workspace, v_network) > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
    END IF;
    -- A gateway reports at most 64 groups: the rules of one cluster grant no
    -- more.
    IF EXISTS (
        SELECT 1 FROM mesh.compiled_policy_group_rule AS attached
        CROSS JOIN LATERAL pg_catalog.unnest(attached.kubernetes_groups) AS kubernetes_group(name)
        WHERE attached.policy_release_id = v_release.id
        GROUP BY attached.destination_device_group_id
        HAVING pg_catalog.count(DISTINCT kubernetes_group.name) > 64
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP07',
            MESSAGE = 'the rules of a Kubernetes cluster grant more than 64 Kubernetes groups';
    END IF;
    PERFORM pg_catalog.set_config('mesh.kubernetes_groups_aware', 'off', TRUE);
    RETURN v_inserted;
END;
$function$;
