-- K2h h1: permission sets (access profiles) belong to one Kubernetes
-- cluster (K2 design §32, v2.3).
--
-- A release's set row names its cluster, or none for a set of every cluster
-- (legacy). The first cluster an ID is bound to is recorded and never
-- changes. Writers that know clusters attach sets with
-- attach_policy_kubernetes_profiles_v2; any other insert (an older Core,
-- the carry of schema 258) takes the cluster the ID is bound to. A rule
-- applies only a set of its own cluster (MTP09), maps leave out a rule that
-- does not, and copies of one content in several clusters share one entry
-- of a gateway's table.

ALTER TABLE mesh.policy_release_kubernetes_profile
    ADD COLUMN kubernetes_cluster_id BIGINT,
    ADD COLUMN copied_from UUID,
    ADD COLUMN cluster_hashed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mesh.policy_release_kubernetes_profile
    ADD CONSTRAINT policy_release_kubernetes_profile_cluster_fk
        FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT policy_release_kubernetes_profile_copied_from_check CHECK (
        copied_from IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(copied_from), 6) >> 4 = 7
    ) NOT VALID;
-- Every existing row has the new columns NULL: nothing to check.
ALTER TABLE mesh.policy_release_kubernetes_profile VALIDATE CONSTRAINT policy_release_kubernetes_profile_cluster_fk;
ALTER TABLE mesh.policy_release_kubernetes_profile
    VALIDATE CONSTRAINT policy_release_kubernetes_profile_copied_from_check;

-- The cluster each set ID was first bound to, for good (§32.12 M-1).
CREATE TABLE mesh.kubernetes_profile_binding (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    profile_public_id UUID NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workspace_id, network_id, profile_public_id),
    CONSTRAINT kubernetes_profile_binding_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT
);
CREATE TRIGGER kubernetes_profile_binding_immutable
BEFORE UPDATE OR DELETE ON mesh.kubernetes_profile_binding
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
ALTER TABLE mesh.kubernetes_profile_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_profile_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_profile_binding_migrator_policy ON mesh.kubernetes_profile_binding
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_profile_binding
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Each set row of a release, before it is inserted. A writer that knows
-- clusters (v2, mesh.kubernetes_profiles_clustered_aware on) sends the
-- cluster: an ID bound before keeps its cluster (MTP10), a new binding is
-- recorded and needs an active cluster. Any other writer gets the cluster
-- the ID is bound to (none for a legacy set) and the copied_from it has in
-- the release replaced, decided by the flag, never by the value being NULL
-- (M1).
CREATE FUNCTION mesh_ops.bind_kubernetes_profile_cluster_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_aware BOOLEAN :=
        COALESCE(pg_catalog.current_setting('mesh.kubernetes_profiles_clustered_aware', TRUE), '') = 'on';
    v_bound BIGINT;
BEGIN
    SELECT binding.kubernetes_cluster_id INTO v_bound FROM mesh.kubernetes_profile_binding AS binding
    WHERE binding.workspace_id = NEW.workspace_id AND binding.network_id = NEW.network_id
      AND binding.profile_public_id = NEW.profile_public_id;
    IF NOT v_aware THEN
        NEW.kubernetes_cluster_id := v_bound;
        NEW.cluster_hashed := FALSE;
        -- As the carry of schema 258 finds the replaced release: by index.
        SELECT held.copied_from INTO NEW.copied_from FROM mesh.policy_release_kubernetes_profile AS held
        JOIN mesh.policy_release AS previous ON previous.id = held.policy_release_id
        WHERE previous.workspace_id = NEW.workspace_id AND previous.network_id = NEW.network_id
          AND previous.policy_revision = NEW.policy_revision - 1
          AND held.profile_public_id = NEW.profile_public_id;
        RETURN NEW;
    END IF;
    NEW.cluster_hashed := TRUE;
    IF v_bound IS NOT NULL THEN
        IF NEW.kubernetes_cluster_id IS DISTINCT FROM v_bound THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP10',
                MESSAGE = 'a permission set keeps the cluster it was first bound to',
                DETAIL = NEW.profile_public_id::TEXT;
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.kubernetes_cluster_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM mesh.kubernetes_cluster AS cluster
            WHERE cluster.workspace_id = NEW.workspace_id AND cluster.network_id = NEW.network_id
              AND cluster.id = NEW.kubernetes_cluster_id AND cluster.state = 'active'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP10',
                MESSAGE = 'a permission set is first bound to an active cluster of its Network',
                DETAIL = NEW.profile_public_id::TEXT;
        END IF;
        INSERT INTO mesh.kubernetes_profile_binding (
            workspace_id, network_id, profile_public_id, kubernetes_cluster_id, created_at
        ) VALUES (NEW.workspace_id, NEW.network_id, NEW.profile_public_id, NEW.kubernetes_cluster_id, NEW.created_at);
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.bind_kubernetes_profile_cluster_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER policy_release_kubernetes_profile_cluster
BEFORE INSERT ON mesh.policy_release_kubernetes_profile
FOR EACH ROW EXECUTE FUNCTION mesh_ops.bind_kubernetes_profile_cluster_v1();

-- schema 258's carry, then MTP09 (§32.11 M-C). Same trigger.
CREATE OR REPLACE FUNCTION mesh_ops.carry_kubernetes_rule_access_v1()
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
    -- K2h: a rule applies only a set of its own cluster, or a set of every
    -- cluster (legacy). Checked after carrying, whoever writes; the set
    -- rows of the release are attached before its rules (MTP09).
    IF NEW.kubernetes_profile_public_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM mesh.policy_release_kubernetes_profile AS held
        JOIN mesh.device_group AS cluster_group ON cluster_group.id = NEW.destination_device_group_id
        WHERE held.policy_release_id = NEW.policy_release_id
          AND held.profile_public_id = NEW.kubernetes_profile_public_id
          AND held.kubernetes_cluster_id IS NOT NULL
          AND held.kubernetes_cluster_id IS DISTINCT FROM cluster_group.kubernetes_cluster_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP09',
            MESSAGE = 'a rule to a Kubernetes cluster applies a permission set of another cluster',
            DETAIL = NEW.access_rule_public_id::TEXT;
    END IF;
    RETURN NEW;
END;
$function$;

-- A Core that knows clusters attaches a release's sets with their clusters.
CREATE FUNCTION mesh_ops.attach_policy_kubernetes_profiles_v2(
    p_release_public_id UUID, p_created_at TIMESTAMPTZ, p_profiles JSONB
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
    v_deployment BIGINT;
    v_release mesh.policy_release%ROWTYPE;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_profiles IS NULL
        OR pg_catalog.jsonb_typeof(p_profiles) <> 'array'
        OR pg_catalog.jsonb_array_length(p_profiles) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy Kubernetes profile input is invalid';
    END IF;
    -- The release published in this transaction, before any of its rules
    -- or profiles.
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM mesh.policy_release_kubernetes_profile AS held WHERE held.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'policy Kubernetes profiles need the release published now, before its rules';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace;
    v_expected := pg_catalog.jsonb_array_length(p_profiles);
    -- A cluster not of this Network is the user's mistake, not a broken
    -- input: MTP10, as a cluster that is not active (review h1 M4).
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(cluster_id UUID)
        WHERE profile.cluster_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM mesh.kubernetes_cluster AS cluster
            WHERE cluster.workspace_id = v_workspace AND cluster.network_id = v_network
              AND cluster.public_id = profile.cluster_id
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP10',
            MESSAGE = 'a permission set names a cluster of another Network or none';
    END IF;
    -- Core checks profiles in full (owner: compute in Go); here only their
    -- shape, IDs once each, names once each within a cluster and among the
    -- sets of every cluster, and that each cluster is of this Network.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(
            profile_public_id UUID, content_hash TEXT, name TEXT, rules JSONB, description TEXT,
            cluster_id UUID, copied_from UUID
        )
        WHERE profile.profile_public_id IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(profile.profile_public_id), 6) >> 4 <> 7
           OR profile.content_hash IS NULL OR profile.content_hash !~ '^[0-9a-f]{64}$'
           OR profile.name IS NULL OR profile.rules IS NULL OR profile.description IS NULL
           OR (profile.copied_from IS NOT NULL
               AND pg_catalog.get_byte(pg_catalog.uuid_send(profile.copied_from), 6) >> 4 <> 7)
    ) OR (
        SELECT pg_catalog.count(DISTINCT profile.profile_public_id) <> v_expected
            OR pg_catalog.count(DISTINCT (profile.cluster_id, profile.name)) <> v_expected
            OR pg_catalog.count(DISTINCT profile.name) FILTER (WHERE profile.cluster_id IS NULL)
                <> pg_catalog.count(*) FILTER (WHERE profile.cluster_id IS NULL)
            OR EXISTS (
                SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_profiles) AS legacy(name TEXT, cluster_id UUID)
                JOIN pg_catalog.jsonb_to_recordset(p_profiles) AS bound(name TEXT, cluster_id UUID)
                  ON bound.name = legacy.name AND bound.cluster_id IS NOT NULL
                WHERE legacy.cluster_id IS NULL
            )
        FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(profile_public_id UUID, name TEXT, cluster_id UUID)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy Kubernetes profile input is invalid';
    END IF;
    INSERT INTO mesh.kubernetes_access_profile_content (
        deployment_id, workspace_id, network_id, content_hash, name, rules, created_at
    )
    SELECT v_deployment, v_workspace, v_network, pg_catalog.decode(profile.content_hash, 'hex'), profile.name,
           profile.rules, p_created_at
    FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(content_hash TEXT, name TEXT, rules JSONB)
    ORDER BY profile.content_hash
    ON CONFLICT (workspace_id, network_id, content_hash) DO NOTHING;
    -- A content hash names one content forever.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(content_hash TEXT, name TEXT, rules JSONB)
        JOIN mesh.kubernetes_access_profile_content AS content
          ON content.workspace_id = v_workspace AND content.network_id = v_network
         AND content.content_hash = pg_catalog.decode(profile.content_hash, 'hex')
        WHERE content.name <> profile.name OR content.rules <> profile.rules
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTP08',
            MESSAGE = 'a Kubernetes access profile hash names other content';
    END IF;
    -- The binding trigger checks each set against the cluster its ID was
    -- first bound to, and records first bindings (K2h §32.12 M-1).
    PERFORM pg_catalog.set_config('mesh.kubernetes_profiles_clustered_aware', 'on', TRUE);
    INSERT INTO mesh.policy_release_kubernetes_profile (
        workspace_id, network_id, policy_release_id, policy_revision, profile_public_id, content_hash,
        description, created_at, kubernetes_cluster_id, copied_from, cluster_hashed
    )
    SELECT v_workspace, v_network, v_release.id, v_release.policy_revision, profile.profile_public_id,
           pg_catalog.decode(profile.content_hash, 'hex'), profile.description, p_created_at, cluster.id,
           profile.copied_from, TRUE
    FROM pg_catalog.jsonb_to_recordset(p_profiles) AS profile(
        profile_public_id UUID, content_hash TEXT, description TEXT, cluster_id UUID, copied_from UUID
    )
    LEFT JOIN mesh.kubernetes_cluster AS cluster
      ON cluster.workspace_id = v_workspace AND cluster.network_id = v_network
     AND cluster.public_id = profile.cluster_id
    ORDER BY profile.profile_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.kubernetes_profiles_clustered_aware', 'off', TRUE);
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy Kubernetes profile input is invalid';
    END IF;
    RETURN v_inserted;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_kubernetes_profiles_v2(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_kubernetes_profiles_v2(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;

-- read_policy_kubernetes_access_v1 with each set's cluster and copy origin,
-- and whether a writer that hashes clusters wrote the release.
CREATE FUNCTION mesh_ops.read_policy_kubernetes_access_v2(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_policy_revision BIGINT, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_release BIGINT;
    v_result JSONB;
    v_permission TEXT;
    v_allowed BOOLEAN := FALSE;
BEGIN
    IF p_policy_revision IS NULL OR p_policy_revision < 1 OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Invalid Kubernetes access read';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL OR NOT EXISTS (
        SELECT 1 FROM mesh.network AS network
        JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
        WHERE network.id = v_network AND network.workspace_id = v_workspace
          AND network.public_id = p_network_public_id AND workspace.public_id = p_workspace_public_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    -- Whoever reads, validates or publishes the Network's policy compiles
    -- or shows its rules, groups and profiles included.
    FOREACH v_permission IN ARRAY ARRAY['policy.read', 'policy.validate', 'policy.publish'] LOOP
        PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, v_permission, p_evaluated_at
        );
        IF FOUND THEN
            v_allowed := TRUE;
            EXIT;
        END IF;
    END LOOP;
    IF NOT v_allowed THEN RETURN NULL; END IF;
    SELECT release.id INTO v_release FROM mesh.policy_release AS release
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.policy_revision = p_policy_revision;
    -- No release at the revision holds nothing: a publish on it fails its
    -- revision check, not this read (review d2 L3).
    IF v_release IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('policy_revision', p_policy_revision, 'groups_hashed', FALSE,
            'profiles_hashed', FALSE, 'clusters_hashed', FALSE, 'rules', '[]'::JSONB, 'profiles', '[]'::JSONB);
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'policy_revision', p_policy_revision,
        'groups_hashed', COALESCE(pg_catalog.bool_or(rule.kubernetes_groups_hashed), FALSE),
        'profiles_hashed', COALESCE(pg_catalog.bool_or(rule.kubernetes_profile_hashed), FALSE),
        -- A writer that hashes the clusters of sets wrote this release.
        'clusters_hashed', COALESCE((
            SELECT pg_catalog.bool_or(held.cluster_hashed) FROM mesh.policy_release_kubernetes_profile AS held
            WHERE held.policy_release_id = v_release
        ), FALSE),
        'rules', COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id', rule.access_rule_public_id, 'cluster_id', cluster.public_id,
            'source_kind', CASE WHEN rule.source_device_group_id IS NOT NULL THEN 'device_group'
                                WHEN rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                                WHEN rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                                ELSE 'device' END,
            'source_id', COALESCE(source_group.public_id, source_identity.public_id, source_tag.public_id,
                                  source_device.public_id),
            'groups', pg_catalog.to_jsonb(rule.kubernetes_groups),
            'profile', CASE WHEN rule.kubernetes_profile_public_id IS NULL THEN NULL ELSE pg_catalog.jsonb_build_object(
                'id', rule.kubernetes_profile_public_id,
                'hash', pg_catalog.encode(rule.kubernetes_profile_hash, 'hex'),
                'namespaces', pg_catalog.to_jsonb(rule.kubernetes_namespaces),
                'cluster_part', rule.kubernetes_cluster_part,
                'mode', rule.kubernetes_mode,
                'report_until_ms', pg_catalog.floor(
                    EXTRACT(EPOCH FROM rule.kubernetes_report_until) * 1000)::BIGINT
            ) END
        ) ORDER BY rule.access_rule_public_id), '[]'::JSONB),
        -- Every profile of the release, used or not, with its content.
        'profiles', (
            SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'id', held.profile_public_id, 'hash', pg_catalog.encode(held.content_hash, 'hex'),
                'name', content.name, 'rules', content.rules, 'description', held.description,
                'cluster_id', bound.public_id, 'copied_from', held.copied_from
            ) ORDER BY held.profile_public_id), '[]'::JSONB)
            FROM mesh.policy_release_kubernetes_profile AS held
            JOIN mesh.kubernetes_access_profile_content AS content
              ON content.workspace_id = held.workspace_id AND content.network_id = held.network_id
             AND content.content_hash = held.content_hash
            LEFT JOIN mesh.kubernetes_cluster AS bound
              ON bound.workspace_id = held.workspace_id AND bound.network_id = held.network_id
             AND bound.id = held.kubernetes_cluster_id
            WHERE held.policy_release_id = v_release
        ))
    INTO v_result
    FROM mesh.compiled_policy_group_rule AS rule
    JOIN mesh.device_group AS cluster_group
      ON cluster_group.id = rule.destination_device_group_id AND cluster_group.kind = 'kubernetes_cluster'
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = cluster_group.kubernetes_cluster_id
    LEFT JOIN mesh.device AS source_device ON source_device.id = rule.source_device_id
    LEFT JOIN mesh.device_group AS source_group ON source_group.id = rule.source_device_group_id
    LEFT JOIN mesh.identity_group AS source_identity ON source_identity.id = rule.source_identity_group_id
    LEFT JOIN mesh.device_tag AS source_tag ON source_tag.id = rule.source_device_tag_id
    WHERE rule.policy_release_id = v_release;
    RETURN v_result;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_kubernetes_access_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, TIMESTAMPTZ
)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_kubernetes_access_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, TIMESTAMPTZ
) TO mesh_runtime;

-- Maps, for this Core and older ones: no rule of a set of another cluster,
-- one table entry per content.
CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_kubernetes_rule_access_v1(p_policy_revision BIGINT)
RETURNS TABLE (
    access_rule_public_id UUID, kubernetes_groups TEXT[], profile_public_id UUID, profile_hash BYTEA,
    namespaces TEXT[], cluster_part BOOLEAN, mode TEXT, report_until TIMESTAMPTZ
)
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map Kubernetes access request is invalid';
    END IF;
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT rule.access_rule_public_id, rule.kubernetes_groups, rule.kubernetes_profile_public_id,
           rule.kubernetes_profile_hash, rule.kubernetes_namespaces, rule.kubernetes_cluster_part,
           rule.kubernetes_mode, rule.kubernetes_report_until
    FROM mesh.policy_release AS release
    JOIN mesh.compiled_policy_group_rule AS rule ON rule.policy_release_id = release.id
    WHERE release.workspace_id = v_workspace_id AND release.network_id = v_network_id
      AND release.policy_revision = p_policy_revision AND release.state = 'active'
      AND rule.kubernetes_groups IS NOT NULL
      -- K2h: a rule applying a set of another cluster grants nothing; its
      -- whole row goes, since a row without a profile grants whole groups
      -- (review h-design v1 H3).
      AND NOT EXISTS (
          SELECT 1 FROM mesh.policy_release_kubernetes_profile AS held
          JOIN mesh.device_group AS cluster_group ON cluster_group.id = rule.destination_device_group_id
          WHERE held.policy_release_id = release.id
            AND held.profile_public_id = rule.kubernetes_profile_public_id
            AND held.kubernetes_cluster_id IS NOT NULL
            AND held.kubernetes_cluster_id IS DISTINCT FROM cluster_group.kubernetes_cluster_id
      )
    ORDER BY rule.access_rule_public_id;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_kubernetes_profiles_v1(p_policy_revision BIGINT)
RETURNS TABLE (profile_public_id UUID, content_hash BYTEA, name TEXT, rules JSONB)
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map Kubernetes profiles request is invalid';
    END IF;
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    -- Only profiles a rule pins: what a gateway's table can hold.
    RETURN QUERY
    -- One row per content: copies of a set in several clusters share it, and
    -- a gateway's table holds each content once (review h-design v1 C1). The
    -- smallest ID, so that rereads never see the table change (M-A).
    SELECT DISTINCT ON (held.content_hash)
           held.profile_public_id, held.content_hash, content.name, content.rules
    FROM mesh.policy_release AS release
    JOIN mesh.policy_release_kubernetes_profile AS held ON held.policy_release_id = release.id
    JOIN mesh.kubernetes_access_profile_content AS content
      ON content.workspace_id = held.workspace_id AND content.network_id = held.network_id
     AND content.content_hash = held.content_hash
    WHERE release.workspace_id = v_workspace_id AND release.network_id = v_network_id
      AND release.policy_revision = p_policy_revision AND release.state = 'active'
      AND EXISTS (
          SELECT 1 FROM mesh.compiled_policy_group_rule AS rule
          WHERE rule.policy_release_id = release.id AND rule.kubernetes_profile_public_id = held.profile_public_id
      )
    ORDER BY held.content_hash, held.profile_public_id;
END;
$function$;
