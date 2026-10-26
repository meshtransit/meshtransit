-- Schema 230 (K1a2a): access to a Kubernetes cluster is granted to the
-- cluster as a whole (K1a2 design §11).
--
-- Each cluster gets one Device Group of kind kubernetes_cluster whose
-- members are exactly its active gateway Devices. A rule to the cluster is
-- an ordinary group rule to that group, so maps, Explain, the Access Graph,
-- the ledger and the fan-out on membership changes stay as they are; a
-- replica that joins later is reached by every rule to its cluster.
--
-- * The group is made on first use by ensure_kubernetes_cluster_policy_group_v1,
--   which Core calls with its evidence (audit, outbox, member hashes): an
--   authority row changes only with signed evidence, so this migration
--   backfills nothing.
-- * Members change only here: a gateway joins its cluster's group when its
--   Device is created (also from an older Core) and leaves it when it stops
--   being active; a trigger keeps the group to its cluster's active
--   gateways and every gateway out of any other group.
-- * A rule reaches a cluster's group on TCP 443 only and never selects it
--   as a source. No compiled rule names a gateway Device itself, except a
--   rule the replaced release held unchanged, so a Network that already had
--   rules to replicas keeps publishing until they are removed (MTP06, with
--   the rule's ID as DETAIL).
-- * DNS zones, unmanaged DNS groups and DNS resolvers never name the group
--   or a gateway (MTL01).
-- * The ordinary group functions neither list, read nor change the group
--   (it answers as unknown), its name is internal and it does not count
--   toward the 200 groups of a Network.
-- * A user group never makes a gateway a rule source, although the gateway
--   has an owner.
-- * Approving a replica is refused when a rule to the cluster would give a
--   Device more than 10,000 rule edges (MTD06); completing it re-checks and
--   answers MTK11, which a replica retries.
-- * A cluster whose group a rule still names is not deleted (MTK05); its
--   group is deleted with it.
--
-- Rollback: an older Core reads none of the new columns or functions; the
-- functions it calls keep their signatures and outputs and only refuse more.

-- Group kind. Every existing group is a user group.
ALTER TABLE mesh.device_group
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN kubernetes_cluster_id BIGINT;
ALTER TABLE mesh.device_group
    ADD CONSTRAINT device_group_kind_check CHECK (
        kind IN ('user', 'kubernetes_cluster')
        AND (kind = 'kubernetes_cluster') = (kubernetes_cluster_id IS NOT NULL)
    ) NOT VALID,
    ADD CONSTRAINT device_group_kubernetes_cluster_fk FOREIGN KEY (
        workspace_id, network_id, kubernetes_cluster_id
    ) REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT device_group_kubernetes_cluster_key UNIQUE (kubernetes_cluster_id);
ALTER TABLE mesh.device_group VALIDATE CONSTRAINT device_group_kind_check;
ALTER TABLE mesh.device_group VALIDATE CONSTRAINT device_group_kubernetes_cluster_fk;

-- Names are unique among user groups only; a cluster's group is named after
-- the cluster's ID.
DROP INDEX mesh.device_group_active_name_uidx;
CREATE UNIQUE INDEX device_group_active_name_uidx
    ON mesh.device_group (workspace_id, network_id, name_key)
    WHERE state = 'active' AND kind = 'user';

-- A group never changes kind or cluster; a cluster's group keeps its name.
CREATE FUNCTION mesh_ops.enforce_kubernetes_cluster_group_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.kubernetes_cluster_id IS DISTINCT FROM OLD.kubernetes_cluster_id
        OR (OLD.kind = 'kubernetes_cluster'
            AND (NEW.name <> OLD.name OR NEW.name_key <> OLD.name_key OR NEW.description <> OLD.description)) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes cluster group transition';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_kubernetes_cluster_group_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER device_group_kubernetes_cluster
BEFORE UPDATE ON mesh.device_group
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_kubernetes_cluster_group_v1();

-- The cluster's active group, or NULL.
CREATE FUNCTION mesh_ops.kubernetes_cluster_group_internal_v1(p_cluster_id BIGINT)
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT device_group.id FROM mesh.device_group AS device_group
    WHERE device_group.kubernetes_cluster_id = p_cluster_id AND device_group.state = 'active'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_group_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Members: a cluster's group holds only that cluster's active gateways, and
-- a gateway is in no other group. Replaces the schema 224 reference guard on
-- this table.
DROP TRIGGER device_group_member_kubernetes_gateway ON mesh.device_group_member;
CREATE FUNCTION mesh_ops.enforce_kubernetes_group_member_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_group mesh.device_group%ROWTYPE;
    v_device mesh.device%ROWTYPE;
BEGIN
    SELECT * INTO v_group FROM mesh.device_group AS device_group WHERE device_group.id = NEW.device_group_id;
    SELECT * INTO v_device FROM mesh.device AS device WHERE device.id = NEW.device_id;
    IF v_group.kind = 'kubernetes_cluster' THEN
        IF v_device.kind IS DISTINCT FROM 'kubernetes_gateway'
            OR v_device.kubernetes_cluster_id IS DISTINCT FROM v_group.kubernetes_cluster_id
            OR v_device.state IS DISTINCT FROM 'active' OR v_device.deleted_at IS NOT NULL
            OR v_group.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01',
                MESSAGE = 'a Kubernetes cluster''s group holds only the cluster''s active gateways';
        END IF;
    ELSIF v_device.kind IS DISTINCT FROM 'standard' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'a Kubernetes gateway Device cannot be used here';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_kubernetes_group_member_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER device_group_member_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_group_member
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_kubernetes_group_member_v1();

-- The most rule edges each Device would load from the Network's active
-- release, as max_device_policy_edges_internal_v1 counts them.
CREATE FUNCTION mesh_ops.device_policy_edge_totals_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS TABLE (device_id BIGINT, edges BIGINT)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    WITH release AS (
        SELECT release.id
        FROM mesh.policy_release AS release
        WHERE release.workspace_id = p_workspace_id AND release.network_id = p_network_id
          AND release.state = 'active'
    ),
    member AS (
        SELECT * FROM mesh_ops.selector_devices_internal_v1(p_workspace_id, p_network_id)
    ),
    selector_size AS (
        SELECT member.selector_kind, member.selector_id, pg_catalog.count(*) AS size
        FROM member GROUP BY member.selector_kind, member.selector_id
    ),
    rule AS (
        SELECT group_rule.source_device_id, group_rule.destination_device_id,
               CASE WHEN group_rule.source_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                    WHEN group_rule.source_device_tag_id IS NOT NULL THEN 'device_tag' END AS source_kind,
               COALESCE(group_rule.source_device_group_id, group_rule.source_identity_group_id,
                        group_rule.source_device_tag_id) AS source_selector,
               CASE WHEN group_rule.destination_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.destination_device_tag_id IS NOT NULL THEN 'device_tag' END AS destination_kind,
               COALESCE(group_rule.destination_device_group_id, group_rule.destination_device_tag_id)
                   AS destination_selector
        FROM release
        JOIN mesh.compiled_policy_group_rule AS group_rule ON group_rule.policy_release_id = release.id
    ),
    sized AS (
        SELECT rule.*,
               CASE WHEN rule.source_device_id IS NOT NULL THEN 1
                    ELSE COALESCE((SELECT size FROM selector_size WHERE selector_size.selector_kind = rule.source_kind
                                     AND selector_size.selector_id = rule.source_selector), 0) END AS source_size,
               CASE WHEN rule.destination_device_id IS NOT NULL THEN 1
                    ELSE COALESCE((SELECT size FROM selector_size
                                   WHERE selector_size.selector_kind = rule.destination_kind
                                     AND selector_size.selector_id = rule.destination_selector), 0) END
                   AS destination_size
        FROM rule
    ),
    per_device AS (
        SELECT COALESCE(sized.destination_device_id, member.device_id) AS device_id, sized.source_size AS edges
        FROM sized
        LEFT JOIN member ON member.selector_kind = sized.destination_kind
                        AND member.selector_id = sized.destination_selector
        UNION ALL
        SELECT COALESCE(sized.source_device_id, member.device_id), sized.destination_size
        FROM sized
        LEFT JOIN member ON member.selector_kind = sized.source_kind AND member.selector_id = sized.source_selector
        UNION ALL
        SELECT device_rule.source_device_id, 1
        FROM release JOIN mesh.compiled_policy_rule AS device_rule ON device_rule.policy_release_id = release.id
        UNION ALL
        SELECT device_rule.destination_device_id, 1
        FROM release JOIN mesh.compiled_policy_rule AS device_rule ON device_rule.policy_release_id = release.id
    )
    SELECT per_device.device_id, pg_catalog.sum(per_device.edges)::BIGINT
    FROM per_device WHERE per_device.device_id IS NOT NULL
    GROUP BY per_device.device_id$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_policy_edge_totals_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Refuses one more replica of a cluster when a rule to the cluster would
-- then give a Device more than p_limit rule edges: each source Device of
-- such a rule gains one edge per rule, and the new replica gets the sources
-- of all of them (MTD06). Nothing to check without the group or a rule.
CREATE FUNCTION mesh_ops.check_kubernetes_cluster_edge_budget_internal_v1(p_cluster_id BIGINT, p_limit BIGINT)
RETURNS VOID
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_group BIGINT;
    v_source UUID;
    v_replica_edges BIGINT;
BEGIN
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster WHERE cluster.id = p_cluster_id;
    v_group := mesh_ops.kubernetes_cluster_group_internal_v1(p_cluster_id);
    IF v_group IS NULL OR mesh_ops.device_group_rule_count_internal_v1(v_group) = 0 THEN
        RETURN;
    END IF;
    WITH rule AS (
        SELECT group_rule.source_device_id,
               CASE WHEN group_rule.source_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                    WHEN group_rule.source_device_tag_id IS NOT NULL THEN 'device_tag' END AS source_kind,
               COALESCE(group_rule.source_device_group_id, group_rule.source_identity_group_id,
                        group_rule.source_device_tag_id) AS source_selector
        FROM mesh.compiled_policy_group_rule AS group_rule
        JOIN mesh.policy_release AS release ON release.id = group_rule.policy_release_id
        WHERE release.state = 'active' AND release.workspace_id = v_cluster.workspace_id
          AND release.network_id = v_cluster.network_id
          AND group_rule.destination_device_group_id = v_group
    ),
    gained AS (
        SELECT COALESCE(rule.source_device_id, member.device_id) AS device_id, pg_catalog.count(*) AS edges
        FROM rule
        LEFT JOIN mesh_ops.selector_devices_internal_v1(v_cluster.workspace_id, v_cluster.network_id) AS member
          ON member.selector_kind = rule.source_kind AND member.selector_id = rule.source_selector
        GROUP BY 1
    )
    SELECT (SELECT device.public_id FROM gained
            JOIN mesh.device AS device ON device.id = gained.device_id
            LEFT JOIN mesh_ops.device_policy_edge_totals_internal_v1(
                v_cluster.workspace_id, v_cluster.network_id) AS total ON total.device_id = gained.device_id
            WHERE COALESCE(total.edges, 0) + gained.edges > p_limit
            ORDER BY device.public_id LIMIT 1),
           (SELECT COALESCE(pg_catalog.sum(gained.edges), 0) FROM gained WHERE gained.device_id IS NOT NULL)
    INTO v_source, v_replica_edges;
    IF v_source IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD06',
            MESSAGE = 'the source Device ' || v_source::TEXT || ' would load more than '
                || p_limit::TEXT || ' rule edges', DETAIL = v_source::TEXT;
    END IF;
    IF v_replica_edges > p_limit THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD06',
            MESSAGE = 'the new replica would load more than ' || p_limit::TEXT || ' rule edges';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.check_kubernetes_cluster_edge_budget_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Approval is checked before the join key's use is counted: the function
-- updates the key first, but a refusal here rolls the whole approval back.
CREATE FUNCTION mesh_ops.check_kubernetes_replica_approval_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM mesh_ops.check_kubernetes_cluster_edge_budget_internal_v1(NEW.kubernetes_cluster_id, 10000);
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.check_kubernetes_replica_approval_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER kubernetes_replica_request_edge_budget
BEFORE UPDATE ON mesh.kubernetes_replica_request
FOR EACH ROW WHEN (OLD.state = 'pending' AND NEW.state = 'approved')
EXECUTE FUNCTION mesh_ops.check_kubernetes_replica_approval_v1();

-- A gateway Device joins its cluster's group when it is created, in the
-- completion's transaction and under its locks (cluster, key, request,
-- Network revision, then group), so the completion's single Network
-- revision covers it and the group revision advances with it. Without the
-- group there is nothing to join: the group takes every active replica
-- when it is made. A replica that would push a Device past its rule edges
-- is not completed (MTK11); the replica asks again.
CREATE FUNCTION mesh_ops.join_kubernetes_cluster_group_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_group mesh.device_group%ROWTYPE;
BEGIN
    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.kubernetes_cluster_id = NEW.kubernetes_cluster_id AND device_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RETURN NULL;
    END IF;
    INSERT INTO mesh.device_group_member (public_id, workspace_id, network_id, device_group_id, device_id, created_at)
    VALUES (pg_catalog.uuidv7(), NEW.workspace_id, NEW.network_id, v_group.id, NEW.id, NEW.created_at);
    UPDATE mesh.device_group AS device_group
    SET member_count = device_group.member_count + 1, version = device_group.version + 1,
        updated_at = GREATEST(pg_catalog.transaction_timestamp(), device_group.updated_at)
    WHERE device_group.id = v_group.id;
    UPDATE mesh_ops.network_revision AS revision
    SET group_revision = revision.group_revision + 1, updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = NEW.workspace_id AND revision.network_id = NEW.network_id;
    IF NOT FOUND THEN
        -- The revision row is visible only in the bound Network scope.
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'a gateway joins its cluster''s group only in its Network scope';
    END IF;
    IF mesh_ops.device_group_rule_count_internal_v1(v_group.id) > 0
        AND mesh_ops.max_device_policy_edges_internal_v1(NEW.workspace_id, NEW.network_id) > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK11',
            MESSAGE = 'a Device would load more than 10000 rule edges with this replica';
    END IF;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.join_kubernetes_cluster_group_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER device_kubernetes_group_join
AFTER INSERT ON mesh.device
FOR EACH ROW WHEN (NEW.kind = 'kubernetes_gateway' AND NEW.state = 'active')
EXECUTE FUNCTION mesh_ops.join_kubernetes_cluster_group_v1();

-- A gateway that stops being active (revoked or deleted, also by an older
-- Core) leaves its cluster's group. Lifecycle changes lock the Network
-- revision before the Device, so the group revision advances under that
-- lock; the change's own evidence covers the membership row.
CREATE FUNCTION mesh_ops.release_kubernetes_cluster_group_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_group BIGINT;
    v_left BOOLEAN := FALSE;
BEGIN
    FOR v_group IN
        DELETE FROM mesh.device_group_member AS member
        WHERE member.device_id = NEW.id
        RETURNING member.device_group_id
    LOOP
        UPDATE mesh.device_group AS device_group
        SET member_count = (SELECT pg_catalog.count(*) FROM mesh.device_group_member AS member
                            WHERE member.device_group_id = device_group.id),
            version = device_group.version + 1,
            updated_at = GREATEST(pg_catalog.transaction_timestamp(), device_group.updated_at)
        WHERE device_group.id = v_group;
        v_left := TRUE;
    END LOOP;
    IF v_left THEN
        UPDATE mesh_ops.network_revision AS revision
        SET group_revision = revision.group_revision + 1, updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = NEW.workspace_id AND revision.network_id = NEW.network_id;
        IF NOT FOUND THEN
            -- Without the Network scope the revision row is not visible, and
            -- sources' maps would keep the gateway: refuse instead.
            RAISE EXCEPTION USING ERRCODE = '42501',
                MESSAGE = 'a gateway leaves its cluster''s group only in its Network scope';
        END IF;
    END IF;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.release_kubernetes_cluster_group_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER device_kubernetes_group_release
AFTER UPDATE OF state ON mesh.device
FOR EACH ROW WHEN (OLD.kind = 'kubernetes_gateway' AND OLD.state = 'active' AND NEW.state <> 'active')
EXECUTE FUNCTION mesh_ops.release_kubernetes_cluster_group_v1();

-- A cluster goes only when no rule names its group; the group goes with it.
CREATE FUNCTION mesh_ops.delete_kubernetes_cluster_group_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_group BIGINT := mesh_ops.kubernetes_cluster_group_internal_v1(NEW.id);
BEGIN
    IF v_group IS NULL THEN
        RETURN NULL;
    END IF;
    -- Serializes with publication, which locks the Network revision too, so
    -- no rule to the group commits after this check.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = NEW.workspace_id AND revision.network_id = NEW.network_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'a cluster is deleted only in its Network scope';
    END IF;
    IF mesh_ops.device_group_rule_count_internal_v1(v_group) > 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK05', MESSAGE = 'rules still grant access to the Kubernetes cluster';
    END IF;
    DELETE FROM mesh.device_group_member AS member WHERE member.device_group_id = v_group;
    UPDATE mesh.device_group AS device_group
    SET state = 'deleted', member_count = 0,
        deleted_at = GREATEST(pg_catalog.transaction_timestamp(), device_group.updated_at),
        version = device_group.version + 1,
        updated_at = GREATEST(pg_catalog.transaction_timestamp(), device_group.updated_at)
    WHERE device_group.id = v_group;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.delete_kubernetes_cluster_group_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER kubernetes_cluster_group_deletion
AFTER UPDATE OF state ON mesh.kubernetes_cluster
FOR EACH ROW WHEN (OLD.state = 'active' AND NEW.state = 'deleted')
EXECUTE FUNCTION mesh_ops.delete_kubernetes_cluster_group_v1();

-- Compiled rules: no column names a gateway Device, a cluster's group is a
-- destination only, and only for TCP 443. A row the replaced release held
-- unchanged (same rule, sides, protocol and ports) is carried as it was, so
-- rules written before this schema keep working until they are removed.
CREATE FUNCTION mesh_ops.refuse_kubernetes_policy_rule_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_row JSONB := pg_catalog.to_jsonb(NEW);
    v_column TEXT;
    v_refused BOOLEAN := FALSE;
    v_previous BIGINT;
    v_carried BOOLEAN;
BEGIN
    FOREACH v_column IN ARRAY ARRAY['source_device_id', 'destination_device_id'] LOOP
        IF v_row ? v_column AND pg_catalog.jsonb_typeof(v_row -> v_column) = 'number' AND EXISTS (
            SELECT 1 FROM mesh.device AS device
            WHERE device.id = (v_row ->> v_column)::BIGINT AND device.kind = 'kubernetes_gateway'
        ) THEN
            v_refused := TRUE;
        END IF;
    END LOOP;
    IF v_row ? 'source_device_group_id' AND EXISTS (
        SELECT 1 FROM mesh.device_group AS device_group
        WHERE device_group.id = (v_row ->> 'source_device_group_id')::BIGINT
          AND device_group.kind = 'kubernetes_cluster'
    ) THEN
        v_refused := TRUE;
    END IF;
    IF v_row ? 'destination_device_group_id' AND EXISTS (
        SELECT 1 FROM mesh.device_group AS device_group
        WHERE device_group.id = (v_row ->> 'destination_device_group_id')::BIGINT
          AND device_group.kind = 'kubernetes_cluster'
    ) AND NOT (NEW.protocol = 'tcp' AND NEW.destination_ports = '{[443,444)}'::INT4MULTIRANGE) THEN
        v_refused := TRUE;
    END IF;
    IF NOT v_refused THEN
        RETURN NEW;
    END IF;
    SELECT previous.id INTO v_previous FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = NEW.workspace_id AND previous.network_id = NEW.network_id
      AND previous.policy_revision = NEW.policy_revision - 1;
    EXECUTE pg_catalog.format(
        'SELECT EXISTS (SELECT 1 FROM %I.%I AS carried WHERE carried.policy_release_id = $1
           AND carried.access_rule_public_id = $2
           AND (pg_catalog.to_jsonb(carried) - $3) = ($4 - $3))',
        TG_TABLE_SCHEMA, TG_TABLE_NAME)
    INTO v_carried
    USING v_previous, NEW.access_rule_public_id,
        ARRAY['id', 'public_id', 'policy_release_id', 'policy_revision', 'version', 'created_at'], v_row;
    IF v_carried THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'MTP06',
        MESSAGE = 'a rule names a Kubernetes gateway Device or a cluster''s group in a way rules may not',
        DETAIL = NEW.access_rule_public_id::TEXT;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.refuse_kubernetes_policy_rule_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER compiled_policy_rule_kubernetes
BEFORE INSERT OR UPDATE ON mesh.compiled_policy_rule
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_policy_rule_v1();
CREATE TRIGGER compiled_policy_group_rule_kubernetes
BEFORE INSERT OR UPDATE ON mesh.compiled_policy_group_rule
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_policy_rule_v1();
CREATE TRIGGER compiled_policy_route_rule_kubernetes
BEFORE INSERT OR UPDATE ON mesh.compiled_policy_route_rule
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_policy_rule_v1();
CREATE TRIGGER compiled_policy_exit_rule_kubernetes
BEFORE INSERT OR UPDATE ON mesh.compiled_policy_exit_rule
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_policy_rule_v1();
CREATE TRIGGER compiled_policy_imported_resource_destination_kubernetes
BEFORE INSERT OR UPDATE ON mesh.compiled_policy_imported_resource_destination
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_policy_rule_v1();

-- DNS: a zone's resolvers (by public ID) are never gateways, and a zone's
-- groups and the Devices that keep their own DNS never name a cluster's group.
CREATE FUNCTION mesh_ops.refuse_kubernetes_dns_reference_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_row JSONB := pg_catalog.to_jsonb(NEW);
    v_groups JSONB := COALESCE(v_row -> 'distribution_group_ids', v_row -> 'unmanaged_group_ids');
BEGIN
    IF pg_catalog.jsonb_typeof(v_row -> 'resolvers') = 'array' AND EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(v_row -> 'resolvers') AS resolver(item)
        JOIN mesh.device AS device ON device.public_id::TEXT = resolver.item ->> 'device_id'
        WHERE device.kind = 'kubernetes_gateway'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'a Kubernetes gateway Device cannot be used here';
    END IF;
    IF pg_catalog.jsonb_typeof(v_groups) = 'array' AND EXISTS (
        SELECT 1 FROM mesh.device_group AS device_group
        WHERE device_group.kind = 'kubernetes_cluster'
          AND device_group.id IN (SELECT element::BIGINT FROM pg_catalog.jsonb_array_elements_text(v_groups) AS element)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'a Kubernetes cluster''s group cannot be used here';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.refuse_kubernetes_dns_reference_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER network_dns_zone_kubernetes
BEFORE INSERT OR UPDATE ON mesh.network_dns_zone
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_dns_reference_v1();
CREATE TRIGGER network_dns_setting_kubernetes
BEFORE INSERT OR UPDATE ON mesh.network_dns_setting
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_dns_reference_v1();

-- Makes a cluster's group on first use, with every active replica as a
-- member, for a caller who may manage the cluster or publish or check
-- policy. Locks the cluster first (as completion and deletion do), then the
-- Network revision, then writes the group: a replica completed at the same
-- time either sees the group and joins it, or is already active and is
-- taken here. A group that exists is returned as it is (created false) and
-- nothing is written; Core then commits nothing. Core records the creation
-- with the member hashes before and after. P0002: unknown cluster.
CREATE FUNCTION mesh_ops.ensure_kubernetes_cluster_policy_group_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_group_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_granted BOOLEAN := FALSE;
    v_permission TEXT;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_group mesh.device_group%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_hash_before BYTEA;
    v_added INTEGER;
    v_network_revision BIGINT;
    v_group_revision BIGINT;
BEGIN
    IF p_cluster_public_id IS NULL OR p_group_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    FOREACH v_permission IN ARRAY ARRAY['policy.publish', 'policy.validate', 'kubernetes_cluster.manage'] LOOP
        BEGIN
            SELECT * INTO STRICT v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
                p_session_public_id, p_deployment_public_id, p_principal_public_id,
                p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
                p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
                p_workspace_public_id, p_network_public_id, v_permission);
            v_granted := TRUE;
            EXIT;
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;
        END;
    END LOOP;
    IF NOT v_granted THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: permission';
    END IF;
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR UPDATE;
    IF v_cluster.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.kubernetes_cluster_id = v_cluster.id AND device_group.state = 'active';
    IF v_group.id IS NOT NULL THEN
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id, 'cluster_id', v_cluster.public_id,
            'group_id', v_group.public_id, 'created', FALSE);
    END IF;
    SELECT revision.network_revision, revision.group_revision INTO v_network_revision, v_group_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_grant.workspace_id AND revision.network_id = v_grant.network_id
    FOR UPDATE;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.device_group (
        public_id, deployment_id, workspace_id, network_id, name, name_key, description,
        kind, kubernetes_cluster_id, created_at, updated_at
    ) VALUES (
        p_group_public_id, v_grant.deployment_id, v_grant.workspace_id, v_grant.network_id,
        'kubernetes-cluster:' || v_cluster.public_id::TEXT, 'kubernetes-cluster:' || v_cluster.public_id::TEXT,
        '', 'kubernetes_cluster', v_cluster.id, v_now, v_now
    ) RETURNING * INTO v_group;
    v_hash_before := mesh_ops.device_group_member_hash_internal_v1(v_group.id);
    INSERT INTO mesh.device_group_member (public_id, workspace_id, network_id, device_group_id, device_id, created_at)
    SELECT pg_catalog.uuidv7(), device.workspace_id, device.network_id, v_group.id, device.id, v_now
    FROM mesh.device AS device
    WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
      AND device.kubernetes_cluster_id = v_cluster.id AND device.state = 'active' AND device.deleted_at IS NULL
    ORDER BY device.id;
    GET DIAGNOSTICS v_added = ROW_COUNT;
    IF v_added > 0 THEN
        UPDATE mesh.device_group AS device_group
        SET member_count = v_added, version = device_group.version + 1
        WHERE device_group.id = v_group.id
        RETURNING * INTO v_group;
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1, group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = v_grant.workspace_id AND revision.network_id = v_grant.network_id
        RETURNING revision.network_revision, revision.group_revision INTO v_network_revision, v_group_revision;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id, 'cluster_id', v_cluster.public_id, 'cluster_name', v_cluster.name,
        'group_id', v_group.public_id, 'created', TRUE, 'group_version', v_group.version,
        'members_added', v_added,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.device_group_member_hash_internal_v1(v_group.id), 'hex'),
        'network_revision', v_network_revision, 'group_revision', v_group_revision,
        'permission', v_permission, 'authority', v_grant.authority);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.ensure_kubernetes_cluster_policy_group_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.ensure_kubernetes_cluster_policy_group_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;

-- The groups of the Network's active clusters, so Core names a rule to such
-- a group as a rule to its cluster. For a caller who may read the Network or
-- read, explain, check or publish its policy.
CREATE FUNCTION mesh_ops.read_kubernetes_cluster_policy_groups_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_granted BOOLEAN := FALSE;
    v_permission TEXT;
BEGIN
    FOREACH v_permission IN ARRAY ARRAY['network.read', 'policy.read', 'policy.explain', 'policy.validate',
                                        'policy.publish'] LOOP
        BEGIN
            SELECT * INTO STRICT v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
                p_session_public_id, p_deployment_public_id, p_principal_public_id,
                p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
                p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
                p_workspace_public_id, p_network_public_id, v_permission);
            v_granted := TRUE;
            EXIT;
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;
        END;
    END LOOP;
    IF NOT v_granted THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: permission';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'groups', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'group_id', device_group.public_id, 'cluster_id', cluster.public_id, 'name', cluster.name
            ) ORDER BY cluster.name, cluster.public_id)
            FROM mesh.device_group AS device_group
            JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = device_group.kubernetes_cluster_id
            WHERE device_group.workspace_id = v_grant.workspace_id AND device_group.network_id = v_grant.network_id
              AND device_group.kind = 'kubernetes_cluster' AND device_group.state = 'active'
              AND cluster.state = 'active'
        ), '[]'::JSONB)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_policy_groups_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_policy_groups_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_runtime;

-- What a completion records about the cluster's group the new gateway
-- joined in its transaction: the group, the member hashes without and with
-- it, and the group revision. No row when the cluster has no group yet.
-- Reads only the scope the transaction bound.
CREATE FUNCTION mesh_ops.kubernetes_cluster_policy_group_evidence_v1(p_device_id BIGINT)
RETURNS TABLE (group_public_id UUID, member_hash_before BYTEA, member_hash_after BYTEA, group_revision BIGINT)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT device_group.public_id,
           (SELECT pg_catalog.sha256(pg_catalog.convert_to(COALESCE(
                pg_catalog.string_agg(member_device.public_id::TEXT, E'\n' ORDER BY member_device.public_id::TEXT), ''
            ), 'UTF8'))
            FROM mesh.device_group_member AS member
            JOIN mesh.device AS member_device ON member_device.id = member.device_id
            WHERE member.device_group_id = device_group.id AND member.device_id <> device.id),
           mesh_ops.device_group_member_hash_internal_v1(device_group.id),
           revision.group_revision
    FROM mesh.device AS device
    JOIN mesh.device_group_member AS joined ON joined.device_id = device.id
    JOIN mesh.device_group AS device_group
      ON device_group.id = joined.device_group_id AND device_group.kind = 'kubernetes_cluster'
    JOIN mesh_ops.network_revision AS revision
      ON revision.workspace_id = device.workspace_id AND revision.network_id = device.network_id
    WHERE device.id = p_device_id AND device.kind = 'kubernetes_gateway'
      AND device.workspace_id = mesh_ops.current_workspace_id()
      AND device.network_id = mesh_ops.current_network_id()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_policy_group_evidence_v1(BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.kubernetes_cluster_policy_group_evidence_v1(BIGINT) TO mesh_runtime;

-- The Console's Devices name a gateway replica's cluster (a Device the
-- Network's rules, DNS and shares never name on its own).
CREATE FUNCTION mesh_ops.console_device_cluster_internal_v1(p_device_public_id UUID)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object('kubernetes_cluster', pg_catalog.jsonb_build_object(
        'cluster_id', cluster.public_id, 'name', cluster.name))
    FROM mesh.device AS device
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = device.kubernetes_cluster_id
    WHERE device.public_id = p_device_public_id AND device.kind = 'kubernetes_gateway'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.console_device_cluster_internal_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- read_console_devices_v5 with each replica's cluster.
CREATE FUNCTION mesh_ops.read_console_devices_v6(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ,
    p_name_prefix TEXT, p_state TEXT, p_after_hostname TEXT, p_after_device_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    v_result := mesh_ops.read_console_devices_v5(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at, p_name_prefix, p_state, p_after_hostname, p_after_device_public_id, p_limit);
    IF v_result IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN v_result || pg_catalog.jsonb_build_object('devices', COALESCE((
        SELECT pg_catalog.jsonb_agg(
            item.value || COALESCE(mesh_ops.console_device_cluster_internal_v1((item.value ->> 'id')::UUID), '{}'::JSONB)
            ORDER BY item.ordinal)
        FROM pg_catalog.jsonb_array_elements(v_result -> 'devices') WITH ORDINALITY AS item(value, ordinal)
    ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_devices_v6(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_devices_v6(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) TO mesh_runtime;

-- read_console_device_v3 with the replica's cluster.
CREATE FUNCTION mesh_ops.read_console_device_v4(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_device_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    v_result := mesh_ops.read_console_device_v3(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at, p_device_public_id);
    IF v_result IS NULL OR NOT v_result ? 'device' THEN
        RETURN v_result;
    END IF;
    RETURN v_result || pg_catalog.jsonb_build_object('device', (v_result -> 'device')
        || COALESCE(mesh_ops.console_device_cluster_internal_v1(p_device_public_id), '{}'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_device_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_device_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) TO mesh_runtime;

-- In place, same signatures and outputs:
-- * the cluster grant also answers for the policy permissions the ensure
--   and group read functions accept;
-- * a user group selects only ordinary Devices, never a gateway whose owner
--   is a member (edge budget, Access Graph inputs and maps);
-- * the ordinary group functions see user groups only: a cluster's group is
--   unknown to them (P0002) and outside the 200-group limit.
CREATE OR REPLACE FUNCTION mesh_ops.kubernetes_cluster_grant_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT, actor_id BIGINT, authority JSONB)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_grant RECORD;
    v_actor BIGINT;
BEGIN
    IF p_permission NOT IN ('network.read', 'kubernetes_cluster.manage', 'kubernetes_cluster.approve',
        'policy.read', 'policy.explain', 'policy.validate', 'policy.publish')
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: scope';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, pg_catalog.transaction_timestamp()
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: permission';
    END IF;
    SELECT principal.id INTO v_actor FROM mesh.principal AS principal
    JOIN mesh.deployment AS deployment ON deployment.id = principal.deployment_id
    WHERE principal.deployment_id = v_scope.deployment_id AND principal.public_id = p_principal_public_id
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND deployment.recovery_epoch = p_deployment_recovery_epoch;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: actor';
    END IF;
    RETURN QUERY SELECT v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, v_actor,
        mesh_ops.enrollment_key_authority_internal_v1(
            v_grant.role_binding_public_id, v_grant.role_definition_public_id,
            v_grant.binding_authority_generation, v_grant.membership_authority_generation,
            v_grant.workspace_owner_authority_generation);
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.selector_devices_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS TABLE (selector_kind TEXT, selector_id BIGINT, device_id BIGINT)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT 'device_group', member.device_group_id, member.device_id
    FROM mesh.device_group_member AS member
    JOIN mesh.device_group AS device_group ON device_group.id = member.device_group_id AND device_group.state = 'active'
    WHERE member.workspace_id = p_workspace_id AND member.network_id = p_network_id
    UNION ALL
    SELECT 'identity_group', member.identity_group_id, device.id
    FROM mesh.identity_group_member AS member
    JOIN mesh.identity_group AS identity_group
      ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = p_network_id
    JOIN mesh.principal AS principal
      ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
    JOIN mesh.workspace_membership AS membership
      ON membership.workspace_id = p_workspace_id AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    JOIN mesh.network_membership AS network_member
      ON network_member.workspace_id = p_workspace_id AND network_member.network_id = p_network_id
     AND network_member.principal_id = principal.id AND network_member.state = 'active'
     AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
    JOIN mesh.device AS device
      ON device.workspace_id = p_workspace_id AND device.network_id = p_network_id
     AND device.owner_principal_id = principal.id AND device.kind = 'standard'
    WHERE member.workspace_id = p_workspace_id
      AND NOT EXISTS (
          SELECT 1 FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_id = device.id
      )
    UNION ALL
    SELECT 'device_tag', assignment.device_tag_id, assignment.device_id
    FROM mesh.device_tag_assignment AS assignment
    JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id AND tag.state = 'active'
    WHERE assignment.workspace_id = p_workspace_id AND assignment.network_id = p_network_id
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_selector_members_v1(p_limit INTEGER)
RETURNS TABLE (selector_kind TEXT, selector_id BIGINT, device_id BIGINT, valid_until TIMESTAMPTZ)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network selector request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network selector scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT members.selector_kind, members.selector_id, members.device_id, members.valid_until
    FROM (
        SELECT 'device_group'::TEXT AS selector_kind, member.device_group_id AS selector_id,
               member.device_id, NULL::TIMESTAMPTZ AS valid_until
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace_id AND member.network_id = scoped_network_id
        UNION ALL
        SELECT 'identity_group'::TEXT, member.identity_group_id, device.id,
               LEAST(membership.expires_at, network_member.expires_at)
        FROM mesh.identity_group_member AS member
        JOIN mesh.identity_group AS identity_group
          ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = scoped_network_id
        JOIN mesh.principal AS principal
          ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = scoped_workspace_id AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
        JOIN mesh.network_membership AS network_member
          ON network_member.workspace_id = scoped_workspace_id AND network_member.network_id = scoped_network_id
         AND network_member.principal_id = principal.id AND network_member.state = 'active'
         AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
        JOIN mesh.device AS device
          ON device.workspace_id = scoped_workspace_id AND device.network_id = scoped_network_id
         AND device.owner_principal_id = principal.id AND device.kind = 'standard'
        WHERE member.workspace_id = scoped_workspace_id
          AND NOT EXISTS (
              SELECT 1 FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_id = device.id
          )
        UNION ALL
        SELECT 'device_tag'::TEXT, assignment.device_tag_id, assignment.device_id, NULL::TIMESTAMPTZ
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id AND tag.state = 'active'
        WHERE assignment.workspace_id = scoped_workspace_id AND assignment.network_id = scoped_network_id
    ) AS members
    ORDER BY members.selector_kind, members.selector_id, members.device_id
    LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.list_device_groups_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.read', p_evaluated_at
    );
    RETURN pg_catalog.jsonb_build_object(
        'groups', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.device_group_document_internal_v1(device_group)
                ORDER BY device_group.name_key, device_group.public_id)
            FROM mesh.device_group AS device_group
            WHERE device_group.workspace_id = v_scope.workspace_id
              AND device_group.network_id = v_scope.network_id
              AND device_group.state = 'active' AND device_group.kind = 'user'
        ), '[]'::JSONB),
        'can_manage', mesh_ops.holds_device_group_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device_group.manage', p_evaluated_at),
        'can_manage_members', mesh_ops.holds_device_group_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device_group.members.manage', p_evaluated_at)
    );
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.read_device_group_members_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_group_public_id UUID,
    p_after_device_public_id UUID, p_limit INTEGER, p_evaluated_at TIMESTAMPTZ
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
    v_group mesh.device_group%ROWTYPE;
    v_members JSONB;
    v_count INTEGER;
BEGIN
    IF p_group_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group member page input is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.read', p_evaluated_at
    );
    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active'
      AND device_group.kind = 'user';
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    WITH page AS (
        SELECT device.public_id, device.hostname, device.state, device.deleted_at, device.expires_at,
               member.created_at
        FROM mesh.device_group_member AS member
        JOIN mesh.device AS device ON device.id = member.device_id
        WHERE member.device_group_id = v_group.id
          AND (p_after_device_public_id IS NULL OR device.public_id::TEXT > p_after_device_public_id::TEXT)
        ORDER BY device.public_id::TEXT
        LIMIT p_limit + 1
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'device_id', page.public_id,
               'name', page.hostname,
               'active', page.state = 'active' AND page.deleted_at IS NULL
                         AND (page.expires_at IS NULL OR page.expires_at > p_evaluated_at),
               'added_at', page.created_at
           ) ORDER BY page.public_id::TEXT),
           pg_catalog.count(*)::INTEGER
    INTO v_members, v_count
    FROM page;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'members', CASE WHEN v_count > p_limit
            THEN (SELECT pg_catalog.jsonb_agg(item.value ORDER BY item.ordinal)
                  FROM pg_catalog.jsonb_array_elements(v_members) WITH ORDINALITY AS item(value, ordinal)
                  WHERE item.ordinal <= p_limit)
            ELSE COALESCE(v_members, '[]'::JSONB) END,
        'has_more', COALESCE(v_count, 0) > p_limit
    );
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_group_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_operation text, p_group_public_id uuid, p_expected_version bigint, p_name text, p_description text, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_group mesh.device_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_network_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_group_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_description IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.manage', pg_catalog.transaction_timestamp()
    );
    -- Serializes group changes with publication and membership changes.
    SELECT revision.network_revision INTO v_network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.device_group AS device_group
            WHERE device_group.workspace_id = v_scope.workspace_id
              AND device_group.network_id = v_scope.network_id
              AND device_group.state = 'active' AND device_group.kind = 'user') >= 200 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD02', MESSAGE = 'Network already has the maximum Device Groups';
        END IF;
        BEGIN
            INSERT INTO mesh.device_group (
                public_id, deployment_id, workspace_id, network_id, name, name_key, description,
                created_at, updated_at
            ) VALUES (
                p_group_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_description, v_now, v_now
            ) RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD04', MESSAGE = 'Device Group name is taken';
        END;
        RETURN pg_catalog.jsonb_build_object(
            'group', mesh_ops.device_group_document_internal_v1(v_group),
            'previous', NULL,
            'member_hash_before', NULL,
            'member_hash_after', pg_catalog.encode(mesh_ops.device_group_member_hash_internal_v1(v_group.id), 'hex'),
            'network_revision', v_network_revision,
            'role_binding_id', v_scope.role_binding_public_id);
    END IF;

    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active'
      AND device_group.kind = 'user'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device Group version changed';
    END IF;
    v_before := mesh_ops.device_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.device_group_member_hash_internal_v1(v_group.id);

    IF p_operation = 'update' THEN
        BEGIN
            UPDATE mesh.device_group
            SET name = p_name, name_key = pg_catalog.lower(p_name), description = p_description,
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_group.id
            RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD04', MESSAGE = 'Device Group name is taken';
        END;
    ELSE
        IF mesh_ops.device_group_rule_count_internal_v1(v_group.id) > 0 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD05', MESSAGE = 'Device Group is selected by active rules';
        END IF;
        DELETE FROM mesh.device_group_member WHERE device_group_id = v_group.id;
        UPDATE mesh.device_group
        SET state = 'deleted', member_count = 0, deleted_at = GREATEST(v_now, updated_at),
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'previous', v_before,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.device_group_member_hash_internal_v1(v_group.id), 'hex'),
        'network_revision', v_network_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_group_members_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_group_public_id uuid, p_expected_version bigint, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_scope RECORD;
    v_group mesh.device_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_hash_after BYTEA;
    v_requested INTEGER;
    v_eligible INTEGER;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_count INTEGER;
    v_network_revision BIGINT;
    v_group_revision BIGINT;
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
               OR NOT entry.value ? 'device_id' OR NOT entry.value ? 'member_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
            WHERE item.device_id IS NULL OR item.member_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.member_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.device_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
            WHERE item.device_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group membership change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.members.manage', pg_catalog.transaction_timestamp()
    );
    SELECT revision.network_revision, revision.group_revision
    INTO v_network_revision, v_group_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group scope is unavailable';
    END IF;
    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active'
      AND device_group.kind = 'user'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device Group version changed';
    END IF;
    v_before := mesh_ops.device_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.device_group_member_hash_internal_v1(v_group.id);

    v_requested := pg_catalog.jsonb_array_length(p_add);
    IF v_requested > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_eligible
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        JOIN mesh.device AS device
          ON device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
         AND device.public_id = item.device_id
         AND device.state = 'active' AND device.deleted_at IS NULL;
        IF v_eligible <> v_requested THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD01', MESSAGE = 'a Device is not an active Device of this Network';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.device_group_member AS member
        USING mesh.device AS device
        WHERE member.device_group_id = v_group.id AND device.id = member.device_id
          AND device.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF v_requested > 0 THEN
        INSERT INTO mesh.device_group_member (
            public_id, workspace_id, network_id, device_group_id, device_id, created_at
        )
        SELECT item.member_id, v_scope.workspace_id, v_scope.network_id, v_group.id, device.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        JOIN mesh.device AS device
          ON device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
         AND device.public_id = item.device_id
        ORDER BY device.id
        ON CONFLICT (device_group_id, device_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;

    IF v_added + v_removed > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_count
        FROM mesh.device_group_member AS member WHERE member.device_group_id = v_group.id;
        IF v_count > 5000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD03', MESSAGE = 'Device Group would exceed 5000 members';
        END IF;
        UPDATE mesh.device_group
        SET member_count = v_count, version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
        RETURNING revision.network_revision, revision.group_revision
        INTO v_network_revision, v_group_revision;
        IF v_added > 0 AND mesh_ops.device_group_rule_count_internal_v1(v_group.id) > 0
            AND mesh_ops.max_device_policy_edges_internal_v1(v_scope.workspace_id, v_scope.network_id) > 10000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD06',
                MESSAGE = 'a Device would load more than 10000 rule edges';
        END IF;
    END IF;
    v_hash_after := mesh_ops.device_group_member_hash_internal_v1(v_group.id);
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'previous', v_before,
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(v_hash_after, 'hex'),
        'network_revision', v_network_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_scope.role_binding_public_id
    );
END;
$function$
;
