-- Schema 237 (K1a3b, docs/k8s-k1a3-gateway-identity-design.md §4, §12.2,
-- §13.5–§13.7, §16): what a cluster gateway's map needs to know of the
-- Devices that reach it. Nothing here changes a map yet.
--
-- mesh.device_owner_change keeps when each Device last changed owner. Only
-- the trigger on mesh.device writes it, so a direct write to a Device row
-- cannot clear it, and the backfill below writes no Device row. A Device
-- with no row never changed owner.
--
-- Two map reads, called only for a Network that has a Kubernetes cluster:
-- the Kubernetes groups of the active release's rules, and for each Device
-- of the Network its owner, whether a member owns it (tagged or not) and that
-- member is still active and until when, when it last changed owner, and
-- whether it forwards traffic for others (a Site router or an exit node, in
-- any state).

CREATE TABLE mesh.device_owner_change (
    device_id BIGINT PRIMARY KEY REFERENCES mesh.device (id) ON DELETE CASCADE,
    changed_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE mesh.device_owner_change ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_owner_change FORCE ROW LEVEL SECURITY;
CREATE POLICY device_owner_change_migrator_policy ON mesh.device_owner_change
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.device_owner_change
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.record_device_owner_change_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    INSERT INTO mesh.device_owner_change (device_id, changed_at)
    VALUES (NEW.id, pg_catalog.transaction_timestamp())
    ON CONFLICT (device_id) DO UPDATE SET changed_at = EXCLUDED.changed_at;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.record_device_owner_change_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER device_owner_change
AFTER UPDATE OF owner_principal_id, ownership ON mesh.device
FOR EACH ROW
WHEN (OLD.owner_principal_id IS DISTINCT FROM NEW.owner_principal_id OR OLD.ownership IS DISTINCT FROM NEW.ownership)
EXECUTE FUNCTION mesh_ops.record_device_owner_change_v1();

-- Backfill, conservatively: a Device not provably still owned by whoever
-- registered it changed hands now, as far as anyone can tell. The audit
-- trail would date some changes earlier, but an owner removal names its
-- Devices only in the event's payload, and scanning it per Device would hold
-- mesh.device locked; now() only ever delays what a recent change gates
-- (K1a3 §13.7, b1 review M1/M2). A member's Device its registrant still owns
-- has no row: it never changed owner.
INSERT INTO mesh.device_owner_change (device_id, changed_at)
SELECT device.id, pg_catalog.transaction_timestamp()
FROM mesh.device AS device
WHERE device.deleted_at IS NULL AND device.kind = 'standard'
  AND NOT (device.ownership = 'member' AND device.registered_by_principal_id IS NOT NULL
      AND device.owner_principal_id = device.registered_by_principal_id);

-- The Kubernetes groups of the active release's rules at a policy revision
-- of the scoped Network (schema 236): one row per rule that names groups.
CREATE FUNCTION mesh_ops.load_map_network_kubernetes_rule_groups_v1(p_policy_revision BIGINT)
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
      AND rule.kubernetes_groups IS NOT NULL
    ORDER BY rule.access_rule_public_id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_rule_groups_v1(BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_rule_groups_v1(BIGINT) TO mesh_runtime;

-- For each Device of the scoped Network that a rule may name as a source:
-- its owner (its tags, the member, or the Workspace), whether a member owns
-- it, tagged or not, and if so whether that member holds active Workspace
-- and Network memberships and the earlier of their ends, when it last
-- changed owner, and whether it routes for others.
CREATE FUNCTION mesh_ops.load_map_network_kubernetes_sources_v1(p_limit INTEGER)
RETURNS TABLE (
    device_id BIGINT, owner_kind TEXT, owner_ref TEXT, member_owned BOOLEAN, owner_active BOOLEAN,
    owner_valid_until TIMESTAMPTZ, owner_changed_at TIMESTAMPTZ, forwards BOOLEAN
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
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map Kubernetes sources request is invalid';
    END IF;
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT device.id,
           CASE WHEN tags.ids IS NOT NULL THEN 'tags'
                WHEN device.ownership = 'workspace' THEN 'workspace'
                ELSE 'member' END,
           CASE WHEN tags.ids IS NOT NULL THEN 'tags:' || pg_catalog.array_to_string(tags.ids, ',')
                WHEN device.ownership = 'workspace' THEN ''
                ELSE principal.public_id::TEXT END,
           device.ownership = 'member',
           device.ownership = 'member' AND principal.state = 'active'
               AND principal.deleted_at IS NULL AND membership.id IS NOT NULL AND network_member.id IS NOT NULL,
           CASE WHEN device.ownership = 'member'
                THEN LEAST(membership.expires_at, network_member.expires_at) END,
           owner_change.changed_at,
           EXISTS (SELECT 1 FROM mesh.network_site_router AS router WHERE router.device_id = device.id)
               OR EXISTS (SELECT 1 FROM mesh.network_exit_node AS exit_node WHERE exit_node.device_id = device.id)
    FROM mesh.device AS device
    JOIN mesh.principal AS principal ON principal.id = device.owner_principal_id
    LEFT JOIN LATERAL (
        SELECT pg_catalog.array_agg(tag.public_id::TEXT ORDER BY tag.public_id::TEXT COLLATE "C") AS ids
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id AND tag.state = 'active'
        WHERE assignment.device_id = device.id
    ) AS tags ON TRUE
    LEFT JOIN mesh.workspace_membership AS membership
      ON membership.workspace_id = v_workspace_id AND membership.principal_id = device.owner_principal_id
     AND membership.state = 'active'
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    LEFT JOIN mesh.network_membership AS network_member
      ON network_member.workspace_id = v_workspace_id AND network_member.network_id = v_network_id
     AND network_member.principal_id = device.owner_principal_id AND network_member.state = 'active'
     AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
    LEFT JOIN mesh.device_owner_change AS owner_change ON owner_change.device_id = device.id
    WHERE device.workspace_id = v_workspace_id AND device.network_id = v_network_id
      AND device.kind = 'standard' AND device.deleted_at IS NULL
    ORDER BY device.id
    LIMIT p_limit;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_sources_v1(INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_sources_v1(INTEGER) TO mesh_runtime;
