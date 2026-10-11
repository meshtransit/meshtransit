-- Schema 141: a Network's packet policy at selector level, read once per
-- policy revision for every Device's map (scale-out design S2). It returns
-- the active release's rules without expanding group rules into Device
-- pairs (one group-to-group rule may pair every Device with every other),
-- the members of every selector, and the Devices the policy treats as live.
-- Expanding these for one Device reproduces exactly what the per-Device
-- read (compiled rules touching it plus resolve_group_policy_edges_v2)
-- returns, liveness included.

-- The active release's rules: Device-to-Device compiled rules and group
-- rules, each side named by its selector kind and internal reference.
CREATE FUNCTION mesh_ops.load_map_network_policy_rules_v1(
    p_policy_revision BIGINT,
    p_limit INTEGER
)
RETURNS TABLE (
    rule_kind TEXT,
    access_rule_public_id UUID,
    source_kind TEXT,
    source_ref BIGINT,
    destination_kind TEXT,
    destination_ref BIGINT,
    protocol TEXT,
    port_first INTEGER[],
    port_last INTEGER[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_policy_revision IS NULL OR p_policy_revision < 1 OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network policy request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network policy scope is unavailable';
    END IF;

    RETURN QUERY
    WITH release AS (
        SELECT policy_release.id, policy_release.policy_revision
        FROM mesh.policy_release AS policy_release
        WHERE policy_release.workspace_id = scoped_workspace_id
          AND policy_release.network_id = scoped_network_id
          AND policy_release.policy_revision = p_policy_revision
          AND policy_release.state = 'active'
    ),
    rules AS (
        SELECT 'device'::TEXT AS rule_kind, rule.access_rule_public_id,
               'device'::TEXT AS source_kind, rule.source_device_id AS source_ref,
               'device'::TEXT AS destination_kind, rule.destination_device_id AS destination_ref,
               rule.protocol, rule.destination_ports
        FROM release
        JOIN mesh.compiled_policy_rule AS rule
          ON rule.workspace_id = scoped_workspace_id
         AND rule.network_id = scoped_network_id
         AND rule.policy_release_id = release.id
         AND rule.policy_revision = release.policy_revision
        UNION ALL
        SELECT 'group'::TEXT, group_rule.access_rule_public_id,
               CASE WHEN group_rule.source_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.source_identity_group_id IS NOT NULL THEN 'identity_group'
                    WHEN group_rule.source_device_tag_id IS NOT NULL THEN 'device_tag'
                    ELSE 'device' END,
               COALESCE(group_rule.source_device_id, group_rule.source_device_group_id,
                        group_rule.source_identity_group_id, group_rule.source_device_tag_id),
               CASE WHEN group_rule.destination_device_group_id IS NOT NULL THEN 'device_group'
                    WHEN group_rule.destination_device_tag_id IS NOT NULL THEN 'device_tag'
                    ELSE 'device' END,
               COALESCE(group_rule.destination_device_id, group_rule.destination_device_group_id,
                        group_rule.destination_device_tag_id),
               group_rule.protocol, group_rule.destination_ports
        FROM release
        JOIN mesh.compiled_policy_group_rule AS group_rule
          ON group_rule.policy_release_id = release.id
    )
    SELECT rules.rule_kind, rules.access_rule_public_id, rules.source_kind, rules.source_ref,
           rules.destination_kind, rules.destination_ref, rules.protocol,
           ARRAY(
               SELECT pg_catalog.lower(port_range)::INTEGER
               FROM pg_catalog.unnest(rules.destination_ports) AS port_range
               ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
           ),
           ARRAY(
               SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
               FROM pg_catalog.unnest(rules.destination_ports) AS port_range
               ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
           )
    FROM rules
    ORDER BY rules.access_rule_public_id, rules.rule_kind, rules.source_kind, rules.source_ref,
             rules.destination_kind, rules.destination_ref
    LIMIT p_limit;
END;
$function$;

-- The members of every selector of the installed Network, with the same
-- membership conditions as selector_devices_internal_v1 (schema 122). An
-- Identity Group membership that expires carries its deadline.
CREATE FUNCTION mesh_ops.load_map_network_selector_members_v1(p_limit INTEGER)
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
        SELECT 'identity_group'::TEXT, member.identity_group_id, device.id, membership.expires_at
        FROM mesh.identity_group_member AS member
        JOIN mesh.identity_group AS identity_group
          ON identity_group.id = member.identity_group_id AND identity_group.state = 'active'
        JOIN mesh.principal AS principal
          ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = scoped_workspace_id AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
        JOIN mesh.device AS device
          ON device.workspace_id = scoped_workspace_id AND device.network_id = scoped_network_id
         AND device.owner_principal_id = principal.id
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

-- Every Device of the installed Network the packet policy treats as live
-- (active and not deleted; live while its expiry is ahead), with its public
-- identity: the endpoints a rule may name.
CREATE FUNCTION mesh_ops.load_map_network_policy_devices_v1(p_limit INTEGER)
RETURNS TABLE (device_id BIGINT, device_public_id UUID, expires_at TIMESTAMPTZ)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network policy device request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network policy device scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT device.id, device.public_id, device.expires_at
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp()
    ORDER BY device.id
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_policy_rules_v1(BIGINT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_policy_rules_v1(BIGINT, INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_policy_rules_v1(BIGINT, INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_selector_members_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_selector_members_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_selector_members_v1(INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_policy_devices_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_policy_devices_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_policy_devices_v1(INTEGER) TO mesh_runtime;
