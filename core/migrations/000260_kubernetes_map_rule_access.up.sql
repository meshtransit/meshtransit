-- K2d d3: maps carry access profiles to Kubernetes gateways (K2 design §27).
--
-- load_map_network_kubernetes_rule_access_v1 reads every rule to a cluster
-- that names groups, with its profile when it applies one; and
-- load_map_network_kubernetes_profiles_v1 the content of every profile the
-- release's rules pin. Core checks each profile against its hash. Schema
-- 258's load_map_network_kubernetes_rule_groups_v1 stays for a Core before
-- d3, which grants nothing through a rule with a profile.

CREATE FUNCTION mesh_ops.load_map_network_kubernetes_rule_access_v1(p_policy_revision BIGINT)
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
    ORDER BY rule.access_rule_public_id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_rule_access_v1(BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_rule_access_v1(BIGINT) TO mesh_runtime;

CREATE FUNCTION mesh_ops.load_map_network_kubernetes_profiles_v1(p_policy_revision BIGINT)
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
    SELECT held.profile_public_id, held.content_hash, content.name, content.rules
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
    ORDER BY held.content_hash;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_profiles_v1(BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_profiles_v1(BIGINT) TO mesh_runtime;
