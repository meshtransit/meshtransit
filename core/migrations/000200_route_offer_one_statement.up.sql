-- Schema 200: storing a route offer costs one statement, and a removed
-- Device keeps no offer (TD-CORE-63).
--
-- Every session sends its offer, empty for nodes that route nothing, so a
-- reconnect storm stores one offer per Device. report_device_route_offer_v2
-- resolves the session's Network and binds it itself before running v1, in
-- one statement instead of three; an unchanged offer still writes nothing.
-- It returns the scope with v1's result for the audit event of a change.
--
-- A Device that leaves the Network (revoked, logged out, removed) keeps its
-- row today: readers ignore it, as they check the Device is active, but it
-- is stale data. The offer is now deleted in the transaction that takes the
-- Device out, recorded with that change. A suspended Device keeps its offer:
-- it comes back with the same keys. Rows of Devices that left before this
-- schema stay (deleting them needs an audited change); readers ignore them.

CREATE FUNCTION mesh_ops.report_device_route_offer_v2(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_prefixes CIDR[], p_change_public_id UUID
)
RETURNS TABLE (workspace_public_id UUID, network_public_id UUID, result JSONB)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace UUID;
    v_network UUID;
BEGIN
    SELECT scope.workspace_public_id, scope.network_public_id INTO v_workspace, v_network
    FROM mesh_ops.resolve_map_session_scope(p_machine_fingerprint, p_node_key) AS scope;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'route offer Device not found';
    END IF;
    PERFORM bound.workspace_internal_id FROM mesh_ops.set_network_scope(v_workspace, v_network) AS bound;
    RETURN QUERY SELECT v_workspace, v_network,
        mesh_ops.report_device_route_offer_v1(p_machine_fingerprint, p_node_key, p_prefixes, p_change_public_id);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.report_device_route_offer_v2(BYTEA, BYTEA, CIDR[], UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.report_device_route_offer_v2(BYTEA, BYTEA, CIDR[], UUID) TO mesh_runtime;

CREATE FUNCTION mesh_ops.drop_route_offer_of_removed_device_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.deleted_at IS NOT NULL OR NEW.state NOT IN ('active', 'suspended') THEN
        DELETE FROM mesh.device_route_advertisement AS offer
        WHERE offer.workspace_id = NEW.workspace_id
          AND offer.network_id = NEW.network_id
          AND offer.device_id = NEW.id;
    END IF;
    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.drop_route_offer_of_removed_device_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER device_drop_route_offer
AFTER UPDATE OF state, deleted_at ON mesh.device
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
EXECUTE FUNCTION mesh_ops.drop_route_offer_of_removed_device_v1();

