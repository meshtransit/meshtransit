-- Schema 145: whether the scoped Network takes part in a Device share, as
-- the provider or the consumer, for the shared Network map view (scale-out
-- design S2b). A running map stream keeps or derives its map from that view
-- only for Networks without shares: a stream opened before a share took
-- effect has no sharing dependency of its own, so without this signal it
-- would never read the share's peers and aliases (seen 2026-10-12: the
-- provider Device of an enabled share kept a map without its consumers).
-- Contracts count from acceptance to expiry, the same states the per-Device
-- sharing dependency read (schema 84) follows.
CREATE FUNCTION mesh_ops.map_network_has_sharing_v1()
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network sharing scope is unavailable';
    END IF;

    RETURN EXISTS (
        SELECT 1
        FROM mesh.trust_contract AS contract
        WHERE contract.state IN ('activating', 'active')
          AND contract.expires_at > pg_catalog.transaction_timestamp()
          AND ((contract.provider_workspace_id = scoped_workspace_id
                AND contract.provider_network_id = scoped_network_id)
            OR (contract.consumer_workspace_id = scoped_workspace_id
                AND contract.consumer_network_id = scoped_network_id))
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.map_network_has_sharing_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.map_network_has_sharing_v1()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.map_network_has_sharing_v1() TO mesh_runtime;
