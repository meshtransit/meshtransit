-- Schema 111 (R1-62): name both ends of a share by their display codes.
--
-- A provider listing its outgoing shares sees each consumer Network only by
-- UUID, and the display codes live in mesh_ops.tenant_display_identity,
-- which the runtime role cannot read. read_share_offer_display_codes_v1
-- returns the four codes of one offer, but only when the caller's own
-- Network holds a locator for that offer; any other offer yields NULL. Each
-- side already knows these codes: the provider typed the consumer Network
-- code, and the consumer reaches the provider by a name that contains its
-- codes. No other tenant row is read.

CREATE FUNCTION mesh_ops.read_share_offer_display_codes_v1(p_offer_public_id UUID)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'provider_workspace_code', provider_workspace.display_code,
        'provider_network_code', provider_network.display_code,
        'consumer_workspace_code', consumer_workspace.display_code,
        'consumer_network_code', consumer_network.display_code
    )
    FROM mesh.share_offer_locator AS locator
    LEFT JOIN mesh_ops.tenant_display_identity AS provider_workspace
      ON provider_workspace.workspace_public_id = locator.provider_workspace_public_id
    LEFT JOIN mesh_ops.tenant_display_identity AS provider_network
      ON provider_network.network_public_id = locator.provider_network_public_id
    LEFT JOIN mesh_ops.tenant_display_identity AS consumer_workspace
      ON consumer_workspace.workspace_public_id = locator.consumer_workspace_public_id
    LEFT JOIN mesh_ops.tenant_display_identity AS consumer_network
      ON consumer_network.network_public_id = locator.consumer_network_public_id
    WHERE locator.local_workspace_id = mesh_ops.current_workspace_id()
      AND locator.local_network_id = mesh_ops.current_network_id()
      AND locator.offer_public_id = p_offer_public_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_share_offer_display_codes_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_share_offer_display_codes_v1(UUID) TO mesh_runtime;
