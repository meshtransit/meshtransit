-- Schema 168: publish a Private Endpoint only once the database clock has
-- reached its creation.
--
-- A Private Endpoint's created_at is the activating MeshCore's clock
-- (activate_resource_share_v4 p_occurred_at), while the publication snapshot
-- stamps snapshot_at with this database's clock, and publish_private_endpoint_v1
-- requires p_observed_at >= endpoint.created_at. When the activating MeshCore
-- runs ahead of the database host, a reconciler that picks the endpoint up
-- within that skew read a snapshot older than the endpoint: it applied the
-- gateway route, the confirmation failed with 40001 ("authority changed"), it
-- withdrew the route again and retried later. Now:
--   list_private_endpoint_publication_candidates_v2 is v1 that also requires
--   endpoint.created_at <= the database clock, so the endpoint is not a
--   candidate until a snapshot of it can be confirmed;
--   read_private_endpoint_publication_snapshot_v3 is v2 that fails with 40001
--   when its snapshot_at is still before the endpoint's created_at, so no
--   caller applies a route for a snapshot the confirmation would refuse.
--
-- The schema 55 and 56 functions stay for the previous binary.

CREATE FUNCTION mesh_ops.list_private_endpoint_publication_candidates_v2(
    p_deployment_public_id UUID,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    decision_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
    result JSONB;
BEGIN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    IF p_deployment_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 128 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Private Endpoint publication selection';
    END IF;

    SELECT COALESCE(
        pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.endpoint_public_id),
        '[]'::JSONB
    ) INTO result
    FROM (
        SELECT endpoint.public_id AS endpoint_public_id,
            pg_catalog.jsonb_build_object(
                'deployment_public_id', p_deployment_public_id,
                'endpoint_public_id', endpoint.public_id,
                'endpoint_version', endpoint.version,
                'endpoint_generation', endpoint.generation,
                'alias_lease_version', lease.version,
                'contract_version', contract.version,
                'imported_resource_version', imported.version,
                'target_device_id', device.public_id,
                'target_generation', contract.target_generation,
                'target_addresses', (
                    SELECT COALESCE(
                        pg_catalog.jsonb_agg(address.address::TEXT ORDER BY address.family),
                        '[]'::JSONB
                    )
                    FROM mesh.node_address_lease AS address
                    WHERE address.workspace_id = contract.provider_workspace_id
                      AND address.network_id = contract.provider_network_id
                      AND address.device_id = device.id
                      AND address.state = 'active'
                      AND address.lease_role = 'primary'
                ),
                'resource_alias', endpoint.resource_alias::TEXT,
                'access_name', access_name.access_name,
                'constraint_hash', pg_catalog.encode(endpoint.constraint_hash, 'hex'),
                'expires_at', endpoint.expires_at
            ) AS payload
        FROM mesh.private_endpoint AS endpoint
        JOIN mesh.deployment AS deployment
          ON deployment.id = endpoint.deployment_id
         AND deployment.installation_public_id = p_deployment_public_id
         AND deployment.state = 'active'
         AND deployment.recovery_epoch = endpoint.recovery_epoch
        JOIN mesh.trust_contract AS contract
          ON contract.id = endpoint.trust_contract_id
         AND contract.version = endpoint.contract_version
         AND contract.state = 'active'
         AND contract.expires_at = endpoint.expires_at
        JOIN mesh.imported_resource AS imported
          ON imported.id = endpoint.imported_resource_id
         AND imported.version = endpoint.imported_resource_version
         AND imported.state = 'active'
        JOIN mesh.imported_resource_access_name AS access_name
          ON access_name.id = endpoint.access_name_id
         AND access_name.imported_resource_id = imported.id
         AND access_name.state = 'reserved'
        JOIN mesh.federation_alias_lease AS lease
          ON lease.id = endpoint.alias_lease_id
         AND lease.resource_alias = endpoint.resource_alias
         AND lease.state = 'reserved'
        JOIN mesh.resource AS resource
          ON resource.id = contract.resource_id
         AND resource.workspace_id = contract.provider_workspace_id
         AND resource.network_id = contract.provider_network_id
         AND resource.version = contract.resource_version
         AND resource.target_generation = contract.target_generation
         AND resource.semantic_hash = contract.resource_semantic_hash
         AND resource.state = 'active'
        JOIN mesh.resource_device_target AS target
          ON target.resource_id = resource.id
         AND target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.device AS device
          ON device.id = target.device_id
         AND device.workspace_id = target.workspace_id
         AND device.network_id = target.network_id
         AND device.state = 'active'
         AND device.expires_at > decision_at
        WHERE endpoint.state = 'provisioning'
          AND endpoint.version = 1
          AND endpoint.expires_at > decision_at
          AND endpoint.created_at <= decision_at
          AND lease.version = 1
          AND EXISTS (
              SELECT 1
              FROM mesh.node_address_lease AS address
              WHERE address.workspace_id = contract.provider_workspace_id
                AND address.network_id = contract.provider_network_id
                AND address.device_id = device.id
                AND address.state = 'active'
                AND address.lease_role = 'primary'
          )
        ORDER BY endpoint.public_id
        LIMIT p_limit
    ) AS candidate;
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_private_endpoint_publication_candidates_v2(UUID, INTEGER)
FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_private_endpoint_publication_candidates_v2(UUID, INTEGER)
TO mesh_worker;

CREATE FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v3(
    p_deployment_public_id UUID,
    p_endpoint_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    snapshot JSONB;
    endpoint_created_at TIMESTAMPTZ;
BEGIN
    snapshot := mesh_ops.read_private_endpoint_publication_snapshot_v2(
        p_deployment_public_id, p_endpoint_public_id
    );
    SELECT endpoint.created_at INTO STRICT endpoint_created_at
    FROM mesh.private_endpoint AS endpoint
    WHERE endpoint.public_id = p_endpoint_public_id;
    IF (snapshot->>'snapshot_at')::TIMESTAMPTZ < endpoint_created_at THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'Private Endpoint is newer than the database clock';
    END IF;
    RETURN snapshot;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v3(UUID, UUID)
FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_private_endpoint_publication_snapshot_v3(UUID, UUID)
TO mesh_worker;
