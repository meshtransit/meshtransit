-- The current schema has no independently configured Guardrail or Resource
-- traffic ceilings. This durable feature profile records that fact explicitly.
-- Installing such authority must block this profile until its reader is ready.
ALTER TABLE mesh.deployment ADD COLUMN direct_sharing_ceiling_profile TEXT NOT NULL
    DEFAULT 'no-additional-traffic-ceilings-v1'
    CHECK (direct_sharing_ceiling_profile IN ('no-additional-traffic-ceilings-v1', 'blocked'));

GRANT USAGE ON SCHEMA mesh, mesh_ops TO mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.current_workspace_id(), mesh_ops.current_network_id()
    TO mesh_direct_map_reader;

CREATE POLICY network_direct_map_reader_policy ON mesh.network
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.network TO mesh_direct_map_reader;
CREATE POLICY device_direct_map_reader_policy ON mesh.device
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.device TO mesh_direct_map_reader;
CREATE POLICY device_machine_key_epoch_direct_map_reader_policy ON mesh.device_machine_key_epoch
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.device_machine_key_epoch TO mesh_direct_map_reader;
CREATE POLICY device_node_key_epoch_direct_map_reader_policy ON mesh.device_node_key_epoch
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.device_node_key_epoch TO mesh_direct_map_reader;
CREATE POLICY node_address_lease_direct_map_reader_policy ON mesh.node_address_lease
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.node_address_lease TO mesh_direct_map_reader;
CREATE POLICY resource_direct_map_reader_policy ON mesh.resource
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.resource TO mesh_direct_map_reader;
CREATE POLICY resource_device_target_direct_map_reader_policy ON mesh.resource_device_target
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.resource_device_target TO mesh_direct_map_reader;
CREATE POLICY imported_resource_direct_map_reader_policy ON mesh.imported_resource
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.imported_resource TO mesh_direct_map_reader;
CREATE POLICY imported_resource_access_name_direct_map_reader_policy ON mesh.imported_resource_access_name
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.imported_resource_access_name TO mesh_direct_map_reader;
CREATE POLICY policy_release_direct_map_reader_policy ON mesh.policy_release
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.policy_release TO mesh_direct_map_reader;
CREATE POLICY compiled_policy_imported_resource_destination_direct_map_reader_policy ON mesh.compiled_policy_imported_resource_destination
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh.compiled_policy_imported_resource_destination TO mesh_direct_map_reader;
CREATE POLICY network_revision_direct_map_reader_policy ON mesh_ops.network_revision
    FOR SELECT TO mesh_direct_map_reader USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id IN (mesh_ops.current_network_id(),
            NULLIF(pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE), '')::BIGINT)
    );
GRANT SELECT ON mesh_ops.network_revision TO mesh_direct_map_reader;
CREATE POLICY workspace_direct_map_reader_policy ON mesh.workspace
    FOR SELECT TO mesh_direct_map_reader USING (id = mesh_ops.current_workspace_id());
GRANT SELECT ON mesh.workspace, mesh.deployment, mesh.principal TO mesh_direct_map_reader;
CREATE POLICY direct_device_endpoint_direct_map_reader_policy ON mesh.direct_device_endpoint
    FOR SELECT TO mesh_direct_map_reader USING (
        provider_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_workspace_id = mesh_ops.current_workspace_id()
        AND (provider_network_id = mesh_ops.current_network_id()
            OR consumer_network_id = mesh_ops.current_network_id())
    );
GRANT SELECT ON mesh.direct_device_endpoint TO mesh_direct_map_reader;
CREATE POLICY trust_contract_direct_map_reader_policy ON mesh.trust_contract
    FOR SELECT TO mesh_direct_map_reader USING (
        provider_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_workspace_id = mesh_ops.current_workspace_id()
        AND (provider_network_id = mesh_ops.current_network_id()
            OR consumer_network_id = mesh_ops.current_network_id())
    );
GRANT SELECT ON mesh.trust_contract TO mesh_direct_map_reader;
CREATE POLICY resource_export_direct_map_reader_policy ON mesh.resource_export
    FOR SELECT TO mesh_direct_map_reader USING (
        provider_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_workspace_id = mesh_ops.current_workspace_id()
        AND (provider_network_id = mesh_ops.current_network_id()
            OR consumer_network_id = mesh_ops.current_network_id())
    );
GRANT SELECT ON mesh.resource_export TO mesh_direct_map_reader;
CREATE POLICY resource_export_constraint_direct_map_reader_policy ON mesh.resource_export_constraint
    FOR SELECT TO mesh_direct_map_reader USING (
        provider_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_workspace_id = mesh_ops.current_workspace_id()
        AND (provider_network_id = mesh_ops.current_network_id()
            OR consumer_network_id = mesh_ops.current_network_id())
    );
GRANT SELECT ON mesh.resource_export_constraint TO mesh_direct_map_reader;
CREATE POLICY share_offer_direct_map_reader_policy ON mesh.share_offer
    FOR SELECT TO mesh_direct_map_reader USING (
        provider_workspace_id = mesh_ops.current_workspace_id()
        AND consumer_workspace_id = mesh_ops.current_workspace_id()
        AND (provider_network_id = mesh_ops.current_network_id()
            OR consumer_network_id = mesh_ops.current_network_id())
    );
GRANT SELECT ON mesh.share_offer TO mesh_direct_map_reader;

CREATE FUNCTION mesh_ops.load_direct_share_map_edges_v1(
    p_machine_key_fingerprint BYTEA, p_node_key BYTEA, p_limit INTEGER
)
RETURNS SETOF JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    self_id BIGINT;
    self_workspace BIGINT;
    self_network BIGINT;
    previous_remote TEXT;
    endpoint_row mesh.direct_device_endpoint%ROWTYPE;
    endpoint_count INTEGER := 0;
    edge_count INTEGER := 0;
    edge JSONB;
BEGIN
    previous_remote := pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE);
    -- Discard caller-controlled remote scope before authenticating self.
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', '', TRUE);
    self_workspace := mesh_ops.current_workspace_id();
    self_network := mesh_ops.current_network_id();
    IF self_workspace IS NULL OR self_network IS NULL
        OR p_machine_key_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 257 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid direct map request';
    END IF;
    SELECT device.id INTO self_id
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
     AND machine.state = 'active' AND machine.valid_from <= pg_catalog.transaction_timestamp()
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
     AND node_key.state = 'active' AND node_key.valid_from <= pg_catalog.transaction_timestamp()
    JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
    JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.id = device.network_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    JOIN mesh.principal AS owner ON owner.id = device.owner_principal_id AND owner.deployment_id = deployment.id
    WHERE device.workspace_id = self_workspace AND device.network_id = self_network
      AND machine.fingerprint = p_machine_key_fingerprint AND node_key.public_key = p_node_key
      AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.created_at <= pg_catalog.transaction_timestamp()
      AND device.expires_at > pg_catalog.transaction_timestamp()
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL
      AND deployment.state = 'active' AND deployment.recovery_state = 'verified' AND deployment.deleted_at IS NULL
      AND owner.state = 'active' AND owner.deleted_at IS NULL;
    IF self_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'direct map authority unavailable';
    END IF;

    -- Bound endpoints as well as output rules, including endpoints with no rule.
    FOR endpoint_row IN
        SELECT endpoint.* FROM mesh.direct_device_endpoint AS endpoint
        WHERE endpoint.provider_workspace_id = self_workspace
          AND endpoint.consumer_workspace_id = self_workspace AND endpoint.state = 'ready'
          AND ((endpoint.provider_network_id = self_network AND endpoint.target_device_id = self_id)
            OR endpoint.consumer_network_id = self_network)
        ORDER BY endpoint.id LIMIT 257
    LOOP
        endpoint_count := endpoint_count + 1;
        IF endpoint_count > 256 THEN
            RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'direct map endpoint limit exceeded';
        END IF;
        PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id',
            CASE WHEN endpoint_row.provider_network_id = self_network
                THEN endpoint_row.consumer_network_id ELSE endpoint_row.provider_network_id END::TEXT, TRUE);
        FOR edge IN
            SELECT pg_catalog.jsonb_build_object(
                'evaluated_at', pg_catalog.transaction_timestamp(),
                'ceiling_profile', deployment.direct_sharing_ceiling_profile,
                'provider_workspace_id', workspace.public_id,
                'consumer_workspace_id', workspace.public_id,
                'provider_network_id', provider_network.public_id,
                'consumer_network_id', consumer_network.public_id,
                'provider_network_revision', provider_revision.network_revision,
                'consumer_network_revision', consumer_revision.network_revision,
                'consumer_policy_revision', consumer_revision.policy_revision,
                'provider_inventory_revision', provider_revision.inventory_revision,
                'provider_sharing_revision', provider_revision.sharing_revision,
                'consumer_sharing_revision', consumer_revision.sharing_revision,
                'provider_authority_generation', provider_network.authority_generation,
                'consumer_authority_generation', consumer_network.authority_generation,
                'recovery_epoch', deployment.recovery_epoch,
                'contract', pg_catalog.jsonb_build_object(
                    'id', contract.public_id, 'version', contract.version,
                    'imported_resource_id', imported.public_id, 'imported_resource_version', imported.version,
                    'offer_id', offer.public_id, 'export_id', export.public_id,
                    'expires_at', contract.expires_at, 'constraint_hash', pg_catalog.encode(contract.constraint_hash, 'hex')),
                'export', pg_catalog.jsonb_build_object(
                    'version', export.version, 'expires_at', export.expires_at,
                    'constraints', COALESCE((
                        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                            'protocol', ceiling.protocol, 'ranges', COALESCE((
                                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
                                    pg_catalog.lower(port_range), pg_catalog.upper(port_range) - 1)
                                    ORDER BY pg_catalog.lower(port_range))
                                FROM pg_catalog.unnest(ceiling.destination_ports) AS port_range
                            ), '[]'::JSONB)) ORDER BY ceiling.protocol)
                        FROM mesh.resource_export_constraint AS ceiling
                        WHERE ceiling.resource_export_id = export.id
                          AND ceiling.provider_workspace_id = endpoint_row.provider_workspace_id
                          AND ceiling.provider_network_id = endpoint_row.provider_network_id
                          AND ceiling.consumer_workspace_id = endpoint_row.consumer_workspace_id
                          AND ceiling.consumer_network_id = endpoint_row.consumer_network_id
                    ), '[]'::JSONB)),
                'endpoint', pg_catalog.jsonb_build_object(
                    'id', endpoint_row.public_id, 'access_name', access_name.access_name,
                    'generation', endpoint_row.generation, 'expires_at', endpoint_row.expires_at,
                    'resource_address', pg_catalog.host(endpoint_row.resource_address)),
                'target', pg_catalog.jsonb_build_object(
                    'id', resource.public_id, 'version', resource.version,
                    'target_generation', resource.target_generation,
                    'semantic_hash', pg_catalog.encode(resource.semantic_hash, 'hex'),
                    'display_name', resource.display_name, 'device_id', provider.public_id,
                    'owner_id', resource_owner.public_id, 'custodian_id', custodian.public_id,
                    'activated_network_revision', resource.activated_network_revision,
                    'inventory_revision', resource.inventory_revision,
                    'created_at', resource.created_at, 'updated_at', resource.updated_at),
                'rule', pg_catalog.jsonb_build_object(
                    'id', rule.access_rule_public_id, 'source_id', consumer.public_id,
                    'protocol', rule.protocol, 'ranges', COALESCE((
                        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
                            pg_catalog.lower(port_range), pg_catalog.upper(port_range) - 1)
                            ORDER BY pg_catalog.lower(port_range))
                        FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                    ), '[]'::JSONB)),
                'peer', CASE WHEN self_network = endpoint_row.provider_network_id THEN
                    pg_catalog.jsonb_build_object(
                        'numeric_node_id', consumer.id, 'numeric_owner_id', consumer.owner_principal_id,
                        'id', consumer.public_id, 'owner_id', consumer_owner.public_id,
                        'hostname', consumer.hostname, 'machine_key', pg_catalog.encode(consumer_machine.public_key, 'hex'),
                        'node_key', pg_catalog.encode(consumer_node.public_key, 'hex'),
                        'session_generation', consumer.session_generation,
                        'created_at', consumer.created_at, 'key_expiry', consumer.expires_at,
                        'addresses', consumer_addresses.addresses)
                ELSE pg_catalog.jsonb_build_object(
                        'numeric_node_id', provider.id, 'numeric_owner_id', provider.owner_principal_id,
                        'id', provider.public_id, 'owner_id', provider_owner.public_id,
                        'hostname', provider.hostname, 'machine_key', pg_catalog.encode(provider_machine.public_key, 'hex'),
                        'node_key', pg_catalog.encode(provider_node.public_key, 'hex'),
                        'session_generation', provider.session_generation,
                        'created_at', provider.created_at, 'key_expiry', provider.expires_at,
                        'addresses', provider_addresses.addresses) END)
            FROM mesh.trust_contract AS contract
            JOIN mesh.imported_resource AS imported
              ON imported.workspace_id = endpoint_row.consumer_workspace_id
             AND imported.network_id = endpoint_row.consumer_network_id
             AND imported.id = endpoint_row.imported_resource_id
             AND imported.trust_contract_id = contract.id AND imported.public_id = contract.imported_resource_public_id
             AND imported.state = 'active' AND imported.version = endpoint_row.imported_resource_version
            JOIN mesh.share_offer AS offer ON offer.id = contract.share_offer_id
             AND offer.state = 'accepted' AND offer.accepted_contract_public_id = contract.public_id
            JOIN mesh.resource_export AS export ON export.id = contract.resource_export_id
             AND export.provider_workspace_id = endpoint_row.provider_workspace_id
             AND export.provider_network_id = endpoint_row.provider_network_id
             AND export.consumer_workspace_id = endpoint_row.consumer_workspace_id
             AND export.consumer_network_id = endpoint_row.consumer_network_id
             AND export.resource_id = contract.resource_id AND export.resource_version = contract.resource_version
             AND export.target_generation = contract.target_generation AND export.resource_semantic_hash = contract.resource_semantic_hash
             AND export.constraint_hash = contract.constraint_hash AND export.state = 'active'
             AND export.provider_authority_generation = contract.provider_authority_generation
             AND export.expires_at >= contract.expires_at AND export.expires_at > pg_catalog.transaction_timestamp()
            JOIN mesh.resource AS resource ON resource.workspace_id = endpoint_row.provider_workspace_id
             AND resource.network_id = endpoint_row.provider_network_id AND resource.id = endpoint_row.resource_id
             AND resource.id = contract.resource_id AND resource.version = contract.resource_version
             AND resource.target_generation = contract.target_generation AND resource.semantic_hash = contract.resource_semantic_hash
             AND resource.version = endpoint_row.resource_version AND resource.target_generation = endpoint_row.target_generation
             AND resource.semantic_hash = endpoint_row.resource_semantic_hash
             AND resource.kind = 'device' AND resource.provenance_kind = 'manual'
             AND resource.state = 'active' AND resource.deleted_at IS NULL
            JOIN mesh.resource_device_target AS target ON target.workspace_id = resource.workspace_id
             AND target.network_id = resource.network_id AND target.resource_id = resource.id
             AND target.target_generation = resource.target_generation AND target.state = 'active'
             AND target.device_id = endpoint_row.target_device_id
            JOIN mesh.device AS provider ON provider.workspace_id = target.workspace_id
             AND provider.network_id = target.network_id AND provider.id = target.device_id
             AND provider.state = 'active' AND provider.deleted_at IS NULL
             AND provider.created_at <= pg_catalog.transaction_timestamp() AND provider.expires_at > pg_catalog.transaction_timestamp()
             AND provider.session_generation = endpoint_row.target_session_generation
             AND provider.current_machine_key_epoch = endpoint_row.target_machine_key_epoch
             AND provider.current_node_key_epoch = endpoint_row.target_node_key_epoch
            JOIN mesh.device_machine_key_epoch AS provider_machine ON provider_machine.workspace_id = provider.workspace_id
             AND provider_machine.network_id = provider.network_id AND provider_machine.device_id = provider.id
             AND provider_machine.epoch = provider.current_machine_key_epoch AND provider_machine.state = 'active'
             AND provider_machine.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.device_node_key_epoch AS provider_node ON provider_node.workspace_id = provider.workspace_id
             AND provider_node.network_id = provider.network_id AND provider_node.device_id = provider.id
             AND provider_node.epoch = provider.current_node_key_epoch AND provider_node.state = 'active'
             AND provider_node.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.node_address_lease AS pinned_lease ON pinned_lease.workspace_id = provider.workspace_id
             AND pinned_lease.network_id = provider.network_id AND pinned_lease.device_id = provider.id
             AND pinned_lease.id = endpoint_row.target_address_lease_id
             AND pinned_lease.generation = endpoint_row.target_address_generation AND pinned_lease.address = endpoint_row.resource_address
             AND pinned_lease.state = 'active' AND pinned_lease.lease_role = 'primary'
             AND pinned_lease.created_at <= pg_catalog.transaction_timestamp()
            JOIN mesh.workspace AS workspace ON workspace.id = self_workspace
             AND workspace.id = contract.provider_workspace_id AND workspace.id = contract.consumer_workspace_id
             AND workspace.state = 'active' AND workspace.deleted_at IS NULL
            JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
             AND deployment.id = contract.deployment_id AND deployment.id = endpoint_row.deployment_id
             AND deployment.state = 'active' AND deployment.recovery_state = 'verified' AND deployment.deleted_at IS NULL
             AND deployment.recovery_epoch = contract.recovery_epoch AND deployment.recovery_epoch = endpoint_row.recovery_epoch
             AND deployment.direct_sharing_ceiling_profile = 'no-additional-traffic-ceilings-v1'
            JOIN mesh.network AS provider_network ON provider_network.workspace_id = workspace.id
             AND provider_network.id = endpoint_row.provider_network_id
             AND provider_network.state = 'active' AND provider_network.deleted_at IS NULL
             AND provider_network.authority_generation = contract.provider_authority_generation
             AND provider_network.authority_generation = endpoint_row.provider_authority_generation
            JOIN mesh.network AS consumer_network ON consumer_network.workspace_id = workspace.id
             AND consumer_network.id = endpoint_row.consumer_network_id
             AND consumer_network.state = 'active' AND consumer_network.deleted_at IS NULL
             AND consumer_network.authority_generation = contract.consumer_authority_generation
             AND consumer_network.authority_generation = endpoint_row.consumer_authority_generation
            JOIN mesh_ops.network_revision AS provider_revision ON provider_revision.workspace_id = workspace.id
             AND provider_revision.network_id = provider_network.id
            JOIN mesh_ops.network_revision AS consumer_revision ON consumer_revision.workspace_id = workspace.id
             AND consumer_revision.network_id = consumer_network.id
            JOIN mesh.policy_release AS release ON release.workspace_id = workspace.id
             AND release.network_id = consumer_network.id AND release.policy_revision = consumer_revision.policy_revision
             AND release.state = 'active'
            JOIN mesh.compiled_policy_imported_resource_destination AS rule ON rule.workspace_id = workspace.id
             AND rule.network_id = consumer_network.id AND rule.policy_release_id = release.id
             AND rule.policy_revision = release.policy_revision
             AND rule.imported_resource_id = imported.id AND rule.imported_resource_version = imported.version
             AND rule.trust_contract_id = contract.id AND rule.trust_contract_version = contract.version
             AND rule.resource_export_id = export.id AND rule.resource_export_version = export.version
             AND rule.provider_workspace_id = workspace.id AND rule.provider_network_id = provider_network.id
             AND rule.destination_resource_id = resource.id AND rule.resource_version = resource.version
             AND rule.target_generation = resource.target_generation AND rule.resource_semantic_hash = resource.semantic_hash
             AND rule.provider_authority_generation = provider_network.authority_generation
             AND rule.consumer_authority_generation = consumer_network.authority_generation
             AND rule.recovery_epoch = deployment.recovery_epoch AND rule.contract_expires_at = contract.expires_at
             AND rule.constraint_hash = contract.constraint_hash
             AND rule.provider_inventory_revision <= provider_revision.inventory_revision
             AND rule.provider_sharing_revision <= provider_revision.sharing_revision
             AND rule.consumer_sharing_revision <= consumer_revision.sharing_revision
            JOIN mesh.device AS consumer ON consumer.workspace_id = workspace.id AND consumer.network_id = consumer_network.id
             AND consumer.id = rule.source_device_id AND consumer.state = 'active' AND consumer.deleted_at IS NULL
             AND consumer.created_at <= pg_catalog.transaction_timestamp() AND consumer.expires_at > pg_catalog.transaction_timestamp()
            JOIN mesh.device_machine_key_epoch AS consumer_machine ON consumer_machine.workspace_id = consumer.workspace_id
             AND consumer_machine.network_id = consumer.network_id AND consumer_machine.device_id = consumer.id
             AND consumer_machine.epoch = consumer.current_machine_key_epoch AND consumer_machine.state = 'active'
             AND consumer_machine.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.device_node_key_epoch AS consumer_node ON consumer_node.workspace_id = consumer.workspace_id
             AND consumer_node.network_id = consumer.network_id AND consumer_node.device_id = consumer.id
             AND consumer_node.epoch = consumer.current_node_key_epoch AND consumer_node.state = 'active'
             AND consumer_node.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.principal AS provider_owner ON provider_owner.id = provider.owner_principal_id
             AND provider_owner.deployment_id = deployment.id AND provider_owner.state = 'active' AND provider_owner.deleted_at IS NULL
            JOIN mesh.principal AS consumer_owner ON consumer_owner.id = consumer.owner_principal_id
             AND consumer_owner.deployment_id = deployment.id AND consumer_owner.state = 'active' AND consumer_owner.deleted_at IS NULL
            JOIN mesh.principal AS resource_owner ON resource_owner.id = resource.owner_principal_id
             AND resource_owner.deployment_id = deployment.id AND resource_owner.state = 'active' AND resource_owner.deleted_at IS NULL
            JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
             AND custodian.deployment_id = deployment.id AND custodian.state = 'active' AND custodian.deleted_at IS NULL
            JOIN mesh.imported_resource_access_name AS access_name ON access_name.id = endpoint_row.access_name_id
             AND access_name.workspace_id = imported.workspace_id AND access_name.network_id = imported.network_id
             AND access_name.imported_resource_id = imported.id AND access_name.state = 'reserved'
            CROSS JOIN LATERAL (SELECT ARRAY(SELECT lease.address::TEXT FROM mesh.node_address_lease AS lease
                WHERE lease.workspace_id = provider.workspace_id AND lease.network_id = provider.network_id
                  AND lease.device_id = provider.id AND lease.state = 'active' AND lease.lease_role = 'primary'
                  AND lease.created_at <= pg_catalog.transaction_timestamp()
                ORDER BY lease.family, lease.address, lease.id) AS addresses) AS provider_addresses
            CROSS JOIN LATERAL (SELECT ARRAY(SELECT lease.address::TEXT FROM mesh.node_address_lease AS lease
                WHERE lease.workspace_id = consumer.workspace_id AND lease.network_id = consumer.network_id
                  AND lease.device_id = consumer.id AND lease.state = 'active' AND lease.lease_role = 'primary'
                  AND lease.created_at <= pg_catalog.transaction_timestamp()
                ORDER BY lease.family, lease.address, lease.id) AS addresses) AS consumer_addresses
            WHERE contract.id = endpoint_row.trust_contract_id AND contract.state = 'active'
              AND contract.provider_workspace_id = endpoint_row.provider_workspace_id
              AND contract.provider_network_id = endpoint_row.provider_network_id
              AND contract.consumer_workspace_id = endpoint_row.consumer_workspace_id
              AND contract.consumer_network_id = endpoint_row.consumer_network_id
              AND contract.version = endpoint_row.contract_version AND contract.constraint_hash = endpoint_row.constraint_hash
              AND contract.expires_at > pg_catalog.transaction_timestamp() AND endpoint_row.expires_at > pg_catalog.transaction_timestamp()
              AND ((self_network = provider.network_id AND self_id = provider.id)
                OR (self_network = consumer.network_id AND self_id = consumer.id))
              AND pg_catalog.cardinality(provider_addresses.addresses) BETWEEN 1 AND 2
              AND pg_catalog.cardinality(consumer_addresses.addresses) BETWEEN 1 AND 2
            ORDER BY rule.access_rule_public_id LIMIT p_limit - edge_count
        LOOP
            RETURN NEXT edge;
            edge_count := edge_count + 1;
            IF edge_count >= p_limit THEN
                PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
                RETURN;
            END IF;
        END LOOP;
    END LOOP;
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_direct_share_map_edges_v1(BYTEA, BYTEA, INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_direct_share_map_edges_v1(BYTEA, BYTEA, INTEGER)
    TO mesh_runtime;
