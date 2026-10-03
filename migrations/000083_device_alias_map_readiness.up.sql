-- Client readiness is separate from gateway/route readiness. No serving writer
-- is granted by this migration; runtime activation remains explicitly disabled.
CREATE TABLE mesh.device_alias_client_readiness (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE CHECK (get_byte(uuid_send(public_id),6)>>4=7),
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    private_endpoint_id BIGINT NOT NULL,
    endpoint_generation BIGINT NOT NULL CHECK (endpoint_generation>0),
    consumer_device_id BIGINT NOT NULL,
    provider_device_id BIGINT NOT NULL,
    contract_version BIGINT NOT NULL CHECK (contract_version>0),
    imported_resource_version BIGINT NOT NULL CHECK (imported_resource_version>0),
    resource_version BIGINT NOT NULL CHECK (resource_version>0),
    target_generation BIGINT NOT NULL CHECK (target_generation>0),
    recovery_epoch BIGINT NOT NULL CHECK (recovery_epoch>0),
    lease_public_ids UUID[] NOT NULL CHECK (cardinality(lease_public_ids) IN (2,4)),
    expires_at TIMESTAMPTZ NOT NULL CHECK (isfinite(expires_at)),
    state TEXT NOT NULL CHECK (state IN ('ready','withdrawn')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version>0),
    created_at TIMESTAMPTZ NOT NULL CHECK (isfinite(created_at)),
    updated_at TIMESTAMPTZ NOT NULL CHECK (isfinite(updated_at) AND updated_at>=created_at),
    provider_network_revision BIGINT NOT NULL CHECK (provider_network_revision>0),
    provider_sharing_revision BIGINT NOT NULL CHECK (provider_sharing_revision>0),
    consumer_network_revision BIGINT NOT NULL CHECK (consumer_network_revision>0),
    consumer_sharing_revision BIGINT NOT NULL CHECK (consumer_sharing_revision>0),
    CHECK (provider_workspace_id<>consumer_workspace_id AND expires_at>created_at),
    UNIQUE (private_endpoint_id,consumer_device_id),
    FOREIGN KEY (provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id,private_endpoint_id)
      REFERENCES mesh.private_endpoint(provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id,id),
    FOREIGN KEY (consumer_workspace_id,consumer_network_id,consumer_device_id) REFERENCES mesh.device(workspace_id,network_id,id),
    FOREIGN KEY (provider_workspace_id,provider_network_id,provider_device_id) REFERENCES mesh.device(workspace_id,network_id,id)
);
ALTER TABLE mesh.device_alias_client_readiness ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_alias_client_readiness FORCE ROW LEVEL SECURITY;
CREATE POLICY device_alias_readiness_migrator ON mesh.device_alias_client_readiness TO mesh_migrator USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON mesh.device_alias_client_readiness FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_direct_map_reader;
REVOKE ALL ON SEQUENCE mesh.device_alias_client_readiness_id_seq FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_direct_map_reader;
CREATE POLICY device_alias_readiness_map_read ON mesh.device_alias_client_readiness FOR SELECT TO mesh_device_alias_map_reader
  USING (private_endpoint_id=NULLIF(current_setting('mesh.alias_map_endpoint_id',TRUE),'')::BIGINT
    AND (provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(
      NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,
      NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT,
      NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,
      NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.device_alias_client_readiness TO mesh_device_alias_map_reader;
CREATE POLICY federation_alias_lease_map_read ON mesh.federation_alias_lease FOR SELECT TO mesh_device_alias_map_reader
  USING ((provider_workspace_id=mesh_ops.current_workspace_id() AND provider_network_id=mesh_ops.current_network_id())
    OR (consumer_workspace_id=mesh_ops.current_workspace_id() AND consumer_network_id=mesh_ops.current_network_id()));
GRANT SELECT ON mesh.federation_alias_lease TO mesh_device_alias_map_reader;
-- Isolated reader: role has no login/membership; only guarded function access
-- is granted by the database operator after migration.
GRANT USAGE ON SCHEMA mesh,mesh_ops TO mesh_device_alias_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.current_workspace_id(),mesh_ops.current_network_id() TO mesh_device_alias_map_reader;
CREATE POLICY network_alias_map_read ON mesh.network FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.network TO mesh_device_alias_map_reader;
CREATE POLICY device_alias_map_read ON mesh.device FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device TO mesh_device_alias_map_reader;
CREATE POLICY device_machine_key_epoch_alias_map_read ON mesh.device_machine_key_epoch FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device_machine_key_epoch TO mesh_device_alias_map_reader;
CREATE POLICY device_node_key_epoch_alias_map_read ON mesh.device_node_key_epoch FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device_node_key_epoch TO mesh_device_alias_map_reader;
CREATE POLICY resource_alias_map_read ON mesh.resource FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.resource TO mesh_device_alias_map_reader;
CREATE POLICY resource_device_target_alias_map_read ON mesh.resource_device_target FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.resource_device_target TO mesh_device_alias_map_reader;
CREATE POLICY imported_resource_alias_map_read ON mesh.imported_resource FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.imported_resource TO mesh_device_alias_map_reader;
CREATE POLICY imported_resource_access_name_alias_map_read ON mesh.imported_resource_access_name FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.imported_resource_access_name TO mesh_device_alias_map_reader;
CREATE POLICY policy_release_alias_map_read ON mesh.policy_release FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.policy_release TO mesh_device_alias_map_reader;
CREATE POLICY compiled_policy_imported_resource_destination_alias_map_read ON mesh.compiled_policy_imported_resource_destination FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.compiled_policy_imported_resource_destination TO mesh_device_alias_map_reader;
CREATE POLICY network_revision_alias_map_read ON mesh_ops.network_revision FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh_ops.network_revision TO mesh_device_alias_map_reader;
CREATE POLICY device_alias_client_version_alias_map_read ON mesh.device_alias_client_version FOR SELECT TO mesh_device_alias_map_reader USING ((workspace_id,network_id) IN ((mesh_ops.current_workspace_id(),mesh_ops.current_network_id()),(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device_alias_client_version TO mesh_device_alias_map_reader;
CREATE POLICY private_endpoint_alias_map_read ON mesh.private_endpoint FOR SELECT TO mesh_device_alias_map_reader USING ((provider_workspace_id=mesh_ops.current_workspace_id() AND provider_network_id=mesh_ops.current_network_id()) OR (consumer_workspace_id=mesh_ops.current_workspace_id() AND consumer_network_id=mesh_ops.current_network_id()));
GRANT SELECT ON mesh.private_endpoint TO mesh_device_alias_map_reader;
CREATE POLICY trust_contract_alias_map_read ON mesh.trust_contract FOR SELECT TO mesh_device_alias_map_reader USING ((provider_workspace_id=mesh_ops.current_workspace_id() AND provider_network_id=mesh_ops.current_network_id()) OR (consumer_workspace_id=mesh_ops.current_workspace_id() AND consumer_network_id=mesh_ops.current_network_id()));
GRANT SELECT ON mesh.trust_contract TO mesh_device_alias_map_reader;
CREATE POLICY share_offer_alias_map_read ON mesh.share_offer FOR SELECT TO mesh_device_alias_map_reader USING ((provider_workspace_id=mesh_ops.current_workspace_id() AND provider_network_id=mesh_ops.current_network_id()) OR (consumer_workspace_id=mesh_ops.current_workspace_id() AND consumer_network_id=mesh_ops.current_network_id()));
GRANT SELECT ON mesh.share_offer TO mesh_device_alias_map_reader;
CREATE POLICY resource_export_alias_map_read ON mesh.resource_export FOR SELECT TO mesh_device_alias_map_reader USING ((provider_workspace_id=mesh_ops.current_workspace_id() AND provider_network_id=mesh_ops.current_network_id()) OR (consumer_workspace_id=mesh_ops.current_workspace_id() AND consumer_network_id=mesh_ops.current_network_id()));
GRANT SELECT ON mesh.resource_export TO mesh_device_alias_map_reader;
CREATE POLICY resource_export_constraint_alias_map_read ON mesh.resource_export_constraint FOR SELECT TO mesh_device_alias_map_reader USING ((provider_workspace_id=mesh_ops.current_workspace_id() AND provider_network_id=mesh_ops.current_network_id()) OR (consumer_workspace_id=mesh_ops.current_workspace_id() AND consumer_network_id=mesh_ops.current_network_id()));
GRANT SELECT ON mesh.resource_export_constraint TO mesh_device_alias_map_reader;
CREATE POLICY workspace_alias_map_read ON mesh.workspace FOR SELECT TO mesh_device_alias_map_reader USING (id IN (mesh_ops.current_workspace_id(),NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.workspace,mesh.deployment,mesh.principal TO mesh_device_alias_map_reader;
CREATE POLICY device_alias_lease_alias_map_read ON mesh.device_alias_lease FOR SELECT TO mesh_device_alias_map_reader USING (private_endpoint_id=NULLIF(current_setting('mesh.alias_map_endpoint_id',TRUE),'')::BIGINT AND (provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_map_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_map_consumer_network_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.device_alias_lease TO mesh_device_alias_map_reader;
CREATE POLICY address_realm_alias_map_read ON mesh.address_realm FOR SELECT TO mesh_device_alias_map_reader USING (kind='federation_alias' AND EXISTS (SELECT 1 FROM mesh.private_endpoint AS endpoint WHERE endpoint.id=NULLIF(current_setting('mesh.alias_map_endpoint_id',TRUE),'')::BIGINT AND endpoint.deployment_id=address_realm.deployment_id));
CREATE POLICY address_pool_alias_map_read ON mesh.address_pool FOR SELECT TO mesh_device_alias_map_reader USING (workspace_id IS NULL AND purpose IN ('federation_resource_alias','federation_consumer_alias') AND EXISTS (SELECT 1 FROM mesh.private_endpoint AS endpoint WHERE endpoint.id=NULLIF(current_setting('mesh.alias_map_endpoint_id',TRUE),'')::BIGINT AND endpoint.deployment_id=address_pool.deployment_id));
GRANT SELECT ON mesh.address_realm,mesh.address_pool TO mesh_device_alias_map_reader;
CREATE FUNCTION mesh_ops.load_device_alias_map_edges_v1(
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
    previous_alias_provider_workspace TEXT;
    previous_alias_provider_network TEXT;
    previous_alias_consumer_workspace TEXT;
    previous_alias_consumer_network TEXT;
    previous_alias_endpoint TEXT;

    endpoint_row mesh.private_endpoint%ROWTYPE;
    endpoint_count INTEGER := 0;
    edge_count INTEGER := 0;
    edge JSONB;
BEGIN
    previous_remote := pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE);
    -- Discard caller-controlled remote scope before authenticating self.
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', '', TRUE);
    previous_alias_provider_workspace := current_setting('mesh.alias_map_provider_workspace_id',TRUE);
    PERFORM set_config('mesh.alias_map_provider_workspace_id','',TRUE);
    previous_alias_provider_network := current_setting('mesh.alias_map_provider_network_id',TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id','',TRUE);
    previous_alias_consumer_workspace := current_setting('mesh.alias_map_consumer_workspace_id',TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id','',TRUE);
    previous_alias_consumer_network := current_setting('mesh.alias_map_consumer_network_id',TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id','',TRUE);
    previous_alias_endpoint := current_setting('mesh.alias_map_endpoint_id',TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id','',TRUE);
    self_workspace := mesh_ops.current_workspace_id();
    self_network := mesh_ops.current_network_id();
    IF self_workspace IS NULL OR self_network IS NULL
        OR p_machine_key_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 257 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid alias map request';
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'alias map authority unavailable';
    END IF;

    -- Bound endpoints as well as output rules, including endpoints with no rule.
    FOR endpoint_row IN
        SELECT endpoint.* FROM mesh.private_endpoint AS endpoint
        WHERE endpoint.provider_workspace_id <> endpoint.consumer_workspace_id
          AND endpoint.state='provisioning'
          AND ((endpoint.provider_workspace_id=self_workspace AND endpoint.provider_network_id=self_network
            AND EXISTS (SELECT 1 FROM mesh.resource_device_target AS target JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
              WHERE target.workspace_id=self_workspace AND target.network_id=self_network AND target.resource_id=contract.resource_id
                AND target.device_id=self_id AND target.target_generation=contract.target_generation AND target.state='active'))
            OR (endpoint.consumer_workspace_id=self_workspace AND endpoint.consumer_network_id=self_network))
        ORDER BY endpoint.id LIMIT 257
    LOOP
        endpoint_count := endpoint_count + 1;
        IF endpoint_count > 256 THEN
            RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'alias map endpoint limit exceeded';
        END IF;
        PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id',
            CASE WHEN endpoint_row.provider_network_id = self_network
                THEN endpoint_row.consumer_network_id ELSE endpoint_row.provider_network_id END::TEXT, TRUE);
        PERFORM set_config('mesh.alias_map_provider_workspace_id',endpoint_row.provider_workspace_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_provider_network_id',endpoint_row.provider_network_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_consumer_workspace_id',endpoint_row.consumer_workspace_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_consumer_network_id',endpoint_row.consumer_network_id::TEXT,TRUE);
        PERFORM set_config('mesh.alias_map_endpoint_id',endpoint_row.id::TEXT,TRUE);
        FOR edge IN
            SELECT pg_catalog.jsonb_build_object(
                'evaluated_at', pg_catalog.transaction_timestamp(),
                'ceiling_profile', deployment.direct_sharing_ceiling_profile,
                'provider_workspace_id', provider_workspace.public_id,
                'consumer_workspace_id', consumer_workspace.public_id,
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
                    'resource_address', pg_catalog.host(endpoint_row.resource_alias)),
                'aliases', jsonb_build_object('expires_at',LEAST(readiness.expires_at,provider_aliases.expires_at,consumer_aliases.expires_at),
                  'local_addresses', CASE WHEN self_workspace=endpoint_row.provider_workspace_id THEN provider_aliases.addresses ELSE consumer_aliases.addresses END,
                  'remote_addresses', CASE WHEN self_workspace=endpoint_row.provider_workspace_id THEN consumer_aliases.addresses ELSE provider_aliases.addresses END),
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
                        'addresses', consumer_aliases.addresses)
                ELSE pg_catalog.jsonb_build_object(
                        'numeric_node_id', provider.id, 'numeric_owner_id', provider.owner_principal_id,
                        'id', provider.public_id, 'owner_id', provider_owner.public_id,
                        'hostname', provider.hostname, 'machine_key', pg_catalog.encode(provider_machine.public_key, 'hex'),
                        'node_key', pg_catalog.encode(provider_node.public_key, 'hex'),
                        'session_generation', provider.session_generation,
                        'created_at', provider.created_at, 'key_expiry', provider.expires_at,
                        'addresses', provider_aliases.addresses) END)
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
             AND resource.network_id = endpoint_row.provider_network_id AND resource.id = contract.resource_id
             AND resource.id = contract.resource_id AND resource.version = contract.resource_version
             AND resource.target_generation = contract.target_generation AND resource.semantic_hash = contract.resource_semantic_hash
             AND resource.kind = 'device' AND resource.provenance_kind = 'manual'
             AND resource.state = 'active' AND resource.deleted_at IS NULL
            JOIN mesh.resource_device_target AS target ON target.workspace_id = resource.workspace_id
             AND target.network_id = resource.network_id AND target.resource_id = resource.id
             AND target.target_generation = resource.target_generation AND target.state = 'active'
            JOIN mesh.device AS provider ON provider.workspace_id = target.workspace_id
             AND provider.network_id = target.network_id AND provider.id = target.device_id
             AND provider.state = 'active' AND provider.deleted_at IS NULL
             AND provider.created_at <= pg_catalog.transaction_timestamp() AND provider.expires_at > pg_catalog.transaction_timestamp()
            JOIN mesh.device_machine_key_epoch AS provider_machine ON provider_machine.workspace_id = provider.workspace_id
             AND provider_machine.network_id = provider.network_id AND provider_machine.device_id = provider.id
             AND provider_machine.epoch = provider.current_machine_key_epoch AND provider_machine.state = 'active'
             AND provider_machine.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.device_node_key_epoch AS provider_node ON provider_node.workspace_id = provider.workspace_id
             AND provider_node.network_id = provider.network_id AND provider_node.device_id = provider.id
             AND provider_node.epoch = provider.current_node_key_epoch AND provider_node.state = 'active'
             AND provider_node.valid_from <= pg_catalog.transaction_timestamp()
            JOIN mesh.workspace AS provider_workspace ON provider_workspace.id=contract.provider_workspace_id
             AND provider_workspace.state='active' AND provider_workspace.deleted_at IS NULL
            JOIN mesh.workspace AS consumer_workspace ON consumer_workspace.id=contract.consumer_workspace_id
             AND consumer_workspace.state='active' AND consumer_workspace.deleted_at IS NULL
            JOIN mesh.deployment AS deployment ON deployment.id=provider_workspace.deployment_id AND deployment.id=consumer_workspace.deployment_id
             AND deployment.id=contract.deployment_id AND deployment.id=endpoint_row.deployment_id
             AND deployment.state='active' AND deployment.recovery_state='verified' AND deployment.deleted_at IS NULL
             AND deployment.recovery_epoch=contract.recovery_epoch AND deployment.recovery_epoch=endpoint_row.recovery_epoch
             AND deployment.direct_sharing_ceiling_profile='no-additional-traffic-ceilings-v1'
            JOIN mesh.network AS provider_network ON provider_network.workspace_id = provider_workspace.id
             AND provider_network.id = endpoint_row.provider_network_id
             AND provider_network.state = 'active' AND provider_network.deleted_at IS NULL
             AND provider_network.authority_generation = contract.provider_authority_generation
             AND provider_network.authority_generation = endpoint_row.provider_authority_generation
            JOIN mesh.network AS consumer_network ON consumer_network.workspace_id = consumer_workspace.id
             AND consumer_network.id = endpoint_row.consumer_network_id
             AND consumer_network.state = 'active' AND consumer_network.deleted_at IS NULL
             AND consumer_network.authority_generation = contract.consumer_authority_generation
             AND consumer_network.authority_generation = endpoint_row.consumer_authority_generation
            JOIN mesh_ops.network_revision AS provider_revision ON provider_revision.workspace_id = provider_workspace.id
             AND provider_revision.network_id = provider_network.id
            JOIN mesh_ops.network_revision AS consumer_revision ON consumer_revision.workspace_id = consumer_workspace.id
             AND consumer_revision.network_id = consumer_network.id
            JOIN mesh.policy_release AS release ON release.workspace_id = consumer_workspace.id
             AND release.network_id = consumer_network.id AND release.policy_revision = consumer_revision.policy_revision
             AND release.state = 'active'
            JOIN mesh.compiled_policy_imported_resource_destination AS rule ON rule.workspace_id = consumer_workspace.id
             AND rule.network_id = consumer_network.id AND rule.policy_release_id = release.id
             AND rule.policy_revision = release.policy_revision
             AND rule.imported_resource_id = imported.id AND rule.imported_resource_version = imported.version
             AND rule.trust_contract_id = contract.id AND rule.trust_contract_version = contract.version
             AND rule.resource_export_id = export.id AND rule.resource_export_version = export.version
             AND rule.provider_workspace_id = provider_workspace.id AND rule.provider_network_id = provider_network.id
             AND rule.destination_resource_id = resource.id AND rule.resource_version = resource.version
             AND rule.target_generation = resource.target_generation AND rule.resource_semantic_hash = resource.semantic_hash
             AND rule.provider_authority_generation = provider_network.authority_generation
             AND rule.consumer_authority_generation = consumer_network.authority_generation
             AND rule.recovery_epoch = deployment.recovery_epoch AND rule.contract_expires_at = contract.expires_at
             AND rule.constraint_hash = contract.constraint_hash
             AND rule.provider_inventory_revision <= provider_revision.inventory_revision
             AND rule.provider_sharing_revision <= provider_revision.sharing_revision
             AND rule.consumer_sharing_revision <= consumer_revision.sharing_revision
            JOIN mesh.device AS consumer ON consumer.workspace_id = consumer_workspace.id AND consumer.network_id = consumer_network.id
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
            JOIN mesh.federation_alias_lease AS legacy ON legacy.id=endpoint_row.alias_lease_id
             AND legacy.deployment_id=deployment.id AND legacy.provider_workspace_id=provider_workspace.id
             AND legacy.provider_network_id=provider_network.id AND legacy.consumer_workspace_id=consumer_workspace.id
             AND legacy.consumer_network_id=consumer_network.id AND legacy.imported_resource_id=imported.id
             AND legacy.generation=endpoint_row.generation AND legacy.resource_alias=endpoint_row.resource_alias
             AND legacy.family=family(endpoint_row.resource_alias) AND legacy.state='reserved'
            JOIN mesh.device_alias_client_readiness AS readiness ON readiness.private_endpoint_id=endpoint_row.id
             AND readiness.deployment_id=deployment.id AND readiness.state='ready'
             AND readiness.provider_workspace_id=provider_workspace.id AND readiness.provider_network_id=provider_network.id
             AND readiness.consumer_workspace_id=consumer_workspace.id AND readiness.consumer_network_id=consumer_network.id
             AND readiness.endpoint_generation=endpoint_row.generation AND readiness.provider_device_id=provider.id
             AND readiness.consumer_device_id=consumer.id AND readiness.contract_version=contract.version
             AND readiness.imported_resource_version=imported.version AND readiness.resource_version=resource.version
             AND readiness.target_generation=resource.target_generation AND readiness.recovery_epoch=deployment.recovery_epoch
             AND readiness.created_at<=transaction_timestamp() AND readiness.expires_at>transaction_timestamp()
             AND readiness.expires_at<=LEAST(endpoint_row.expires_at,provider.expires_at,consumer.expires_at)
             AND readiness.provider_network_revision<=provider_revision.network_revision
             AND readiness.provider_sharing_revision<=provider_revision.sharing_revision
             AND readiness.consumer_network_revision<=consumer_revision.network_revision
             AND readiness.consumer_sharing_revision<=consumer_revision.sharing_revision
            JOIN mesh.device_alias_client_version AS provider_compat ON provider_compat.workspace_id=provider.workspace_id
             AND provider_compat.network_id=provider.network_id AND provider_compat.device_id=provider.id
             AND provider_compat.alias_version=1 AND provider_compat.session_generation=provider.session_generation
             AND provider_compat.machine_key_epoch=provider.current_machine_key_epoch AND provider_compat.node_key_epoch=provider.current_node_key_epoch
             AND provider_compat.node_public_key=provider_node.public_key
            CROSS JOIN LATERAL (SELECT array_agg(host(lease.address)||CASE lease.family WHEN 4 THEN '/32' ELSE '/128' END ORDER BY lease.family) AS addresses,
                array_agg(lease.public_id ORDER BY lease.public_id) AS lease_ids,min(lease.expires_at) AS expires_at,count(*) AS family_count,bool_or(lease.family=4) AS ipv4,bool_or(lease.family=6) AS ipv6
                FROM mesh.device_alias_lease AS lease
                JOIN mesh.address_realm AS realm ON realm.id=lease.address_realm_id AND realm.deployment_id=deployment.id
                 AND realm.kind='federation_alias' AND realm.state='active' AND realm.deleted_at IS NULL
                JOIN mesh.address_pool AS pool ON pool.id=lease.address_pool_id AND pool.deployment_id=deployment.id
                 AND pool.address_realm_id=realm.id AND pool.family=lease.family AND pool.workspace_id IS NULL
                 AND pool.purpose='federation_resource_alias' AND pool.state='active' AND pool.deleted_at IS NULL AND lease.address << pool.prefix
                WHERE lease.private_endpoint_id=endpoint_row.id AND lease.alias_role='resource'
                  AND lease.deployment_id=deployment.id AND lease.endpoint_generation=endpoint_row.generation
                  AND lease.recovery_epoch=deployment.recovery_epoch AND lease.state='reserved'
                  AND lease.provider_workspace_id=provider_workspace.id AND lease.provider_network_id=provider_network.id
                  AND lease.consumer_workspace_id=consumer_workspace.id AND lease.consumer_network_id=consumer_network.id
                  AND lease.owner_workspace_id=provider.workspace_id AND lease.owner_network_id=provider.network_id AND lease.owner_device_id=provider.id
                  AND lease.session_generation=provider.session_generation AND lease.machine_key_epoch=provider.current_machine_key_epoch
                  AND lease.node_key_epoch=provider.current_node_key_epoch AND lease.node_public_key=provider_node.public_key
                  AND lease.resource_version=resource.version AND lease.target_generation=resource.target_generation
                  AND lease.created_at<=transaction_timestamp() AND lease.expires_at>transaction_timestamp()
                  AND lease.expires_at<=LEAST(endpoint_row.expires_at,provider.expires_at)
                  AND (lease.family=4 AND realm.ipv4_enabled OR lease.family=6 AND realm.ipv6_enabled)) AS provider_aliases
            JOIN mesh.device_alias_client_version AS consumer_compat ON consumer_compat.workspace_id=consumer.workspace_id
             AND consumer_compat.network_id=consumer.network_id AND consumer_compat.device_id=consumer.id
             AND consumer_compat.alias_version=1 AND consumer_compat.session_generation=consumer.session_generation
             AND consumer_compat.machine_key_epoch=consumer.current_machine_key_epoch AND consumer_compat.node_key_epoch=consumer.current_node_key_epoch
             AND consumer_compat.node_public_key=consumer_node.public_key
            CROSS JOIN LATERAL (SELECT array_agg(host(lease.address)||CASE lease.family WHEN 4 THEN '/32' ELSE '/128' END ORDER BY lease.family) AS addresses,
                array_agg(lease.public_id ORDER BY lease.public_id) AS lease_ids,min(lease.expires_at) AS expires_at,count(*) AS family_count,bool_or(lease.family=4) AS ipv4,bool_or(lease.family=6) AS ipv6
                FROM mesh.device_alias_lease AS lease
                JOIN mesh.address_realm AS realm ON realm.id=lease.address_realm_id AND realm.deployment_id=deployment.id
                 AND realm.kind='federation_alias' AND realm.state='active' AND realm.deleted_at IS NULL
                JOIN mesh.address_pool AS pool ON pool.id=lease.address_pool_id AND pool.deployment_id=deployment.id
                 AND pool.address_realm_id=realm.id AND pool.family=lease.family AND pool.workspace_id IS NULL
                 AND pool.purpose='federation_consumer_alias' AND pool.state='active' AND pool.deleted_at IS NULL AND lease.address << pool.prefix
                WHERE lease.private_endpoint_id=endpoint_row.id AND lease.alias_role='consumer_source'
                  AND lease.deployment_id=deployment.id AND lease.endpoint_generation=endpoint_row.generation
                  AND lease.recovery_epoch=deployment.recovery_epoch AND lease.state='reserved'
                  AND lease.provider_workspace_id=provider_workspace.id AND lease.provider_network_id=provider_network.id
                  AND lease.consumer_workspace_id=consumer_workspace.id AND lease.consumer_network_id=consumer_network.id
                  AND lease.owner_workspace_id=consumer.workspace_id AND lease.owner_network_id=consumer.network_id AND lease.owner_device_id=consumer.id
                  AND lease.session_generation=consumer.session_generation AND lease.machine_key_epoch=consumer.current_machine_key_epoch
                  AND lease.node_key_epoch=consumer.current_node_key_epoch AND lease.node_public_key=consumer_node.public_key
                  AND lease.resource_version=resource.version AND lease.target_generation=resource.target_generation
                  AND lease.created_at<=transaction_timestamp() AND lease.expires_at>transaction_timestamp()
                  AND lease.expires_at<=LEAST(endpoint_row.expires_at,consumer.expires_at)
                  AND (lease.family=4 AND realm.ipv4_enabled OR lease.family=6 AND realm.ipv6_enabled)) AS consumer_aliases
            WHERE contract.id = endpoint_row.trust_contract_id AND contract.state = 'active'
              AND contract.provider_workspace_id = endpoint_row.provider_workspace_id
              AND contract.provider_network_id = endpoint_row.provider_network_id
              AND contract.consumer_workspace_id = endpoint_row.consumer_workspace_id
              AND contract.consumer_network_id = endpoint_row.consumer_network_id
              AND endpoint_row.state='provisioning' AND contract.version = endpoint_row.contract_version AND contract.constraint_hash = endpoint_row.constraint_hash
              AND contract.expires_at > pg_catalog.transaction_timestamp() AND endpoint_row.expires_at > pg_catalog.transaction_timestamp()
              AND ((self_network = provider.network_id AND self_id = provider.id)
                OR (self_network = consumer.network_id AND self_id = consumer.id))
              AND EXISTS (SELECT 1 FROM mesh.device_alias_lease AS resource_lease
                WHERE resource_lease.private_endpoint_id=endpoint_row.id AND resource_lease.alias_role='resource'
                  AND resource_lease.family=legacy.family AND resource_lease.address=legacy.resource_alias
                  AND resource_lease.address_pool_id=legacy.address_pool_id AND resource_lease.address_realm_id=legacy.address_realm_id
                  AND resource_lease.state='reserved')
              AND provider_aliases.family_count BETWEEN 1 AND 2
              AND consumer_aliases.family_count=provider_aliases.family_count
              AND readiness.lease_public_ids=ARRAY(SELECT lease_id FROM unnest(provider_aliases.lease_ids || consumer_aliases.lease_ids) AS lease_id ORDER BY lease_id)
              AND consumer_aliases.ipv4 IS NOT DISTINCT FROM provider_aliases.ipv4
              AND consumer_aliases.ipv6 IS NOT DISTINCT FROM provider_aliases.ipv6
              AND EXISTS (SELECT 1 FROM mesh.address_realm AS realm WHERE realm.deployment_id=deployment.id
                AND realm.kind='federation_alias' AND realm.state='active' AND realm.deleted_at IS NULL
                AND realm.ipv4_enabled=COALESCE(provider_aliases.ipv4,FALSE) AND realm.ipv6_enabled=COALESCE(provider_aliases.ipv6,FALSE))
            ORDER BY rule.access_rule_public_id LIMIT p_limit - edge_count
        LOOP
            RETURN NEXT edge;
            edge_count := edge_count + 1;
            IF edge_count >= p_limit THEN
                    PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
                RETURN;
            END IF;
        END LOOP;
    END LOOP;
        PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
EXCEPTION WHEN OTHERS THEN
        PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', COALESCE(previous_remote, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_map_edges_v1(BYTEA,BYTEA,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;


-- No serving writer is granted here. A later guarded worker must produce this
-- evidence in the same transaction; operator fixtures cannot silently omit it.
CREATE FUNCTION mesh_ops.enforce_device_alias_readiness_transition_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $function$
DECLARE leases UUID[]; family_count INTEGER; deadline TIMESTAMPTZ;
    previous_workspace TEXT := current_setting('mesh.workspace_id',TRUE);
    previous_network TEXT := current_setting('mesh.network_id',TRUE);
    previous_deployment TEXT := current_setting('mesh.device_alias_deployment_id',TRUE);
    provider_revision_matches BOOLEAN;
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias readiness history is retained'; END IF;
    IF TG_OP='UPDATE' THEN
        IF NEW.updated_at>clock_timestamp() OR OLD.state<>'ready' OR NEW.state<>'withdrawn' OR NEW.version<>OLD.version+1
          OR NEW.updated_at<OLD.updated_at
          OR NEW.provider_network_revision<=OLD.provider_network_revision
          OR NEW.provider_sharing_revision<=OLD.provider_sharing_revision
          OR NEW.consumer_network_revision<=OLD.consumer_network_revision
          OR NEW.consumer_sharing_revision<=OLD.consumer_sharing_revision
          OR (to_jsonb(OLD)-ARRAY['state','version','updated_at','provider_network_revision','provider_sharing_revision','consumer_network_revision','consumer_sharing_revision'])
             IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['state','version','updated_at','provider_network_revision','provider_sharing_revision','consumer_network_revision','consumer_sharing_revision']) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='invalid Device alias readiness transition';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.updated_at>clock_timestamp() OR NEW.state<>'ready' OR NEW.version<>1 OR NEW.created_at<>NEW.updated_at OR NEW.expires_at<=clock_timestamp()
      OR array_ndims(NEW.lease_public_ids)<>1 OR array_lower(NEW.lease_public_ids,1)<>1
      OR NEW.lease_public_ids IS DISTINCT FROM ARRAY(SELECT DISTINCT value FROM unnest(NEW.lease_public_ids) AS value ORDER BY value)
      OR EXISTS(SELECT 1 FROM unnest(NEW.lease_public_ids) AS value WHERE value IS NULL OR get_byte(uuid_send(value),6)>>4<>7) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='invalid Device alias readiness proof';
    END IF;
    -- The migration owner also obeys exact Network revision RLS. Validate each
    -- side under its derived scope; never broaden its revision policy.
    PERFORM set_config('mesh.device_alias_deployment_id',NEW.deployment_id::TEXT,TRUE);
    PERFORM set_config('mesh.workspace_id',NEW.provider_workspace_id::TEXT,TRUE);
    PERFORM set_config('mesh.network_id',NEW.provider_network_id::TEXT,TRUE);
    SELECT EXISTS(SELECT 1 FROM mesh_ops.network_revision AS revision
      WHERE revision.workspace_id=NEW.provider_workspace_id AND revision.network_id=NEW.provider_network_id
        AND revision.network_revision=NEW.provider_network_revision AND revision.sharing_revision=NEW.provider_sharing_revision)
      INTO provider_revision_matches;
    PERFORM set_config('mesh.workspace_id',NEW.consumer_workspace_id::TEXT,TRUE);
    PERFORM set_config('mesh.network_id',NEW.consumer_network_id::TEXT,TRUE);
    IF NOT EXISTS (SELECT 1 FROM mesh.private_endpoint AS endpoint
       JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
       JOIN mesh.imported_resource AS imported ON imported.id=endpoint.imported_resource_id
       JOIN mesh.resource AS resource ON resource.id=contract.resource_id
       JOIN mesh.resource_device_target AS target ON target.resource_id=resource.id AND target.target_generation=resource.target_generation
       JOIN mesh.deployment AS deployment ON deployment.id=endpoint.deployment_id
       WHERE endpoint.id=NEW.private_endpoint_id AND endpoint.deployment_id=NEW.deployment_id
         AND (endpoint.provider_workspace_id,endpoint.provider_network_id,endpoint.consumer_workspace_id,endpoint.consumer_network_id)=
             (NEW.provider_workspace_id,NEW.provider_network_id,NEW.consumer_workspace_id,NEW.consumer_network_id)
         AND endpoint.state='provisioning' AND endpoint.generation=NEW.endpoint_generation
         AND endpoint.recovery_epoch=NEW.recovery_epoch AND deployment.recovery_epoch=NEW.recovery_epoch
         AND deployment.state='active' AND deployment.recovery_state='verified'
         AND endpoint.contract_version=NEW.contract_version AND contract.version=NEW.contract_version AND contract.state='active'
         AND endpoint.constraint_hash=contract.constraint_hash AND imported.state='active' AND imported.version=NEW.imported_resource_version
         AND endpoint.imported_resource_version=imported.version AND resource.state='active' AND resource.deleted_at IS NULL
         AND resource.kind='device' AND resource.version=NEW.resource_version AND resource.target_generation=NEW.target_generation
         AND contract.resource_version=resource.version AND contract.target_generation=resource.target_generation
         AND contract.resource_semantic_hash=resource.semantic_hash AND target.state='active' AND target.device_id=NEW.provider_device_id
         AND NEW.expires_at<=LEAST(endpoint.expires_at,contract.expires_at)
         AND provider_revision_matches
         AND EXISTS(SELECT 1 FROM mesh_ops.network_revision AS revision WHERE revision.workspace_id=NEW.consumer_workspace_id
           AND revision.network_id=NEW.consumer_network_id AND revision.network_revision=NEW.consumer_network_revision AND revision.sharing_revision=NEW.consumer_sharing_revision)
         AND EXISTS(SELECT 1 FROM mesh.compiled_policy_imported_resource_destination AS rule
           JOIN mesh_ops.network_revision AS revision ON revision.workspace_id=rule.workspace_id AND revision.network_id=rule.network_id
           JOIN mesh.policy_release AS release ON release.workspace_id=rule.workspace_id AND release.network_id=rule.network_id
             AND release.policy_revision=revision.policy_revision AND release.id=rule.policy_release_id AND rule.policy_revision=release.policy_revision AND release.state='active'
           WHERE rule.workspace_id=NEW.consumer_workspace_id AND rule.network_id=NEW.consumer_network_id
             AND rule.source_device_id=NEW.consumer_device_id AND rule.trust_contract_id=contract.id
             AND rule.imported_resource_id=imported.id AND rule.imported_resource_version=imported.version
             AND rule.trust_contract_version=contract.version AND rule.resource_version=resource.version
             AND rule.target_generation=resource.target_generation AND rule.recovery_epoch=NEW.recovery_epoch)) THEN
       RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias readiness authority mismatch';
    END IF;
    SELECT array_agg(lease.public_id ORDER BY lease.public_id),min(lease.expires_at),count(*)
      INTO leases,deadline,family_count
    FROM mesh.device_alias_lease AS lease
    JOIN mesh.device AS device ON device.id=lease.owner_device_id AND device.workspace_id=lease.owner_workspace_id AND device.network_id=lease.owner_network_id
    JOIN mesh.device_node_key_epoch AS node_key ON node_key.device_id=device.id AND node_key.epoch=device.current_node_key_epoch AND node_key.public_key=lease.node_public_key AND node_key.state='active' AND node_key.valid_from<=clock_timestamp()
    JOIN mesh.device_machine_key_epoch AS machine ON machine.device_id=device.id AND machine.epoch=device.current_machine_key_epoch AND machine.state='active' AND machine.valid_from<=clock_timestamp()
    JOIN mesh.device_alias_client_version AS compatibility ON compatibility.device_id=device.id AND compatibility.workspace_id=device.workspace_id AND compatibility.network_id=device.network_id
      AND compatibility.alias_version=1 AND compatibility.session_generation=device.session_generation
      AND compatibility.machine_key_epoch=device.current_machine_key_epoch AND compatibility.node_key_epoch=device.current_node_key_epoch AND compatibility.node_public_key=node_key.public_key
    JOIN mesh.address_realm AS realm ON realm.id=lease.address_realm_id AND realm.deployment_id=NEW.deployment_id AND realm.kind='federation_alias' AND realm.state='active' AND realm.deleted_at IS NULL
    JOIN mesh.address_pool AS pool ON pool.id=lease.address_pool_id AND pool.address_realm_id=realm.id AND pool.deployment_id=NEW.deployment_id AND pool.family=lease.family
      AND pool.workspace_id IS NULL AND pool.state='active' AND pool.deleted_at IS NULL AND lease.address<<pool.prefix
      AND pool.purpose=CASE lease.alias_role WHEN 'resource' THEN 'federation_resource_alias' ELSE 'federation_consumer_alias' END
    WHERE lease.private_endpoint_id=NEW.private_endpoint_id AND lease.deployment_id=NEW.deployment_id
      AND (lease.provider_workspace_id,lease.provider_network_id,lease.consumer_workspace_id,lease.consumer_network_id)=
          (NEW.provider_workspace_id,NEW.provider_network_id,NEW.consumer_workspace_id,NEW.consumer_network_id)
      AND lease.endpoint_generation=NEW.endpoint_generation AND lease.recovery_epoch=NEW.recovery_epoch
      AND lease.resource_version=NEW.resource_version AND lease.target_generation=NEW.target_generation
      AND lease.state='reserved' AND lease.expires_at>clock_timestamp() AND NEW.expires_at<=device.expires_at
      AND device.state='active' AND device.deleted_at IS NULL AND device.created_at<=clock_timestamp()
      AND lease.session_generation=device.session_generation AND lease.machine_key_epoch=device.current_machine_key_epoch AND lease.node_key_epoch=device.current_node_key_epoch
      AND (lease.alias_role='resource' AND lease.owner_device_id=NEW.provider_device_id OR lease.alias_role='consumer_source' AND lease.owner_device_id=NEW.consumer_device_id)
      AND (lease.family=4 AND realm.ipv4_enabled OR lease.family=6 AND realm.ipv6_enabled);
    IF leases IS DISTINCT FROM NEW.lease_public_ids OR NEW.expires_at>deadline OR family_count NOT IN (2,4)
       OR NOT EXISTS(SELECT 1 FROM mesh.address_realm AS realm WHERE realm.deployment_id=NEW.deployment_id AND realm.kind='federation_alias'
           AND realm.state='active' AND realm.deleted_at IS NULL AND family_count=2*(realm.ipv4_enabled::INTEGER+realm.ipv6_enabled::INTEGER)) THEN
       RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias readiness lease pins mismatch';
    END IF;
    PERFORM set_config('mesh.workspace_id',COALESCE(previous_workspace,''),TRUE);
    PERFORM set_config('mesh.network_id',COALESCE(previous_network,''),TRUE);
    PERFORM set_config('mesh.device_alias_deployment_id',COALESCE(previous_deployment,''),TRUE);
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('mesh.workspace_id',COALESCE(previous_workspace,''),TRUE);
    PERFORM set_config('mesh.network_id',COALESCE(previous_network,''),TRUE);
    PERFORM set_config('mesh.device_alias_deployment_id',COALESCE(previous_deployment,''),TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_device_alias_readiness_transition_v1() FROM PUBLIC;
CREATE TRIGGER device_alias_readiness_transition BEFORE INSERT OR UPDATE OR DELETE ON mesh.device_alias_client_readiness
  FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_alias_readiness_transition_v1();
CREATE TRIGGER device_alias_readiness_authority_mutation AFTER INSERT OR UPDATE OR DELETE ON mesh.device_alias_client_readiness
  FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_alias_client_readiness','public_id');

CREATE FUNCTION mesh_audit.enforce_device_alias_readiness_evidence_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $function$
DECLARE change_id UUID; side RECORD; endpoint_public_id UUID; mutated_readiness JSONB;
BEGIN
    SELECT mutation.change_public_id INTO STRICT change_id FROM mesh_audit.authority_mutation AS mutation
    WHERE mutation.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT AND mutation.aggregate_kind='device_alias_client_readiness'
      AND mutation.row_public_id=NEW.public_id AND mutation.after_version=NEW.version;
    SELECT endpoint.public_id INTO STRICT endpoint_public_id FROM mesh.private_endpoint AS endpoint WHERE endpoint.id=NEW.private_endpoint_id;
    SELECT jsonb_agg(jsonb_build_object('public_id',readiness.public_id,'version',mutation.after_version) ORDER BY readiness.public_id)
      INTO mutated_readiness FROM mesh_audit.authority_mutation AS mutation
      JOIN mesh.device_alias_client_readiness AS readiness ON readiness.public_id=mutation.row_public_id
      WHERE mutation.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT AND mutation.change_public_id=change_id
        AND mutation.aggregate_kind='device_alias_client_readiness' AND readiness.private_endpoint_id=NEW.private_endpoint_id;
    FOR side IN SELECT * FROM (VALUES
      (NEW.provider_workspace_id,NEW.provider_network_id,NEW.provider_network_revision,NEW.provider_sharing_revision),
      (NEW.consumer_workspace_id,NEW.consumer_network_id,NEW.consumer_network_revision,NEW.consumer_sharing_revision)
    ) AS scopes(workspace_id,network_id,network_revision,sharing_revision) LOOP
      IF NOT EXISTS(SELECT 1 FROM mesh_audit.audit_event_identity AS identity
        JOIN mesh_audit.audit_event AS event ON event.event_identity_id=identity.id AND event.occurred_at=identity.occurred_at
        JOIN mesh_audit.audit_stream AS stream ON stream.id=identity.stream_id
        WHERE identity.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT AND identity.change_public_id=change_id
          AND stream.workspace_id=side.workspace_id AND stream.network_id=side.network_id AND event.target_kind='device_alias_client_readiness'
          AND event.payload->>'endpoint_public_id'=endpoint_public_id::TEXT AND event.payload->'mutated_readiness'=mutated_readiness
          AND event.payload->>'network_revision'=side.network_revision::TEXT AND event.payload->>'sharing_revision'=side.sharing_revision::TEXT)
        OR NOT EXISTS(SELECT 1 FROM mesh_ops.outbox_event AS event WHERE event.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT
          AND event.change_public_id=change_id AND event.workspace_id=side.workspace_id AND event.network_id=side.network_id
          AND event.network_revision=side.network_revision AND event.aggregate_kind='device_alias_client_readiness'
          AND event.payload->>'endpoint_public_id'=endpoint_public_id::TEXT AND event.payload->>'subsystem'='sharing'
          AND event.payload->>'subsystem_revision'=side.sharing_revision::TEXT) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='bilateral Device alias readiness evidence incomplete';
      END IF;
    END LOOP;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.enforce_device_alias_readiness_evidence_v1() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER device_alias_readiness_evidence AFTER INSERT OR UPDATE ON mesh.device_alias_client_readiness
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mesh_audit.enforce_device_alias_readiness_evidence_v1();
