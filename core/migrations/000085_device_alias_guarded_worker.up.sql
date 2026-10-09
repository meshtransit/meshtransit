-- Guarded client-only reservation and readiness. No gateway, route or DNS
-- readiness is reused. The database operator provisions an isolated NOLOGIN
-- owner and exposes only bounded entry points to mesh_worker after migration.
GRANT USAGE ON SCHEMA mesh,mesh_ops,mesh_audit TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_workspace_id(),mesh_ops.current_network_id() TO mesh_device_alias_writer;
GRANT SELECT ON mesh.deployment,mesh.principal TO mesh_device_alias_writer;
CREATE POLICY private_endpoint_alias_worker_read ON mesh.private_endpoint FOR SELECT TO mesh_device_alias_writer USING (public_id=NULLIF(current_setting('mesh.alias_worker_endpoint_public_id',TRUE),'')::UUID AND EXISTS(SELECT 1 FROM mesh.deployment AS deployment WHERE deployment.id=private_endpoint.deployment_id AND deployment.installation_public_id=NULLIF(current_setting('mesh.alias_worker_deployment_public_id',TRUE),'')::UUID));
GRANT SELECT,UPDATE(id) ON mesh.private_endpoint TO mesh_device_alias_writer;
CREATE POLICY private_endpoint_alias_worker_lock ON mesh.private_endpoint FOR UPDATE TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)) WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
CREATE POLICY network_alias_worker_read ON mesh.network FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.network TO mesh_device_alias_writer;
CREATE POLICY device_alias_worker_read ON mesh.device FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device TO mesh_device_alias_writer;
CREATE POLICY device_alias_worker_lock ON mesh.device FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(id) ON mesh.device TO mesh_device_alias_writer;
CREATE POLICY device_machine_key_epoch_alias_worker_read ON mesh.device_machine_key_epoch FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device_machine_key_epoch TO mesh_device_alias_writer;
CREATE POLICY device_machine_key_epoch_alias_worker_lock ON mesh.device_machine_key_epoch FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(id) ON mesh.device_machine_key_epoch TO mesh_device_alias_writer;
CREATE POLICY device_node_key_epoch_alias_worker_read ON mesh.device_node_key_epoch FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device_node_key_epoch TO mesh_device_alias_writer;
CREATE POLICY device_node_key_epoch_alias_worker_lock ON mesh.device_node_key_epoch FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(id) ON mesh.device_node_key_epoch TO mesh_device_alias_writer;
CREATE POLICY resource_alias_worker_read ON mesh.resource FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.resource TO mesh_device_alias_writer;
CREATE POLICY resource_alias_worker_lock ON mesh.resource FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(id) ON mesh.resource TO mesh_device_alias_writer;
CREATE POLICY resource_device_target_alias_worker_read ON mesh.resource_device_target FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.resource_device_target TO mesh_device_alias_writer;
CREATE POLICY resource_device_target_alias_worker_lock ON mesh.resource_device_target FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(id) ON mesh.resource_device_target TO mesh_device_alias_writer;
CREATE POLICY imported_resource_alias_worker_read ON mesh.imported_resource FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.imported_resource TO mesh_device_alias_writer;
CREATE POLICY imported_resource_alias_worker_lock ON mesh.imported_resource FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(id) ON mesh.imported_resource TO mesh_device_alias_writer;
CREATE POLICY device_alias_client_version_alias_worker_read ON mesh.device_alias_client_version FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.device_alias_client_version TO mesh_device_alias_writer;
CREATE POLICY policy_release_alias_worker_read ON mesh.policy_release FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.policy_release TO mesh_device_alias_writer;
CREATE POLICY compiled_policy_imported_resource_destination_alias_worker_read ON mesh.compiled_policy_imported_resource_destination FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh.compiled_policy_imported_resource_destination TO mesh_device_alias_writer;
CREATE POLICY trust_contract_alias_worker_read ON mesh.trust_contract FOR SELECT TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.trust_contract TO mesh_device_alias_writer;
CREATE POLICY trust_contract_alias_worker_lock ON mesh.trust_contract FOR UPDATE TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)) WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT UPDATE(id) ON mesh.trust_contract TO mesh_device_alias_writer;
CREATE POLICY share_offer_alias_worker_read ON mesh.share_offer FOR SELECT TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.share_offer TO mesh_device_alias_writer;
CREATE POLICY resource_export_alias_worker_read ON mesh.resource_export FOR SELECT TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.resource_export TO mesh_device_alias_writer;
CREATE POLICY resource_export_alias_worker_lock ON mesh.resource_export FOR UPDATE TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)) WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT UPDATE(id) ON mesh.resource_export TO mesh_device_alias_writer;
CREATE POLICY resource_export_constraint_alias_worker_read ON mesh.resource_export_constraint FOR SELECT TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.resource_export_constraint TO mesh_device_alias_writer;
CREATE POLICY network_revision_alias_worker_read ON mesh_ops.network_revision FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh_ops.network_revision TO mesh_device_alias_writer;
CREATE POLICY audit_stream_alias_worker_read ON mesh_audit.audit_stream FOR SELECT TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT SELECT ON mesh_audit.audit_stream TO mesh_device_alias_writer;
CREATE POLICY audit_stream_alias_worker_lock ON mesh_audit.audit_stream FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(id) ON mesh_audit.audit_stream TO mesh_device_alias_writer;
CREATE POLICY address_realm_alias_worker_read ON mesh.address_realm FOR SELECT TO mesh_device_alias_writer USING (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT);
GRANT SELECT ON mesh.address_realm TO mesh_device_alias_writer;
CREATE POLICY address_realm_alias_worker_lock ON mesh.address_realm FOR UPDATE TO mesh_device_alias_writer USING (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT) WITH CHECK (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT);
GRANT UPDATE(id) ON mesh.address_realm TO mesh_device_alias_writer;
CREATE POLICY address_pool_alias_worker_read ON mesh.address_pool FOR SELECT TO mesh_device_alias_writer USING (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT);
GRANT SELECT ON mesh.address_pool TO mesh_device_alias_writer;
CREATE POLICY address_pool_alias_worker_lock ON mesh.address_pool FOR UPDATE TO mesh_device_alias_writer USING (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT) WITH CHECK (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT);
GRANT UPDATE(id) ON mesh.address_pool TO mesh_device_alias_writer;
CREATE POLICY federation_alias_lease_alias_worker_read ON mesh.federation_alias_lease FOR SELECT TO mesh_device_alias_writer USING (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT);
GRANT SELECT ON mesh.federation_alias_lease TO mesh_device_alias_writer;
CREATE POLICY federation_alias_lease_alias_worker_lock ON mesh.federation_alias_lease FOR UPDATE TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)) WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT UPDATE(id) ON mesh.federation_alias_lease TO mesh_device_alias_writer;
CREATE POLICY node_address_lease_alias_worker_read ON mesh.node_address_lease FOR SELECT TO mesh_device_alias_writer USING (EXISTS(SELECT 1 FROM mesh.address_pool AS pool WHERE pool.id=node_address_lease.address_pool_id AND pool.deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.node_address_lease TO mesh_device_alias_writer;
CREATE POLICY device_alias_lease_alias_worker_read ON mesh.device_alias_lease FOR SELECT TO mesh_device_alias_writer USING (deployment_id=NULLIF(current_setting('mesh.device_alias_deployment_id',TRUE),'')::BIGINT);
GRANT SELECT ON mesh.device_alias_lease TO mesh_device_alias_writer;
CREATE POLICY device_alias_client_readiness_alias_worker_read ON mesh.device_alias_client_readiness FOR SELECT TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.device_alias_client_readiness TO mesh_device_alias_writer;
CREATE POLICY workspace_alias_worker_read ON mesh.workspace FOR SELECT TO mesh_device_alias_writer USING (id IN (NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT));
GRANT SELECT ON mesh.workspace TO mesh_device_alias_writer;
CREATE POLICY network_revision_alias_worker_update ON mesh_ops.network_revision FOR UPDATE TO mesh_device_alias_writer USING ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT))) WITH CHECK ((workspace_id,network_id) IN ((NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT),(NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)));
GRANT UPDATE(network_revision,sharing_revision,updated_at) ON mesh_ops.network_revision TO mesh_device_alias_writer;
CREATE POLICY device_alias_lease_alias_worker_update ON mesh.device_alias_lease FOR UPDATE TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)) WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT UPDATE(state,quarantine_until,version,updated_at,provider_network_revision,provider_sharing_revision,consumer_network_revision,consumer_sharing_revision) ON mesh.device_alias_lease TO mesh_device_alias_writer;
CREATE POLICY device_alias_client_readiness_alias_worker_update ON mesh.device_alias_client_readiness FOR UPDATE TO mesh_device_alias_writer USING ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT)) WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT));
GRANT UPDATE(state,version,updated_at,provider_network_revision,provider_sharing_revision,consumer_network_revision,consumer_sharing_revision) ON mesh.device_alias_client_readiness TO mesh_device_alias_writer;
CREATE POLICY device_alias_lease_alias_worker_insert ON mesh.device_alias_lease FOR INSERT TO mesh_device_alias_writer WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT) AND private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT);
GRANT INSERT ON mesh.device_alias_lease TO mesh_device_alias_writer;
GRANT USAGE ON SEQUENCE mesh.device_alias_lease_id_seq TO mesh_device_alias_writer;
CREATE POLICY device_alias_client_readiness_alias_worker_insert ON mesh.device_alias_client_readiness FOR INSERT TO mesh_device_alias_writer WITH CHECK ((provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id)=(NULLIF(current_setting('mesh.alias_worker_provider_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_provider_network_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_workspace_id',TRUE),'')::BIGINT,NULLIF(current_setting('mesh.alias_worker_consumer_network_id',TRUE),'')::BIGINT) AND private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT);
GRANT INSERT ON mesh.device_alias_client_readiness TO mesh_device_alias_writer;
GRANT USAGE ON SEQUENCE mesh.device_alias_client_readiness_id_seq TO mesh_device_alias_writer;
-- Existing cursor storage has no RLS. Only this NOLOGIN owner gets table
-- capability; the internal allocator always binds pool and Deployment explicitly.
GRANT SELECT,INSERT,UPDATE ON mesh_ops.federation_alias_pool_cursor TO mesh_device_alias_writer;
CREATE POLICY authority_mutation_alias_worker_read ON mesh_audit.authority_mutation FOR SELECT TO mesh_device_alias_writer
 USING(transaction_id=(pg_current_xact_id()::TEXT)::BIGINT AND change_public_id=NULLIF(current_setting('mesh.change_public_id',TRUE),'')::UUID);
GRANT SELECT ON mesh_audit.authority_mutation TO mesh_device_alias_writer;
CREATE POLICY audit_identity_alias_worker_read ON mesh_audit.audit_event_identity FOR SELECT TO mesh_device_alias_writer
 USING(EXISTS(SELECT 1 FROM mesh_audit.audit_stream AS stream WHERE stream.id=audit_event_identity.stream_id));
GRANT SELECT ON mesh_audit.audit_event_identity TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.reserve_device_aliases_internal_v1(UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[]) TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_device_alias_map_edges_v1(BYTEA,BYTEA,INTEGER) TO mesh_device_alias_writer;
GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence(BIGINT,UUID,UUID,BIGINT,BYTEA,BYTEA,TEXT,UUID,BIGINT,BIGINT,UUID,TEXT,TEXT,UUID,BYTEA,BYTEA,JSONB,TEXT,JSONB) TO mesh_device_alias_writer;
CREATE FUNCTION mesh_ops.save_device_alias_worker_context_v1() RETURNS JSONB
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $function$
 SELECT jsonb_object_agg(name,COALESCE(current_setting(name,TRUE),'')) FROM unnest(ARRAY['mesh.workspace_id','mesh.network_id','mesh.share_provider_workspace_id','mesh.share_provider_network_id','mesh.share_consumer_workspace_id','mesh.share_consumer_network_id','mesh.device_alias_deployment_id','mesh.change_public_id','mesh.alias_worker_deployment_public_id','mesh.alias_worker_endpoint_public_id','mesh.alias_worker_endpoint_id','mesh.alias_worker_provider_workspace_id','mesh.alias_worker_provider_network_id','mesh.alias_worker_consumer_workspace_id','mesh.alias_worker_consumer_network_id','mesh.alias_map_provider_workspace_id','mesh.alias_map_provider_network_id','mesh.alias_map_consumer_workspace_id','mesh.alias_map_consumer_network_id','mesh.alias_map_endpoint_id','mesh.direct_map_remote_network_id']) AS name
$function$;
CREATE FUNCTION mesh_ops.restore_device_alias_worker_context_v1(p_context JSONB) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $function$
DECLARE setting RECORD;
BEGIN
 FOR setting IN SELECT key,value FROM jsonb_each_text(p_context) LOOP PERFORM set_config(setting.key,setting.value,TRUE); END LOOP;
END;
$function$;
CREATE FUNCTION mesh_ops.derive_device_alias_worker_scope_v1(p_deployment UUID,p_endpoint UUID) RETURNS mesh.private_endpoint
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $function$
DECLARE endpoint mesh.private_endpoint%ROWTYPE; name TEXT;
BEGIN
 FOREACH name IN ARRAY ARRAY['mesh.workspace_id','mesh.network_id','mesh.share_provider_workspace_id','mesh.share_provider_network_id','mesh.share_consumer_workspace_id','mesh.share_consumer_network_id','mesh.device_alias_deployment_id','mesh.change_public_id','mesh.alias_worker_deployment_public_id','mesh.alias_worker_endpoint_public_id','mesh.alias_worker_endpoint_id','mesh.alias_worker_provider_workspace_id','mesh.alias_worker_provider_network_id','mesh.alias_worker_consumer_workspace_id','mesh.alias_worker_consumer_network_id','mesh.alias_map_provider_workspace_id','mesh.alias_map_provider_network_id','mesh.alias_map_consumer_workspace_id','mesh.alias_map_consumer_network_id','mesh.alias_map_endpoint_id','mesh.direct_map_remote_network_id'] LOOP PERFORM set_config(name,'',TRUE); END LOOP;
 IF p_deployment IS NULL OR p_endpoint IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias worker scope'; END IF;
 PERFORM set_config('mesh.alias_worker_deployment_public_id',p_deployment::TEXT,TRUE);
 PERFORM set_config('mesh.alias_worker_endpoint_public_id',p_endpoint::TEXT,TRUE);
 SELECT selected.* INTO STRICT endpoint FROM mesh.private_endpoint AS selected JOIN mesh.deployment AS deployment ON deployment.id=selected.deployment_id
 WHERE selected.public_id=p_endpoint AND deployment.installation_public_id=p_deployment;
 PERFORM set_config('mesh.alias_worker_endpoint_id',endpoint.id::TEXT,TRUE);
 PERFORM set_config('mesh.device_alias_deployment_id',endpoint.deployment_id::TEXT,TRUE);
 PERFORM set_config('mesh.alias_worker_provider_workspace_id',endpoint.provider_workspace_id::TEXT,TRUE);
 PERFORM set_config('mesh.alias_worker_provider_network_id',endpoint.provider_network_id::TEXT,TRUE);
 PERFORM set_config('mesh.alias_worker_consumer_workspace_id',endpoint.consumer_workspace_id::TEXT,TRUE);
 PERFORM set_config('mesh.alias_worker_consumer_network_id',endpoint.consumer_network_id::TEXT,TRUE);
 RETURN endpoint;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Device alias worker scope unavailable';
END;
$function$;
CREATE FUNCTION mesh_ops.device_alias_change_proof_internal_v1(p_endpoint UUID,p_change UUID,p_kind TEXT) RETURNS JSONB
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $function$
DECLARE members JSONB; aggregate_id UUID; aggregate_version BIGINT; events JSONB:='[]'; side RECORD; head RECORD;
 audit_payload JSONB; outbox_payload JSONB; deadline TIMESTAMPTZ; transaction_value BIGINT:=(pg_current_xact_id()::TEXT)::BIGINT;
BEGIN
 SELECT jsonb_agg(jsonb_build_object('public_id',mutation.row_public_id,'version',mutation.after_version) ORDER BY mutation.row_public_id),
  min(mutation.row_public_id::TEXT)::UUID,(array_agg(mutation.after_version ORDER BY mutation.row_public_id))[1]
 INTO members,aggregate_id,aggregate_version FROM mesh_audit.authority_mutation AS mutation
 WHERE mutation.transaction_id=transaction_value AND mutation.change_public_id=p_change AND mutation.aggregate_kind=p_kind
 AND (p_kind='device_alias_lease' AND EXISTS(SELECT 1 FROM mesh.device_alias_lease AS lease WHERE lease.public_id=mutation.row_public_id AND lease.private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT)
  OR p_kind='device_alias_client_readiness' AND EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness AS readiness WHERE readiness.public_id=mutation.row_public_id AND readiness.private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT));
 IF members IS NULL THEN RETURN jsonb_build_object('changed',FALSE,'events','[]'::JSONB); END IF;
 IF jsonb_array_length(members)>4 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='Device alias mutation batch exceeded'; END IF;
 IF EXISTS(SELECT 1 FROM mesh_audit.audit_event_identity WHERE change_public_id=p_change AND transaction_id=transaction_value) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias evidence already finalized';
 END IF;
 SELECT min(value.expires_at) INTO deadline FROM (
  SELECT lease.expires_at FROM mesh.device_alias_lease AS lease JOIN mesh_audit.authority_mutation AS mutation ON mutation.row_public_id=lease.public_id
   WHERE p_kind='device_alias_lease' AND lease.private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT
    AND mutation.transaction_id=transaction_value AND mutation.change_public_id=p_change AND mutation.aggregate_kind=p_kind AND lease.state='reserved'
  UNION ALL
  SELECT readiness.expires_at FROM mesh.device_alias_client_readiness AS readiness JOIN mesh_audit.authority_mutation AS mutation ON mutation.row_public_id=readiness.public_id
   WHERE p_kind='device_alias_client_readiness' AND readiness.private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT
    AND mutation.transaction_id=transaction_value AND mutation.change_public_id=p_change AND mutation.aggregate_kind=p_kind AND readiness.state='ready'
 ) AS value;
 IF p_kind='device_alias_lease' THEN
  SELECT min(LEAST(deadline,endpoint.expires_at,contract.expires_at,provider.expires_at,consumer.expires_at)) INTO deadline
  FROM mesh.private_endpoint AS endpoint JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
  JOIN mesh.resource_device_target AS target ON target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation AND target.state='active'
  JOIN mesh.device AS provider ON provider.id=target.device_id
  JOIN mesh.device_alias_lease AS source ON source.private_endpoint_id=endpoint.id AND source.alias_role='consumer_source' AND source.state='reserved'
  JOIN mesh.device AS consumer ON consumer.id=source.owner_device_id
  JOIN mesh_audit.authority_mutation AS mutation ON mutation.row_public_id=source.public_id AND mutation.aggregate_kind=p_kind
    AND mutation.transaction_id=transaction_value AND mutation.change_public_id=p_change
  WHERE endpoint.id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT;
 END IF;
 -- Audit heads are locked last, after all authority and allocation locks.
 FOR side IN SELECT revision.*,workspace.public_id AS workspace_public_id,network.public_id AS network_public_id
  FROM mesh_ops.network_revision AS revision JOIN mesh.workspace AS workspace ON workspace.id=revision.workspace_id
  JOIN mesh.network AS network ON network.id=revision.network_id AND network.workspace_id=revision.workspace_id
  ORDER BY revision.workspace_id,revision.network_id LOOP
  SELECT id,next_sequence,latest_event_hash INTO STRICT head FROM mesh_audit.audit_stream
   WHERE workspace_id=side.workspace_id AND network_id=side.network_id FOR UPDATE;
  audit_payload:=jsonb_build_object('endpoint_public_id',p_endpoint,
   CASE p_kind WHEN 'device_alias_lease' THEN 'mutated_leases' ELSE 'mutated_readiness' END,members,
   'network_revision',side.network_revision,'sharing_revision',side.sharing_revision);
  outbox_payload:=jsonb_build_object('endpoint_public_id',p_endpoint,'subsystem','sharing','subsystem_revision',side.sharing_revision);
  events:=events||jsonb_build_array(jsonb_build_object('workspace_id',side.workspace_public_id,'network_id',side.network_public_id,
   'stream_id',head.id,'sequence',head.next_sequence,'previous_hash',encode(head.latest_event_hash,'hex'),
   'network_revision',side.network_revision,'sharing_revision',side.sharing_revision,'audit_payload',audit_payload::TEXT,'outbox_payload',outbox_payload::TEXT));
 END LOOP;
 IF jsonb_array_length(events)<>2 OR deadline IS NULL OR deadline<=clock_timestamp() THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias change authority expired';
 END IF;
 RETURN jsonb_build_object('changed',TRUE,'transaction_id',transaction_value::TEXT,'change_id',p_change,'endpoint_id',p_endpoint,
  'aggregate_kind',p_kind,'aggregate_id',aggregate_id,'aggregate_version',aggregate_version,'deadline',deadline,'events',events);
END;
$function$;
CREATE FUNCTION mesh_ops.prepare_device_alias_change_v1(p_deployment UUID,p_endpoint UUID,p_consumer UUID,p_generation BIGINT,
 p_provider_node_epoch BIGINT,p_consumer_node_epoch BIGINT,p_leases UUID[],p_readiness UUID,p_change UUID,p_mode TEXT) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE;
 provider mesh.device%ROWTYPE; consumer mesh.device%ROWTYPE; contract mesh.trust_contract%ROWTYPE; imported mesh.imported_resource%ROWTYPE;
 lease_ids UUID[]; deadline TIMESTAMPTZ; provider_revision BIGINT; provider_sharing BIGINT; consumer_revision BIGINT; consumer_sharing BIGINT;
 fingerprint BYTEA; node_key BYTEA; proof JSONB; kind TEXT; scope RECORD;
BEGIN
 IF p_mode IS NULL OR p_mode NOT IN ('reserve','ready') OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7
  OR p_readiness IS NULL OR get_byte(uuid_send(p_readiness),6)>>4<>7 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias worker change';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 IF endpoint.state<>'provisioning' OR endpoint.provider_workspace_id=endpoint.consumer_workspace_id THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias endpoint not client-only';
 END IF;
 PERFORM mesh_ops.reserve_device_aliases_internal_v1(p_endpoint,p_consumer,p_generation,p_provider_node_epoch,p_consumer_node_epoch,p_leases);
 -- The allocator holds both Network revisions and exact Device/key locks.
 -- Recheck bilateral consent and client claims before any allocation can commit.
 IF NOT EXISTS(SELECT 1 FROM mesh.trust_contract AS accepted
  JOIN mesh.share_offer AS offer ON offer.id=accepted.share_offer_id AND offer.state='accepted' AND offer.accepted_contract_public_id=accepted.public_id
  JOIN mesh.resource_export AS export ON export.id=accepted.resource_export_id AND export.state='active'
   AND export.resource_id=accepted.resource_id AND export.resource_version=accepted.resource_version AND export.target_generation=accepted.target_generation
   AND export.resource_semantic_hash=accepted.resource_semantic_hash AND export.constraint_hash=accepted.constraint_hash
   AND export.expires_at>=accepted.expires_at AND export.provider_authority_generation=accepted.provider_authority_generation
   AND (export.provider_workspace_id,export.provider_network_id,export.consumer_workspace_id,export.consumer_network_id)=
       (accepted.provider_workspace_id,accepted.provider_network_id,accepted.consumer_workspace_id,accepted.consumer_network_id)
  WHERE accepted.id=endpoint.trust_contract_id AND accepted.state='active' AND accepted.version=endpoint.contract_version
   AND accepted.expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias acceptance changed';
 END IF;
 IF (SELECT count(DISTINCT device.id) FROM mesh.device_alias_lease AS lease
  JOIN mesh.device AS device ON device.id=lease.owner_device_id
  JOIN mesh.device_alias_client_version AS compatibility ON compatibility.device_id=device.id AND compatibility.workspace_id=device.workspace_id AND compatibility.network_id=device.network_id
   AND compatibility.alias_version=1 AND compatibility.session_generation=device.session_generation AND compatibility.machine_key_epoch=device.current_machine_key_epoch
   AND compatibility.node_key_epoch=device.current_node_key_epoch AND compatibility.node_public_key=lease.node_public_key
  WHERE lease.private_endpoint_id=endpoint.id AND lease.state='reserved'
   AND (lease.alias_role='resource' OR lease.alias_role='consumer_source' AND device.public_id=p_consumer))<>2 THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias client claims unavailable';
 END IF;
 kind:='device_alias_lease';
 IF p_mode='ready' THEN
  IF EXISTS(SELECT 1 FROM mesh_audit.authority_mutation WHERE transaction_id=(pg_current_xact_id()::TEXT)::BIGINT AND change_public_id=p_change AND aggregate_kind='device_alias_lease') THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device aliases must be reserved before readiness';
  END IF;
  SELECT * INTO STRICT contract FROM mesh.trust_contract WHERE id=endpoint.trust_contract_id;
  SELECT * INTO STRICT imported FROM mesh.imported_resource WHERE id=endpoint.imported_resource_id;
  SELECT device.* INTO STRICT provider FROM mesh.device AS device JOIN mesh.resource_device_target AS target ON target.device_id=device.id
   WHERE target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation AND target.state='active';
  SELECT * INTO STRICT consumer FROM mesh.device WHERE public_id=p_consumer AND workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
  IF NOT EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id) THEN
   FOR scope IN SELECT * FROM (VALUES (endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
    ORDER BY workspace_id,network_id LOOP
    UPDATE mesh_ops.network_revision SET network_revision=network_revision+1,sharing_revision=sharing_revision+1,updated_at=clock_timestamp()
     WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id;
   END LOOP;
   SELECT network_revision,sharing_revision INTO STRICT provider_revision,provider_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.provider_workspace_id AND network_id=endpoint.provider_network_id;
   SELECT network_revision,sharing_revision INTO STRICT consumer_revision,consumer_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
   SELECT array_agg(public_id ORDER BY public_id),min(expires_at) INTO lease_ids,deadline FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND state='reserved'
    AND (alias_role='resource' AND owner_device_id=provider.id OR alias_role='consumer_source' AND owner_device_id=consumer.id);
   INSERT INTO mesh.device_alias_client_readiness(public_id,deployment_id,provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id,private_endpoint_id,endpoint_generation,
    consumer_device_id,provider_device_id,contract_version,imported_resource_version,resource_version,target_generation,recovery_epoch,lease_public_ids,expires_at,state,created_at,updated_at,
    provider_network_revision,provider_sharing_revision,consumer_network_revision,consumer_sharing_revision)
   VALUES(p_readiness,endpoint.deployment_id,endpoint.provider_workspace_id,endpoint.provider_network_id,endpoint.consumer_workspace_id,endpoint.consumer_network_id,endpoint.id,endpoint.generation,
    consumer.id,provider.id,contract.version,imported.version,contract.resource_version,contract.target_generation,endpoint.recovery_epoch,lease_ids,
    LEAST(deadline,endpoint.expires_at,contract.expires_at,provider.expires_at,consumer.expires_at),'ready',transaction_timestamp(),transaction_timestamp(),provider_revision,provider_sharing,consumer_revision,consumer_sharing);
  END IF;
  -- Reuse the complete authenticated projection predicate, never the trigger's
  -- smaller insertion subset, before marking this pair ready.
  PERFORM set_config('mesh.workspace_id',endpoint.consumer_workspace_id::TEXT,TRUE);
  PERFORM set_config('mesh.network_id',endpoint.consumer_network_id::TEXT,TRUE);
  SELECT machine.fingerprint,key.public_key INTO STRICT fingerprint,node_key FROM mesh.device_machine_key_epoch AS machine JOIN mesh.device_node_key_epoch AS key ON key.device_id=machine.device_id
   WHERE machine.device_id=consumer.id AND machine.epoch=consumer.current_machine_key_epoch AND key.epoch=consumer.current_node_key_epoch;
  IF NOT EXISTS(SELECT 1 FROM mesh_ops.load_device_alias_map_edges_v1(fingerprint,node_key,257) AS edge
    WHERE edge->'endpoint'->>'id'=p_endpoint::TEXT AND edge->'peer'->>'id'=provider.public_id::TEXT) THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias complete map authority unavailable';
  END IF;
  kind:='device_alias_client_readiness';
 END IF;
 proof:=mesh_ops.device_alias_change_proof_internal_v1(p_endpoint,p_change,kind);
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN proof;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
CREATE FUNCTION mesh_ops.finalize_device_alias_change_v1(p_deployment UUID,p_endpoint UUID,p_generation BIGINT,p_change UUID,p_kind TEXT,p_events JSONB) RETURNS INTEGER
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE; proof JSONB; expected JSONB; supplied JSONB;
 count_value INTEGER:=0; action TEXT;
BEGIN
 IF p_kind IS NULL OR p_kind NOT IN ('device_alias_lease','device_alias_client_readiness') OR p_events IS NULL OR jsonb_typeof(p_events)<>'array'
  OR jsonb_array_length(p_events)<>2 OR octet_length(p_events::TEXT)>32768 OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7
  OR p_generation IS NULL OR p_generation<=0 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias evidence';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 IF endpoint.generation<>p_generation OR endpoint.state<>'provisioning' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias endpoint changed'; END IF;
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 proof:=mesh_ops.device_alias_change_proof_internal_v1(p_endpoint,p_change,p_kind);
 IF NOT COALESCE((proof->>'changed')::BOOLEAN,FALSE) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias mutation missing'; END IF;
 action:=CASE p_kind WHEN 'device_alias_lease' THEN 'sharing.device_alias.reserve' ELSE 'sharing.device_alias.ready' END;
 FOR expected IN SELECT value FROM jsonb_array_elements(proof->'events') LOOP
  SELECT value INTO STRICT supplied FROM jsonb_array_elements(p_events) WHERE value->>'stream_id'=expected->>'stream_id';
  IF supplied->>'sequence' IS DISTINCT FROM expected->>'sequence' OR supplied->>'previous_hash' IS DISTINCT FROM expected->>'previous_hash'
   OR supplied->>'audit_payload' IS DISTINCT FROM expected->>'audit_payload' OR supplied->>'outbox_payload' IS DISTINCT FROM expected->>'outbox_payload'
   OR supplied->>'network_revision' IS DISTINCT FROM expected->>'network_revision' OR supplied->>'sharing_revision' IS DISTINCT FROM expected->>'sharing_revision'
   OR supplied->>'workspace_id' IS DISTINCT FROM expected->>'workspace_id' OR supplied->>'network_id' IS DISTINCT FROM expected->>'network_id' THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias evidence does not match mutation';
  END IF;
  PERFORM mesh_audit.append_authority_evidence((expected->>'stream_id')::BIGINT,(supplied->>'event_id')::UUID,(supplied->>'outbox_id')::UUID,
   (expected->>'sequence')::BIGINT,decode(expected->>'previous_hash','hex'),decode(supplied->>'event_hash','hex'),p_kind,(proof->>'aggregate_id')::UUID,
   (proof->>'aggregate_version')::BIGINT,(expected->>'network_revision')::BIGINT,NULL::UUID,action,'sharing.client_alias',NULL::UUID,NULL::BYTEA,NULL::BYTEA,
   (expected->>'audit_payload')::JSONB,'network.revision.advanced',(expected->>'outbox_payload')::JSONB);
  count_value:=count_value+1;
 END LOOP;
 IF (proof->>'deadline')::TIMESTAMPTZ<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias evidence expired during finalization'; END IF;
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN count_value;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.save_device_alias_worker_context_v1() FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.restore_device_alias_worker_context_v1(JSONB) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.derive_device_alias_worker_scope_v1(UUID,UUID) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.device_alias_change_proof_internal_v1(UUID,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_change_v1(UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,UUID[],UUID,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.finalize_device_alias_change_v1(UUID,UUID,BIGINT,UUID,TEXT,JSONB) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
