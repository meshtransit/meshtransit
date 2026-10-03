-- Synthetic rollback-owned intent for alias map reader qualification only.
-- Administrator fault injection is unavailable to serving roles.
SET LOCAL session_replication_role=replica;
-- Earlier qualification publishes this endpoint through the legacy gateway.
-- Restore a synthetic client-only intent inside this rolled-back transaction.
UPDATE mesh.private_endpoint SET state='provisioning',ready_at=NULL WHERE public_id=$1::UUID;
UPDATE mesh.federation_alias_lease AS lease SET state='reserved',activated_at=NULL
FROM mesh.private_endpoint AS endpoint WHERE endpoint.public_id=$1::UUID AND lease.id=endpoint.alias_lease_id;
UPDATE mesh.imported_resource_access_name AS name SET state='reserved'
FROM mesh.private_endpoint AS endpoint WHERE endpoint.public_id=$1::UUID AND name.id=endpoint.access_name_id;
UPDATE mesh.deployment SET direct_sharing_ceiling_profile='no-additional-traffic-ceilings-v1' WHERE id=1;
INSERT INTO mesh.device_alias_client_version(workspace_id,network_id,device_id,session_generation,machine_key_epoch,node_key_epoch,node_public_key,alias_version,observed_at)
SELECT device.workspace_id,device.network_id,device.id,device.session_generation,device.current_machine_key_epoch,device.current_node_key_epoch,node_key.public_key,1,clock_timestamp()
FROM mesh.device AS device JOIN mesh.device_node_key_epoch AS node_key ON node_key.device_id=device.id AND node_key.epoch=device.current_node_key_epoch
WHERE device.id IN (SELECT target.device_id FROM mesh.private_endpoint AS endpoint JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id JOIN mesh.resource_device_target AS target ON target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation WHERE endpoint.public_id=$1::UUID)
 OR device.public_id=$2::UUID
ON CONFLICT(workspace_id,network_id,device_id) DO UPDATE SET alias_version=1,session_generation=EXCLUDED.session_generation,machine_key_epoch=EXCLUDED.machine_key_epoch,node_key_epoch=EXCLUDED.node_key_epoch,node_public_key=EXCLUDED.node_public_key;
UPDATE mesh.policy_release AS release SET state='superseded',superseded_at=clock_timestamp(),version=release.version+1
FROM mesh.private_endpoint AS endpoint WHERE endpoint.public_id=$1::UUID AND release.workspace_id=endpoint.consumer_workspace_id AND release.network_id=endpoint.consumer_network_id AND release.state='active';
UPDATE mesh_ops.network_revision AS revision SET policy_revision=policy_revision+1,network_revision=network_revision+1,sharing_revision=sharing_revision+1,updated_at=clock_timestamp()
FROM mesh.private_endpoint AS endpoint WHERE endpoint.public_id=$1::UUID AND (revision.workspace_id,revision.network_id) IN ((endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id));
INSERT INTO mesh.policy_release(public_id,workspace_id,network_id,policy_revision,semantic_hash,compiler_format_version,state)
SELECT '01890fb0-0000-7000-8000-000000004001',endpoint.consumer_workspace_id,endpoint.consumer_network_id,revision.policy_revision,decode(repeat('ef',32),'hex'),4,'active'
FROM mesh.private_endpoint AS endpoint JOIN mesh_ops.network_revision AS revision ON revision.workspace_id=endpoint.consumer_workspace_id AND revision.network_id=endpoint.consumer_network_id WHERE endpoint.public_id=$1::UUID;
INSERT INTO mesh.compiled_policy_imported_resource_destination(public_id,access_rule_public_id,workspace_id,network_id,policy_release_id,policy_revision,source_device_id,
 imported_resource_id,imported_resource_version,trust_contract_id,trust_contract_version,resource_export_id,resource_export_version,provider_workspace_id,provider_network_id,
 destination_resource_id,resource_version,target_generation,resource_semantic_hash,provider_inventory_revision,provider_sharing_revision,consumer_sharing_revision,
 provider_authority_generation,consumer_authority_generation,recovery_epoch,contract_expires_at,constraint_hash,protocol,destination_ports,created_at)
SELECT '01890fb0-0000-7000-8000-000000004002','01890fb0-0000-7000-8000-000000004003',endpoint.consumer_workspace_id,endpoint.consumer_network_id,release.id,release.policy_revision,consumer.id,
 imported.id,imported.version,contract.id,contract.version,export.id,export.version,endpoint.provider_workspace_id,endpoint.provider_network_id,
 resource.id,resource.version,resource.target_generation,resource.semantic_hash,provider_revision.inventory_revision,provider_revision.sharing_revision,consumer_revision.sharing_revision,
 contract.provider_authority_generation,contract.consumer_authority_generation,contract.recovery_epoch,contract.expires_at,contract.constraint_hash,'tcp','{[443,444)}'::INT4MULTIRANGE,transaction_timestamp()
FROM mesh.private_endpoint AS endpoint JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
JOIN mesh.resource_export AS export ON export.id=contract.resource_export_id JOIN mesh.resource AS resource ON resource.id=contract.resource_id
JOIN mesh.imported_resource AS imported ON imported.id=endpoint.imported_resource_id JOIN mesh.device AS consumer ON consumer.public_id=$2::UUID
JOIN mesh.policy_release AS release ON release.workspace_id=consumer.workspace_id AND release.network_id=consumer.network_id AND release.state='active'
JOIN mesh_ops.network_revision AS provider_revision ON provider_revision.workspace_id=endpoint.provider_workspace_id AND provider_revision.network_id=endpoint.provider_network_id
JOIN mesh_ops.network_revision AS consumer_revision ON consumer_revision.workspace_id=endpoint.consumer_workspace_id AND consumer_revision.network_id=endpoint.consumer_network_id
WHERE endpoint.public_id=$1::UUID;
SET LOCAL session_replication_role=origin;
