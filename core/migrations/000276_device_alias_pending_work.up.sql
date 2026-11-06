-- Device alias work reads only endpoints that can yield work
-- (docs/performance-logic-plan.md §6, TD-CORE-140).
--
-- load_device_alias_work_v4 selects every cross-Network private endpoint
-- that is not ready, including the ones that ended (revoked, expired,
-- invalidated), and runs some twenty reads per endpoint and per consumer on
-- every worker pass. Ended endpoints only accumulate, so the worker's
-- database CPU grew without bound while nothing happened: on the POC this
-- one function was about 7 % of a core while idle, for 36 ended endpoints
-- and one provisioning.
--
-- An ended endpoint is terminal in v4 (state <> 'provisioning'), so it can
-- produce only quarantine_resource (a reserved Resource lease),
-- quarantine_consumer (a reserved consumer_source lease) or withdraw (a
-- ready readiness row). v5 is v4 with one more condition on the endpoints it
-- selects: provisioning, or still holding a reserved lease or a ready
-- readiness row. Every item v4 hands out, v5 hands out, in the same order;
-- only page boundaries can differ, because v4 also spent its page budget on
-- consumers of endpoints that yield nothing.
--
-- Operator step 276 hands v5 to mesh_device_alias_writer and grants it to
-- mesh_worker; until then the worker keeps load v4.

CREATE FUNCTION mesh_ops.load_device_alias_work_v5(p_deployment UUID,p_after_endpoint UUID,p_after_consumer UUID,p_limit INTEGER) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); name TEXT; selected RECORD;
 endpoint mesh.private_endpoint%ROWTYPE; contract mesh.trust_contract%ROWTYPE; resource mesh.resource%ROWTYPE; provider mesh.device%ROWTYPE;
 consumer mesh.device%ROWTYPE; selected_consumer RECORD; mode TEXT; decision_at TIMESTAMPTZ;
 terminal_endpoint BOOLEAN; terminal_consumer BOOLEAN; eligible BOOLEAN; claim_count INTEGER;
 resource_reserved INTEGER; source_reserved INTEGER; source_count INTEGER; readiness_state TEXT; readiness_expiry TIMESTAMPTZ; readiness_leases UUID[];
 work JSONB:='[]'; visited INTEGER:=0; endpoint_count INTEGER:=0; endpoint_ids UUID[]; next_endpoint UUID:=p_after_endpoint; next_consumer UUID:=p_after_consumer;
BEGIN
 IF p_deployment IS NULL OR p_limit IS NULL OR p_limit<1 OR p_limit>128 OR (p_after_consumer IS NOT NULL AND p_after_endpoint IS NULL) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias work cursor';
 END IF;
 -- Clearing the closed selector set prevents caller-controlled scope widening.
 FOR name IN SELECT jsonb_object_keys(saved) LOOP PERFORM set_config(name,'',TRUE); END LOOP;
 IF NOT EXISTS(SELECT 1 FROM mesh.deployment WHERE installation_public_id=p_deployment) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Device alias work Deployment unavailable';
 END IF;
 PERFORM set_config('mesh.alias_worker_deployment_public_id',p_deployment::TEXT,TRUE);
 SELECT array_agg(page.public_id ORDER BY page.public_id) INTO endpoint_ids FROM (SELECT pending.public_id FROM mesh.private_endpoint AS pending JOIN mesh.deployment ON deployment.id=pending.deployment_id
  WHERE deployment.installation_public_id=p_deployment AND pending.provider_network_id<>pending.consumer_network_id AND pending.state<>'ready'
   AND (p_after_endpoint IS NULL OR pending.public_id>p_after_endpoint OR pending.public_id=p_after_endpoint AND p_after_consumer IS NOT NULL)
  ORDER BY pending.public_id LIMIT 128) AS page;
 -- Materialize the bounded endpoint IDs before changing per-endpoint RLS
 -- context; lazy cursor fetch must never depend on a later selector.
 FOR selected IN SELECT public_id FROM unnest(endpoint_ids) AS public_id LOOP
  endpoint_count:=endpoint_count+1;
  endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,selected.public_id);
  -- Schema 276: an ended endpoint (revoked, expired, invalidated) yields
  -- work only while it still holds a reserved lease (quarantine) or a ready
  -- consumer (withdraw). Checked once the endpoint's scope is set, so row
  -- security shows exactly its leases and readiness.
  IF endpoint.state<>'provisioning'
   AND NOT EXISTS(SELECT 1 FROM mesh.device_alias_lease AS held WHERE held.private_endpoint_id=endpoint.id AND held.state='reserved')
   AND NOT EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness AS shown WHERE shown.private_endpoint_id=endpoint.id AND shown.state='ready') THEN
   next_endpoint:=endpoint.public_id; next_consumer:=NULL;
   CONTINUE;
  END IF;
  decision_at:=clock_timestamp();
  SELECT * INTO STRICT contract FROM mesh.trust_contract WHERE id=endpoint.trust_contract_id;
  SELECT * INTO STRICT resource FROM mesh.resource WHERE id=contract.resource_id;
  SELECT * INTO provider FROM mesh.device WHERE id=COALESCE(
    (SELECT device_id FROM mesh.resource_device_target WHERE resource_id=resource.id AND target_generation=resource.target_generation AND state='active'),
    (SELECT owner_device_id FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' ORDER BY id LIMIT 1));
  SELECT count(*) INTO resource_reserved FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved';
  terminal_endpoint:=endpoint.state<>'provisioning' OR endpoint.expires_at<=decision_at OR contract.state<>'active' OR contract.expires_at<=decision_at
   OR contract.version<>endpoint.contract_version OR contract.constraint_hash<>endpoint.constraint_hash
   OR resource.kind<>'device' OR resource.state<>'active' OR resource.deleted_at IS NOT NULL OR resource.version<>contract.resource_version
   OR resource.target_generation<>contract.target_generation OR resource.semantic_hash<>contract.resource_semantic_hash
   OR provider.id IS NULL OR provider.state<>'active' OR provider.deleted_at IS NOT NULL OR provider.expires_at<=decision_at
   OR NOT EXISTS(SELECT 1 FROM mesh.deployment WHERE id=endpoint.deployment_id AND state='active' AND recovery_state='verified' AND recovery_epoch=endpoint.recovery_epoch)
   OR NOT EXISTS(SELECT 1 FROM mesh.resource_device_target WHERE resource_id=resource.id AND target_generation=resource.target_generation AND state='active' AND workspace_id=endpoint.provider_workspace_id AND network_id=endpoint.provider_network_id AND device_id=provider.id)
   OR NOT EXISTS(SELECT 1 FROM mesh.imported_resource WHERE id=endpoint.imported_resource_id AND state='active' AND version=endpoint.imported_resource_version AND trust_contract_id=contract.id)
   OR NOT EXISTS(SELECT 1 FROM mesh.workspace AS owner WHERE owner.id=endpoint.provider_workspace_id AND owner.state='active')
   OR NOT EXISTS(SELECT 1 FROM mesh.workspace AS owner WHERE owner.id=endpoint.consumer_workspace_id AND owner.state='active')
   OR NOT EXISTS(SELECT 1 FROM mesh.network WHERE id=endpoint.provider_network_id AND workspace_id=endpoint.provider_workspace_id AND state='active' AND authority_generation=endpoint.provider_authority_generation)
   OR NOT EXISTS(SELECT 1 FROM mesh.network WHERE id=endpoint.consumer_network_id AND workspace_id=endpoint.consumer_workspace_id AND state='active' AND authority_generation=endpoint.consumer_authority_generation)
   OR EXISTS(SELECT 1 FROM mesh.device_alias_lease AS lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved'
    AND (owner_device_id IS DISTINCT FROM provider.id OR expires_at<=decision_at OR session_generation IS DISTINCT FROM provider.session_generation
      OR machine_key_epoch IS DISTINCT FROM provider.current_machine_key_epoch OR node_key_epoch IS DISTINCT FROM provider.current_node_key_epoch
      OR NOT EXISTS(SELECT 1 FROM mesh.device_node_key_epoch WHERE device_id=provider.id AND epoch=provider.current_node_key_epoch AND state='active' AND public_key=lease.node_public_key)))
   OR NOT EXISTS(SELECT 1 FROM mesh.share_offer AS offer JOIN mesh.resource_export AS export ON export.id=contract.resource_export_id
    WHERE offer.id=contract.share_offer_id AND offer.state='accepted' AND offer.accepted_contract_public_id=contract.public_id
     AND export.state='active' AND export.resource_id=contract.resource_id
     AND export.resource_version=contract.resource_version AND export.target_generation=contract.target_generation
     AND export.resource_semantic_hash=contract.resource_semantic_hash AND export.constraint_hash=contract.constraint_hash
     AND export.expires_at>=contract.expires_at AND export.provider_authority_generation=contract.provider_authority_generation
     AND (export.provider_workspace_id,export.provider_network_id,export.consumer_workspace_id,export.consumer_network_id)=
      (endpoint.provider_workspace_id,endpoint.provider_network_id,endpoint.consumer_workspace_id,endpoint.consumer_network_id));
  -- Endpoint-level cleanup is independent of consumer retention. Resource
  -- quarantine invalidates every dependent projection before later cleanup.
  IF terminal_endpoint AND resource_reserved>0 THEN
   work:=work||jsonb_build_array(jsonb_build_object('endpoint_id',endpoint.public_id,'consumer_id',NULL,'generation',endpoint.generation,
    'provider_node_epoch',0,'consumer_node_epoch',0,'mode','quarantine_resource'));
   visited:=visited+1;next_endpoint:=endpoint.public_id;next_consumer:=NULL;
   IF visited=p_limit THEN
    PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
    RETURN jsonb_build_object('items',work,'cursor',jsonb_build_object('endpoint_id',next_endpoint,'consumer_id',NULL),'done',FALSE);
   END IF;
   CONTINUE;
  END IF;
  FOR selected_consumer IN SELECT device.public_id FROM mesh.device AS device WHERE device.workspace_id=endpoint.consumer_workspace_id AND device.network_id=endpoint.consumer_network_id
   AND (endpoint.public_id IS DISTINCT FROM p_after_endpoint OR p_after_consumer IS NULL OR device.public_id>p_after_consumer)
   AND device.id IN (
    SELECT source_device_id FROM mesh.compiled_policy_imported_resource_destination WHERE imported_resource_id=endpoint.imported_resource_id AND trust_contract_id=contract.id
    UNION SELECT owner_device_id FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source'
    UNION SELECT consumer_device_id FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id)
   ORDER BY device.public_id LIMIT p_limit-visited LOOP
   SELECT * INTO STRICT consumer FROM mesh.device WHERE public_id=selected_consumer.public_id;
   next_endpoint:=endpoint.public_id; next_consumer:=consumer.public_id; visited:=visited+1; mode:=NULL;
   SELECT count(*),count(*) FILTER(WHERE state='reserved') INTO source_count,source_reserved FROM mesh.device_alias_lease
    WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source' AND owner_device_id=consumer.id;
   SELECT state,expires_at,lease_public_ids INTO readiness_state,readiness_expiry,readiness_leases FROM mesh.device_alias_client_readiness
    WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id ORDER BY state='ready' DESC,id DESC LIMIT 1;
   terminal_consumer:=consumer.state<>'active' OR consumer.deleted_at IS NOT NULL OR consumer.expires_at<=decision_at OR readiness_state='ready' AND (readiness_expiry<=decision_at
     OR EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND public_id=ANY(readiness_leases) AND state<>'reserved'))
    OR EXISTS(SELECT 1 FROM mesh.device_alias_lease AS lease WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source' AND owner_device_id=consumer.id AND state='reserved'
     AND (expires_at<=decision_at OR session_generation<>consumer.session_generation OR machine_key_epoch<>consumer.current_machine_key_epoch OR node_key_epoch<>consumer.current_node_key_epoch
      OR NOT EXISTS(SELECT 1 FROM mesh.device_node_key_epoch WHERE device_id=consumer.id AND epoch=consumer.current_node_key_epoch AND state='active' AND public_key=lease.node_public_key)));
   IF (terminal_endpoint OR COALESCE(terminal_consumer,FALSE)) AND readiness_state='ready' THEN mode:='withdraw';
   ELSIF (terminal_endpoint OR COALESCE(terminal_consumer,FALSE)) AND source_reserved>0 THEN mode:='quarantine_consumer';
   ELSIF NOT terminal_endpoint AND NOT COALESCE(terminal_consumer,FALSE) AND readiness_state IS DISTINCT FROM 'ready' THEN
    SELECT EXISTS(SELECT 1 FROM mesh.compiled_policy_imported_resource_destination AS rule
     JOIN mesh.policy_release AS release ON release.id=rule.policy_release_id AND release.state='active'
     JOIN mesh_ops.network_revision AS revision ON revision.workspace_id=rule.workspace_id AND revision.network_id=rule.network_id AND revision.policy_revision=release.policy_revision
     WHERE rule.workspace_id=endpoint.consumer_workspace_id AND rule.network_id=endpoint.consumer_network_id AND rule.source_device_id=consumer.id
      AND rule.trust_contract_id=contract.id AND rule.imported_resource_id=endpoint.imported_resource_id AND rule.policy_revision=release.policy_revision) INTO eligible;
    SELECT count(DISTINCT device_id) INTO claim_count FROM mesh.device_alias_client_version WHERE device_id IN (provider.id,consumer.id)
     AND alias_version=1 AND (device_id=provider.id AND session_generation=provider.session_generation AND machine_key_epoch=provider.current_machine_key_epoch AND node_key_epoch=provider.current_node_key_epoch
      OR device_id=consumer.id AND session_generation=consumer.session_generation AND machine_key_epoch=consumer.current_machine_key_epoch AND node_key_epoch=consumer.current_node_key_epoch);
    IF eligible AND claim_count=2 THEN
     IF source_reserved=0 OR resource_reserved=0 THEN mode:='reserve';
     ELSE mode:='ready'; END IF;
    END IF;
   END IF;
   IF mode IS NOT NULL THEN work:=work||jsonb_build_array(jsonb_build_object('endpoint_id',endpoint.public_id,'consumer_id',consumer.public_id,
    'generation',endpoint.generation,'provider_node_epoch',COALESCE(provider.current_node_key_epoch,0),'consumer_node_epoch',consumer.current_node_key_epoch,'mode',mode)); END IF;
   IF visited=p_limit THEN
    PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
    RETURN jsonb_build_object('items',work,'cursor',jsonb_build_object('endpoint_id',next_endpoint,'consumer_id',next_consumer),'done',FALSE);
   END IF;
  END LOOP;
  next_endpoint:=endpoint.public_id; next_consumer:=NULL;
 END LOOP;
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN jsonb_build_object('items',work,'cursor',jsonb_build_object('endpoint_id',next_endpoint,'consumer_id',next_consumer),'done',endpoint_count<128);
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_device_alias_work_v5(UUID,UUID,UUID,INTEGER) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
