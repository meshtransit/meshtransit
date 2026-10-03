-- No-grant lifecycle capabilities. Each bounded change has bilateral evidence.
-- Consumer withdrawal does not quarantine the Resource aliases of other clients.
CREATE FUNCTION mesh_ops.device_alias_withdrawal_proof_internal_v1(p_endpoint UUID,p_change UUID,p_mode TEXT) RETURNS JSONB
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $function$
DECLARE members JSONB; aggregate_id UUID; aggregate_version BIGINT; kind TEXT;
 events JSONB:='[]'; side RECORD; head RECORD; audit_payload JSONB; outbox_payload JSONB;
 transaction_value BIGINT:=(pg_current_xact_id()::TEXT)::BIGINT;
BEGIN
 kind:=CASE p_mode WHEN 'withdraw' THEN 'device_alias_client_readiness' ELSE 'device_alias_lease' END;
 SELECT jsonb_agg(jsonb_build_object('public_id',mutation.row_public_id,'version',mutation.after_version) ORDER BY mutation.row_public_id),
  min(mutation.row_public_id::TEXT)::UUID,(array_agg(mutation.after_version ORDER BY mutation.row_public_id))[1]
 INTO members,aggregate_id,aggregate_version FROM mesh_audit.authority_mutation AS mutation
 WHERE mutation.transaction_id=transaction_value AND mutation.change_public_id=p_change AND mutation.aggregate_kind=kind
 AND (kind='device_alias_lease' AND EXISTS(SELECT 1 FROM mesh.device_alias_lease AS lease WHERE lease.public_id=mutation.row_public_id AND lease.private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT AND lease.state='quarantined' AND (p_mode='quarantine_resource' AND lease.alias_role='resource' OR p_mode='quarantine_consumer' AND lease.alias_role='consumer_source'))
  OR kind='device_alias_client_readiness' AND EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness AS readiness WHERE readiness.public_id=mutation.row_public_id AND readiness.private_endpoint_id=NULLIF(current_setting('mesh.alias_worker_endpoint_id',TRUE),'')::BIGINT AND readiness.state='withdrawn'));
 IF members IS NULL THEN RETURN jsonb_build_object('changed',FALSE,'events','[]'::JSONB); END IF;
 IF jsonb_array_length(members)>(CASE p_mode WHEN 'withdraw' THEN 1 ELSE 2 END) THEN
  RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='Device alias withdrawal batch exceeded';
 END IF;
 IF EXISTS(SELECT 1 FROM mesh_audit.audit_event_identity WHERE change_public_id=p_change AND transaction_id=transaction_value) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias withdrawal already finalized';
 END IF;
 -- Audit heads last. The preceding prepare holds both Network revisions and
 -- the exact endpoint/lifecycle rows until this transaction ends.
 FOR side IN SELECT revision.*,workspace.public_id AS workspace_public_id,network.public_id AS network_public_id
  FROM mesh_ops.network_revision AS revision JOIN mesh.workspace AS workspace ON workspace.id=revision.workspace_id
  JOIN mesh.network AS network ON network.id=revision.network_id AND network.workspace_id=revision.workspace_id
  ORDER BY revision.workspace_id,revision.network_id LOOP
  SELECT id,next_sequence,latest_event_hash INTO STRICT head FROM mesh_audit.audit_stream
   WHERE workspace_id=side.workspace_id AND network_id=side.network_id FOR UPDATE;
  audit_payload:=jsonb_build_object('endpoint_public_id',p_endpoint,
   CASE kind WHEN 'device_alias_lease' THEN 'mutated_leases' ELSE 'mutated_readiness' END,members,
   'network_revision',side.network_revision,'sharing_revision',side.sharing_revision);
  outbox_payload:=jsonb_build_object('endpoint_public_id',p_endpoint,'subsystem','sharing','subsystem_revision',side.sharing_revision);
  events:=events||jsonb_build_array(jsonb_build_object('workspace_id',side.workspace_public_id,'network_id',side.network_public_id,
   'stream_id',head.id,'sequence',head.next_sequence,'previous_hash',encode(head.latest_event_hash,'hex'),
   'network_revision',side.network_revision,'sharing_revision',side.sharing_revision,'audit_payload',audit_payload::TEXT,'outbox_payload',outbox_payload::TEXT));
 END LOOP;
 IF jsonb_array_length(events)<>2 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias withdrawal scope changed'; END IF;
 RETURN jsonb_build_object('changed',TRUE,'transaction_id',transaction_value::TEXT,'change_id',p_change,'endpoint_id',p_endpoint,
  'aggregate_kind',kind,'aggregate_id',aggregate_id,'aggregate_version',aggregate_version,
  'action','sharing.device_alias.'||p_mode,'deadline',clock_timestamp()+INTERVAL '15 seconds','events',events);
END;
$function$;
CREATE FUNCTION mesh_ops.prepare_device_alias_withdrawal_v1(p_deployment UUID,p_endpoint UUID,p_consumer UUID,p_generation BIGINT,p_change UUID,p_mode TEXT) RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE;
 consumer_id BIGINT; scope RECORD; changed BOOLEAN; proof JSONB; decision_at TIMESTAMPTZ;
 provider_revision BIGINT; provider_sharing BIGINT; consumer_revision BIGINT; consumer_sharing BIGINT;
BEGIN
 IF p_mode IS NULL OR p_mode NOT IN ('withdraw','quarantine_consumer','quarantine_resource') OR p_generation IS NULL OR p_generation<=0
  OR p_consumer IS NULL OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias withdrawal';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 FOR scope IN SELECT * FROM (VALUES (endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
  ORDER BY workspace_id,network_id LOOP
  PERFORM network_id FROM mesh_ops.network_revision WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias withdrawal Network unavailable'; END IF;
 END LOOP;
 SELECT * INTO STRICT endpoint FROM mesh.private_endpoint WHERE public_id=p_endpoint FOR UPDATE;
 IF endpoint.generation<>p_generation OR endpoint.provider_workspace_id=endpoint.consumer_workspace_id OR endpoint.state='ready' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias withdrawal endpoint changed';
 END IF;
 SELECT id INTO consumer_id FROM mesh.device WHERE public_id=p_consumer AND workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
 IF consumer_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Device alias consumer scope unavailable'; END IF;
 IF p_mode='withdraw' THEN
  PERFORM id FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer_id ORDER BY id FOR UPDATE;
  SELECT EXISTS(SELECT 1 FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer_id AND state='ready') INTO changed;
 ELSE
  PERFORM id FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND
   (p_mode='quarantine_resource' AND alias_role='resource' OR p_mode='quarantine_consumer' AND alias_role='consumer_source' AND owner_device_id=consumer_id) ORDER BY id FOR UPDATE;
  SELECT EXISTS(SELECT 1 FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND state='reserved' AND
   (p_mode='quarantine_resource' AND alias_role='resource' OR p_mode='quarantine_consumer' AND alias_role='consumer_source' AND owner_device_id=consumer_id)) INTO changed;
 END IF;
 IF NOT changed THEN
  PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
  RETURN jsonb_build_object('changed',FALSE,'events','[]'::JSONB);
 END IF;
 decision_at:=clock_timestamp();
 FOR scope IN SELECT * FROM (VALUES (endpoint.provider_workspace_id,endpoint.provider_network_id),(endpoint.consumer_workspace_id,endpoint.consumer_network_id)) AS scopes(workspace_id,network_id)
  ORDER BY workspace_id,network_id LOOP
  UPDATE mesh_ops.network_revision SET network_revision=network_revision+1,sharing_revision=sharing_revision+1,updated_at=decision_at
   WHERE workspace_id=scope.workspace_id AND network_id=scope.network_id;
 END LOOP;
 SELECT network_revision,sharing_revision INTO STRICT provider_revision,provider_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.provider_workspace_id AND network_id=endpoint.provider_network_id;
 SELECT network_revision,sharing_revision INTO STRICT consumer_revision,consumer_sharing FROM mesh_ops.network_revision WHERE workspace_id=endpoint.consumer_workspace_id AND network_id=endpoint.consumer_network_id;
 IF p_mode='withdraw' THEN
  UPDATE mesh.device_alias_client_readiness SET state='withdrawn',version=version+1,updated_at=decision_at,
   provider_network_revision=provider_revision,provider_sharing_revision=provider_sharing,consumer_network_revision=consumer_revision,consumer_sharing_revision=consumer_sharing
   WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer_id AND state='ready';
 ELSE
  UPDATE mesh.device_alias_lease SET state='quarantined',version=version+1,updated_at=decision_at,
   quarantine_until=GREATEST(decision_at,expires_at,endpoint.expires_at)+INTERVAL '24 hours',
   provider_network_revision=provider_revision,provider_sharing_revision=provider_sharing,consumer_network_revision=consumer_revision,consumer_sharing_revision=consumer_sharing
   WHERE private_endpoint_id=endpoint.id AND state='reserved' AND
    (p_mode='quarantine_resource' AND alias_role='resource' OR p_mode='quarantine_consumer' AND alias_role='consumer_source' AND owner_device_id=consumer_id);
 END IF;
 proof:=mesh_ops.device_alias_withdrawal_proof_internal_v1(p_endpoint,p_change,p_mode);
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN proof;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
CREATE FUNCTION mesh_ops.finalize_device_alias_withdrawal_v1(p_deployment UUID,p_endpoint UUID,p_generation BIGINT,p_change UUID,p_mode TEXT,p_events JSONB) RETURNS INTEGER
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE saved JSONB:=mesh_ops.save_device_alias_worker_context_v1(); endpoint mesh.private_endpoint%ROWTYPE; proof JSONB; expected JSONB; supplied JSONB; count_value INTEGER:=0;
BEGIN
 IF p_mode IS NULL OR p_mode NOT IN ('withdraw','quarantine_consumer','quarantine_resource') OR p_generation IS NULL OR p_generation<=0
  OR p_change IS NULL OR get_byte(uuid_send(p_change),6)>>4<>7 OR p_events IS NULL OR jsonb_typeof(p_events)<>'array'
  OR jsonb_array_length(p_events)<>2 OR octet_length(p_events::TEXT)>32768 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid Device alias withdrawal evidence';
 END IF;
 endpoint:=mesh_ops.derive_device_alias_worker_scope_v1(p_deployment,p_endpoint);
 IF endpoint.generation<>p_generation OR endpoint.provider_workspace_id=endpoint.consumer_workspace_id OR endpoint.state='ready' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Device alias withdrawal endpoint changed';
 END IF;
 PERFORM set_config('mesh.change_public_id',p_change::TEXT,TRUE);
 proof:=mesh_ops.device_alias_withdrawal_proof_internal_v1(p_endpoint,p_change,p_mode);
 IF NOT COALESCE((proof->>'changed')::BOOLEAN,FALSE) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias withdrawal mutation missing'; END IF;
 FOR expected IN SELECT value FROM jsonb_array_elements(proof->'events') LOOP
  SELECT value INTO STRICT supplied FROM jsonb_array_elements(p_events) WHERE value->>'stream_id'=expected->>'stream_id';
  IF supplied->>'sequence' IS DISTINCT FROM expected->>'sequence' OR supplied->>'previous_hash' IS DISTINCT FROM expected->>'previous_hash'
   OR supplied->>'audit_payload' IS DISTINCT FROM expected->>'audit_payload' OR supplied->>'outbox_payload' IS DISTINCT FROM expected->>'outbox_payload'
   OR supplied->>'network_revision' IS DISTINCT FROM expected->>'network_revision' OR supplied->>'sharing_revision' IS DISTINCT FROM expected->>'sharing_revision'
   OR supplied->>'workspace_id' IS DISTINCT FROM expected->>'workspace_id' OR supplied->>'network_id' IS DISTINCT FROM expected->>'network_id' THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Device alias withdrawal evidence mismatch';
  END IF;
  PERFORM mesh_audit.append_authority_evidence((expected->>'stream_id')::BIGINT,(supplied->>'event_id')::UUID,(supplied->>'outbox_id')::UUID,
   (expected->>'sequence')::BIGINT,decode(expected->>'previous_hash','hex'),decode(supplied->>'event_hash','hex'),proof->>'aggregate_kind',(proof->>'aggregate_id')::UUID,
   (proof->>'aggregate_version')::BIGINT,(expected->>'network_revision')::BIGINT,NULL::UUID,proof->>'action','sharing.client_alias',NULL::UUID,NULL::BYTEA,NULL::BYTEA,
   (expected->>'audit_payload')::JSONB,'network.revision.advanced',(expected->>'outbox_payload')::JSONB);
  count_value:=count_value+1;
 END LOOP;
 PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved);
 RETURN count_value;
EXCEPTION WHEN OTHERS THEN PERFORM mesh_ops.restore_device_alias_worker_context_v1(saved); RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_alias_withdrawal_proof_internal_v1(UUID,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.prepare_device_alias_withdrawal_v1(UUID,UUID,UUID,BIGINT,UUID,TEXT) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.finalize_device_alias_withdrawal_v1(UUID,UUID,BIGINT,UUID,TEXT,JSONB) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
