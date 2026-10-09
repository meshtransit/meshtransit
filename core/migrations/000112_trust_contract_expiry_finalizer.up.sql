-- Finalizes Trust Contracts whose expiry has passed. Traffic already stops at
-- expiry; this moves the contract, Imported Resource, consumer access name,
-- Private Endpoint and Federation Alias to their terminal states so the
-- consumer access name can be reserved again by a new share. The worker role
-- calls bounded entry points that the database operator moves to the sharing
-- writer. Evidence uses a system actor; there is no renewal path.

CREATE INDEX trust_contract_open_expiry_idx
    ON mesh.trust_contract (deployment_id, expires_at, public_id)
    WHERE state IN ('activating', 'active');

-- Expiry scans are read-only and limited to contracts already past expiry in
-- one installation. Every mutation re-derives the exact sharing scope.
CREATE POLICY deployment_share_expiry_scan ON mesh.deployment
    FOR SELECT TO mesh_share_writer
    USING (
        installation_public_id = NULLIF(
            pg_catalog.current_setting('mesh.share_expiry_deployment_public_id', TRUE), ''
        )::UUID
    );
CREATE POLICY trust_contract_share_expiry_scan ON mesh.trust_contract
    FOR SELECT TO mesh_share_writer
    USING (
        deployment_id = NULLIF(
            pg_catalog.current_setting('mesh.share_expiry_deployment_id', TRUE), ''
        )::BIGINT
        AND expires_at <= pg_catalog.clock_timestamp()
    );

-- Audit heads and mutation coverage are visible only inside the current
-- sharing scope and the current change of the current transaction.
GRANT USAGE ON SCHEMA mesh_audit TO mesh_share_writer;
CREATE POLICY audit_stream_share_expiry_read ON mesh_audit.audit_stream
    FOR SELECT TO mesh_share_writer
    USING (
        (workspace_id, network_id) IN (
            (mesh_ops.current_share_provider_workspace_id(), mesh_ops.current_share_provider_network_id()),
            (mesh_ops.current_share_consumer_workspace_id(), mesh_ops.current_share_consumer_network_id())
        )
    );
CREATE POLICY audit_stream_share_expiry_lock ON mesh_audit.audit_stream
    FOR UPDATE TO mesh_share_writer
    USING (
        (workspace_id, network_id) IN (
            (mesh_ops.current_share_provider_workspace_id(), mesh_ops.current_share_provider_network_id()),
            (mesh_ops.current_share_consumer_workspace_id(), mesh_ops.current_share_consumer_network_id())
        )
    )
    WITH CHECK (
        (workspace_id, network_id) IN (
            (mesh_ops.current_share_provider_workspace_id(), mesh_ops.current_share_provider_network_id()),
            (mesh_ops.current_share_consumer_workspace_id(), mesh_ops.current_share_consumer_network_id())
        )
    );
GRANT SELECT, UPDATE (id) ON mesh_audit.audit_stream TO mesh_share_writer;
CREATE POLICY authority_mutation_share_expiry_read ON mesh_audit.authority_mutation
    FOR SELECT TO mesh_share_writer
    USING (
        transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
        AND change_public_id = NULLIF(pg_catalog.current_setting('mesh.change_public_id', TRUE), '')::UUID
    );
GRANT SELECT ON mesh_audit.authority_mutation TO mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence(
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT,
    UUID, TEXT, TEXT, UUID, BYTEA, BYTEA, JSONB, TEXT, JSONB
) TO mesh_share_writer;

CREATE FUNCTION mesh_ops.save_trust_contract_expiry_context_v1()
RETURNS JSONB
LANGUAGE sql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_object_agg(name, COALESCE(pg_catalog.current_setting(name, TRUE), ''))
    FROM pg_catalog.unnest(ARRAY[
        'mesh.workspace_id', 'mesh.network_id',
        'mesh.share_provider_workspace_id', 'mesh.share_provider_network_id',
        'mesh.share_consumer_workspace_id', 'mesh.share_consumer_network_id',
        'mesh.share_expiry_deployment_public_id', 'mesh.share_expiry_deployment_id',
        'mesh.change_public_id'
    ]) AS name
$function$;

CREATE FUNCTION mesh_ops.restore_trust_contract_expiry_context_v1(p_context JSONB)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_setting RECORD;
BEGIN
    FOR v_setting IN SELECT key, value FROM pg_catalog.jsonb_each_text(p_context) LOOP
        PERFORM pg_catalog.set_config(v_setting.key, v_setting.value, TRUE);
    END LOOP;
END;
$function$;

-- Binds the installation and returns its internal id. Every other scan and
-- sharing setting is cleared first so no caller context leaks in.
CREATE FUNCTION mesh_ops.bind_trust_contract_expiry_deployment_v1(p_deployment UUID)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_name TEXT;
    v_deployment_id BIGINT;
BEGIN
    FOREACH v_name IN ARRAY ARRAY[
        'mesh.workspace_id', 'mesh.network_id',
        'mesh.share_provider_workspace_id', 'mesh.share_provider_network_id',
        'mesh.share_consumer_workspace_id', 'mesh.share_consumer_network_id',
        'mesh.share_expiry_deployment_public_id', 'mesh.share_expiry_deployment_id',
        'mesh.change_public_id'
    ] LOOP
        PERFORM pg_catalog.set_config(v_name, '', TRUE);
    END LOOP;
    IF p_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Trust Contract expiry scope';
    END IF;
    PERFORM pg_catalog.set_config('mesh.share_expiry_deployment_public_id', p_deployment::TEXT, TRUE);
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Trust Contract expiry scope unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.share_expiry_deployment_id', v_deployment_id::TEXT, TRUE);
    RETURN v_deployment_id;
END;
$function$;

-- Resolves the exact sharing scope of one contract past its expiry, then
-- closes the installation-wide scan before any lock or write.
CREATE FUNCTION mesh_ops.bind_trust_contract_expiry_scope_v1(p_deployment UUID, p_contract UUID)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT := mesh_ops.bind_trust_contract_expiry_deployment_v1(p_deployment);
    v_scope RECORD;
BEGIN
    SELECT contract.id, contract.provider_workspace_id, contract.provider_network_id,
        contract.consumer_workspace_id, contract.consumer_network_id
    INTO v_scope
    FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract AND contract.deployment_id = v_deployment_id;
    PERFORM pg_catalog.set_config('mesh.share_expiry_deployment_public_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.share_expiry_deployment_id', '', TRUE);
    IF v_scope.id IS NULL THEN
        RETURN NULL;
    END IF;
    PERFORM mesh_ops.set_share_scope_v1(
        v_scope.provider_workspace_id, v_scope.provider_network_id,
        v_scope.consumer_workspace_id, v_scope.consumer_network_id
    );
    RETURN v_scope.id;
END;
$function$;

-- Gateway-published state belongs to the reconciled withdrawal path. The
-- sharing writer has no grant on those tables, so the check stays here.
CREATE FUNCTION mesh_ops.private_endpoint_gateway_state_exists_internal_v1(p_endpoint_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh.private_endpoint_readiness AS readiness
        WHERE readiness.private_endpoint_id = p_endpoint_id
    ) OR EXISTS (
        SELECT 1 FROM mesh.imported_resource_dns_publication AS publication
        WHERE publication.private_endpoint_id = p_endpoint_id
    ) OR EXISTS (
        SELECT 1 FROM mesh_ops.private_endpoint_route_intent AS intent
        WHERE intent.private_endpoint_id = p_endpoint_id
    )
$function$;

-- Builds both audit/outbox events from committed-in-transaction state. It
-- locks the audit heads last and is recomputed by finalize for comparison.
CREATE FUNCTION mesh_ops.trust_contract_expiry_proof_internal_v1(p_contract_id BIGINT, p_change UUID)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_transaction BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    v_contract mesh.trust_contract%ROWTYPE;
    v_imported_public_id UUID;
    v_endpoints JSONB;
    v_side RECORD;
    v_head RECORD;
    v_audit JSONB;
    v_outbox JSONB;
    v_events JSONB := '[]'::JSONB;
BEGIN
    SELECT * INTO STRICT v_contract FROM mesh.trust_contract WHERE id = p_contract_id;
    IF v_contract.state <> 'expired' OR NOT EXISTS (
        SELECT 1 FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.transaction_id = v_transaction
          AND mutation.change_public_id = p_change
          AND mutation.aggregate_kind = 'trust_contract'
          AND mutation.row_public_id = v_contract.public_id
          AND mutation.after_version = v_contract.version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Trust Contract expiry mutation missing';
    END IF;
    SELECT imported.public_id INTO STRICT v_imported_public_id
    FROM mesh.imported_resource AS imported
    WHERE imported.trust_contract_id = v_contract.id
      AND imported.workspace_id = v_contract.consumer_workspace_id
      AND imported.network_id = v_contract.consumer_network_id;
    SELECT COALESCE(pg_catalog.jsonb_agg(endpoint.public_id ORDER BY endpoint.public_id), '[]'::JSONB)
    INTO v_endpoints
    FROM mesh.private_endpoint AS endpoint
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.row_public_id = endpoint.public_id
     AND mutation.aggregate_kind = 'private_endpoint'
     AND mutation.transaction_id = v_transaction
     AND mutation.change_public_id = p_change
    WHERE endpoint.trust_contract_id = v_contract.id;

    FOR v_side IN
        SELECT revision.workspace_id, revision.network_id,
            revision.network_revision, revision.sharing_revision,
            workspace.public_id AS workspace_public_id, network.public_id AS network_public_id,
            CASE WHEN revision.workspace_id = v_contract.provider_workspace_id
                AND revision.network_id = v_contract.provider_network_id
                THEN 'provider' ELSE 'consumer' END AS authority_side
        FROM mesh_ops.network_revision AS revision
        JOIN mesh.workspace AS workspace ON workspace.id = revision.workspace_id
        JOIN mesh.network AS network
          ON network.id = revision.network_id AND network.workspace_id = revision.workspace_id
        WHERE (revision.workspace_id, revision.network_id) IN (
            (v_contract.provider_workspace_id, v_contract.provider_network_id),
            (v_contract.consumer_workspace_id, v_contract.consumer_network_id)
        )
        ORDER BY revision.workspace_id, revision.network_id
    LOOP
        SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
        FROM mesh_audit.audit_stream AS stream
        WHERE stream.workspace_id = v_side.workspace_id AND stream.network_id = v_side.network_id
        FOR UPDATE;
        v_audit := pg_catalog.jsonb_build_object(
            'contract_public_id', v_contract.public_id,
            'imported_resource_public_id', v_imported_public_id,
            'private_endpoint_public_ids', v_endpoints,
            'authority_side', v_side.authority_side,
            'reason', 'expired',
            'expires_at', v_contract.expires_at,
            'ended_at', v_contract.ended_at,
            'network_revision', v_side.network_revision,
            'sharing_revision', v_side.sharing_revision
        );
        v_outbox := pg_catalog.jsonb_build_object(
            'contract_public_id', v_contract.public_id,
            'network_revision', v_side.network_revision,
            'subsystem', 'sharing',
            'subsystem_revision', v_side.sharing_revision
        );
        v_events := v_events || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'workspace_id', v_side.workspace_public_id,
            'network_id', v_side.network_public_id,
            'stream_id', v_head.id,
            'sequence', v_head.next_sequence,
            'previous_hash', pg_catalog.encode(v_head.latest_event_hash, 'hex'),
            'network_revision', v_side.network_revision,
            'sharing_revision', v_side.sharing_revision,
            'audit_payload', v_audit::TEXT,
            'outbox_payload', v_outbox::TEXT
        ));
    END LOOP;
    IF pg_catalog.jsonb_array_length(v_events) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Trust Contract expiry audit scope unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE,
        'transaction_id', v_transaction::TEXT,
        'change_id', p_change,
        'contract_id', v_contract.public_id,
        'aggregate_kind', 'trust_contract',
        'aggregate_id', v_contract.public_id,
        'aggregate_version', v_contract.version,
        'action', 'trust_contract.expired',
        'events', v_events
    );
END;
$function$;

-- Lists at most p_limit open contracts already past expiry, in keyset order.
-- The result is a discovery hint; prepare rechecks everything under locks.
CREATE FUNCTION mesh_ops.list_expired_trust_contracts_v1(
    p_deployment UUID,
    p_after_expires_at TIMESTAMPTZ,
    p_after_contract UUID,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_saved JSONB := mesh_ops.save_trust_contract_expiry_context_v1();
    v_deployment_id BIGINT;
    v_items JSONB;
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 128
        OR (p_after_expires_at IS NULL) <> (p_after_contract IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Trust Contract expiry page';
    END IF;
    v_deployment_id := mesh_ops.bind_trust_contract_expiry_deployment_v1(p_deployment);
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'contract_id', page.public_id, 'expires_at', page.expires_at
        ) ORDER BY page.expires_at, page.public_id), '[]'::JSONB),
        pg_catalog.count(*)
    INTO v_items, v_count
    FROM (
        SELECT contract.public_id, contract.expires_at
        FROM mesh.trust_contract AS contract
        WHERE contract.deployment_id = v_deployment_id
          AND contract.state IN ('activating', 'active')
          AND contract.expires_at <= pg_catalog.clock_timestamp()
          AND (
              p_after_expires_at IS NULL
              OR (contract.expires_at, contract.public_id) > (p_after_expires_at, p_after_contract)
          )
        ORDER BY contract.expires_at, contract.public_id
        LIMIT p_limit + 1
    ) AS page;
    IF v_count > p_limit THEN
        v_items := v_items - p_limit;
    END IF;
    PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
    RETURN pg_catalog.jsonb_build_object('items', v_items, 'done', v_count <= p_limit);
EXCEPTION WHEN OTHERS THEN
    PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
    RAISE;
END;
$function$;

-- Moves one expired contract and everything that names it to a terminal
-- state, advances both Network revisions and returns the evidence to hash.
-- Lock order: both revisions, the contract (skipping a concurrent writer),
-- the Imported Resource, access name, endpoints and aliases, audit heads.
CREATE FUNCTION mesh_ops.prepare_trust_contract_expiry_v1(
    p_deployment UUID,
    p_contract UUID,
    p_change UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_saved JSONB := mesh_ops.save_trust_contract_expiry_context_v1();
    v_unchanged CONSTANT JSONB := '{"changed":false,"events":[]}'::JSONB;
    v_contract_id BIGINT;
    v_contract mesh.trust_contract%ROWTYPE;
    v_imported mesh.imported_resource%ROWTYPE;
    v_name_id BIGINT;
    v_name_updated_at TIMESTAMPTZ;
    v_endpoint_ids BIGINT[];
    v_lease_ids BIGINT[];
    v_latest TIMESTAMPTZ;
    v_endpoint_expiry TIMESTAMPTZ;
    v_gateway BOOLEAN;
    v_direct INTEGER;
    v_rows INTEGER;
    v_decision TIMESTAMPTZ;
    v_scope RECORD;
    v_expected INTEGER;
    v_proof JSONB;
BEGIN
    IF p_contract IS NULL OR p_change IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_contract), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Trust Contract expiry';
    END IF;
    v_contract_id := mesh_ops.bind_trust_contract_expiry_scope_v1(p_deployment, p_contract);
    IF v_contract_id IS NULL THEN
        PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
        RETURN v_unchanged;
    END IF;

    FOR v_scope IN
        SELECT revision.workspace_id, revision.network_id
        FROM mesh_ops.network_revision AS revision
        WHERE (revision.workspace_id, revision.network_id) IN (
            (mesh_ops.current_share_provider_workspace_id(), mesh_ops.current_share_provider_network_id()),
            (mesh_ops.current_share_consumer_workspace_id(), mesh_ops.current_share_consumer_network_id())
        )
        ORDER BY revision.workspace_id, revision.network_id
        FOR UPDATE
    LOOP
        NULL;
    END LOOP;

    SELECT * INTO v_contract
    FROM mesh.trust_contract AS contract
    WHERE contract.id = v_contract_id
    FOR UPDATE SKIP LOCKED;
    IF v_contract.id IS NULL OR v_contract.state NOT IN ('activating', 'active')
        OR v_contract.expires_at > pg_catalog.clock_timestamp() THEN
        PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
        RETURN v_unchanged;
    END IF;

    SELECT * INTO STRICT v_imported
    FROM mesh.imported_resource AS imported
    WHERE imported.trust_contract_id = v_contract.id
      AND imported.workspace_id = v_contract.consumer_workspace_id
      AND imported.network_id = v_contract.consumer_network_id
    FOR UPDATE;
    IF v_imported.state NOT IN ('activating', 'active') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Imported Resource ended before its Trust Contract';
    END IF;
    SELECT name.id, name.updated_at INTO v_name_id, v_name_updated_at
    FROM mesh.imported_resource_access_name AS name
    WHERE name.imported_resource_id = v_imported.id
      AND name.workspace_id = v_imported.workspace_id
      AND name.network_id = v_imported.network_id
      AND name.state = 'reserved'
    FOR UPDATE;

    SELECT pg_catalog.array_agg(locked.id ORDER BY locked.id),
        pg_catalog.array_agg(locked.alias_lease_id ORDER BY locked.id),
        pg_catalog.max(locked.updated_at), pg_catalog.max(locked.expires_at),
        pg_catalog.bool_or(locked.state = 'ready'
            OR mesh_ops.private_endpoint_gateway_state_exists_internal_v1(locked.id))
    INTO v_endpoint_ids, v_lease_ids, v_latest, v_endpoint_expiry, v_gateway
    FROM (
        SELECT endpoint.id, endpoint.alias_lease_id, endpoint.updated_at,
            endpoint.expires_at, endpoint.state
        FROM mesh.private_endpoint AS endpoint
        WHERE endpoint.trust_contract_id = v_contract.id
          AND endpoint.state IN ('provisioning', 'ready')
        ORDER BY endpoint.id
        FOR UPDATE
    ) AS locked;
    IF COALESCE(v_gateway, FALSE) THEN
        -- Gateway-backed endpoints are withdrawn with route evidence elsewhere.
        PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
        RETURN v_unchanged;
    END IF;
    v_decision := pg_catalog.clock_timestamp();
    IF v_endpoint_expiry > v_decision THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Private Endpoint outlives its Trust Contract';
    END IF;
    v_decision := GREATEST(v_decision, v_contract.updated_at, v_imported.updated_at, v_name_updated_at, v_latest);
    IF v_lease_ids IS NOT NULL THEN
        SELECT pg_catalog.max(locked.updated_at) INTO v_latest
        FROM (
            SELECT lease.updated_at
            FROM mesh.federation_alias_lease AS lease
            WHERE lease.id = ANY(v_lease_ids) AND lease.state IN ('reserved', 'active')
            ORDER BY lease.id
            FOR UPDATE
        ) AS locked;
        v_decision := GREATEST(v_decision, v_latest);
    END IF;
    SELECT pg_catalog.count(*), pg_catalog.max(locked.updated_at) INTO v_direct, v_latest
    FROM (
        SELECT direct.updated_at
        FROM mesh.direct_device_endpoint AS direct
        WHERE direct.trust_contract_id = v_contract.id AND direct.state = 'ready'
        ORDER BY direct.id
        FOR UPDATE
    ) AS locked;
    v_decision := GREATEST(v_decision, v_latest);

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    -- The direct-endpoint trigger copies state, updated_at and ended_at.
    UPDATE mesh.trust_contract
    SET state = 'expired', version = version + 1, updated_at = v_decision, ended_at = v_decision
    WHERE id = v_contract.id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_expected := v_rows + v_direct;
    UPDATE mesh.imported_resource
    SET state = 'expired', version = version + 1, updated_at = v_decision, ended_at = v_decision
    WHERE id = v_imported.id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_expected + v_rows <> 2 + v_direct THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Trust Contract expiry authority changed';
    END IF;
    v_expected := v_expected + v_rows;
    IF v_name_id IS NOT NULL THEN
        UPDATE mesh.imported_resource_access_name
        SET state = 'withdrawn', version = version + 1, updated_at = v_decision, withdrawn_at = v_decision
        WHERE id = v_name_id;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_expected := v_expected + v_rows;
    END IF;
    IF v_endpoint_ids IS NOT NULL THEN
        UPDATE mesh.private_endpoint
        SET state = 'expired', version = version + 1, updated_at = v_decision, ended_at = v_decision
        WHERE id = ANY(v_endpoint_ids);
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_expected := v_expected + v_rows;
        UPDATE mesh.federation_alias_lease
        SET state = 'withdrawn', version = version + 1, updated_at = v_decision, withdrawn_at = v_decision
        WHERE id = ANY(v_lease_ids) AND state IN ('reserved', 'active');
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_expected := v_expected + v_rows;
    END IF;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = GREATEST(revision.updated_at, v_decision)
    WHERE (revision.workspace_id, revision.network_id) IN (
        (v_contract.provider_workspace_id, v_contract.provider_network_id),
        (v_contract.consumer_workspace_id, v_contract.consumer_network_id)
    );
    IF (
        SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = p_change
          AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
    ) <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Trust Contract expiry mutation set is invalid';
    END IF;
    v_proof := mesh_ops.trust_contract_expiry_proof_internal_v1(v_contract.id, p_change);
    PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
    RETURN v_proof;
EXCEPTION WHEN OTHERS THEN
    PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
    RAISE;
END;
$function$;

-- Recomputes the proof, compares it with the hashed events, then appends one
-- audit event and one outbox event per Network with a system actor.
CREATE FUNCTION mesh_ops.finalize_trust_contract_expiry_v1(
    p_deployment UUID,
    p_contract UUID,
    p_change UUID,
    p_events JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_saved JSONB := mesh_ops.save_trust_contract_expiry_context_v1();
    v_contract_id BIGINT;
    v_proof JSONB;
    v_expected JSONB;
    v_supplied JSONB;
    v_sequence BIGINT;
    v_count INTEGER := 0;
BEGIN
    IF p_contract IS NULL OR p_change IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_contract), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7
        OR p_events IS NULL OR pg_catalog.jsonb_typeof(p_events) <> 'array'
        OR pg_catalog.jsonb_array_length(p_events) <> 2
        OR pg_catalog.octet_length(p_events::TEXT) > 32768 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Trust Contract expiry evidence';
    END IF;
    v_contract_id := mesh_ops.bind_trust_contract_expiry_scope_v1(p_deployment, p_contract);
    IF v_contract_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Trust Contract expiry scope changed';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    v_proof := mesh_ops.trust_contract_expiry_proof_internal_v1(v_contract_id, p_change);
    FOR v_expected IN SELECT value FROM pg_catalog.jsonb_array_elements(v_proof -> 'events') LOOP
        SELECT value INTO v_supplied
        FROM pg_catalog.jsonb_array_elements(p_events)
        WHERE value ->> 'stream_id' = v_expected ->> 'stream_id';
        IF v_supplied IS NULL
            OR v_supplied ->> 'workspace_id' IS DISTINCT FROM v_expected ->> 'workspace_id'
            OR v_supplied ->> 'network_id' IS DISTINCT FROM v_expected ->> 'network_id'
            OR v_supplied ->> 'sequence' IS DISTINCT FROM v_expected ->> 'sequence'
            OR v_supplied ->> 'previous_hash' IS DISTINCT FROM v_expected ->> 'previous_hash'
            OR v_supplied ->> 'network_revision' IS DISTINCT FROM v_expected ->> 'network_revision'
            OR v_supplied ->> 'sharing_revision' IS DISTINCT FROM v_expected ->> 'sharing_revision'
            OR v_supplied ->> 'audit_payload' IS DISTINCT FROM v_expected ->> 'audit_payload'
            OR v_supplied ->> 'outbox_payload' IS DISTINCT FROM v_expected ->> 'outbox_payload' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Trust Contract expiry evidence mismatch';
        END IF;
        v_sequence := mesh_audit.append_authority_evidence(
            (v_expected ->> 'stream_id')::BIGINT,
            (v_supplied ->> 'event_id')::UUID,
            (v_supplied ->> 'outbox_id')::UUID,
            (v_expected ->> 'sequence')::BIGINT,
            pg_catalog.decode(v_expected ->> 'previous_hash', 'hex'),
            pg_catalog.decode(v_supplied ->> 'event_hash', 'hex'),
            'trust_contract',
            (v_proof ->> 'aggregate_id')::UUID,
            (v_proof ->> 'aggregate_version')::BIGINT,
            (v_expected ->> 'network_revision')::BIGINT,
            NULL::UUID,
            'trust_contract.expired',
            'system.reconcile',
            NULL::UUID,
            NULL::BYTEA,
            NULL::BYTEA,
            (v_expected ->> 'audit_payload')::JSONB,
            'network.revision.advanced',
            (v_expected ->> 'outbox_payload')::JSONB
        );
        IF v_sequence <> (v_expected ->> 'sequence')::BIGINT THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Trust Contract expiry evidence changed';
        END IF;
        v_count := v_count + 1;
    END LOOP;
    PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
    RETURN v_count;
EXCEPTION WHEN OTHERS THEN
    PERFORM mesh_ops.restore_trust_contract_expiry_context_v1(v_saved);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.save_trust_contract_expiry_context_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.restore_trust_contract_expiry_context_v1(JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.bind_trust_contract_expiry_deployment_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.bind_trust_contract_expiry_scope_v1(UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.private_endpoint_gateway_state_exists_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.trust_contract_expiry_proof_internal_v1(BIGINT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.list_expired_trust_contracts_v1(UUID, TIMESTAMPTZ, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.prepare_trust_contract_expiry_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;
REVOKE ALL ON FUNCTION mesh_ops.finalize_trust_contract_expiry_v1(UUID, UUID, UUID, JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer,
        mesh_device_alias_writer, mesh_direct_map_reader;

-- Helpers run inside the sharing writer's entry points only.
GRANT EXECUTE ON FUNCTION
    mesh_ops.save_trust_contract_expiry_context_v1(),
    mesh_ops.restore_trust_contract_expiry_context_v1(JSONB),
    mesh_ops.bind_trust_contract_expiry_deployment_v1(UUID),
    mesh_ops.bind_trust_contract_expiry_scope_v1(UUID, UUID),
    mesh_ops.private_endpoint_gateway_state_exists_internal_v1(BIGINT),
    mesh_ops.trust_contract_expiry_proof_internal_v1(BIGINT, UUID)
TO mesh_share_writer;
