-- K2d d4a: Kubernetes operation records name the access profile that let a
-- request through, and denials the requests a profile refused (K2 design
-- §7.5, §29).
--
-- An intent's profile is the scope hash of the grant that let it through
-- (empty: a whole grant), report_allowed when a reporting grant let it
-- through what it would deny. A denial of a profile reason may carry one
-- sample request (no body, no credentials). Constraints are added NOT
-- VALID: every existing row has the new columns NULL or FALSE, and
-- scanning every partition under this migration's lock would stop the
-- writers. Schema 245's writers stay for a Core before d4.

ALTER TABLE mesh_audit.kubernetes_operation
    ADD COLUMN profile_hash BYTEA,
    ADD COLUMN report_allowed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mesh_audit.kubernetes_operation
    ADD CONSTRAINT kubernetes_operation_profile_check CHECK (
        (profile_hash IS NULL OR pg_catalog.octet_length(profile_hash) = 32)
        AND (NOT report_allowed OR profile_hash IS NOT NULL)
    ) NOT VALID;

ALTER TABLE mesh_audit.kubernetes_operation_denial
    ADD COLUMN sample_verb TEXT,
    ADD COLUMN sample_api_group TEXT,
    ADD COLUMN sample_resource TEXT,
    ADD COLUMN sample_subresource TEXT,
    ADD COLUMN sample_namespace TEXT,
    ADD COLUMN sample_scope BYTEA;
ALTER TABLE mesh_audit.kubernetes_operation_denial
    DROP CONSTRAINT kubernetes_operation_denial_reason_check;
ALTER TABLE mesh_audit.kubernetes_operation_denial
    ADD CONSTRAINT kubernetes_operation_denial_reason_check CHECK (
        reason IN ('unauthenticated', 'forbidden', 'not_granted', 'stale', 'limited', 'other', 'profile_denied',
            'profile_would_deny')
    ) NOT VALID,
    ADD CONSTRAINT kubernetes_operation_denial_sample_check CHECK (
        (sample_verb IS NULL AND sample_api_group IS NULL AND sample_resource IS NULL
            AND sample_subresource IS NULL AND sample_namespace IS NULL AND sample_scope IS NULL)
        OR (reason IN ('profile_denied', 'profile_would_deny')
            -- Every field, or a NULL would pass the comparisons below.
            AND sample_verb IS NOT NULL AND sample_api_group IS NOT NULL AND sample_resource IS NOT NULL
            AND sample_subresource IS NOT NULL AND sample_namespace IS NOT NULL AND sample_scope IS NOT NULL
            AND pg_catalog.octet_length(sample_verb) BETWEEN 1 AND 32
            AND pg_catalog.octet_length(sample_api_group) <= 253
            AND pg_catalog.octet_length(sample_resource) <= 63
            AND pg_catalog.octet_length(sample_subresource) <= 63
            AND pg_catalog.octet_length(sample_namespace) <= 63
            AND pg_catalog.octet_length(sample_scope) = 32)
    ) NOT VALID;

-- Schema 245's check, and the profile fields: a 32-byte hex scope hash or
-- none, report_allowed a boolean only with one.
CREATE FUNCTION mesh_ops.kubernetes_operation_intent_valid_internal_v2(p_row JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.kubernetes_operation_intent_valid_internal_v1(p_row)
        AND CASE WHEN p_row->'profile' IS NULL OR pg_catalog.jsonb_typeof(p_row->'profile') = 'null' THEN TRUE
            ELSE COALESCE(p_row->>'profile' ~ '^[0-9a-f]{64}$', FALSE) END
        AND CASE WHEN p_row->'report_allowed' IS NULL THEN TRUE
            WHEN pg_catalog.jsonb_typeof(p_row->'report_allowed') <> 'boolean' THEN FALSE
            ELSE NOT (p_row->>'report_allowed')::BOOLEAN OR COALESCE(p_row->>'profile' ~ '^[0-9a-f]{64}$', FALSE) END
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_operation_intent_valid_internal_v2(JSONB) FROM PUBLIC;

-- record_kubernetes_operations_v1 of schema 245 with the intent's profile.
CREATE FUNCTION mesh_ops.record_kubernetes_operations_v2(p_rows JSONB)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_gateways JSONB;
    v_existing JSONB;
    v_answers JSONB;
    v_lock BIGINT;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION USING ERRCODE = '25001', MESSAGE = 'Kubernetes operations are recorded at READ COMMITTED';
    END IF;
    IF p_rows IS NULL OR pg_catalog.jsonb_typeof(p_rows) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rows) NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes operation batch';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_rows) AS element
        WHERE CASE WHEN element->>'audit_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            THEN pg_catalog.abs(EXTRACT(EPOCH FROM
                pg_catalog.uuid_extract_timestamp((element->>'audit_id')::UUID) - v_now)) > 5
            ELSE TRUE END
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes operation audit_id out of range';
    END IF;

    SELECT COALESCE(pg_catalog.jsonb_object_agg(gateway.gateway_key, pg_catalog.jsonb_build_object(
        'id', gateway.device_id, 'workspace', gateway.workspace_id, 'network', gateway.network_id,
        'cluster', gateway.cluster_id)), '{}'::JSONB)
    INTO v_gateways
    FROM mesh_ops.kubernetes_operation_gateways_internal_v1(
        ARRAY(SELECT DISTINCT element->>'gateway' FROM pg_catalog.jsonb_array_elements(p_rows) AS element
              WHERE element->>'gateway' IS NOT NULL), v_now) AS gateway;

    -- (1) One lock per gateway, in the order of the locks' own keys.
    FOR v_lock IN
        SELECT DISTINCT pg_catalog.hashtextextended('mesh_audit.kubernetes_operation:' || (value->>'id'), 0)
        FROM pg_catalog.jsonb_each(v_gateways) ORDER BY 1
    LOOP
        PERFORM pg_catalog.pg_advisory_xact_lock(v_lock);
    END LOOP;

    -- (2) What those gateways already sent within 10 minutes.
    SELECT COALESCE(pg_catalog.jsonb_object_agg(
        operation.gateway_device_id::TEXT || ':' || pg_catalog.encode(operation.intent_id, 'hex'),
        pg_catalog.jsonb_build_object('audit_id', operation.audit_id,
            'digest', pg_catalog.encode(operation.intent_digest, 'hex'))), '{}'::JSONB)
    INTO v_existing
    FROM mesh_audit.kubernetes_operation AS operation
    WHERE operation.received_at > v_now - INTERVAL '10 minutes'
      AND (operation.gateway_device_id, operation.intent_id) IN (
          SELECT (v_gateways->(element->>'gateway')->>'id')::BIGINT,
              CASE WHEN element->>'intent_id' ~ '^[0-9a-f]{32}$' THEN pg_catalog.decode(element->>'intent_id', 'hex') END
          FROM pg_catalog.jsonb_array_elements(p_rows) AS element
          WHERE v_gateways ? (element->>'gateway'));

    -- (3) Each intent's answer, then the accepted ones inserted.
    WITH input AS (
        SELECT element.ordinal, element.value AS item, v_gateways->(element.value->>'gateway') AS gateway_row,
            mesh_ops.kubernetes_operation_intent_valid_internal_v2(element.value) AS valid
        FROM pg_catalog.jsonb_array_elements(p_rows) WITH ORDINALITY AS element(value, ordinal)
    ), resolved AS (
        SELECT input.*, peer.id AS peer_id,
            v_existing->((input.gateway_row->>'id') || ':' || (input.item->>'intent_id')) AS earlier,
            -- The first intent of a gateway with this id in the batch decides
            -- for the rest (review b0a H2).
            pg_catalog.first_value(input.ordinal) OVER same AS first_ordinal,
            pg_catalog.first_value(input.item->>'digest') OVER same AS first_digest,
            pg_catalog.first_value(input.item->>'audit_id') OVER same AS first_audit_id
        FROM input
        LEFT JOIN mesh.device AS peer
          ON input.gateway_row IS NOT NULL
         AND peer.public_id = CASE WHEN input.valid THEN (input.item->>'peer')::UUID END
         AND peer.workspace_id = (input.gateway_row->>'workspace')::BIGINT
         AND peer.network_id = (input.gateway_row->>'network')::BIGINT
         AND peer.state = 'active' AND peer.deleted_at IS NULL AND peer.expires_at > v_now
         AND peer.kind <> 'kubernetes_gateway'
        -- Only rows in form share a window: an invalid first never decides
        -- for a valid one.
        WINDOW same AS (PARTITION BY input.valid, input.gateway_row->>'id', input.item->>'intent_id' ORDER BY input.ordinal
            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)
    ), first_outcome AS (
        SELECT resolved.*, CASE
            WHEN NOT resolved.valid THEN 'invalid'
            WHEN resolved.gateway_row IS NULL THEN 'gateway'
            WHEN resolved.earlier IS NOT NULL AND resolved.earlier->>'digest' = resolved.item->>'digest'
                THEN 'duplicate'
            WHEN resolved.earlier IS NOT NULL THEN 'conflict'
            WHEN resolved.peer_id IS NULL THEN 'device'
            ELSE 'accepted' END AS own_outcome
        FROM resolved
    ), ranked AS (
        SELECT first_outcome.*,
            pg_catalog.first_value(first_outcome.own_outcome) OVER same_valid AS first_outcome_of_id
        FROM first_outcome
        WINDOW same_valid AS (PARTITION BY first_outcome.valid, first_outcome.gateway_row->>'id',
            first_outcome.item->>'intent_id'
            ORDER BY first_outcome.ordinal ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)
    ), answered AS (
        SELECT ranked.*, CASE
            -- A later intent of the batch with the first's id and gateway: the
            -- first decides (one window, not a lookup per row).
            WHEN ranked.own_outcome IN ('invalid', 'gateway') OR ranked.ordinal = ranked.first_ordinal
                THEN ranked.own_outcome
            WHEN ranked.item->>'digest' IS DISTINCT FROM ranked.first_digest THEN 'conflict'
            WHEN ranked.first_outcome_of_id = 'accepted' THEN 'duplicate'
            ELSE ranked.first_outcome_of_id
            END AS outcome
        FROM ranked
    ), inserted AS (
        INSERT INTO mesh_audit.kubernetes_operation (received_at, audit_id, workspace_id, network_id,
            kubernetes_cluster_id, gateway_device_id, peer_device_id, owner_kind, owner_ref, network_revision,
            class, groups, verb, api_group, resource, subresource, namespace, name, impersonated, token_id,
            observed_at, clock_skew, intent_id, intent_digest, profile_hash, report_allowed)
        SELECT pg_catalog.uuid_extract_timestamp((answered.item->>'audit_id')::UUID),
            (answered.item->>'audit_id')::UUID,
            (answered.gateway_row->>'workspace')::BIGINT, (answered.gateway_row->>'network')::BIGINT,
            (answered.gateway_row->>'cluster')::BIGINT, (answered.gateway_row->>'id')::BIGINT, answered.peer_id,
            answered.item->>'owner_kind', answered.item->>'owner_ref', (answered.item->>'network_revision')::BIGINT,
            answered.item->>'class',
            ARRAY(SELECT pg_catalog.jsonb_array_elements_text(answered.item->'groups')),
            answered.item->>'verb', answered.item->>'api_group', answered.item->>'resource',
            answered.item->>'subresource', answered.item->>'namespace', answered.item->>'name',
            answered.item->>'impersonated', pg_catalog.decode(answered.item->>'token_id', 'hex'),
            pg_catalog.to_timestamp((answered.item->>'observed_ms')::BIGINT / 1000.0),
            (answered.item->>'clock_skew')::BOOLEAN,
            pg_catalog.decode(answered.item->>'intent_id', 'hex'), pg_catalog.decode(answered.item->>'digest', 'hex'),
            pg_catalog.decode(answered.item->>'profile', 'hex'),
            COALESCE((answered.item->>'report_allowed')::BOOLEAN, FALSE)
        FROM answered
        WHERE answered.outcome = 'accepted'
        RETURNING audit_id
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('outcome', answered.outcome,
        'audit_id', CASE
            WHEN answered.outcome = 'accepted' THEN answered.item->>'audit_id'
            WHEN answered.outcome = 'duplicate' AND answered.earlier IS NOT NULL THEN answered.earlier->>'audit_id'
            WHEN answered.outcome = 'duplicate' THEN answered.first_audit_id END)
        ORDER BY answered.ordinal)
    INTO v_answers
    FROM answered;
    RETURN pg_catalog.jsonb_build_object('answers', v_answers);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_operations_v2(JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_operations_v2(JSONB) TO mesh_runtime;

-- record_kubernetes_operation_outcomes_v1 of schema 245 with the profile
-- reasons and their samples.
CREATE FUNCTION mesh_ops.record_kubernetes_operation_outcomes_v2(p_outcomes JSONB, p_denials JSONB)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_gateways JSONB;
    v_outcomes INTEGER;
    v_denials INTEGER;
BEGIN
    IF p_outcomes IS NULL OR pg_catalog.jsonb_typeof(p_outcomes) <> 'array'
        OR pg_catalog.jsonb_array_length(p_outcomes) > 10000
        OR p_denials IS NULL OR pg_catalog.jsonb_typeof(p_denials) <> 'array'
        OR pg_catalog.jsonb_array_length(p_denials) > 2560 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes operation outcomes';
    END IF;
    SELECT COALESCE(pg_catalog.jsonb_object_agg(gateway.gateway_key, pg_catalog.jsonb_build_object(
        'id', gateway.device_id, 'workspace', gateway.workspace_id, 'network', gateway.network_id,
        'cluster', gateway.cluster_id)), '{}'::JSONB)
    INTO v_gateways
    FROM mesh_ops.kubernetes_operation_gateways_internal_v1(
        ARRAY(SELECT DISTINCT sent->>'gateway'
              FROM (SELECT value FROM pg_catalog.jsonb_array_elements(p_outcomes)
                    UNION ALL SELECT value FROM pg_catalog.jsonb_array_elements(p_denials)) AS listed(sent)
              WHERE sent->>'gateway' IS NOT NULL), v_now) AS gateway;

    INSERT INTO mesh_audit.kubernetes_operation_outcome (recorded_at, audit_id, workspace_id,
        gateway_device_id, status, duration_ms)
    SELECT v_now, (item->>'audit_id')::UUID, (v_gateways->(item->>'gateway')->>'workspace')::BIGINT,
        (v_gateways->(item->>'gateway')->>'id')::BIGINT, (item->>'status')::INTEGER, (item->>'duration_ms')::INTEGER
    FROM pg_catalog.jsonb_array_elements(p_outcomes) AS listed(item)
    WHERE v_gateways ? (item->>'gateway')
      AND COALESCE(item->>'audit_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', FALSE)
      AND COALESCE(item->>'status' ~ '^[0-9]{1,3}$', FALSE)
      AND COALESCE(item->>'duration_ms' ~ '^[0-9]{1,9}$', FALSE);
    GET DIAGNOSTICS v_outcomes = ROW_COUNT;

    INSERT INTO mesh_audit.kubernetes_operation_denial (recorded_at, workspace_id, network_id,
        kubernetes_cluster_id, gateway_device_id, peer_device_id, reason, count, first_at, last_at,
        sample_verb, sample_api_group, sample_resource, sample_subresource, sample_namespace, sample_scope)
    SELECT v_now, (v_gateways->(item->>'gateway')->>'workspace')::BIGINT,
        (v_gateways->(item->>'gateway')->>'network')::BIGINT, (v_gateways->(item->>'gateway')->>'cluster')::BIGINT,
        (v_gateways->(item->>'gateway')->>'id')::BIGINT, peer.id, item->>'reason', (item->>'count')::INTEGER,
        pg_catalog.to_timestamp((item->>'first_ms')::BIGINT / 1000.0),
        pg_catalog.to_timestamp((item->>'last_ms')::BIGINT / 1000.0),
        item->'sample'->>'verb', item->'sample'->>'api_group', item->'sample'->>'resource',
        item->'sample'->>'subresource', item->'sample'->>'namespace',
        pg_catalog.decode(item->'sample'->>'scope', 'hex')
    FROM pg_catalog.jsonb_array_elements(p_denials) AS listed(item)
    LEFT JOIN mesh.device AS peer
      ON peer.public_id = CASE WHEN item->>'peer' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN (item->>'peer')::UUID END
     AND peer.workspace_id = (v_gateways->(item->>'gateway')->>'workspace')::BIGINT
     AND peer.network_id = (v_gateways->(item->>'gateway')->>'network')::BIGINT
    WHERE v_gateways ? (item->>'gateway')
      AND COALESCE(item->>'reason' IN ('unauthenticated', 'forbidden', 'not_granted', 'stale', 'limited', 'other',
          'profile_denied', 'profile_would_deny'), FALSE)
      -- A sample only with a profile reason, and in form (K2 §7.5).
      AND CASE WHEN item->'sample' IS NULL OR pg_catalog.jsonb_typeof(item->'sample') = 'null' THEN TRUE
          WHEN pg_catalog.jsonb_typeof(item->'sample') = 'object'
              AND item->>'reason' IN ('profile_denied', 'profile_would_deny')
          THEN COALESCE(pg_catalog.octet_length(item->'sample'->>'verb') BETWEEN 1 AND 32, FALSE)
              AND COALESCE(pg_catalog.octet_length(item->'sample'->>'api_group') <= 253, FALSE)
              AND COALESCE(pg_catalog.octet_length(item->'sample'->>'resource') <= 63, FALSE)
              AND COALESCE(pg_catalog.octet_length(item->'sample'->>'subresource') <= 63, FALSE)
              AND COALESCE(pg_catalog.octet_length(item->'sample'->>'namespace') <= 63, FALSE)
              AND COALESCE(item->'sample'->>'scope' ~ '^[0-9a-f]{64}$', FALSE)
          ELSE FALSE END
      AND COALESCE(item->>'count' ~ '^[1-9][0-9]{0,8}$', FALSE)
      AND CASE WHEN item->>'first_ms' ~ '^[0-9]{1,15}$' AND item->>'last_ms' ~ '^[0-9]{1,15}$'
          THEN (item->>'last_ms')::BIGINT <= 253402300799999
              AND (item->>'first_ms')::BIGINT <= (item->>'last_ms')::BIGINT
          ELSE FALSE END;
    GET DIAGNOSTICS v_denials = ROW_COUNT;
    RETURN pg_catalog.jsonb_build_object('outcomes', v_outcomes, 'denials', v_denials);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_operation_outcomes_v2(JSONB, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_operation_outcomes_v2(JSONB, JSONB) TO mesh_runtime;
