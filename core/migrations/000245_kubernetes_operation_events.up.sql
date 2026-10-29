-- Schema 245 (K1b0, docs/k8s-k1b0-operation-events-design.md §4): the
-- Kubernetes operations gateways record before they forward a type A
-- request (K1-I10), their outcomes and the type B denials.
--
-- Not the management audit stream: its sealed chain and outbox are for
-- operator actions, too dear for millions of kubectl operations a day.
-- Append only (no UPDATE, no role may DELETE), monthly partitions without a
-- DEFAULT, kept 13 months by the worker. received_at is the millisecond of
-- the Core-issued UUIDv7 audit_id, so a lookup by audit_id touches one
-- partition.
--
-- Control checks every intent in Go before it reaches the writer (§3.3):
-- sizes, characters, the peer and its groups against the gateway's own map.
-- The writer function checks every field again before any cast and never
-- raises for one row: a row it cannot take is answered on its own, so one
-- gateway's row never fails another tenant's (review b0a H1). Gateways are
-- found by the keys control proved in their sessions; a writer batch spans
-- sessions, so this is a lookup, and only mesh_runtime may write.

CREATE TABLE mesh_audit.kubernetes_operation (
    received_at TIMESTAMPTZ NOT NULL,
    audit_id UUID NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    gateway_device_id BIGINT NOT NULL,
    peer_device_id BIGINT NOT NULL,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('member', 'tags', 'workspace')),
    owner_ref TEXT NOT NULL CHECK (pg_catalog.octet_length(owner_ref) <= 1024),
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    class TEXT NOT NULL CHECK (class IN ('write', 'exec', 'proxy', 'secret_read', 'privileged', 'unparsed')),
    groups TEXT[] NOT NULL CHECK (pg_catalog.cardinality(groups) BETWEEN 0 AND 16),
    verb TEXT NOT NULL CHECK (pg_catalog.octet_length(verb) BETWEEN 1 AND 32),
    api_group TEXT NOT NULL CHECK (pg_catalog.octet_length(api_group) <= 253),
    resource TEXT NOT NULL CHECK (pg_catalog.octet_length(resource) <= 63),
    subresource TEXT NOT NULL CHECK (pg_catalog.octet_length(subresource) <= 63),
    namespace TEXT NOT NULL CHECK (pg_catalog.octet_length(namespace) <= 63),
    name TEXT NOT NULL CHECK (pg_catalog.octet_length(name) <= 253),
    impersonated TEXT NOT NULL CHECK (pg_catalog.octet_length(impersonated) <= 253),
    token_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(token_id) <= 32),
    observed_at TIMESTAMPTZ NOT NULL,
    clock_skew BOOLEAN NOT NULL,
    intent_id BYTEA NOT NULL CHECK (pg_catalog.octet_length(intent_id) = 16),
    intent_digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(intent_digest) = 32),
    CONSTRAINT kubernetes_operation_audit_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(audit_id), 6) >> 4 = 7
        AND received_at = pg_catalog.uuid_extract_timestamp(audit_id)
    ),
    PRIMARY KEY (received_at, audit_id)
) PARTITION BY RANGE (received_at);

CREATE INDEX kubernetes_operation_workspace_idx
    ON mesh_audit.kubernetes_operation (workspace_id, received_at DESC);
CREATE INDEX kubernetes_operation_cluster_idx
    ON mesh_audit.kubernetes_operation (kubernetes_cluster_id, received_at DESC);
CREATE INDEX kubernetes_operation_intent_idx
    ON mesh_audit.kubernetes_operation (gateway_device_id, intent_id, received_at);

-- Outcomes and denials carry the gateway and Workspace of the session that
-- wrote them: readers join on (audit_id, gateway_device_id), so no gateway
-- writes onto another's operations (review v1 H3).
CREATE TABLE mesh_audit.kubernetes_operation_outcome (
    recorded_at TIMESTAMPTZ NOT NULL,
    audit_id UUID NOT NULL,
    workspace_id BIGINT NOT NULL,
    gateway_device_id BIGINT NOT NULL,
    status INTEGER NOT NULL CHECK (status BETWEEN 0 AND 999),
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0)
) PARTITION BY RANGE (recorded_at);
CREATE INDEX kubernetes_operation_outcome_audit_idx
    ON mesh_audit.kubernetes_operation_outcome (audit_id, gateway_device_id);
CREATE INDEX kubernetes_operation_outcome_workspace_idx
    ON mesh_audit.kubernetes_operation_outcome (workspace_id, recorded_at DESC);

CREATE TABLE mesh_audit.kubernetes_operation_denial (
    recorded_at TIMESTAMPTZ NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    gateway_device_id BIGINT NOT NULL,
    peer_device_id BIGINT,
    reason TEXT NOT NULL CHECK (
        reason IN ('unauthenticated', 'forbidden', 'not_granted', 'stale', 'limited', 'other')
    ),
    count INTEGER NOT NULL CHECK (count > 0),
    first_at TIMESTAMPTZ NOT NULL,
    last_at TIMESTAMPTZ NOT NULL CHECK (last_at >= first_at)
) PARTITION BY RANGE (recorded_at);
CREATE INDEX kubernetes_operation_denial_workspace_idx
    ON mesh_audit.kubernetes_operation_denial (workspace_id, recorded_at DESC);

-- Append only: nothing changes a row; only the erase and retention
-- functions below remove any.
CREATE FUNCTION mesh_audit.refuse_kubernetes_operation_update_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes operations are append only';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.refuse_kubernetes_operation_update_v1() FROM PUBLIC;
CREATE TRIGGER kubernetes_operation_append_only BEFORE UPDATE ON mesh_audit.kubernetes_operation
    FOR EACH ROW EXECUTE FUNCTION mesh_audit.refuse_kubernetes_operation_update_v1();
CREATE TRIGGER kubernetes_operation_outcome_append_only BEFORE UPDATE ON mesh_audit.kubernetes_operation_outcome
    FOR EACH ROW EXECUTE FUNCTION mesh_audit.refuse_kubernetes_operation_update_v1();
CREATE TRIGGER kubernetes_operation_denial_append_only BEFORE UPDATE ON mesh_audit.kubernetes_operation_denial
    FOR EACH ROW EXECUTE FUNCTION mesh_audit.refuse_kubernetes_operation_update_v1();

ALTER TABLE mesh_audit.kubernetes_operation ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.kubernetes_operation FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.kubernetes_operation_outcome ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.kubernetes_operation_outcome FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.kubernetes_operation_denial ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.kubernetes_operation_denial FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_operation_migrator_policy ON mesh_audit.kubernetes_operation
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY kubernetes_operation_outcome_migrator_policy ON mesh_audit.kubernetes_operation_outcome
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY kubernetes_operation_denial_migrator_policy ON mesh_audit.kubernetes_operation_denial
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_audit.kubernetes_operation, mesh_audit.kubernetes_operation_outcome,
    mesh_audit.kubernetes_operation_denial FROM PUBLIC;

-- Who erased what and why: the erase function's own record, written in its
-- transaction (append only, as the operations).
CREATE TABLE mesh_audit.kubernetes_operation_erasure (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    erased_at TIMESTAMPTZ NOT NULL,
    workspace_id BIGINT NOT NULL,
    actor TEXT NOT NULL CHECK (pg_catalog.octet_length(actor) BETWEEN 1 AND 128 AND actor ~ '^[ -~]+$'),
    change_ref TEXT NOT NULL CHECK (
        pg_catalog.octet_length(change_ref) BETWEEN 1 AND 128 AND change_ref ~ '^[ -~]+$'
    ),
    operations BIGINT NOT NULL CHECK (operations >= 0),
    outcomes BIGINT NOT NULL CHECK (outcomes >= 0),
    denials BIGINT NOT NULL CHECK (denials >= 0)
);
CREATE TRIGGER kubernetes_operation_erasure_append_only BEFORE UPDATE ON mesh_audit.kubernetes_operation_erasure
    FOR EACH ROW EXECUTE FUNCTION mesh_audit.refuse_kubernetes_operation_update_v1();
ALTER TABLE mesh_audit.kubernetes_operation_erasure ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.kubernetes_operation_erasure FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_operation_erasure_migrator_policy ON mesh_audit.kubernetes_operation_erasure
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_audit.kubernetes_operation_erasure FROM PUBLIC;

-- The month partitions of the three tables from this month to p_months_ahead
-- months on, each with row-level security as its parent. Built apart and
-- attached (SHARE UPDATE EXCLUSIVE on the parent, not ACCESS EXCLUSIVE),
-- under a short lock timeout: the worker tries again rather than queue
-- every writer behind a long reader (review b0a M3). No DEFAULT partition: a
-- row outside them fails, and the worker alerts before that.
CREATE FUNCTION mesh_ops.ensure_kubernetes_operation_partitions_v1(p_months_ahead INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET lock_timeout = '2s'
AS $function$
DECLARE
    v_month DATE;
    v_name TEXT;
    v_table TEXT;
    v_column TEXT;
    v_created INTEGER := 0;
BEGIN
    IF p_months_ahead IS NULL OR p_months_ahead < 1 OR p_months_ahead > 36 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes operation partition window';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('mesh_audit.kubernetes_operation.partitions'));
    FOREACH v_table IN ARRAY ARRAY['kubernetes_operation', 'kubernetes_operation_outcome',
        'kubernetes_operation_denial'] LOOP
        v_column := CASE v_table WHEN 'kubernetes_operation' THEN 'received_at' ELSE 'recorded_at' END;
        FOR v_offset IN 0..p_months_ahead LOOP
            v_month := (pg_catalog.date_trunc('month', pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')
                + pg_catalog.make_interval(months => v_offset))::DATE;
            v_name := v_table || '_' || pg_catalog.to_char(v_month, 'YYYY_MM');
            CONTINUE WHEN pg_catalog.to_regclass('mesh_audit.' || v_name) IS NOT NULL;
            EXECUTE pg_catalog.format('CREATE TABLE mesh_audit.%I (LIKE mesh_audit.%I INCLUDING ALL)',
                v_name, v_table);
            -- The bound as a constraint first, so the attach scans nothing.
            EXECUTE pg_catalog.format(
                'ALTER TABLE mesh_audit.%I ADD CONSTRAINT %I CHECK (%I >= %L AND %I < %L)',
                v_name, v_name || '_bound', v_column, (v_month::TEXT || ' 00:00:00+00'),
                v_column, ((v_month + INTERVAL '1 month')::DATE::TEXT || ' 00:00:00+00'));
            EXECUTE pg_catalog.format('ALTER TABLE mesh_audit.%I ENABLE ROW LEVEL SECURITY', v_name);
            EXECUTE pg_catalog.format('ALTER TABLE mesh_audit.%I FORCE ROW LEVEL SECURITY', v_name);
            EXECUTE pg_catalog.format(
                'CREATE POLICY %I ON mesh_audit.%I TO mesh_migrator USING (TRUE) WITH CHECK (TRUE)',
                v_name || '_migrator_policy', v_name);
            EXECUTE pg_catalog.format(
                'ALTER TABLE mesh_audit.%I ATTACH PARTITION mesh_audit.%I FOR VALUES FROM (%L) TO (%L)',
                v_table, v_name, (v_month::TEXT || ' 00:00:00+00'),
                ((v_month + INTERVAL '1 month')::DATE::TEXT || ' 00:00:00+00'));
            EXECUTE pg_catalog.format('ALTER TABLE mesh_audit.%I DROP CONSTRAINT %I', v_name, v_name || '_bound');
            v_created := v_created + 1;
        END LOOP;
    END LOOP;
    RETURN v_created;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.ensure_kubernetes_operation_partitions_v1(INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.ensure_kubernetes_operation_partitions_v1(INTEGER) TO mesh_worker;

SELECT mesh_ops.ensure_kubernetes_operation_partitions_v1(3);

-- Drops the partitions whose month ended before p_keep_months months ago,
-- under a short lock timeout, and answers their names with ahead: of every
-- table, the months present without a gap after this one, or -1 when this
-- month's is missing (the worker's gauge; alert under 2).
CREATE FUNCTION mesh_ops.maintain_kubernetes_operation_partitions_v1(p_keep_months INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
-- DETACH takes the parent ACCESS EXCLUSIVE: never queue writers longer than
-- the writer's latency budget (§5); the worker tries again.
SET lock_timeout = '200ms'
AS $function$
DECLARE
    v_this DATE := pg_catalog.date_trunc('month', pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')::DATE;
    v_cutoff DATE;
    v_dropped TEXT[] := ARRAY[]::TEXT[];
    v_ahead INTEGER;
    v_table_ahead INTEGER;
    v_table TEXT;
    v_partition RECORD;
BEGIN
    IF p_keep_months IS NULL OR p_keep_months < 1 OR p_keep_months > 36 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes operation retention';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('mesh_audit.kubernetes_operation.partitions'));
    v_cutoff := (v_this - pg_catalog.make_interval(months => p_keep_months))::DATE;
    FOR v_partition IN
        SELECT child.relname::TEXT AS relname, parent.relname::TEXT AS parent
        FROM pg_catalog.pg_inherits AS inherits
        JOIN pg_catalog.pg_class AS child ON child.oid = inherits.inhrelid
        JOIN pg_catalog.pg_class AS parent ON parent.oid = inherits.inhparent
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = parent.relnamespace
        WHERE namespace.nspname = 'mesh_audit'
          AND parent.relname IN ('kubernetes_operation', 'kubernetes_operation_outcome', 'kubernetes_operation_denial')
          AND child.relname ~ '_[0-9]{4}_[0-9]{2}$'
          AND pg_catalog.to_date(pg_catalog.right(child.relname::TEXT, 7), 'YYYY_MM') < v_cutoff
        ORDER BY child.relname
    LOOP
        EXECUTE pg_catalog.format('ALTER TABLE mesh_audit.%I DETACH PARTITION mesh_audit.%I',
            v_partition.parent, v_partition.relname);
        EXECUTE pg_catalog.format('DROP TABLE mesh_audit.%I', v_partition.relname);
        v_dropped := v_dropped || v_partition.relname;
    END LOOP;
    FOREACH v_table IN ARRAY ARRAY['kubernetes_operation', 'kubernetes_operation_outcome',
        'kubernetes_operation_denial'] LOOP
        v_table_ahead := -1;
        FOR v_offset IN 0..36 LOOP
            EXIT WHEN pg_catalog.to_regclass('mesh_audit.' || v_table || '_'
                || pg_catalog.to_char((v_this + pg_catalog.make_interval(months => v_offset))::DATE, 'YYYY_MM'))
                IS NULL;
            v_table_ahead := v_offset;
        END LOOP;
        v_ahead := LEAST(COALESCE(v_ahead, v_table_ahead), v_table_ahead);
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('dropped', pg_catalog.to_jsonb(v_dropped), 'ahead', v_ahead);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.maintain_kubernetes_operation_partitions_v1(INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.maintain_kubernetes_operation_partitions_v1(INTEGER) TO mesh_worker;

-- The gateways a batch names (hex machine key fingerprint ':' hex node key,
-- already checked), by the keys of their current epochs, with their Network
-- and cluster: only an active, unexpired gateway of an active cluster. A
-- lookup, not a proof: control proved both keys in the session, and only
-- mesh_runtime calls the writers (design §4).
CREATE FUNCTION mesh_ops.kubernetes_operation_gateways_internal_v1(p_gateways TEXT[], p_now TIMESTAMPTZ)
RETURNS TABLE (gateway_key TEXT, device_id BIGINT, workspace_id BIGINT, network_id BIGINT, cluster_id BIGINT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT asked.key, device.id, device.workspace_id, device.network_id, device.kubernetes_cluster_id
    FROM (SELECT DISTINCT key FROM pg_catalog.unnest(p_gateways) AS key
          WHERE key ~ '^[0-9a-f]{64}:[0-9a-f]{64}$') AS asked
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.fingerprint = pg_catalog.decode(pg_catalog.split_part(asked.key, ':', 1), 'hex')
     AND machine.state = 'active'
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
     AND device.id = machine.device_id AND machine.epoch = device.current_machine_key_epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
     AND node_key.public_key = pg_catalog.decode(pg_catalog.split_part(asked.key, ':', 2), 'hex')
     AND node_key.state = 'active'
    JOIN mesh.kubernetes_cluster AS cluster
      ON cluster.workspace_id = device.workspace_id AND cluster.network_id = device.network_id
     AND cluster.id = device.kubernetes_cluster_id AND cluster.state = 'active'
    WHERE device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > p_now
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_operation_gateways_internal_v1(TEXT[], TIMESTAMPTZ) FROM PUBLIC;

-- Whether one intent, as JSON, has every field in form: checked before any
-- cast, so no row ever raises (review b0a H1). Strings as their columns
-- allow; hex lowercase; numbers in range.
CREATE FUNCTION mesh_ops.kubernetes_operation_intent_valid_internal_v1(p_row JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_typeof(p_row) = 'object'
        AND COALESCE(p_row->>'intent_id' ~ '^[0-9a-f]{32}$', FALSE)
        AND COALESCE(p_row->>'digest' ~ '^[0-9a-f]{64}$', FALSE)
        AND COALESCE(p_row->>'peer' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', FALSE)
        AND COALESCE(p_row->>'owner_kind' IN ('member', 'tags', 'workspace'), FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'owner_ref') <= 1024, FALSE)
        AND COALESCE(p_row->>'network_revision' ~ '^[1-9][0-9]{0,17}$', FALSE)
        AND COALESCE(p_row->>'class' IN ('write', 'exec', 'proxy', 'secret_read', 'privileged', 'unparsed'), FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'verb') BETWEEN 1 AND 32, FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'api_group') <= 253, FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'resource') <= 63, FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'subresource') <= 63, FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'namespace') <= 63, FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'name') <= 253, FALSE)
        AND COALESCE(pg_catalog.octet_length(p_row->>'impersonated') <= 253, FALSE)
        AND COALESCE(p_row->>'token_id' ~ '^([0-9a-f]{2}){0,32}$', FALSE)
        -- Milliseconds of 1970 to 9999.
        AND CASE WHEN p_row->>'observed_ms' ~ '^[0-9]{1,15}$'
            THEN (p_row->>'observed_ms')::BIGINT <= 253402300799999 ELSE FALSE END
        AND COALESCE(pg_catalog.jsonb_typeof(p_row->'clock_skew') = 'boolean', FALSE)
        -- Casts only behind a CASE: Postgres evaluates AND and OR operands
        -- in any order.
        AND CASE WHEN pg_catalog.jsonb_typeof(p_row->'groups') = 'array'
            THEN pg_catalog.jsonb_array_length(p_row->'groups') <= 16
                AND NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_row->'groups') AS item
                    WHERE CASE WHEN pg_catalog.jsonb_typeof(item) = 'string'
                        THEN pg_catalog.octet_length(item #>> '{}') NOT BETWEEN 1 AND 63 ELSE TRUE END)
            ELSE FALSE END
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_operation_intent_valid_internal_v1(JSONB) FROM PUBLIC;

-- Records a batch of type A intents control already checked (§3.3, §4).
-- Must run at READ COMMITTED (it refuses otherwise), in three statements
-- (review v2 H1): one transaction lock per gateway, ordered by the lock's
-- key so two writers never wait on each other in a cycle; the intents those
-- gateways sent in the last 10 minutes, which this statement's snapshot
-- sees though another replica committed them while this one waited; then
-- the rest inserted. Answers, in input order, each intent's outcome and
-- audit_id: accepted; duplicate (sent again with the same content: the
-- first audit_id, also within the batch); conflict (same id, other
-- content); refused invalid (a field out of form), gateway (no active
-- gateway of an active cluster has those keys) or device (the peer is no
-- active, unexpired Device of the gateway's Network, or a gateway).
-- Only an input wrong as a whole raises: not an array, over 1,000 rows, or
-- an audit_id that is not a UUIDv7 of this moment (a Core bug: the
-- writer's clock).
CREATE FUNCTION mesh_ops.record_kubernetes_operations_v1(p_rows JSONB)
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
            mesh_ops.kubernetes_operation_intent_valid_internal_v1(element.value) AS valid
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
            observed_at, clock_skew, intent_id, intent_digest)
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
            pg_catalog.decode(answered.item->>'intent_id', 'hex'), pg_catalog.decode(answered.item->>'digest', 'hex')
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
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_operations_v1(JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_operations_v1(JSONB) TO mesh_runtime;

-- Records outcomes and type B denials, each under the gateway (and its
-- Workspace) that sent it. A row out of form or of an unknown gateway is
-- skipped, never raised for; answers how many of each it wrote.
CREATE FUNCTION mesh_ops.record_kubernetes_operation_outcomes_v1(p_outcomes JSONB, p_denials JSONB)
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
        kubernetes_cluster_id, gateway_device_id, peer_device_id, reason, count, first_at, last_at)
    SELECT v_now, (v_gateways->(item->>'gateway')->>'workspace')::BIGINT,
        (v_gateways->(item->>'gateway')->>'network')::BIGINT, (v_gateways->(item->>'gateway')->>'cluster')::BIGINT,
        (v_gateways->(item->>'gateway')->>'id')::BIGINT, peer.id, item->>'reason', (item->>'count')::INTEGER,
        pg_catalog.to_timestamp((item->>'first_ms')::BIGINT / 1000.0),
        pg_catalog.to_timestamp((item->>'last_ms')::BIGINT / 1000.0)
    FROM pg_catalog.jsonb_array_elements(p_denials) AS listed(item)
    LEFT JOIN mesh.device AS peer
      ON peer.public_id = CASE WHEN item->>'peer' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN (item->>'peer')::UUID END
     AND peer.workspace_id = (v_gateways->(item->>'gateway')->>'workspace')::BIGINT
     AND peer.network_id = (v_gateways->(item->>'gateway')->>'network')::BIGINT
    WHERE v_gateways ? (item->>'gateway')
      AND COALESCE(item->>'reason' IN ('unauthenticated', 'forbidden', 'not_granted', 'stale', 'limited', 'other'),
          FALSE)
      AND COALESCE(item->>'count' ~ '^[1-9][0-9]{0,8}$', FALSE)
      AND CASE WHEN item->>'first_ms' ~ '^[0-9]{1,15}$' AND item->>'last_ms' ~ '^[0-9]{1,15}$'
          THEN (item->>'last_ms')::BIGINT <= 253402300799999
              AND (item->>'first_ms')::BIGINT <= (item->>'last_ms')::BIGINT
          ELSE FALSE END;
    GET DIAGNOSTICS v_denials = ROW_COUNT;
    RETURN pg_catalog.jsonb_build_object('outcomes', v_outcomes, 'denials', v_denials);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_operation_outcomes_v1(JSONB, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_operation_outcomes_v1(JSONB, JSONB) TO mesh_runtime;

-- Deletes up to p_limit of a Workspace's rows of one table, a partition at a
-- time, by TID; answers how many.
CREATE FUNCTION mesh_ops.erase_kubernetes_operation_rows_internal_v1(p_table TEXT, p_workspace BIGINT,
    p_limit INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_partition TEXT;
    v_deleted BIGINT;
    v_total BIGINT := 0;
BEGIN
    IF p_table NOT IN ('kubernetes_operation', 'kubernetes_operation_outcome', 'kubernetes_operation_denial') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes operation table';
    END IF;
    FOR v_partition IN
        SELECT child.relname::TEXT FROM pg_catalog.pg_inherits AS inherits
        JOIN pg_catalog.pg_class AS child ON child.oid = inherits.inhrelid
        JOIN pg_catalog.pg_class AS parent ON parent.oid = inherits.inhparent
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = parent.relnamespace
        WHERE namespace.nspname = 'mesh_audit' AND parent.relname = p_table
        ORDER BY child.relname
    LOOP
        EXIT WHEN v_total >= p_limit;
        EXECUTE pg_catalog.format('DELETE FROM mesh_audit.%I WHERE ctid = ANY (ARRAY(SELECT ctid FROM mesh_audit.%I '
            'WHERE workspace_id = $1 LIMIT $2))', v_partition, v_partition)
            USING p_workspace, p_limit - v_total;
        GET DIAGNOSTICS v_deleted = ROW_COUNT;
        v_total := v_total + v_deleted;
    END LOOP;
    RETURN v_total;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.erase_kubernetes_operation_rows_internal_v1(TEXT, BIGINT, INTEGER) FROM PUBLIC;

-- Erases up to p_limit rows of each kind of a Workspace (it was deleted, or
-- its owner asked): the only way rows leave before retention. Batched, so
-- the operator runs it until remaining is 0 instead of one transaction over
-- months of rows (review b0a M4); each call records who erased what and why
-- in kubernetes_operation_erasure, in its own transaction.
CREATE FUNCTION mesh_ops.erase_kubernetes_operations_v1(p_workspace_public_id UUID, p_actor TEXT,
    p_change_ref TEXT, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
    v_operations BIGINT;
    v_outcomes BIGINT;
    v_denials BIGINT;
    v_remaining BOOLEAN;
BEGIN
    IF p_workspace_public_id IS NULL
        OR p_actor IS NULL OR pg_catalog.octet_length(p_actor) NOT BETWEEN 1 AND 128 OR p_actor !~ '^[ -~]+$'
        OR p_change_ref IS NULL OR pg_catalog.octet_length(p_change_ref) NOT BETWEEN 1 AND 128
        OR p_change_ref !~ '^[ -~]+$' OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes operation erase';
    END IF;
    -- An operator's lookup across Workspaces, as the CA operator commands do.
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT workspace.id INTO v_workspace FROM mesh.workspace AS workspace
    WHERE workspace.public_id = p_workspace_public_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_workspace IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace not found';
    END IF;
    -- Partition by partition, by TID: a plan over the parent could scan
    -- them all; each lock holds one partition at a time (review b0a).
    v_operations := mesh_ops.erase_kubernetes_operation_rows_internal_v1('kubernetes_operation', v_workspace, p_limit);
    v_outcomes := mesh_ops.erase_kubernetes_operation_rows_internal_v1('kubernetes_operation_outcome', v_workspace,
        p_limit);
    v_denials := mesh_ops.erase_kubernetes_operation_rows_internal_v1('kubernetes_operation_denial', v_workspace,
        p_limit);
    INSERT INTO mesh_audit.kubernetes_operation_erasure (erased_at, workspace_id, actor, change_ref, operations,
        outcomes, denials)
    VALUES (pg_catalog.clock_timestamp(), v_workspace, p_actor, p_change_ref, v_operations, v_outcomes, v_denials);
    v_remaining := EXISTS (SELECT 1 FROM mesh_audit.kubernetes_operation WHERE workspace_id = v_workspace)
        OR EXISTS (SELECT 1 FROM mesh_audit.kubernetes_operation_outcome WHERE workspace_id = v_workspace)
        OR EXISTS (SELECT 1 FROM mesh_audit.kubernetes_operation_denial WHERE workspace_id = v_workspace);
    RETURN pg_catalog.jsonb_build_object('operations', v_operations, 'outcomes', v_outcomes,
        'denials', v_denials, 'remaining', v_remaining);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.erase_kubernetes_operations_v1(UUID, TEXT, TEXT, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.erase_kubernetes_operations_v1(UUID, TEXT, TEXT, INTEGER) TO mesh_worker;
