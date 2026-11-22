-- Schema 313 (TD-SEC-94): the audit kept is no longer the caller's choice.
-- The retention functions the worker calls took p_keep_months >= 1, so a
-- compromised worker could drop or prune every Activity and Kubernetes
-- operation record older than a month. They now refuse fewer than 12
-- months, the compliance floor; the worker keeps 12 (Activity) and 13
-- (Kubernetes operations) already. The bodies are schema 274's and 245's
-- with only that bound changed.
--
-- erase_kubernetes_operations_v1 (a Workspace's Kubernetes operations,
-- for an erasure request) has no caller in Core: it is an operator's
-- command, run as the owner. The worker loses it.

CREATE OR REPLACE FUNCTION mesh_ops.drop_audit_event_partitions_v1(p_keep_months INTEGER)
RETURNS TEXT[]
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET lock_timeout = '200ms'
AS $function$
DECLARE
    v_cutoff TIMESTAMPTZ;
    v_dropped TEXT[] := ARRAY[]::TEXT[];
    v_partition RECORD;
BEGIN
    IF p_keep_months IS NULL OR p_keep_months < 12 OR p_keep_months > 120 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid audit retention';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtext('mesh_audit.audit_event.partition_retention')) THEN
        RETURN v_dropped;
    END IF;
    v_cutoff := mesh_ops.audit_retention_cutoff_internal_v1(p_keep_months);
    FOR v_partition IN
        SELECT child.relname::TEXT AS relname
        FROM pg_catalog.pg_inherits AS inherits
        JOIN pg_catalog.pg_class AS child ON child.oid = inherits.inhrelid
        JOIN pg_catalog.pg_class AS parent ON parent.oid = inherits.inhparent
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = parent.relnamespace
        WHERE namespace.nspname = 'mesh_audit'
          AND parent.relname = 'audit_event'
          AND child.relname ~ '^audit_event_[0-9]{4}_[0-9]{2}$'
          -- The month's end, not its name, decides: only a month that ended
          -- before the cutoff goes.
          AND (pg_catalog.to_date(pg_catalog.right(child.relname::TEXT, 7), 'YYYY_MM')
              + INTERVAL '1 month')::TIMESTAMP AT TIME ZONE 'UTC' <= v_cutoff
        ORDER BY child.relname
    LOOP
        EXECUTE pg_catalog.format('ALTER TABLE mesh_audit.audit_event DETACH PARTITION mesh_audit.%I',
            v_partition.relname);
        EXECUTE pg_catalog.format('DROP TABLE mesh_audit.%I', v_partition.relname);
        v_dropped := v_dropped || v_partition.relname;
    END LOOP;
    IF pg_catalog.cardinality(v_dropped) > 0 THEN
        INSERT INTO mesh_audit.retention_run (kind, cutoff, removed)
        VALUES ('audit', v_cutoff, pg_catalog.jsonb_build_object('partitions', pg_catalog.to_jsonb(v_dropped)));
    END IF;
    RETURN v_dropped;
END;
$function$;

CREATE FUNCTION mesh_ops.prune_audit_rows_v2(p_keep_months INTEGER, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET lock_timeout = '200ms'
AS $function$
DECLARE
    v_cutoff TIMESTAMPTZ;
    v_defaults INTEGER := 0;
    v_identities INTEGER := 0;
    v_mutations INTEGER := 0;
BEGIN
    IF p_keep_months IS NULL OR p_keep_months < 12 OR p_keep_months > 120
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 5000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid audit retention';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtext('mesh_audit.audit_event.row_retention')) THEN
        RETURN pg_catalog.jsonb_build_object('defaults', 0, 'identities', 0, 'mutations', 0);
    END IF;
    v_cutoff := mesh_ops.audit_retention_cutoff_internal_v1(p_keep_months);
    PERFORM pg_catalog.set_config('mesh.retention_purge', 'on', TRUE);
    DELETE FROM mesh_audit.audit_event_default AS event
    WHERE (event.occurred_at, event.event_identity_id) IN (
        SELECT stray.occurred_at, stray.event_identity_id
        FROM mesh_audit.audit_event_default AS stray
        WHERE stray.occurred_at < v_cutoff
        LIMIT p_limit
    );
    GET DIAGNOSTICS v_defaults = ROW_COUNT;

    -- Identities no event refers to any more, oldest first; each chain's
    -- checkpoint moves to the last one removed from it.
    WITH doomed AS MATERIALIZED (
        SELECT identity.id, identity.stream_id, identity.stream_sequence, identity.event_hash,
            identity.occurred_at
        FROM mesh_audit.audit_event_identity AS identity
        WHERE identity.occurred_at < v_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM mesh_audit.audit_event AS event
              WHERE event.occurred_at = identity.occurred_at AND event.event_identity_id = identity.id
          )
        ORDER BY identity.occurred_at, identity.id
        LIMIT p_limit
    ), checkpoint AS (
        INSERT INTO mesh_audit.audit_retention_checkpoint AS kept
            (stream_id, through_sequence, through_event_hash, through_occurred_at)
        SELECT DISTINCT ON (doomed.stream_id) doomed.stream_id, doomed.stream_sequence, doomed.event_hash,
            doomed.occurred_at
        FROM doomed
        ORDER BY doomed.stream_id, doomed.stream_sequence DESC
        ON CONFLICT (stream_id) DO UPDATE
            SET through_sequence = EXCLUDED.through_sequence,
                through_event_hash = EXCLUDED.through_event_hash,
                through_occurred_at = EXCLUDED.through_occurred_at,
                updated_at = pg_catalog.transaction_timestamp()
            WHERE EXCLUDED.through_sequence > kept.through_sequence
        RETURNING 1
    )
    DELETE FROM mesh_audit.audit_event_identity AS identity
    USING doomed
    WHERE identity.id = doomed.id;
    GET DIAGNOSTICS v_identities = ROW_COUNT;

    DELETE FROM mesh_audit.authority_mutation AS mutation
    WHERE mutation.id IN (
        SELECT old.id FROM mesh_audit.authority_mutation AS old
        WHERE old.occurred_at < v_cutoff
        ORDER BY old.occurred_at, old.id
        LIMIT p_limit
    );
    GET DIAGNOSTICS v_mutations = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.retention_purge', 'off', TRUE);

    IF v_defaults > 0 OR v_identities > 0 OR v_mutations > 0 THEN
        INSERT INTO mesh_audit.retention_run (kind, cutoff, removed)
        VALUES ('audit', v_cutoff, pg_catalog.jsonb_build_object('defaults', v_defaults,
            'identities', v_identities, 'mutations', v_mutations));
    END IF;
    RETURN pg_catalog.jsonb_build_object('defaults', v_defaults, 'identities', v_identities,
        'mutations', v_mutations);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.prune_audit_rows_v2(INTEGER, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.maintain_kubernetes_operation_partitions_v1(p_keep_months INTEGER)
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
    IF p_keep_months IS NULL OR p_keep_months < 12 OR p_keep_months > 36 THEN
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

REVOKE EXECUTE ON FUNCTION mesh_ops.erase_kubernetes_operations_v1(UUID, TEXT, TEXT, INTEGER) FROM mesh_worker;
