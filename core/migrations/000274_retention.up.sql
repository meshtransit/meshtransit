-- Retention (owner 2026-11-04; docs/database-store-separation.md §6).
-- Activity is kept twelve months: the month that ended thirteen months ago
-- goes. Delivered outbox events go after seven days, terminal ones after
-- thirty, expired idempotency records a day after they expire. Before this
-- nothing ever left these tables.
--
-- The evidence tables stay immutable to every serving session. Evidence
-- rows leave only through the row functions below, which operator step 274
-- hands to mesh_retention: a NOLOGIN role no one is a member of and that
-- owns nothing else, so no runtime or worker session and no other function
-- can delete evidence. (The migrator owns the tables and can always change
-- them by DDL; that is what reviewed migrations are for.) Until the step
-- runs, a batch that reaches evidence is refused, which is safe; expired
-- idempotency records and outbox events without attempts may already go.
-- Old Activity months leave as whole partitions through the migrator's DDL
-- function, as Kubernetes operations do (schema 245). Every pass that
-- removes something records itself in mesh_audit.retention_run.
--
-- Run operator role step 274 (mesh_retention) before this migration.

-- Oldest first for each pass, so a pass with nothing to remove reads one
-- index entry instead of a table. Built before any trigger changes, while
-- the tables take writes as usual.
CREATE INDEX outbox_event_finished_idx
    ON mesh_ops.outbox_event (completed_at, id)
    WHERE state IN ('delivered', 'terminal');
CREATE INDEX audit_event_identity_occurred_idx
    ON mesh_audit.audit_event_identity (occurred_at, id);
CREATE INDEX authority_mutation_occurred_idx
    ON mesh_audit.authority_mutation (occurred_at, id);

-- What each pass removed: retention's own evidence, append only.
CREATE TABLE mesh_audit.retention_run (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ran_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
    kind TEXT NOT NULL,
    cutoff TIMESTAMPTZ NOT NULL,
    removed JSONB NOT NULL,
    CONSTRAINT retention_run_kind_check CHECK (kind IN ('audit', 'outbox', 'idempotency')),
    CONSTRAINT retention_run_removed_check CHECK (
        pg_catalog.jsonb_typeof(removed) = 'object'
        AND pg_catalog.octet_length(removed::TEXT) <= 4096
    )
);

-- Where each audit chain now starts: the last event retention removed from
-- it. A check of the chain left starts at this hash; an event of the stream
-- with a sequence at or below it may be gone, as events near the cutoff are
-- removed by time, not strictly by sequence.
CREATE TABLE mesh_audit.audit_retention_checkpoint (
    stream_id BIGINT PRIMARY KEY,
    through_sequence BIGINT NOT NULL CHECK (through_sequence > 0),
    through_event_hash BYTEA NOT NULL,
    through_occurred_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
    CONSTRAINT audit_retention_checkpoint_hash_check CHECK (
        pg_catalog.octet_length(through_event_hash) = 32
    ),
    CONSTRAINT audit_retention_checkpoint_stream_fk FOREIGN KEY (stream_id)
        REFERENCES mesh_audit.audit_stream (id) ON DELETE RESTRICT
);

CREATE TRIGGER retention_run_immutable
BEFORE UPDATE OR DELETE ON mesh_audit.retention_run
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

ALTER TABLE mesh_audit.retention_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.retention_run FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_run_migrator_policy ON mesh_audit.retention_run
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_audit.audit_retention_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_audit.audit_retention_checkpoint FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_retention_checkpoint_migrator_policy ON mesh_audit.audit_retention_checkpoint
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_audit.retention_run, mesh_audit.audit_retention_checkpoint FROM PUBLIC;

-- What the row functions need as mesh_retention: read and delete the rows
-- they remove, read the events that keep an identity, record the pass and
-- move the checkpoint. No UPDATE on any evidence table.
GRANT USAGE ON SCHEMA mesh_ops, mesh_audit TO mesh_retention;
GRANT SELECT, DELETE ON mesh_ops.idempotency_record, mesh_ops.outbox_event, mesh_ops.outbox_attempt,
    mesh_audit.audit_event_default, mesh_audit.audit_event_identity, mesh_audit.authority_mutation
    TO mesh_retention;
GRANT SELECT ON mesh_audit.audit_event TO mesh_retention;
GRANT INSERT ON mesh_audit.retention_run TO mesh_retention;
GRANT SELECT, INSERT, UPDATE ON mesh_audit.audit_retention_checkpoint TO mesh_retention;
CREATE POLICY idempotency_record_retention_policy ON mesh_ops.idempotency_record
    FOR ALL TO mesh_retention USING (TRUE) WITH CHECK (FALSE);
CREATE POLICY outbox_event_retention_policy ON mesh_ops.outbox_event
    FOR ALL TO mesh_retention USING (TRUE) WITH CHECK (FALSE);
CREATE POLICY audit_event_retention_policy ON mesh_audit.audit_event
    FOR SELECT TO mesh_retention USING (TRUE);
CREATE POLICY audit_event_default_retention_policy ON mesh_audit.audit_event_default
    FOR ALL TO mesh_retention USING (TRUE) WITH CHECK (FALSE);
CREATE POLICY audit_event_identity_retention_policy ON mesh_audit.audit_event_identity
    FOR ALL TO mesh_retention USING (TRUE) WITH CHECK (FALSE);
CREATE POLICY authority_mutation_retention_policy ON mesh_audit.authority_mutation
    FOR ALL TO mesh_retention USING (TRUE) WITH CHECK (FALSE);
CREATE POLICY retention_run_retention_policy ON mesh_audit.retention_run
    FOR INSERT TO mesh_retention WITH CHECK (TRUE);
CREATE POLICY audit_retention_checkpoint_retention_policy ON mesh_audit.audit_retention_checkpoint
    FOR ALL TO mesh_retention USING (TRUE) WITH CHECK (TRUE);

-- Immutable evidence, version 2 (SECURITY INVOKER): nothing updates a row;
-- a row is deleted only by mesh_retention, which only the row functions
-- below run as, with the purge mark they set for their own transaction.
CREATE FUNCTION mesh_audit.reject_immutable_change_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE'
        AND current_user = 'mesh_retention'
        AND pg_catalog.current_setting('mesh.retention_purge', TRUE) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'immutable security evidence cannot be changed';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.reject_immutable_change_v2() FROM PUBLIC;

DROP TRIGGER audit_event_identity_immutable ON mesh_audit.audit_event_identity;
CREATE TRIGGER audit_event_identity_immutable
BEFORE UPDATE OR DELETE ON mesh_audit.audit_event_identity
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change_v2();
DROP TRIGGER authority_mutation_immutable ON mesh_audit.authority_mutation;
CREATE TRIGGER authority_mutation_immutable
BEFORE UPDATE OR DELETE ON mesh_audit.authority_mutation
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change_v2();
DROP TRIGGER audit_event_immutable ON mesh_audit.audit_event;
CREATE TRIGGER audit_event_immutable
BEFORE UPDATE OR DELETE ON mesh_audit.audit_event
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change_v2();
DROP TRIGGER outbox_attempt_immutable ON mesh_ops.outbox_attempt;
CREATE TRIGGER outbox_attempt_immutable
BEFORE UPDATE OR DELETE ON mesh_ops.outbox_attempt
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change_v2();

-- Deletes up to p_limit idempotency records that expired more than
-- p_grace_seconds ago; a replay that late gets a fresh answer, as it would
-- once the record expired anyway. Another worker in the same pass makes this
-- one return 0. Answers how many went.
CREATE FUNCTION mesh_ops.prune_idempotency_records_v1(p_grace_seconds INTEGER, p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET lock_timeout = '200ms'
AS $function$
DECLARE
    v_cutoff TIMESTAMPTZ;
    v_count INTEGER;
BEGIN
    IF p_grace_seconds IS NULL OR p_grace_seconds < 3600 OR p_grace_seconds > 2592000
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 5000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid idempotency retention';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtext('mesh_ops.idempotency_record.retention')) THEN
        RETURN 0;
    END IF;
    v_cutoff := pg_catalog.transaction_timestamp() - pg_catalog.make_interval(secs => p_grace_seconds);
    DELETE FROM mesh_ops.idempotency_record AS record
    WHERE record.id IN (
        SELECT expired.id FROM mesh_ops.idempotency_record AS expired
        WHERE expired.expires_at < v_cutoff
        ORDER BY expired.expires_at, expired.id
        LIMIT p_limit
    );
    GET DIAGNOSTICS v_count = ROW_COUNT;
    IF v_count > 0 THEN
        INSERT INTO mesh_audit.retention_run (kind, cutoff, removed)
        VALUES ('idempotency', v_cutoff, pg_catalog.jsonb_build_object('records', v_count));
    END IF;
    RETURN v_count;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.prune_idempotency_records_v1(INTEGER, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_idempotency_records_v1(INTEGER, INTEGER) TO mesh_worker;

-- Deletes up to p_limit finished outbox events with their delivery
-- attempts: delivered ones finished more than p_delivered_days ago,
-- terminal ones more than p_terminal_days. An event an idempotency record
-- still answers with stays until the record goes. Answers
-- {"events": n, "attempts": m}.
CREATE FUNCTION mesh_ops.prune_outbox_events_v1(p_delivered_days INTEGER, p_terminal_days INTEGER,
    p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET lock_timeout = '200ms'
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_delivered TIMESTAMPTZ;
    v_terminal TIMESTAMPTZ;
    v_ids BIGINT[];
    v_attempts INTEGER := 0;
    v_events INTEGER := 0;
BEGIN
    IF p_delivered_days IS NULL OR p_delivered_days < 1 OR p_delivered_days > 365
        OR p_terminal_days IS NULL OR p_terminal_days < p_delivered_days OR p_terminal_days > 365
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 5000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid outbox retention';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtext('mesh_ops.outbox_event.retention')) THEN
        RETURN pg_catalog.jsonb_build_object('events', 0, 'attempts', 0);
    END IF;
    v_delivered := v_now - pg_catalog.make_interval(days => p_delivered_days);
    v_terminal := v_now - pg_catalog.make_interval(days => p_terminal_days);
    -- A finished event changes no more: nothing else takes these rows.
    SELECT pg_catalog.array_agg(chosen.id) INTO v_ids
    FROM (
        SELECT event.id
        FROM mesh_ops.outbox_event AS event
        WHERE event.state IN ('delivered', 'terminal')
          AND event.completed_at < v_delivered
          AND (event.state = 'delivered' OR event.completed_at < v_terminal)
          AND NOT EXISTS (
              SELECT 1 FROM mesh_ops.idempotency_record AS record
              WHERE record.outbox_public_id = event.public_id
          )
        ORDER BY event.completed_at, event.id
        LIMIT p_limit
    ) AS chosen;
    IF v_ids IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('events', 0, 'attempts', 0);
    END IF;
    PERFORM pg_catalog.set_config('mesh.retention_purge', 'on', TRUE);
    DELETE FROM mesh_ops.outbox_attempt WHERE outbox_event_id = ANY (v_ids);
    GET DIAGNOSTICS v_attempts = ROW_COUNT;
    -- Still finished: insurance should a path ever requeue one.
    DELETE FROM mesh_ops.outbox_event
    WHERE id = ANY (v_ids) AND state IN ('delivered', 'terminal') AND completed_at < v_delivered;
    GET DIAGNOSTICS v_events = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.retention_purge', 'off', TRUE);
    INSERT INTO mesh_audit.retention_run (kind, cutoff, removed)
    VALUES ('outbox', v_delivered,
        pg_catalog.jsonb_build_object('events', v_events, 'attempts', v_attempts,
            'terminal_cutoff', v_terminal));
    RETURN pg_catalog.jsonb_build_object('events', v_events, 'attempts', v_attempts);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.prune_outbox_events_v1(INTEGER, INTEGER, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_outbox_events_v1(INTEGER, INTEGER, INTEGER) TO mesh_worker;

-- The first day kept: the start of the month p_keep_months months before
-- this one, in UTC. The rest of this month and those whole months stay.
CREATE FUNCTION mesh_ops.audit_retention_cutoff_internal_v1(p_keep_months INTEGER)
RETURNS TIMESTAMPTZ
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT ((pg_catalog.date_trunc('month', pg_catalog.transaction_timestamp() AT TIME ZONE 'UTC')
        - pg_catalog.make_interval(months => p_keep_months))::DATE)::TIMESTAMP AT TIME ZONE 'UTC'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.audit_retention_cutoff_internal_v1(INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.audit_retention_cutoff_internal_v1(INTEGER) TO mesh_retention;

-- Drops the monthly audit_event partitions before the cutoff, DDL only:
-- DETACH takes the parent ACCESS EXCLUSIVE, so it waits at most 200 ms and
-- the pass is retried, never queuing writers; its transaction holds nothing
-- else. Another worker in the same pass makes this one drop nothing.
-- Answers the names dropped.
CREATE FUNCTION mesh_ops.drop_audit_event_partitions_v1(p_keep_months INTEGER)
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
    IF p_keep_months IS NULL OR p_keep_months < 1 OR p_keep_months > 120 THEN
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
REVOKE ALL ON FUNCTION mesh_ops.drop_audit_event_partitions_v1(INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.drop_audit_event_partitions_v1(INTEGER) TO mesh_worker;

-- Deletes up to p_limit rows each of what the dropped months leave behind:
-- their events in the DEFAULT partition (a month created late), the event
-- identities no event refers to any more, and authority mutations. The last
-- identity removed from each chain becomes its checkpoint first. Answers
-- {"defaults": n, "identities": n, "mutations": n}.
CREATE FUNCTION mesh_ops.prune_audit_rows_v1(p_keep_months INTEGER, p_limit INTEGER)
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
    IF p_keep_months IS NULL OR p_keep_months < 1 OR p_keep_months > 120
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
REVOKE ALL ON FUNCTION mesh_ops.prune_audit_rows_v1(INTEGER, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_audit_rows_v1(INTEGER, INTEGER) TO mesh_worker;
