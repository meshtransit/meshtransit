-- Schema 115 (R1-64 part A): audit storage that keeps working over time and
-- per Workspace.
--
-- 1. Monthly partitions. audit_event is range-partitioned by occurred_at but
--    only September and October 2026 existed; from November every event
--    would land in the DEFAULT partition, after which that month's
--    partition could never be attached. ensure_audit_event_partitions_v1
--    creates missing monthly partitions from the current month onward with
--    the same row-level security as the existing ones. This migration
--    creates 24 months; the worker role keeps a rolling window ahead.
-- 2. Stream public identifiers, so exported evidence can name a stream
--    without revealing an internal sequence value.
-- 3. One audit stream per Workspace, for events about the Workspace itself
--    (name, members, roles) rather than the shared Deployment stream.
--    Existing Workspaces are backfilled; new ones get a stream on insert.

CREATE FUNCTION mesh_ops.ensure_audit_event_partitions_v1(p_months_ahead INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_month DATE;
    v_name TEXT;
    v_created INTEGER := 0;
BEGIN
    IF p_months_ahead IS NULL OR p_months_ahead < 1 OR p_months_ahead > 36 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid audit partition window';
    END IF;
    -- One maintainer at a time; others find the partitions already present.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('mesh_audit.audit_event.partitions'));
    FOR v_offset IN 0..p_months_ahead LOOP
        v_month := (pg_catalog.date_trunc('month', pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')
            + pg_catalog.make_interval(months => v_offset))::DATE;
        v_name := 'audit_event_' || pg_catalog.to_char(v_month, 'YYYY_MM');
        CONTINUE WHEN pg_catalog.to_regclass('mesh_audit.' || v_name) IS NOT NULL;
        EXECUTE pg_catalog.format(
            'CREATE TABLE mesh_audit.%I PARTITION OF mesh_audit.audit_event FOR VALUES FROM (%L) TO (%L)',
            v_name,
            (v_month::TEXT || ' 00:00:00+00'),
            ((v_month + INTERVAL '1 month')::DATE::TEXT || ' 00:00:00+00')
        );
        EXECUTE pg_catalog.format('ALTER TABLE mesh_audit.%I ENABLE ROW LEVEL SECURITY', v_name);
        EXECUTE pg_catalog.format('ALTER TABLE mesh_audit.%I FORCE ROW LEVEL SECURITY', v_name);
        EXECUTE pg_catalog.format(
            'CREATE POLICY %I ON mesh_audit.%I TO mesh_migrator USING (TRUE) WITH CHECK (TRUE)',
            v_name || '_migrator_policy', v_name
        );
        v_created := v_created + 1;
    END LOOP;
    RETURN v_created;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.ensure_audit_event_partitions_v1(INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.ensure_audit_event_partitions_v1(INTEGER) TO mesh_worker;

SELECT mesh_ops.ensure_audit_event_partitions_v1(24);

-- Stream public identifiers: generated, unique and immutable.
ALTER TABLE mesh_audit.audit_stream ADD COLUMN public_id UUID;
UPDATE mesh_audit.audit_stream SET public_id = pg_catalog.uuidv7() WHERE public_id IS NULL;
ALTER TABLE mesh_audit.audit_stream
    ALTER COLUMN public_id SET DEFAULT pg_catalog.uuidv7(),
    ALTER COLUMN public_id SET NOT NULL,
    ADD CONSTRAINT audit_stream_public_id_key UNIQUE (public_id),
    ADD CONSTRAINT audit_stream_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    );

CREATE FUNCTION mesh_audit.enforce_audit_stream_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF OLD.public_id <> NEW.public_id OR OLD.scope_kind <> NEW.scope_kind
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
        OR OLD.network_id IS DISTINCT FROM NEW.network_id
        OR NEW.next_sequence < OLD.next_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'audit stream identity is immutable';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.enforce_audit_stream_identity()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER audit_stream_identity_immutable
BEFORE UPDATE ON mesh_audit.audit_stream
FOR EACH ROW EXECUTE FUNCTION mesh_audit.enforce_audit_stream_identity();

-- Automatically created streams must not take identifiers that operator
-- tooling and fixtures assign explicitly; start generated values high.
SELECT pg_catalog.setval(
    pg_catalog.pg_get_serial_sequence('mesh_audit.audit_stream', 'id'),
    GREATEST(1000000, COALESCE((SELECT pg_catalog.max(id) FROM mesh_audit.audit_stream), 0)),
    TRUE
);

-- Every Workspace gets its own stream when it is created.
CREATE FUNCTION mesh_audit.create_workspace_audit_stream()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    INSERT INTO mesh_audit.audit_stream (deployment_id, workspace_id, scope_kind)
    VALUES (NEW.deployment_id, NEW.id, 'workspace')
    ON CONFLICT (deployment_id, workspace_id) WHERE scope_kind = 'workspace' DO NOTHING;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.create_workspace_audit_stream()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER workspace_audit_stream
AFTER INSERT ON mesh.workspace
FOR EACH ROW EXECUTE FUNCTION mesh_audit.create_workspace_audit_stream();

-- Backfill existing Workspaces. Workspace rows are hidden from the migrator
-- by row-level security, so a policy exists only for this statement.
CREATE POLICY workspace_audit_stream_backfill ON mesh.workspace
    FOR SELECT TO mesh_migrator USING (TRUE);
INSERT INTO mesh_audit.audit_stream (deployment_id, workspace_id, scope_kind)
SELECT workspace.deployment_id, workspace.id, 'workspace'
FROM mesh.workspace AS workspace
ON CONFLICT (deployment_id, workspace_id) WHERE scope_kind = 'workspace' DO NOTHING;
DROP POLICY workspace_audit_stream_backfill ON mesh.workspace;
