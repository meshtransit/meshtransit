-- Schema 116 (R1-64 part B): audit events a third party can verify.
--
-- Hash v1 is computed by each writer over JSON text that is then stored as
-- JSONB (which reorders keys), and over fields kept only in the mutable
-- outbox; time, stream, sequence and scope are not covered. It cannot be
-- recomputed from stored data.
--
-- Seal v2 is computed by the database, in a BEFORE INSERT trigger on
-- audit_event, so every writer (Go or SQL) is covered and none can supply a
-- wrong value. It chains per stream and covers the stream, sequence, time,
-- scope, actor, action, target, result, semantic hashes and the exact
-- payload text, which is stored next to the payload. Events written before
-- this schema keep hash_version NULL and are reported as legacy_unsealed.
--
-- Streams also carry the public identifiers of their Workspace and Network,
-- so an exported record (or a document in a future search index) states its
-- tenant scope without a join, and that scope is covered by the seal.

-- Scope identifiers on streams.
ALTER TABLE mesh_audit.audit_stream
    ADD COLUMN workspace_public_id UUID,
    ADD COLUMN network_public_id UUID,
    ADD COLUMN latest_seal_hash BYTEA NOT NULL
        DEFAULT pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
    ADD COLUMN sealed_sequence BIGINT;

CREATE POLICY audit_stream_scope_backfill_workspace ON mesh.workspace
    FOR SELECT TO mesh_migrator USING (TRUE);
CREATE POLICY audit_stream_scope_backfill_network ON mesh.network
    FOR SELECT TO mesh_migrator USING (TRUE);
UPDATE mesh_audit.audit_stream AS stream
SET workspace_public_id = workspace.public_id
FROM mesh.workspace AS workspace
WHERE stream.scope_kind IN ('workspace', 'network')
  AND workspace.id = stream.workspace_id
  AND workspace.deployment_id = stream.deployment_id;
UPDATE mesh_audit.audit_stream AS stream
SET network_public_id = network.public_id
FROM mesh.network AS network
WHERE stream.scope_kind = 'network'
  AND network.id = stream.network_id
  AND network.workspace_id = stream.workspace_id;
DROP POLICY audit_stream_scope_backfill_network ON mesh.network;
DROP POLICY audit_stream_scope_backfill_workspace ON mesh.workspace;

ALTER TABLE mesh_audit.audit_stream
    ADD CONSTRAINT audit_stream_scope_public_id_check CHECK (
        (scope_kind = 'deployment' AND workspace_public_id IS NULL AND network_public_id IS NULL)
        OR (scope_kind = 'workspace' AND workspace_public_id IS NOT NULL AND network_public_id IS NULL)
        OR (scope_kind = 'network' AND workspace_public_id IS NOT NULL AND network_public_id IS NOT NULL)
    ),
    ADD CONSTRAINT audit_stream_seal_check CHECK (
        pg_catalog.octet_length(latest_seal_hash) = 32
        -- The seal advances inside the append, before next_sequence does.
        AND (sealed_sequence IS NULL OR (sealed_sequence > 0 AND sealed_sequence <= next_sequence))
    );
CREATE UNIQUE INDEX audit_stream_workspace_public_uidx
    ON mesh_audit.audit_stream (workspace_public_id)
    WHERE scope_kind = 'workspace';

-- New streams resolve their scope identifiers as the inserting function,
-- which already sees its own Workspace and Network. A stream whose scope
-- cannot be resolved fails the check above instead of being stored blank.
CREATE FUNCTION mesh_audit.resolve_audit_stream_scope()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.scope_kind IN ('workspace', 'network') AND NEW.workspace_public_id IS NULL THEN
        SELECT workspace.public_id INTO NEW.workspace_public_id
        FROM mesh.workspace AS workspace
        WHERE workspace.id = NEW.workspace_id AND workspace.deployment_id = NEW.deployment_id;
    END IF;
    IF NEW.scope_kind = 'network' AND NEW.network_public_id IS NULL THEN
        SELECT network.public_id INTO NEW.network_public_id
        FROM mesh.network AS network
        WHERE network.id = NEW.network_id AND network.workspace_id = NEW.workspace_id;
    END IF;
    NEW.latest_seal_hash := pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex');
    NEW.sealed_sequence := NULL;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.resolve_audit_stream_scope()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER audit_stream_scope_resolution
BEFORE INSERT ON mesh_audit.audit_stream
FOR EACH ROW EXECUTE FUNCTION mesh_audit.resolve_audit_stream_scope();

-- Workspace streams are created by a trigger running as the migrator, which
-- cannot see Workspace rows; it passes the identifier from the new row.
CREATE OR REPLACE FUNCTION mesh_audit.create_workspace_audit_stream()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    INSERT INTO mesh_audit.audit_stream (deployment_id, workspace_id, workspace_public_id, scope_kind)
    VALUES (NEW.deployment_id, NEW.id, NEW.public_id, 'workspace')
    ON CONFLICT (deployment_id, workspace_id) WHERE scope_kind = 'workspace' DO NOTHING;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_audit.enforce_audit_stream_identity()
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
        OR OLD.workspace_public_id IS DISTINCT FROM NEW.workspace_public_id
        OR OLD.network_public_id IS DISTINCT FROM NEW.network_public_id
        OR NEW.next_sequence < OLD.next_sequence
        OR (OLD.sealed_sequence IS NOT NULL
            AND (NEW.sealed_sequence IS NULL OR NEW.sealed_sequence < OLD.sealed_sequence)) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'audit stream identity is immutable';
    END IF;
    RETURN NEW;
END;
$function$;

-- Seal columns. NULL hash_version marks an event written before seal v2.
ALTER TABLE mesh_audit.audit_event
    ADD COLUMN hash_version SMALLINT,
    ADD COLUMN previous_seal_hash BYTEA,
    ADD COLUMN seal_hash BYTEA,
    ADD COLUMN payload_canonical TEXT;
ALTER TABLE mesh_audit.audit_event
    ADD CONSTRAINT audit_event_seal_check CHECK (
        (hash_version IS NULL AND previous_seal_hash IS NULL AND seal_hash IS NULL
            AND payload_canonical IS NULL)
        OR (hash_version = 2
            AND pg_catalog.octet_length(previous_seal_hash) = 32
            AND pg_catalog.octet_length(seal_hash) = 32
            AND payload_canonical IS NOT NULL)
    );

-- One length-delimited field: 8-byte big-endian length, then the bytes.
-- An absent optional value is encoded with length zero.
CREATE FUNCTION mesh_audit.audit_seal_field(p_value BYTEA)
RETURNS BYTEA
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
RETURN pg_catalog.int8send(COALESCE(pg_catalog.octet_length(p_value), 0)::BIGINT)
    || COALESCE(p_value, '\x'::BYTEA);
REVOKE ALL ON FUNCTION mesh_audit.audit_seal_field(BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_audit.seal_audit_event()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_event_public_id UUID;
    v_stream_id BIGINT;
    v_sequence BIGINT;
    v_change_public_id UUID;
    v_stream_public_id UUID;
    v_stream_deployment_id BIGINT;
    v_stream_workspace_id BIGINT;
    v_stream_network_id BIGINT;
    v_workspace_public_id UUID;
    v_network_public_id UUID;
    v_previous_seal BYTEA;
    v_sealed_sequence BIGINT;
    v_canonical TEXT;
    v_seal BYTEA;
BEGIN
    IF NEW.hash_version IS NOT NULL OR NEW.previous_seal_hash IS NOT NULL
        OR NEW.seal_hash IS NOT NULL OR NEW.payload_canonical IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'audit seal is computed by the database';
    END IF;

    SELECT identity.public_id, identity.stream_id, identity.stream_sequence, identity.change_public_id
    INTO v_event_public_id, v_stream_id, v_sequence, v_change_public_id
    FROM mesh_audit.audit_event_identity AS identity
    WHERE identity.id = NEW.event_identity_id AND identity.occurred_at = NEW.occurred_at;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'audit event identity is unavailable';
    END IF;

    SELECT stream.public_id, stream.deployment_id, stream.workspace_id, stream.network_id,
        stream.workspace_public_id, stream.network_public_id, stream.latest_seal_hash,
        stream.sealed_sequence
    INTO v_stream_public_id, v_stream_deployment_id, v_stream_workspace_id, v_stream_network_id,
        v_workspace_public_id, v_network_public_id, v_previous_seal, v_sealed_sequence
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.id = v_stream_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'audit stream is unavailable';
    END IF;
    IF v_stream_deployment_id <> NEW.deployment_id
        OR v_stream_workspace_id IS DISTINCT FROM NEW.workspace_id
        OR v_stream_network_id IS DISTINCT FROM NEW.network_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'audit event scope differs from its stream';
    END IF;
    IF v_sealed_sequence IS NOT NULL AND v_sequence <> v_sealed_sequence + 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'audit seal sequence is not contiguous';
    END IF;

    v_canonical := NEW.payload::TEXT;
    v_seal := pg_catalog.sha256(
        pg_catalog.convert_to('meshtransit/audit-event/v2', 'UTF8') || '\x00'::BYTEA
        || mesh_audit.audit_seal_field(v_previous_seal)
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(v_stream_public_id))
        || mesh_audit.audit_seal_field(pg_catalog.int8send(v_sequence))
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(v_event_public_id))
        || mesh_audit.audit_seal_field(pg_catalog.int8send(
            (EXTRACT(EPOCH FROM NEW.occurred_at) * 1000000)::BIGINT))
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(v_workspace_public_id))
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(v_network_public_id))
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(v_change_public_id))
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(NEW.actor_principal_public_id))
        || mesh_audit.audit_seal_field(pg_catalog.convert_to(NEW.action, 'UTF8'))
        || mesh_audit.audit_seal_field(pg_catalog.convert_to(NEW.permission, 'UTF8'))
        || mesh_audit.audit_seal_field(pg_catalog.convert_to(NEW.target_kind, 'UTF8'))
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(NEW.target_public_id))
        || mesh_audit.audit_seal_field(pg_catalog.convert_to(NEW.result, 'UTF8'))
        || mesh_audit.audit_seal_field(pg_catalog.uuid_send(NEW.correlation_public_id))
        || mesh_audit.audit_seal_field(NEW.before_semantic_hash)
        || mesh_audit.audit_seal_field(NEW.after_semantic_hash)
        || mesh_audit.audit_seal_field(pg_catalog.int8send(NEW.payload_version::BIGINT))
        || mesh_audit.audit_seal_field(pg_catalog.convert_to(v_canonical, 'UTF8'))
    );

    NEW.hash_version := 2;
    NEW.previous_seal_hash := v_previous_seal;
    NEW.seal_hash := v_seal;
    NEW.payload_canonical := v_canonical;
    UPDATE mesh_audit.audit_stream
    SET latest_seal_hash = v_seal, sealed_sequence = v_sequence
    WHERE id = v_stream_id;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.seal_audit_event()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER audit_event_seal
BEFORE INSERT ON mesh_audit.audit_event
FOR EACH ROW EXECUTE FUNCTION mesh_audit.seal_audit_event();

-- Workspace-level evidence (creation, rename, roles) goes to the
-- Workspace's own stream instead of the Deployment stream.
CREATE FUNCTION mesh_audit.lock_workspace_stream_head(
    p_deployment_public_id UUID,
    p_workspace_public_id UUID
)
RETURNS TABLE (
    stream_internal_id BIGINT,
    next_sequence BIGINT,
    latest_event_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh
AS $function$
BEGIN
    IF p_deployment_public_id IS NULL OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Workspace audit stream is unavailable';
    END IF;

    RETURN QUERY
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    FROM mesh_audit.audit_stream AS stream
    JOIN mesh.deployment AS deployment
      ON deployment.id = stream.deployment_id
    WHERE stream.scope_kind = 'workspace'
      AND stream.workspace_public_id = p_workspace_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
    FOR UPDATE OF stream;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Workspace audit stream is unavailable';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.lock_workspace_stream_head(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_audit.lock_workspace_stream_head(UUID, UUID)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_audit.lock_workspace_stream_head(UUID, UUID) TO mesh_runtime;
