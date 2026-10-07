-- Schema 119 (R1-67 part A): Workspace guardrails.
--
-- A guardrail is an owner-level invariant that no rule or share may break,
-- whoever makes the change, like a service control policy for reachability.
-- Part A supports three kinds, all about traffic between Networks:
--   network_isolation  Devices in some Networks never reach some others;
--   network_sharing    some Networks share nothing out, in, or either way;
--   external_sharing   no sharing with other Workspaces, optionally per
--                      Network and with an allowlist of partner Workspaces.
-- Each guardrail runs in audit mode (record findings only) or enforce mode
-- (block). MeshCore validates the parameters and decides whether a change
-- narrows or weakens a guardrail; this schema stores them, checks the
-- permission the change needs (guardrail.manage, or guardrail.weaken for
-- anything that loosens), keeps every referenced Network inside the
-- Workspace, and serves the active set to the transactions that enforce it.
--
-- A security_admin built-in role manages guardrails and reads everything
-- else, separating who sets the limits from who operates Networks.

ALTER TABLE mesh.builtin_role DROP CONSTRAINT builtin_role_key_check;
ALTER TABLE mesh.builtin_role ADD CONSTRAINT builtin_role_key_check CHECK (
    role_key IN ('admin', 'network_admin', 'it_admin', 'billing_admin', 'auditor', 'security_admin')
);
INSERT INTO mesh.builtin_role (
    role_key, public_id, display_name, network_scope_allowed, assignable_by, catalog_version
) VALUES (
    'security_admin', '01a10e00-0000-7000-8000-000000000006', 'Security admin', FALSE,
    ARRAY['owner', 'admin'], 1
);
INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT 'security_admin', permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key IN (
    'workspace.read', 'member.read', 'role_definition.read', 'role_binding.read',
    'isolation.read', 'guardrail.read', 'guardrail.manage', 'guardrail.weaken',
    'audit.read', 'audit.export',
    'network.read', 'device.read', 'policy.read', 'policy.explain',
    'resource.read', 'resource_group.read', 'share.read'
);

CREATE TABLE mesh.guardrail (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    mode TEXT NOT NULL,
    params JSONB NOT NULL,
    semantic_hash BYTEA NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT guardrail_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT guardrail_kind_check CHECK (
        kind IN ('network_isolation', 'network_sharing', 'external_sharing')
    ),
    CONSTRAINT guardrail_name_check CHECK (
        pg_catalog.char_length(name) BETWEEN 1 AND 80 AND name = pg_catalog.btrim(name)
    ),
    CONSTRAINT guardrail_description_check CHECK (pg_catalog.char_length(description) <= 280),
    CONSTRAINT guardrail_mode_check CHECK (mode IN ('audit', 'enforce')),
    CONSTRAINT guardrail_params_check CHECK (
        pg_catalog.jsonb_typeof(params) = 'object' AND pg_catalog.octet_length(params::TEXT) <= 16384
    ),
    CONSTRAINT guardrail_semantic_hash_check CHECK (pg_catalog.octet_length(semantic_hash) = 32),
    CONSTRAINT guardrail_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL)
        OR (state = 'deleted' AND deleted_at IS NOT NULL AND deleted_at >= created_at)
    ),
    CONSTRAINT guardrail_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT guardrail_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT
);
CREATE INDEX guardrail_workspace_active_idx ON mesh.guardrail (workspace_id) WHERE state = 'active';

-- Kind and scope never change; every change advances the version; a deleted
-- guardrail stays as the record of what was enforced.
CREATE FUNCTION mesh_ops.enforce_guardrail_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'guardrail is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid guardrail';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.kind <> OLD.kind
        OR NEW.created_at <> OLD.created_at OR OLD.state = 'deleted'
        OR NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid guardrail transition';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_guardrail_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER guardrail_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.guardrail
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_guardrail_transition_v1();
CREATE TRIGGER guardrail_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.guardrail
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('guardrail', 'public_id');

ALTER TABLE mesh.guardrail ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.guardrail FORCE ROW LEVEL SECURITY;
CREATE POLICY guardrail_migrator_policy ON mesh.guardrail
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.guardrail
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One guardrail as the API and enforcement read it.
CREATE FUNCTION mesh_ops.guardrail_document_internal_v1(p_guardrail mesh.guardrail)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'guardrail_id', p_guardrail.public_id,
        'kind', p_guardrail.kind,
        'name', p_guardrail.name,
        'description', p_guardrail.description,
        'mode', p_guardrail.mode,
        'params', p_guardrail.params,
        'version', p_guardrail.version,
        'created_at', p_guardrail.created_at,
        'updated_at', p_guardrail.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.guardrail_document_internal_v1(mesh.guardrail)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The active guardrails of a Workspace the Session may read
-- (guardrail.read at Workspace scope; owners, admins, auditors and security
-- admins), with whether it may also manage and weaken them so the Console
-- shows only actions Core would accept. NULL means not authorized.
CREATE FUNCTION mesh_ops.list_workspace_guardrails_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    evaluated_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    scoped_workspace_id BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN NULL;
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'guardrail.read', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'guardrails', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.guardrail_document_internal_v1(guardrail)
                ORDER BY guardrail.created_at, guardrail.public_id)
            FROM mesh.guardrail AS guardrail
            WHERE guardrail.workspace_id = scoped_workspace_id AND guardrail.state = 'active'
        ), '[]'::JSONB),
        'can_manage', EXISTS (SELECT 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'guardrail.manage', evaluated_at)),
        'can_weaken', EXISTS (SELECT 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'guardrail.weaken', evaluated_at))
    );
END;
$function$;

-- Creates, updates or deletes one guardrail. p_permission is the permission
-- MeshCore computed for this change: guardrail.manage to add or narrow,
-- guardrail.weaken to delete or loosen. Errors: P0002 unknown guardrail,
-- 40001 stale version, MTG01 a referenced Network is not in the Workspace,
-- MTG02 the Workspace already has 100 guardrails.
CREATE FUNCTION mesh_ops.change_workspace_guardrail_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_operation TEXT,
    p_guardrail_public_id UUID,
    p_expected_version BIGINT,
    p_kind TEXT,
    p_name TEXT,
    p_description TEXT,
    p_mode TEXT,
    p_params JSONB,
    p_semantic_hash BYTEA,
    p_network_public_ids UUID[],
    p_permission TEXT,
    p_change_public_id UUID
)
RETURNS TABLE (
    guardrail JSONB,
    previous_semantic_hash BYTEA,
    actor_binding_public_id UUID,
    actor_role_public_id UUID,
    actor_binding_generation BIGINT,
    actor_membership_generation BIGINT,
    actor_owner_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    deployment_internal_id BIGINT;
    actor RECORD;
    existing mesh.guardrail%ROWTYPE;
    saved mesh.guardrail%ROWTYPE;
    evaluated_at TIMESTAMPTZ;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_guardrail_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid guardrail change input';
        END IF;
    END LOOP;
    IF p_operation IS NULL OR p_operation NOT IN ('create', 'update', 'delete')
        OR p_permission IS NULL OR p_permission NOT IN ('guardrail.manage', 'guardrail.weaken')
        OR (p_operation = 'delete' AND p_permission <> 'guardrail.weaken')
        OR (p_operation = 'create' AND p_expected_version IS NOT NULL)
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version <= 0))
        OR (p_operation <> 'delete' AND (p_kind IS NULL OR p_name IS NULL OR p_description IS NULL
            OR p_mode IS NULL OR p_params IS NULL OR p_semantic_hash IS NULL
            OR p_network_public_ids IS NULL OR pg_catalog.cardinality(p_network_public_ids) > 256)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid guardrail change input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_permission, evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF p_operation <> 'delete' AND EXISTS (
        SELECT 1 FROM pg_catalog.unnest(p_network_public_ids) AS referenced(public_id)
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.network AS network
            WHERE network.workspace_id = scoped_workspace_id
              AND network.public_id = referenced.public_id
              AND network.deleted_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTG01', MESSAGE = 'guardrail Network is not in the Workspace';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.guardrail AS counted
            WHERE counted.workspace_id = scoped_workspace_id AND counted.state = 'active') >= 100 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTG02', MESSAGE = 'guardrail limit reached';
        END IF;
        INSERT INTO mesh.guardrail (
            public_id, deployment_id, workspace_id, kind, name, description, mode, params,
            semantic_hash, state, created_at, updated_at
        ) VALUES (
            p_guardrail_public_id, deployment_internal_id, scoped_workspace_id, p_kind, p_name,
            p_description, p_mode, p_params, p_semantic_hash, 'active', evaluated_at, evaluated_at
        ) RETURNING * INTO saved;
    ELSE
        SELECT * INTO existing FROM mesh.guardrail AS current
        WHERE current.public_id = p_guardrail_public_id
          AND current.workspace_id = scoped_workspace_id
          AND current.state = 'active'
        FOR UPDATE;
        IF existing.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'guardrail is unavailable';
        END IF;
        IF existing.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'guardrail changed';
        END IF;
        IF p_operation = 'update' AND existing.kind <> p_kind THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'guardrail kind cannot change';
        END IF;
        previous_semantic_hash := existing.semantic_hash;
        IF p_operation = 'delete' THEN
            UPDATE mesh.guardrail AS current
            SET state = 'deleted', deleted_at = evaluated_at,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        ELSE
            UPDATE mesh.guardrail AS current
            SET name = p_name, description = p_description, mode = p_mode, params = p_params,
                semantic_hash = p_semantic_hash,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        END IF;
    END IF;

    guardrail := mesh_ops.guardrail_document_internal_v1(saved)
        || pg_catalog.jsonb_build_object('state', saved.state);
    actor_binding_public_id := actor.role_binding_public_id;
    actor_role_public_id := actor.role_definition_public_id;
    actor_binding_generation := actor.binding_authority_generation;
    actor_membership_generation := actor.membership_authority_generation;
    actor_owner_generation := actor.workspace_owner_authority_generation;
    RETURN NEXT;
END;
$function$;

-- The active guardrails of the Workspace bound to this transaction, for the
-- share and policy transactions that enforce them. Runs as the definer so
-- the caller needs no access to the table; the scope comes from the
-- transaction's verified Network scope.
CREATE FUNCTION mesh_ops.active_workspace_guardrails_v1()
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
BEGIN
    IF scoped_workspace_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Workspace scope is unavailable';
    END IF;
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.guardrail_document_internal_v1(guardrail)
            ORDER BY guardrail.created_at, guardrail.public_id)
        FROM mesh.guardrail AS guardrail
        WHERE guardrail.workspace_id = scoped_workspace_id AND guardrail.state = 'active'
    ), '[]'::JSONB);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_workspace_guardrails_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_workspace_guardrails_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_workspace_guardrail_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT,
    TEXT, TEXT, TEXT, TEXT, JSONB, BYTEA, UUID[], TEXT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_workspace_guardrail_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT,
    TEXT, TEXT, TEXT, TEXT, JSONB, BYTEA, UUID[], TEXT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.active_workspace_guardrails_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.active_workspace_guardrails_v1() TO mesh_runtime;
