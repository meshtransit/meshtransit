-- Schema 163: a share also answers to the provider's guardrails.
--
-- Accepting an offer, activating its contract and publishing rules to an
-- Imported Resource run in the consumer's Network scope, so they only read
-- the consumer's guardrails (active_workspace_guardrails_v1). A provider that
-- enforced a guardrail after sending an offer could not stop the consumer from
-- accepting, activating or opening new paths to it. These readers return the
-- provider Workspace's active guardrails to the consumer's transaction, and
-- only for a share that transaction is the consumer of:
--
-- share_offer_provider_guardrails_v1: for an offered or accepted offer this
-- Network received (its incoming locator); any other offer is an error. An
-- offer within one Workspace returns [], as the acting side's own guardrails
-- already apply.
--
-- imported_resource_provider_guardrails_v1: for each other Workspace that
-- provides an activating or active Imported Resource of this Network, as
-- [{"workspace_id", "guardrails"}].
--
-- A provider's concurrent guardrail change must be seen, waited for, or make
-- the reader fail. The readers run after the share and publication
-- transactions lock Network revisions, and other flows lock the Workspace row
-- before Network revisions, so locking the Workspace row here could deadlock.
-- Instead each Workspace has one mesh.workspace_guardrail_state row, which a
-- trigger advances on every guardrail change and nothing else locks. The
-- readers take it FOR SHARE: under read committed they wait for the change
-- and read it; under repeatable read (share transactions) a change committed
-- after the snapshot fails them with 40001 rather than reading stale
-- guardrails.
--
-- The caller shows the consumer only a generic refusal and keeps the
-- provider's findings out of the consumer's records.

CREATE TABLE mesh.workspace_guardrail_state (
    workspace_id BIGINT PRIMARY KEY REFERENCES mesh.workspace (id) ON DELETE RESTRICT,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
ALTER TABLE mesh.workspace_guardrail_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace_guardrail_state FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_guardrail_state_migrator_policy ON mesh.workspace_guardrail_state
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.workspace_guardrail_state
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The migration role reads every Workspace only under the schema 99 guard.
SELECT pg_catalog.set_config('mesh.workspace_limit_guard', 'on', TRUE);
INSERT INTO mesh.workspace_guardrail_state (workspace_id)
SELECT workspace.id FROM mesh.workspace AS workspace;
DO $backfill$
BEGIN
    IF (SELECT pg_catalog.count(*) FROM mesh.workspace_guardrail_state)
        <> (SELECT pg_catalog.count(*) FROM mesh.workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'guardrail state backfill missed a Workspace';
    END IF;
END;
$backfill$;
SELECT pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);

CREATE FUNCTION mesh_ops.create_workspace_guardrail_state_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
BEGIN
    INSERT INTO mesh.workspace_guardrail_state (workspace_id) VALUES (NEW.id);
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.create_workspace_guardrail_state_v1() FROM PUBLIC;
CREATE TRIGGER workspace_guardrail_state_created
AFTER INSERT ON mesh.workspace
FOR EACH ROW EXECUTE FUNCTION mesh_ops.create_workspace_guardrail_state_v1();

CREATE FUNCTION mesh_ops.advance_workspace_guardrail_state_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
BEGIN
    UPDATE mesh.workspace_guardrail_state AS state
    SET revision = state.revision + 1
    WHERE state.workspace_id = NEW.workspace_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace guardrail state is missing';
    END IF;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.advance_workspace_guardrail_state_v1() FROM PUBLIC;
CREATE TRIGGER guardrail_state_advanced
AFTER INSERT OR UPDATE ON mesh.guardrail
FOR EACH ROW EXECUTE FUNCTION mesh_ops.advance_workspace_guardrail_state_v1();

-- Unchanged from schema 119 except that it locks the guardrail state row
-- before the Workspace row, so a guardrail change and a share or
-- publication reader never wait on each other in a cycle.
CREATE OR REPLACE FUNCTION mesh_ops.change_workspace_guardrail_v1(
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
    -- The guardrail state row first, then the Workspace row: share and
    -- publication transactions hold the state row FOR SHARE and may then need
    -- the Workspace row (schema 163).
    PERFORM 1 FROM mesh.workspace_guardrail_state AS state
    WHERE state.workspace_id = scoped_workspace_id FOR UPDATE;
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

CREATE FUNCTION mesh_ops.share_offer_provider_guardrails_v1(p_offer_public_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
    v_provider BIGINT;
    v_consumer BIGINT;
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    SELECT locator.provider_workspace_id, locator.consumer_workspace_id INTO v_provider, v_consumer
    FROM mesh.share_offer_locator AS locator
    WHERE locator.local_workspace_id = scoped_workspace_id
      AND locator.local_network_id = scoped_network_id
      AND locator.offer_public_id = p_offer_public_id
      AND locator.direction = 'incoming'
      AND locator.state IN ('offered', 'accepted');
    -- Callers ask only for a share this scope received from another
    -- Workspace; no such offer is an error, never "no guardrails".
    IF v_provider IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'offer is unavailable to this Network';
    END IF;
    IF v_provider = v_consumer THEN
        RETURN '[]'::JSONB;
    END IF;
    PERFORM 1 FROM mesh.workspace_guardrail_state AS state WHERE state.workspace_id = v_provider FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace guardrail state is missing';
    END IF;
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.guardrail_document_internal_v1(guardrail)
            ORDER BY guardrail.created_at, guardrail.public_id)
        FROM mesh.guardrail AS guardrail
        WHERE guardrail.workspace_id = v_provider AND guardrail.state = 'active'
    ), '[]'::JSONB);
END;
$function$;

CREATE FUNCTION mesh_ops.imported_resource_provider_guardrails_v1()
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
    v_providers BIGINT[];
    v_result JSONB;
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    SELECT pg_catalog.array_agg(DISTINCT contract.provider_workspace_id ORDER BY contract.provider_workspace_id)
    INTO v_providers
    FROM mesh.imported_resource AS imported
    JOIN mesh.trust_contract AS contract ON contract.id = imported.trust_contract_id
    WHERE imported.workspace_id = scoped_workspace_id
      AND imported.network_id = scoped_network_id
      AND imported.state IN ('activating', 'active')
      AND contract.provider_workspace_id <> scoped_workspace_id;
    IF v_providers IS NULL THEN
        RETURN '[]'::JSONB;
    END IF;
    PERFORM 1 FROM mesh.workspace_guardrail_state AS state
    WHERE state.workspace_id = ANY (v_providers)
    ORDER BY state.workspace_id
    FOR SHARE;
    IF (SELECT pg_catalog.count(*) FROM mesh.workspace_guardrail_state AS state
        WHERE state.workspace_id = ANY (v_providers)) <> pg_catalog.cardinality(v_providers) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace guardrail state is missing';
    END IF;
    -- Provider public IDs come from this Network's incoming offer locators;
    -- the Workspace rows of other tenants are not readable here.
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'workspace_id', provider.public_id,
            'guardrails', COALESCE((
                SELECT pg_catalog.jsonb_agg(mesh_ops.guardrail_document_internal_v1(guardrail)
                    ORDER BY guardrail.created_at, guardrail.public_id)
                FROM mesh.guardrail AS guardrail
                WHERE guardrail.workspace_id = provider.id AND guardrail.state = 'active'
            ), '[]'::JSONB)
        ) ORDER BY provider.public_id)
    INTO v_result
    FROM (
        SELECT DISTINCT locator.provider_workspace_id AS id, locator.provider_workspace_public_id AS public_id
        FROM mesh.imported_resource AS imported
        JOIN mesh.trust_contract AS contract ON contract.id = imported.trust_contract_id
        JOIN mesh.share_offer_locator AS locator
          ON locator.offer_id = contract.share_offer_id
         AND locator.local_workspace_id = scoped_workspace_id
         AND locator.local_network_id = scoped_network_id
         AND locator.direction = 'incoming'
        WHERE imported.workspace_id = scoped_workspace_id
          AND imported.network_id = scoped_network_id
          AND imported.state IN ('activating', 'active')
          AND locator.provider_workspace_id = ANY (v_providers)
    ) AS provider;
    IF v_result IS NULL OR pg_catalog.jsonb_array_length(v_result) <> pg_catalog.cardinality(v_providers) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'provider Workspace is unavailable';
    END IF;
    RETURN v_result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.share_offer_provider_guardrails_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.share_offer_provider_guardrails_v1(UUID) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.imported_resource_provider_guardrails_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.imported_resource_provider_guardrails_v1() TO mesh_runtime;
