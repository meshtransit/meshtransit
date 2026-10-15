-- Schema 164: an enforced guardrail cuts existing shares.
--
-- Until now guardrails were checked only when a share was offered, accepted
-- or enabled and when rules were published, so enforcing one later left
-- every existing share open. An enforce-mode guardrail is now retroactive:
-- a map leaves out every share an enforced guardrail of either side blocks,
-- and gets it back once the guardrail is weakened or deleted. MeshCore
-- evaluates guardrails; this schema only serves them:
--
-- map_share_guardrails_v1: to a map transaction, the enforce-mode guardrails
-- (kind and parameters only) of the Workspaces of its shares. Only the
-- Workspaces of a share of the transaction's Network are answered; any other
-- one fails the map instead of reading as "no guardrails".
--
-- list_guardrail_share_contracts_v1: to a Session with guardrail.manage, the
-- Workspace's active guardrails and its active shares, so MeshCore previews
-- which shares a guardrail would cut. Saving an enforce-mode guardrail
-- echoes the preview's impact hash and fails when it changed.
--
-- guardrail_change_share_contracts_v1 and bump_guardrail_share_networks_v1:
-- inside the transaction of a guardrail change (proved by its authority
-- mutation), the same read, and an advance of both sides' Network and
-- sharing revisions for each share the change cuts or restores, returning
-- each Network's audit stream head so MeshCore records the change and the
-- revision wakeup on that Network's stream.
--
-- Lock order: the guardrail change locks the guardrail state row, the
-- Workspace row and the guardrail, then Network revisions, then audit
-- streams. Share and publication transactions lock Network revisions before
-- the provider's guardrail state row, so the schema 163 readers now take that
-- row with NOWAIT: a share made while the provider's guardrails change fails
-- as a retryable conflict instead of waiting on the change in a cycle.

-- The guardrail fan-out advances revisions of Networks of other Workspaces;
-- these policies admit them only while bump_guardrail_share_networks_v1 has
-- set mesh.guardrail_share_fanout for its statements.
CREATE POLICY network_revision_guardrail_share_read ON mesh_ops.network_revision
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.guardrail_share_fanout', TRUE) = 'on');
CREATE POLICY network_revision_guardrail_share_mutation ON mesh_ops.network_revision
    FOR UPDATE TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.guardrail_share_fanout', TRUE) = 'on')
    WITH CHECK (pg_catalog.current_setting('mesh.guardrail_share_fanout', TRUE) = 'on');

CREATE FUNCTION mesh_ops.map_share_guardrails_v1(p_workspaces UUID[])
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
    v_requested INTEGER := pg_catalog.cardinality(p_workspaces);
    v_result JSONB;
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_workspaces IS NULL OR v_requested < 1 OR v_requested > 16384
        OR pg_catalog.array_position(p_workspaces, NULL) IS NOT NULL
        OR (SELECT pg_catalog.count(DISTINCT requested.public_id)
            FROM pg_catalog.unnest(p_workspaces) AS requested(public_id)) <> v_requested THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid map guardrail request';
    END IF;
    -- A Workspace is known to this Network only as a side of one of its
    -- share offers; the Workspace rows of other tenants are not read.
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'workspace_id', known.public_id,
            'guardrails', COALESCE((
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                        'kind', guardrail.kind, 'params', guardrail.params)
                    ORDER BY guardrail.created_at, guardrail.public_id)
                FROM mesh.guardrail AS guardrail
                WHERE guardrail.workspace_id = known.id
                  AND guardrail.state = 'active'
                  AND guardrail.mode = 'enforce'
            ), '[]'::JSONB)
        ) ORDER BY known.public_id)
    INTO v_result
    FROM (
        SELECT DISTINCT side.id, side.public_id
        FROM mesh.share_offer_locator AS locator
        CROSS JOIN LATERAL (VALUES
            (locator.provider_workspace_id, locator.provider_workspace_public_id),
            (locator.consumer_workspace_id, locator.consumer_workspace_public_id)
        ) AS side(id, public_id)
        WHERE locator.local_workspace_id = scoped_workspace_id
          AND locator.local_network_id = scoped_network_id
          AND side.public_id = ANY (p_workspaces)
    ) AS known;
    IF v_result IS NULL OR pg_catalog.jsonb_array_length(v_result) <> v_requested THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace is unavailable to this Network';
    END IF;
    RETURN v_result;
END;
$function$;

-- The active guardrails and the active shares of a Workspace. A share
-- appears once; side is provider, consumer, or both for a share between two
-- of its Networks. The label is the one this Workspace already sees: the
-- offer's access label on the provider side, the Imported Resource name
-- otherwise. More than 20000 active shares fail with 54000.
CREATE FUNCTION mesh_ops.guardrail_share_contracts_internal_v1(p_workspace_id BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_candidates BIGINT;
    v_contracts JSONB;
BEGIN
    WITH candidate AS MATERIALIZED (
        SELECT provided.id, provided.public_id, provided.share_offer_id,
            provided.provider_workspace_id, provided.provider_network_id, provided.consumer_workspace_id
        FROM mesh.trust_contract AS provided
        WHERE provided.provider_workspace_id = p_workspace_id
          AND provided.state IN ('activating', 'active')
        UNION
        SELECT received.id, received.public_id, received.share_offer_id,
            received.provider_workspace_id, received.provider_network_id, received.consumer_workspace_id
        FROM mesh.trust_contract AS received
        WHERE received.consumer_workspace_id = p_workspace_id
          AND received.state IN ('activating', 'active')
        LIMIT 20001
    )
    SELECT (SELECT pg_catalog.count(*) FROM candidate), pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'trust_contract_id', contract.public_id,
            'provider_workspace_id', locator.provider_workspace_public_id,
            'provider_network_id', locator.provider_network_public_id,
            'consumer_workspace_id', locator.consumer_workspace_public_id,
            'consumer_network_id', locator.consumer_network_public_id,
            'side', CASE
                WHEN contract.provider_workspace_id = contract.consumer_workspace_id THEN 'both'
                WHEN contract.provider_workspace_id = p_workspace_id THEN 'provider'
                ELSE 'consumer' END,
            'network_id', CASE
                WHEN contract.provider_workspace_id = p_workspace_id THEN locator.provider_network_public_id
                ELSE locator.consumer_network_public_id END,
            'label', CASE
                WHEN contract.consumer_workspace_id = p_workspace_id THEN imported.display_name
                ELSE COALESCE(offer.access_label, '') END
        ) ORDER BY contract.public_id)
    INTO v_candidates, v_contracts
    FROM candidate AS contract
    JOIN mesh.share_offer AS offer ON offer.id = contract.share_offer_id
    JOIN mesh.imported_resource AS imported ON imported.trust_contract_id = contract.id
    CROSS JOIN LATERAL (
        SELECT found.provider_workspace_public_id, found.provider_network_public_id,
            found.consumer_workspace_public_id, found.consumer_network_public_id
        FROM mesh.share_offer_locator AS found
        WHERE found.offer_id = contract.share_offer_id
          AND found.local_workspace_id = contract.provider_workspace_id
          AND found.local_network_id = contract.provider_network_id
          AND found.direction = 'outgoing'
        LIMIT 1
    ) AS locator;
    IF v_candidates > 20000 THEN
        RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'too many shares to preview';
    END IF;
    -- Every active share must be described; a missing part fails closed.
    IF pg_catalog.jsonb_array_length(COALESCE(v_contracts, '[]'::JSONB)) <> COALESCE(v_candidates, 0) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'a share is incomplete';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'guardrails', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.guardrail_document_internal_v1(guardrail)
                ORDER BY guardrail.created_at, guardrail.public_id)
            FROM mesh.guardrail AS guardrail
            WHERE guardrail.workspace_id = p_workspace_id AND guardrail.state = 'active'
        ), '[]'::JSONB),
        'contracts', COALESCE(v_contracts, '[]'::JSONB)
    );
END;
$function$;

-- What list_workspace_guardrails_v1 reads, for a Session that may manage
-- guardrails. NULL means not authorized.
CREATE FUNCTION mesh_ops.list_guardrail_share_contracts_v1(
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
        p_workspace_public_id, 'guardrail.manage', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN mesh_ops.guardrail_share_contracts_internal_v1(scoped_workspace_id);
END;
$function$;

-- Internal: the Workspace whose guardrail this transaction changed under
-- p_change, or an error. The authority mutation row is only written by a
-- guardrail change inside change_workspace_guardrail_v1.
CREATE FUNCTION mesh_ops.guardrail_change_workspace_internal_v1(p_change UUID)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
BEGIN
    IF scoped_workspace_id IS NULL OR p_change IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7
        OR NOT EXISTS (
            SELECT 1
            FROM mesh_audit.authority_mutation AS mutation
            JOIN mesh.guardrail AS guardrail ON guardrail.public_id = mutation.row_public_id
            WHERE mutation.change_public_id = p_change
              AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
              AND mutation.aggregate_kind = 'guardrail'
              AND guardrail.workspace_id = scoped_workspace_id
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'no guardrail change in this transaction';
    END IF;
    RETURN scoped_workspace_id;
END;
$function$;

-- The Workspace's guardrails (after the change) and active shares, inside
-- the transaction of a guardrail change.
CREATE FUNCTION mesh_ops.guardrail_change_share_contracts_v1(p_change UUID)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    RETURN mesh_ops.guardrail_share_contracts_internal_v1(
        mesh_ops.guardrail_change_workspace_internal_v1(p_change));
END;
$function$;

-- Advances the Network and sharing revisions of both sides of each listed
-- share, once per Network in (Workspace, Network) order, then locks those
-- Networks' audit streams in stream order and returns their heads, as
-- [{"workspace_id", "network_id", "own_workspace", "network_revision",
-- "sharing_revision", "stream_id", "next_sequence", "latest_event_hash"}]
-- (the hash in hexadecimal), in stream order. Every
-- share must be active or activating and touch the Workspace whose
-- guardrail this transaction changed; anything else fails with 40001.
CREATE FUNCTION mesh_ops.bump_guardrail_share_networks_v1(p_contracts UUID[], p_change UUID)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    v_requested INTEGER := pg_catalog.cardinality(p_contracts);
    v_found INTEGER;
    v_networks BIGINT[];
    v_scope RECORD;
    v_heads JSONB;
BEGIN
    IF p_contracts IS NULL OR v_requested < 1 OR v_requested > 20000
        OR pg_catalog.array_position(p_contracts, NULL) IS NOT NULL
        OR (SELECT pg_catalog.count(DISTINCT requested.public_id)
            FROM pg_catalog.unnest(p_contracts) AS requested(public_id)) <> v_requested THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid guardrail share fan-out';
    END IF;
    scoped_workspace_id := mesh_ops.guardrail_change_workspace_internal_v1(p_change);
    SELECT pg_catalog.count(*) INTO v_found
    FROM mesh.trust_contract AS contract
    WHERE contract.public_id = ANY (p_contracts)
      AND contract.state IN ('activating', 'active')
      AND scoped_workspace_id IN (contract.provider_workspace_id, contract.consumer_workspace_id);
    IF v_found <> v_requested THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'a share changed during the guardrail change';
    END IF;

    PERFORM pg_catalog.set_config('mesh.guardrail_share_fanout', 'on', TRUE);
    FOR v_scope IN
        SELECT revision.workspace_id, revision.network_id
        FROM mesh_ops.network_revision AS revision
        WHERE (revision.workspace_id, revision.network_id) IN (
            SELECT contract.provider_workspace_id, contract.provider_network_id
            FROM mesh.trust_contract AS contract WHERE contract.public_id = ANY (p_contracts)
            UNION
            SELECT contract.consumer_workspace_id, contract.consumer_network_id
            FROM mesh.trust_contract AS contract WHERE contract.public_id = ANY (p_contracts)
        )
        ORDER BY revision.workspace_id, revision.network_id
        FOR UPDATE
    LOOP
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            sharing_revision = revision.sharing_revision + 1,
            updated_at = GREATEST(revision.updated_at, pg_catalog.clock_timestamp())
        WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id;
        v_networks := pg_catalog.array_append(v_networks, v_scope.network_id);
    END LOOP;

    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'workspace_id', head.workspace_public_id, 'network_id', head.network_public_id,
            'own_workspace', head.workspace_id = scoped_workspace_id,
            'network_revision', head.network_revision, 'sharing_revision', head.sharing_revision,
            'stream_id', head.id, 'next_sequence', head.next_sequence,
            'latest_event_hash', pg_catalog.encode(head.latest_event_hash, 'hex')
        ) ORDER BY head.id), pg_catalog.count(*)
    INTO v_heads, v_found
    FROM (
        SELECT stream.id, stream.workspace_id, stream.workspace_public_id, stream.network_public_id,
            stream.next_sequence, stream.latest_event_hash, revision.network_revision, revision.sharing_revision
        FROM mesh_audit.audit_stream AS stream
        JOIN mesh_ops.network_revision AS revision
          ON revision.workspace_id = stream.workspace_id AND revision.network_id = stream.network_id
        WHERE stream.scope_kind = 'network' AND stream.network_id = ANY (v_networks)
        ORDER BY stream.id
        FOR UPDATE OF stream
    ) AS head;
    PERFORM pg_catalog.set_config('mesh.guardrail_share_fanout', '', TRUE);
    IF v_networks IS NULL OR v_found <> pg_catalog.cardinality(v_networks) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    RETURN v_heads;
END;
$function$;

-- Schema 163 readers, unchanged except that they take the provider's
-- guardrail state row with NOWAIT (see the lock order above).
CREATE OR REPLACE FUNCTION mesh_ops.share_offer_provider_guardrails_v1(p_offer_public_id UUID)
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
    PERFORM 1 FROM mesh.workspace_guardrail_state AS state WHERE state.workspace_id = v_provider FOR SHARE NOWAIT;
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

CREATE OR REPLACE FUNCTION mesh_ops.imported_resource_provider_guardrails_v1()
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
    FOR SHARE NOWAIT;
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

REVOKE ALL ON FUNCTION mesh_ops.guardrail_share_contracts_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.guardrail_change_workspace_internal_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.map_share_guardrails_v1(UUID[])
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.map_share_guardrails_v1(UUID[]) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_guardrail_share_contracts_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_guardrail_share_contracts_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.guardrail_change_share_contracts_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.guardrail_change_share_contracts_v1(UUID) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.bump_guardrail_share_networks_v1(UUID[], UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.bump_guardrail_share_networks_v1(UUID[], UUID) TO mesh_runtime;
