-- Schema 167: guardrail share changes stay consistent under concurrency.
--
-- Schema 164 cut shares an enforced guardrail blocks. Review found four
-- gaps; the schema 164 functions stay for the previous binary.
--
-- A share made while a guardrail changes. A guardrail change read the
-- Workspace's shares before it locked any Network revision, and a share
-- accepted or enabled at the same time did not lock the acting Workspace's
-- guardrails, so the change could miss the new share: no wakeup, and a
-- preview hash that did not cover it. Now:
--   active_workspace_guardrails_v2 takes the acting Workspace's guardrail
--   state row FOR SHARE NOWAIT, as the schema 163 provider readers do, so a
--   share change and a guardrail change of one Workspace never overlap: the
--   share fails as a retryable conflict while a change runs, and a change
--   waits for a share already holding the row and then reads it.
--   bump_guardrail_share_networks_v2 takes the shares MeshCore evaluated
--   and, once the Network revisions are locked, compares them with the
--   Workspace's active shares; any difference fails with MTG03, which
--   MeshCore retries a few times before answering a version conflict.
--
-- A deadlock. change_workspace_guardrail_v1 holds the Workspace row FOR
-- UPDATE and since schema 164 then waits for Network revisions, while an
-- offer holding its Network revision inserts rows whose foreign keys take
-- the Workspace row FOR KEY SHARE. change_workspace_guardrail_v2 is v1 with
-- FOR NO KEY UPDATE, which foreign key checks do not wait for.
--
-- A cap that blocked loosening. The 20000-share bound applied to every
-- guardrail change, so a Workspace above it could not delete or loosen a
-- guardrail. Only a change whose result is in enforce mode can cut shares,
-- so only the preview and such a save read the shares, under a bound
-- MeshCore gives (at most 20000). A change that only restores (a deletion
-- or a switch to audit mode of an enforced guardrail) reads no share list:
-- wake_guardrail_share_networks_v1 picks, in SQL, the Networks on both
-- sides of the active shares of the Networks the guardrail named, and
-- advances at most 1024 of them. Restoring late only withholds access
-- longer, and the Networks past the bound are rebuilt at the next
-- reconcile interval.
--
-- The map reader scanned every offer of the Network. map_share_guardrails_v2
-- looks each requested Workspace up in accepted offers through two partial
-- indexes. An edge always comes from an accepted offer (an accepted
-- locator never changes state again), so the fail-closed check is kept.
--
-- The preview also accepts guardrail.weaken, which a save that loosens an
-- enforce-mode guardrail into a narrower enforce-mode one needs.
--
-- No revision is advanced here: the map filter is in the MeshCore binary,
-- whose rollout reconnects nodes, and map streams reread PostgreSQL every
-- reconcile interval (docs/operations/upgrades.md).

CREATE INDEX share_offer_locator_accepted_provider_idx
    ON mesh.share_offer_locator (local_workspace_id, local_network_id, provider_workspace_public_id)
    WHERE state = 'accepted';
CREATE INDEX share_offer_locator_accepted_consumer_idx
    ON mesh.share_offer_locator (local_workspace_id, local_network_id, consumer_workspace_public_id)
    WHERE state = 'accepted';

CREATE FUNCTION mesh_ops.map_share_guardrails_v2(p_workspaces UUID[])
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
    v_public_id UUID;
    v_internal_id BIGINT;
    v_result JSONB := '[]'::JSONB;
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
    FOR v_public_id IN
        SELECT requested.public_id FROM pg_catalog.unnest(p_workspaces) AS requested(public_id)
        ORDER BY requested.public_id
    LOOP
        -- A Workspace is known to this Network only as a side of one of its
        -- accepted offers; the Workspace rows of other tenants are not read.
        v_internal_id := COALESCE((
            SELECT locator.provider_workspace_id
            FROM mesh.share_offer_locator AS locator
            WHERE locator.local_workspace_id = scoped_workspace_id
              AND locator.local_network_id = scoped_network_id
              AND locator.provider_workspace_public_id = v_public_id
              AND locator.state = 'accepted'
            LIMIT 1
        ), (
            SELECT locator.consumer_workspace_id
            FROM mesh.share_offer_locator AS locator
            WHERE locator.local_workspace_id = scoped_workspace_id
              AND locator.local_network_id = scoped_network_id
              AND locator.consumer_workspace_public_id = v_public_id
              AND locator.state = 'accepted'
            LIMIT 1
        ));
        IF v_internal_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace is unavailable to this Network';
        END IF;
        v_result := v_result || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'workspace_id', v_public_id,
            'guardrails', COALESCE((
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                        'kind', guardrail.kind, 'params', guardrail.params)
                    ORDER BY guardrail.created_at, guardrail.public_id)
                FROM mesh.guardrail AS guardrail
                WHERE guardrail.workspace_id = v_internal_id
                  AND guardrail.state = 'active'
                  AND guardrail.mode = 'enforce'
            ), '[]'::JSONB)
        ));
    END LOOP;
    RETURN v_result;
END;
$function$;

-- Schema 164's reader with the bound given by the caller: more than p_limit
-- active shares fail with 54000.
CREATE FUNCTION mesh_ops.guardrail_share_contracts_internal_v2(p_workspace_id BIGINT, p_limit INTEGER)
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
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 20000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid share limit';
    END IF;
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
        LIMIT p_limit + 1
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
    IF v_candidates > p_limit THEN
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

-- Schema 164's preview reader, open to guardrail.manage or guardrail.weaken,
-- with the caller's bound. NULL means not authorized.
CREATE FUNCTION mesh_ops.list_guardrail_share_contracts_v2(
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
    p_limit INTEGER
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
    -- Whoever may save a guardrail may preview it: guardrail.manage to add
    -- or narrow, guardrail.weaken to loosen one that stays in enforce mode.
    IF NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'guardrail.manage', evaluated_at))
        AND NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'guardrail.weaken', evaluated_at)) THEN
        RETURN NULL;
    END IF;
    RETURN mesh_ops.guardrail_share_contracts_internal_v2(scoped_workspace_id, p_limit);
END;
$function$;

-- Schema 164's in-change reader with the caller's bound.
CREATE FUNCTION mesh_ops.guardrail_change_share_contracts_v2(p_change UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    RETURN mesh_ops.guardrail_share_contracts_internal_v2(
        mesh_ops.guardrail_change_workspace_internal_v1(p_change), p_limit);
END;
$function$;

-- Advances the Network and sharing revisions of both sides of each share in
-- p_contracts (none is allowed), once per Network in (Workspace, Network)
-- order, then checks that p_inventory, the shares MeshCore evaluated, is
-- still exactly the Workspace's active and activating shares; a share made
-- or ended since fails with MTG03. It returns the locked audit stream
-- heads of the advanced Networks as schema 164's bump does.
CREATE FUNCTION mesh_ops.bump_guardrail_share_networks_v2(
    p_contracts UUID[],
    p_inventory UUID[],
    p_change UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    v_requested INTEGER := COALESCE(pg_catalog.cardinality(p_contracts), 0);
    v_inventory INTEGER := COALESCE(pg_catalog.cardinality(p_inventory), 0);
    v_found INTEGER;
    v_networks BIGINT[];
    v_scope RECORD;
    v_heads JSONB;
    v_live BIGINT;
    v_matched BIGINT;
BEGIN
    IF p_contracts IS NULL OR p_inventory IS NULL OR v_requested > v_inventory OR v_inventory > 20000
        OR pg_catalog.array_position(p_contracts, NULL) IS NOT NULL
        OR pg_catalog.array_position(p_inventory, NULL) IS NOT NULL
        OR (SELECT pg_catalog.count(DISTINCT requested.public_id)
            FROM pg_catalog.unnest(p_contracts) AS requested(public_id)) <> v_requested
        OR (SELECT pg_catalog.count(DISTINCT evaluated.public_id)
            FROM pg_catalog.unnest(p_inventory) AS evaluated(public_id)) <> v_inventory
        OR EXISTS (
            SELECT 1 FROM pg_catalog.unnest(p_contracts) AS requested(public_id)
            WHERE NOT EXISTS (
                SELECT 1 FROM pg_catalog.unnest(p_inventory) AS evaluated(public_id)
                WHERE evaluated.public_id = requested.public_id
            )
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid guardrail share fan-out';
    END IF;
    scoped_workspace_id := mesh_ops.guardrail_change_workspace_internal_v1(p_change);

    IF v_requested > 0 THEN
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
    END IF;

    -- Read after the revision locks: a share that committed while this
    -- change waited for them is seen here.
    SELECT pg_catalog.count(*), pg_catalog.count(evaluated.public_id)
    INTO v_live, v_matched
    FROM (
        SELECT provided.public_id FROM mesh.trust_contract AS provided
        WHERE provided.provider_workspace_id = scoped_workspace_id
          AND provided.state IN ('activating', 'active')
        UNION
        SELECT received.public_id FROM mesh.trust_contract AS received
        WHERE received.consumer_workspace_id = scoped_workspace_id
          AND received.state IN ('activating', 'active')
    ) AS live
    LEFT JOIN pg_catalog.unnest(p_inventory) AS evaluated(public_id) ON evaluated.public_id = live.public_id;
    IF v_live <> v_inventory OR v_matched <> v_inventory THEN
        PERFORM pg_catalog.set_config('mesh.guardrail_share_fanout', '', TRUE);
        RAISE EXCEPTION USING ERRCODE = 'MTG03', MESSAGE = 'a share changed during the guardrail change';
    END IF;

    IF v_requested = 0 THEN
        RETURN '[]'::JSONB;
    END IF;
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

-- Wakes the maps a guardrail change that only restores shares affects: the
-- Networks on both sides of the Workspace's active and activating shares
-- that have their Workspace side in p_networks (the Networks the guardrail
-- named; none means every Network of the Workspace). It advances the Network
-- and sharing revisions of at most p_limit of them (at most 1024), in
-- (Workspace, Network) order, locks their audit streams in stream order and
-- returns {"heads": [...as bump_guardrail_share_networks_v2], "deferred":
-- whether more Networks were left to the reconcile interval}. It reads no
-- share list into the caller and needs no recheck: restoring can only open
-- a share later than it could, never earlier.
CREATE FUNCTION mesh_ops.wake_guardrail_share_networks_v1(p_change UUID, p_networks UUID[], p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    v_local BIGINT[];
    v_workspaces BIGINT[];
    v_networks BIGINT[];
    v_deferred BOOLEAN;
    v_scope RECORD;
    v_heads JSONB;
    v_found INTEGER;
BEGIN
    IF p_networks IS NULL OR pg_catalog.cardinality(p_networks) > 256
        OR pg_catalog.array_position(p_networks, NULL) IS NOT NULL
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1024 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid guardrail share wakeup';
    END IF;
    scoped_workspace_id := mesh_ops.guardrail_change_workspace_internal_v1(p_change);
    IF pg_catalog.cardinality(p_networks) > 0 THEN
        SELECT pg_catalog.array_agg(network.id) INTO v_local
        FROM mesh.network AS network
        WHERE network.workspace_id = scoped_workspace_id AND network.public_id = ANY (p_networks);
        IF v_local IS NULL THEN
            RETURN pg_catalog.jsonb_build_object('heads', '[]'::JSONB, 'deferred', FALSE);
        END IF;
    END IF;

    WITH touched AS (
        SELECT provided.provider_workspace_id, provided.provider_network_id,
            provided.consumer_workspace_id, provided.consumer_network_id
        FROM mesh.trust_contract AS provided
        WHERE provided.provider_workspace_id = scoped_workspace_id
          AND provided.state IN ('activating', 'active')
          AND (v_local IS NULL OR provided.provider_network_id = ANY (v_local))
        UNION ALL
        SELECT received.provider_workspace_id, received.provider_network_id,
            received.consumer_workspace_id, received.consumer_network_id
        FROM mesh.trust_contract AS received
        WHERE received.consumer_workspace_id = scoped_workspace_id
          AND received.state IN ('activating', 'active')
          AND (v_local IS NULL OR received.consumer_network_id = ANY (v_local))
    ), side AS (
        SELECT touched.provider_workspace_id AS workspace_id, touched.provider_network_id AS network_id
        FROM touched
        UNION
        SELECT touched.consumer_workspace_id, touched.consumer_network_id FROM touched
    ), chosen AS (
        SELECT side.workspace_id, side.network_id FROM side
        ORDER BY side.workspace_id, side.network_id
        LIMIT p_limit + 1
    )
    SELECT pg_catalog.array_agg(chosen.workspace_id ORDER BY chosen.workspace_id, chosen.network_id),
        pg_catalog.array_agg(chosen.network_id ORDER BY chosen.workspace_id, chosen.network_id)
    INTO v_workspaces, v_networks
    FROM chosen;
    v_deferred := COALESCE(pg_catalog.cardinality(v_networks), 0) > p_limit;
    IF v_deferred THEN
        v_workspaces := v_workspaces[1:p_limit];
        v_networks := v_networks[1:p_limit];
    END IF;
    IF v_networks IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('heads', '[]'::JSONB, 'deferred', FALSE);
    END IF;

    PERFORM pg_catalog.set_config('mesh.guardrail_share_fanout', 'on', TRUE);
    FOR v_scope IN
        SELECT revision.workspace_id, revision.network_id
        FROM mesh_ops.network_revision AS revision
        WHERE (revision.workspace_id, revision.network_id) IN (
            SELECT chosen.workspace_id, chosen.network_id
            FROM ROWS FROM (pg_catalog.unnest(v_workspaces), pg_catalog.unnest(v_networks)) AS chosen(workspace_id, network_id)
        )
        ORDER BY revision.workspace_id, revision.network_id
        FOR UPDATE
    LOOP
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            sharing_revision = revision.sharing_revision + 1,
            updated_at = GREATEST(revision.updated_at, pg_catalog.clock_timestamp())
        WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id;
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
    IF v_found <> pg_catalog.cardinality(v_networks) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('heads', v_heads, 'deferred', v_deferred);
END;
$function$;

-- Schema 119's reader of the acting Workspace's guardrails, for share
-- changes: it also takes the Workspace's guardrail state row FOR SHARE
-- NOWAIT, so it fails while that Workspace's guardrails change and makes a
-- guardrail change wait for a share change that read them.
CREATE FUNCTION mesh_ops.active_workspace_guardrails_v2()
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
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
    PERFORM 1 FROM mesh.workspace_guardrail_state AS state
    WHERE state.workspace_id = scoped_workspace_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Workspace guardrail state is missing';
    END IF;
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(mesh_ops.guardrail_document_internal_v1(guardrail)
            ORDER BY guardrail.created_at, guardrail.public_id)
        FROM mesh.guardrail AS guardrail
        WHERE guardrail.workspace_id = scoped_workspace_id AND guardrail.state = 'active'
    ), '[]'::JSONB);
END;
$function$;

-- Schema 163's guardrail change with the Workspace row taken FOR NO KEY
-- UPDATE instead of FOR UPDATE.
CREATE FUNCTION mesh_ops.change_workspace_guardrail_v2(
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
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
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

REVOKE ALL ON FUNCTION mesh_ops.guardrail_share_contracts_internal_v2(BIGINT, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.map_share_guardrails_v2(UUID[])
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.map_share_guardrails_v2(UUID[]) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_guardrail_share_contracts_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_guardrail_share_contracts_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.guardrail_change_share_contracts_v2(UUID, INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.guardrail_change_share_contracts_v2(UUID, INTEGER) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.bump_guardrail_share_networks_v2(UUID[], UUID[], UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.bump_guardrail_share_networks_v2(UUID[], UUID[], UUID) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.wake_guardrail_share_networks_v1(UUID, UUID[], INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.wake_guardrail_share_networks_v1(UUID, UUID[], INTEGER) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.active_workspace_guardrails_v2()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.active_workspace_guardrails_v2() TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_workspace_guardrail_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT,
    TEXT, TEXT, TEXT, TEXT, JSONB, BYTEA, UUID[], TEXT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_workspace_guardrail_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT,
    TEXT, TEXT, TEXT, TEXT, JSONB, BYTEA, UUID[], TEXT, UUID
) TO mesh_runtime;
