-- Console reads of the Network summaries (docs/console-load-design.md §6,
-- TD-CON-43/48, step C4).
--
-- Which Networks a Session may read, and with which permissions, is
-- console_summary_authority_internal_v1: read_console_management_scopes_v1
-- (000095), the projection the Console navigates by, copied with only these
-- changes (catalog test TestMigration278AuthorityIsTheProjection): it also
-- resolves route.read (never enough on its own to read a Network), keeps
-- the internal keys and display codes, filters to one Network on request,
-- and answers up to 5 001 Networks in one pass instead of pages of 100.
-- Callers that need every Network read it once, so a Workspace of N
-- Networks costs N permission rows, not N²/200 (Opus review of C4, H3). Each figure is
-- returned only where the Session holds its permission (§6.1):
--   - ipv4 range, addresses, Kubernetes clusters: network.read
--   - active Devices: device.read
--   - rules and the active policy: policy.read
--   - policy changes waiting for approval: policy.approve
--   - shares, offers and peers: share.read
--   - Sites (single Network read only): route.read
-- A Network without a summary yet answers with no figures.
--
-- The functions are SECURITY DEFINER, owned by mesh_migrator, granted to
-- mesh_runtime only. They read summary rows by the Networks the projection
-- returned and never widen the Workspace they were asked about.

-- Who may read which Networks of the Workspace (see the header).
CREATE FUNCTION mesh_ops.console_summary_authority_internal_v1(
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
    p_evaluated_at TIMESTAMPTZ,
    p_after_network_public_id UUID,
    p_network_public_id UUID,
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
    result JSONB;
    previous_requested_workspace_public_id TEXT;
    previous_projection_workspace_public_id TEXT;
BEGIN
    previous_requested_workspace_public_id := pg_catalog.current_setting(
        'mesh.requested_workspace_public_id',
        TRUE
    );
    previous_projection_workspace_public_id := pg_catalog.current_setting(
        'mesh.console_management_scope_workspace_public_id',
        TRUE
    );
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR (
            p_after_network_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_after_network_public_id), 6) >> 4 <> 7
        )
        OR (
            p_network_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        )
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_evaluated_at IS NULL
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 5001 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Console management scope input';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.console_management_scope_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );

    WITH authority AS MATERIALIZED (
        SELECT
            workspace.id AS workspace_id,
            workspace.public_id AS workspace_public_id,
            workspace.display_name AS workspace_display_name,
            session.deployment_id,
            session.principal_id,
            membership.id AS membership_id,
            workspace.owner_principal_id = session.principal_id AS is_workspace_owner
        FROM mesh.account_session AS session
        JOIN mesh.deployment AS deployment
          ON deployment.id = session.deployment_id
        JOIN mesh.principal AS principal
          ON principal.deployment_id = session.deployment_id
         AND principal.id = session.principal_id
        JOIN mesh.account AS account
          ON account.deployment_id = session.deployment_id
         AND account.principal_id = session.principal_id
        JOIN mesh.identity_subject AS subject
          ON subject.deployment_id = session.deployment_id
         AND subject.identity_provider_id = session.identity_provider_id
         AND subject.principal_id = session.principal_id
         AND subject.id = session.identity_subject_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = session.deployment_id
         AND provider.id = session.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = session.deployment_id
         AND client.identity_provider_id = session.identity_provider_id
         AND client.id = session.identity_provider_client_id
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = session.deployment_id
         AND workspace.id = session.login_workspace_id
         AND workspace.public_id = p_workspace_public_id
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = session.deployment_id
         AND membership.workspace_id = workspace.id
         AND membership.principal_id = session.principal_id
        WHERE session.public_id = p_session_public_id
          AND deployment.installation_public_id = p_deployment_public_id
          AND principal.public_id = p_principal_public_id
          AND subject.public_id = p_identity_subject_public_id
          AND session.version = p_session_version
          AND session.principal_authority_generation = p_principal_authority_generation
          AND session.account_session_generation = p_account_session_generation
          AND session.provider_generation = p_provider_generation
          AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
          AND session.state = 'active'
          AND session.authentication_time <= p_evaluated_at
          AND session.idle_expires_at > p_evaluated_at
          AND session.absolute_expires_at > p_evaluated_at
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.recovery_epoch = p_deployment_recovery_epoch
          AND principal.state = 'active'
          AND principal.authority_generation = p_principal_authority_generation
          AND account.recovery_state = 'verified'
          AND account.session_generation = p_account_session_generation
          AND subject.state = 'active'
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.current_generation = p_provider_generation
          AND client.state = 'active'
          AND workspace.state = 'active'
          AND membership.state = 'active'
          AND membership.valid_from <= p_evaluated_at
          AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
        LIMIT 1
    ), scope_permissions AS (
        SELECT
            network.public_id,
            network.display_name,
            network.workspace_id AS workspace_key,
            network.id AS network_key,
            CASE WHEN authority.is_workspace_owner THEN ARRAY(
                SELECT permission.permission_key FROM mesh.permission AS permission
                WHERE permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'route.read', 'share.accept', 'share.offer', 'share.read', 'share.revoke'
                ]::TEXT[])
                  AND 'network' = ANY(permission.allowed_scope_kinds)
                ORDER BY permission.permission_key
            ) ELSE ARRAY(
                SELECT granted.permission_key FROM (
                SELECT permission.permission_key
                FROM mesh.workspace_role_assignment AS assignment
                JOIN mesh.builtin_role_permission AS role_permission
                  ON role_permission.role_key = assignment.role_key
                JOIN mesh.permission AS permission
                  ON permission.id = role_permission.permission_id
                 AND permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'route.read', 'share.accept', 'share.offer', 'share.read', 'share.revoke'
                 ]::TEXT[])
                 AND 'network' = ANY(permission.allowed_scope_kinds)
                WHERE assignment.deployment_id = authority.deployment_id
                  AND assignment.workspace_id = authority.workspace_id
                  AND (assignment.network_id IS NULL OR assignment.network_id = network.id)
                  AND assignment.principal_id = authority.principal_id
                  AND assignment.workspace_membership_id = authority.membership_id
                  AND assignment.state = 'active'
                  AND assignment.valid_from <= p_evaluated_at
                  AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
                UNION
                SELECT permission.permission_key
                FROM mesh.role_binding AS binding
                JOIN mesh.role_definition AS role_definition
                  ON role_definition.deployment_id = binding.deployment_id
                 AND role_definition.workspace_id = binding.workspace_id
                 AND role_definition.id = binding.role_definition_id
                JOIN mesh.role_permission AS role_permission
                  ON role_permission.deployment_id = role_definition.deployment_id
                 AND role_permission.workspace_id = role_definition.workspace_id
                 AND role_permission.role_definition_id = role_definition.id
                JOIN mesh.permission AS permission
                  ON permission.id = role_permission.permission_id
                 AND permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'route.read', 'share.accept', 'share.offer', 'share.read', 'share.revoke'
                 ]::TEXT[])
                 AND 'network' = ANY(permission.allowed_scope_kinds)
                WHERE binding.deployment_id = authority.deployment_id
                  AND binding.workspace_id = authority.workspace_id
                  AND binding.network_id = network.id
                  AND binding.principal_id = authority.principal_id
                  AND binding.workspace_membership_id = authority.membership_id
                  AND binding.state = 'active'
                  AND binding.valid_from <= p_evaluated_at
                  AND (binding.expires_at IS NULL OR binding.expires_at > p_evaluated_at)
                  AND role_definition.state = 'active'
                  AND role_permission.state = 'active'
                ) AS granted
                ORDER BY granted.permission_key
            ) END AS permissions
        FROM authority
        JOIN mesh.network AS network
          ON network.workspace_id = authority.workspace_id
        WHERE network.state = 'active'
          AND (p_after_network_public_id IS NULL OR network.public_id > p_after_network_public_id)
          AND (p_network_public_id IS NULL OR network.public_id = p_network_public_id)
    ), scopes AS (
        SELECT scope_permissions.*
        FROM scope_permissions
        -- Readable exactly as the projection: route.read alone is not.
        WHERE pg_catalog.cardinality(pg_catalog.array_remove(scope_permissions.permissions, 'route.read')) > 0
        ORDER BY scope_permissions.public_id
        LIMIT p_limit
    )
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', authority.workspace_public_id,
        'workspace_display_name', authority.workspace_display_name,
        'workspace_display_code', (SELECT identity.display_code FROM mesh_ops.tenant_display_identity AS identity
            WHERE identity.workspace_public_id = authority.workspace_public_id),
        'scopes', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'network_id', scopes.public_id,
                        'network_display_name', scopes.display_name,
                        'network_display_code', (SELECT identity.display_code FROM mesh_ops.tenant_display_identity AS identity
                            WHERE identity.network_public_id = scopes.public_id),
                        'workspace_key', scopes.workspace_key,
                        'network_key', scopes.network_key,
                        'route_read', 'route.read' = ANY(scopes.permissions),
                        'permissions', pg_catalog.to_jsonb(pg_catalog.array_remove(scopes.permissions, 'route.read'))
                    )
                    ORDER BY scopes.public_id
                )
                FROM scopes
            ),
            '[]'::JSONB
        )
    )
    INTO result
    FROM authority;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        COALESCE(previous_requested_workspace_public_id, ''),
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.console_management_scope_workspace_public_id',
        COALESCE(previous_projection_workspace_public_id, ''),
        TRUE
    );
    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.requested_workspace_public_id',
            COALESCE(previous_requested_workspace_public_id, ''),
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.console_management_scope_workspace_public_id',
            COALESCE(previous_projection_workspace_public_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;


-- Like the projection (000107): keep the written join order and one
-- generic plan per backend, instead of planning the ten-table Session join
-- on every call.
ALTER FUNCTION mesh_ops.console_summary_authority_internal_v1(uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint,
    bigint, uuid, timestamp with time zone, uuid, uuid, integer)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;

-- One Network's figures as a JSON object, each only with its permission.
-- p_live, when given, holds figures counted just now; they replace the
-- summary's (the one-Network read, design §5.6).
CREATE FUNCTION mesh_ops.console_network_summary_item_internal_v1(
    p_scope JSONB, p_summary mesh_ops.network_summary, p_live JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    v_permissions JSONB := p_scope -> 'permissions';
    v_item JSONB;
    v_figures JSONB := '{}'::JSONB;
BEGIN
    v_item := pg_catalog.jsonb_build_object(
        'network_id', p_scope ->> 'network_id',
        'display_name', p_scope ->> 'network_display_name',
        'display_code', p_scope ->> 'network_display_code',
        'permissions', v_permissions);
    IF p_summary.network_id IS NULL AND p_live IS NULL THEN
        RETURN v_item;
    END IF;
    v_figures := pg_catalog.jsonb_build_object(
        'ipv4_prefix', p_summary.ipv4_prefix::TEXT, 'addresses_capacity', p_summary.addresses_capacity,
        'addresses_in_use', p_summary.addresses_in_use, 'addresses_held', p_summary.addresses_held,
        'kubernetes_clusters', p_summary.kubernetes_clusters, 'active_devices', p_summary.active_devices,
        'rule_count', p_summary.rule_count, 'policy_revision', p_summary.policy_revision,
        'policy_published_at', p_summary.policy_published_at, 'pending_approvals', p_summary.pending_approvals,
        'shares_out_active', p_summary.shares_out_active, 'shares_in_active', p_summary.shares_in_active,
        'offers_waiting', p_summary.offers_waiting, 'sites', p_summary.sites)
        || COALESCE(p_live, '{}'::JSONB);
    -- Without a summary yet, only the figures counted now: the projection
    -- figures (addresses, Devices) are JSON null and stripped below.
    v_item := v_item || pg_catalog.jsonb_build_object('computed_at', p_summary.computed_at);
    IF v_permissions ? 'network.read' THEN
        v_item := v_item || pg_catalog.jsonb_build_object(
            'ipv4_prefix', v_figures -> 'ipv4_prefix', 'addresses_capacity', v_figures -> 'addresses_capacity',
            'addresses_in_use', v_figures -> 'addresses_in_use', 'addresses_held', v_figures -> 'addresses_held',
            'kubernetes_clusters', v_figures -> 'kubernetes_clusters');
    END IF;
    IF v_permissions ? 'device.read' THEN
        v_item := v_item || pg_catalog.jsonb_build_object('active_devices', v_figures -> 'active_devices');
    END IF;
    IF v_permissions ? 'policy.read' THEN
        v_item := v_item || pg_catalog.jsonb_build_object('rule_count', v_figures -> 'rule_count',
            'policy_revision', v_figures -> 'policy_revision', 'policy_published_at', v_figures -> 'policy_published_at');
    END IF;
    IF v_permissions ? 'policy.approve' THEN
        v_item := v_item || pg_catalog.jsonb_build_object('pending_approvals', v_figures -> 'pending_approvals');
    END IF;
    IF v_permissions ? 'share.read' THEN
        v_item := v_item || pg_catalog.jsonb_build_object('shares_out_active', v_figures -> 'shares_out_active',
            'shares_in_active', v_figures -> 'shares_in_active', 'offers_waiting', v_figures -> 'offers_waiting');
    END IF;
    -- Sites only on the one-Network read, which resolves route.read.
    IF p_live IS NOT NULL AND (p_scope ->> 'route_read')::BOOLEAN THEN
        v_item := v_item || pg_catalog.jsonb_build_object('sites', v_figures -> 'sites');
    END IF;
    -- JSON nulls (a Network without an IPv4 range) are left out.
    RETURN pg_catalog.jsonb_strip_nulls(v_item);
END;
$function$;

-- The small figures of one Network counted now, as compute_network_summary_v1
-- (schema 277) counts them: they change with the person's own writes and
-- with time, so the one-Network read does not wait for the worker.
CREATE FUNCTION mesh_ops.console_network_live_figures_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_now TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_release BIGINT;
    v_revision BIGINT;
    v_published TIMESTAMPTZ;
    v_rules BIGINT := 0;
    v_result JSONB;
BEGIN
    SELECT release.id, release.policy_revision, release.activated_at INTO v_release, v_revision, v_published
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = p_workspace_id AND release.network_id = p_network_id AND release.state = 'active';
    IF v_release IS NOT NULL THEN
        SELECT
            (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_rule AS rule
             WHERE rule.workspace_id = p_workspace_id AND rule.network_id = p_network_id
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_imported_resource_destination AS rule
             WHERE rule.workspace_id = p_workspace_id AND rule.network_id = p_network_id
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_group_rule AS rule
             WHERE rule.workspace_id = p_workspace_id AND rule.network_id = p_network_id
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_route_rule AS rule
             WHERE rule.workspace_id = p_workspace_id AND rule.network_id = p_network_id
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_exit_rule AS rule
             WHERE rule.workspace_id = p_workspace_id AND rule.network_id = p_network_id
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_revision)
        INTO v_rules;
    END IF;
    WITH share AS (
        SELECT locator.direction,
            (offer.state = 'accepted' AND contract.state IN ('activating', 'active')
                AND contract.expires_at > p_now) AS live,
            (offer.state = 'offered' AND offer.expires_at > p_now) AS waiting
        FROM mesh.share_offer_locator AS locator
        JOIN mesh.share_offer AS offer ON offer.id = locator.offer_id
        LEFT JOIN mesh.trust_contract AS contract ON contract.share_offer_id = offer.id
        WHERE locator.local_workspace_id = p_workspace_id AND locator.local_network_id = p_network_id
          AND locator.state IN ('offered', 'accepted') AND offer.state IN ('offered', 'accepted')
    )
    SELECT pg_catalog.jsonb_build_object(
        'rule_count', v_rules,
        'shares_out_active', (SELECT pg_catalog.count(*) FROM share WHERE share.direction = 'outgoing' AND share.live),
        'shares_in_active', (SELECT pg_catalog.count(*) FROM share WHERE share.direction = 'incoming' AND share.live),
        'offers_waiting', (SELECT pg_catalog.count(*) FROM share WHERE share.direction = 'incoming' AND share.waiting),
        'pending_approvals', (SELECT pg_catalog.count(*) FROM mesh.policy_approval_request AS request
            WHERE request.workspace_id = p_workspace_id AND request.network_id = p_network_id
              AND request.state = 'pending' AND request.expires_at > p_now),
        'sites', (SELECT pg_catalog.count(*) FROM mesh.network_site AS site
            WHERE site.workspace_id = p_workspace_id AND site.network_id = p_network_id AND site.state = 'active'),
        'kubernetes_clusters', (SELECT pg_catalog.count(*) FROM mesh.kubernetes_cluster AS cluster
            WHERE cluster.workspace_id = p_workspace_id AND cluster.network_id = p_network_id
              AND cluster.state = 'active'))
        -- No active release: no published policy, whatever the summary said.
        || pg_catalog.jsonb_build_object('policy_revision', v_revision, 'policy_published_at', v_published)
    INTO v_result;
    RETURN v_result;
END;
$function$;

-- A page of the Networks the Session may read, with their summaries, in
-- Network ID order. p_query keeps Networks whose name contains it (case
-- folded) or whose display code contains its digits. The Networks are read
-- once (at most 5 000); searched_all is false past that.
CREATE FUNCTION mesh_ops.read_console_network_summaries_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_after_network_public_id UUID, p_limit INTEGER,
    p_query TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_authority JSONB;
    v_scope JSONB;
    v_seen INTEGER := 0;
    v_picked JSONB := '[]'::JSONB;
    v_name TEXT := pg_catalog.lower(p_query);
    v_digits TEXT := pg_catalog.regexp_replace(COALESCE(p_query, ''), '[\s-]', '', 'g');
    v_items JSONB := '[]'::JSONB;
    v_summary mesh_ops.network_summary;
    v_more BOOLEAN := FALSE;
    v_truncated BOOLEAN;
BEGIN
    IF p_evaluated_at IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50
       OR (p_query IS NOT NULL AND pg_catalog.char_length(p_query) NOT BETWEEN 1 AND 128) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network summary page';
    END IF;
    v_authority := mesh_ops.console_summary_authority_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_evaluated_at,
        -- Without a search a page reads only what follows the cursor, one
        -- more than the page; a search reads every Network once (≤ 5 000).
        CASE WHEN p_query IS NULL THEN p_after_network_public_id END, NULL,
        CASE WHEN p_query IS NULL THEN p_limit + 1 ELSE 5001 END);
    IF v_authority IS NULL THEN
        RETURN NULL;
    END IF;
    v_truncated := p_query IS NOT NULL AND pg_catalog.jsonb_array_length(v_authority -> 'scopes') > 5000;
    FOR v_scope IN SELECT value FROM pg_catalog.jsonb_array_elements(v_authority -> 'scopes') LOOP
        v_seen := v_seen + 1;
        EXIT WHEN v_seen > 5000;
        CONTINUE WHEN p_after_network_public_id IS NOT NULL
            AND (v_scope ->> 'network_id')::UUID <= p_after_network_public_id;
        IF p_query IS NULL
           OR pg_catalog.strpos(pg_catalog.lower(v_scope ->> 'network_display_name'), v_name) > 0
           OR (v_digits ~ '^[0-9]+$' AND pg_catalog.strpos(v_scope ->> 'network_display_code', v_digits) > 0) THEN
            IF pg_catalog.jsonb_array_length(v_picked) = p_limit THEN
                v_more := TRUE;
                EXIT;
            END IF;
            v_picked := v_picked || pg_catalog.jsonb_build_array(v_scope);
        END IF;
    END LOOP;
    FOR v_scope IN SELECT value FROM pg_catalog.jsonb_array_elements(v_picked) LOOP
        SELECT * INTO v_summary FROM mesh_ops.network_summary AS summary
        WHERE summary.workspace_id = (v_scope ->> 'workspace_key')::BIGINT
          AND summary.network_id = (v_scope ->> 'network_key')::BIGINT;
        IF NOT FOUND THEN
            v_summary := NULL;
        END IF;
        v_items := v_items || pg_catalog.jsonb_build_array(
            mesh_ops.console_network_summary_item_internal_v1(v_scope, v_summary, NULL));
    END LOOP;
    RETURN pg_catalog.jsonb_build_object(
        'items', v_items,
        'next_after', CASE WHEN v_more THEN v_picked -> -1 ->> 'network_id' END,
        'searched_all', NOT v_truncated OR v_more);
END;
$function$;

-- The Workspace at a glance, over every Network the Session may read (at
-- most 5 000): how many, addresses taken, live Trust Contracts, those with
-- another Workspace, offers waiting, and up to 200 links between sides.
-- A *_partial flag says a figure is a floor: a Network without the
-- permission for it, without a summary yet, or past the 5 000.
CREATE FUNCTION mesh_ops.read_console_workspace_overview_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_authority JSONB;
    v_scopes JSONB;
    v_truncated BOOLEAN;
    v_result JSONB;
    v_links JSONB;
BEGIN
    IF p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace overview';
    END IF;
    v_authority := mesh_ops.console_summary_authority_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_evaluated_at, NULL, NULL, 5001);
    IF v_authority IS NULL THEN
        RETURN NULL;
    END IF;
    v_truncated := pg_catalog.jsonb_array_length(v_authority -> 'scopes') > 5000;
    SELECT COALESCE(pg_catalog.jsonb_agg(scope.value ORDER BY scope.ordinality), '[]'::JSONB) INTO v_scopes
    FROM pg_catalog.jsonb_array_elements(v_authority -> 'scopes') WITH ORDINALITY AS scope
    WHERE scope.ordinality <= 5000;

    WITH readable AS (
        SELECT (scope.value ->> 'network_id')::UUID AS network_public_id,
            (scope.value ->> 'workspace_key')::BIGINT AS workspace_key,
            (scope.value ->> 'network_key')::BIGINT AS network_key,
            scope.value -> 'permissions' ? 'network.read' AS network_read,
            scope.value -> 'permissions' ? 'share.read' AS share_read
        FROM pg_catalog.jsonb_array_elements(v_scopes) AS scope
    ), counted AS (
        SELECT readable.*, summary.network_id IS NOT NULL AS summarized,
            COALESCE(summary.addresses_in_use + summary.addresses_held, 0) AS taken,
            COALESCE(summary.shares_out_active, 0) AS out_active,
            COALESCE(summary.offers_waiting, 0) AS waiting
        FROM readable
        LEFT JOIN mesh_ops.network_summary AS summary
          ON summary.workspace_id = readable.workspace_key AND summary.network_id = readable.network_key
    ), peer AS (
        -- A hash join on the (workspace, Network) key, not a rescan per row.
        SELECT counted.workspace_key, peer.direction, peer.peer_workspace_id, peer.peer_network_id, peer.active,
            COALESCE(provider.share_read, FALSE) AS peer_share_read
        FROM counted
        JOIN mesh_ops.network_summary_peer AS peer
          ON peer.workspace_id = counted.workspace_key AND peer.network_id = counted.network_key
        LEFT JOIN readable AS provider
          ON provider.workspace_key = peer.peer_workspace_id AND provider.network_key = peer.peer_network_id
        WHERE counted.share_read
    )
    SELECT pg_catalog.jsonb_build_object(
        'networks', (SELECT pg_catalog.count(*) FROM counted),
        'addresses_taken', (SELECT COALESCE(pg_catalog.sum(counted.taken) FILTER (WHERE counted.network_read), 0) FROM counted),
        -- Each live contract once: a contract between two of this
        -- Workspace's Networks at its provider, or at its consumer when the
        -- provider's shares cannot be read; one with another Workspace at
        -- this side.
        'active_contracts', (SELECT COALESCE(pg_catalog.sum(counted.out_active) FILTER (WHERE counted.share_read), 0) FROM counted)
            + (SELECT COALESCE(pg_catalog.sum(peer.active), 0) FROM peer
               WHERE peer.direction = 'incoming'
                 AND (peer.peer_workspace_id <> peer.workspace_key OR NOT peer.peer_share_read)),
        'cross_workspace_contracts', (SELECT COALESCE(pg_catalog.sum(peer.active), 0) FROM peer
            WHERE peer.peer_workspace_id <> peer.workspace_key),
        'offers_waiting', (SELECT COALESCE(pg_catalog.sum(counted.waiting) FILTER (WHERE counted.share_read), 0) FROM counted),
        'addresses_partial', v_truncated
            OR EXISTS (SELECT 1 FROM counted WHERE NOT counted.network_read OR NOT counted.summarized),
        'shares_partial', v_truncated
            OR EXISTS (SELECT 1 FROM counted WHERE NOT counted.share_read OR NOT counted.summarized),
        'oldest_computed_at', (SELECT pg_catalog.min(summary.computed_at) FROM counted
            JOIN mesh_ops.network_summary AS summary
              ON summary.workspace_id = counted.workspace_key AND summary.network_id = counted.network_key)
    )
    INTO v_result;

    -- Links, at most 200: a share between two readable Networks of this
    -- Workspace once, from its provider; a share with another Workspace,
    -- that Workspace by its display code, never its Networks. A share with
    -- one of this Workspace's Networks the Session may not read is left
    -- out, and links_partial says so.
    WITH readable AS (
        SELECT (scope.value ->> 'network_id')::UUID AS network_public_id,
            (scope.value ->> 'workspace_key')::BIGINT AS workspace_key,
            (scope.value ->> 'network_key')::BIGINT AS network_key,
            scope.value -> 'permissions' ? 'share.read' AS share_read
        FROM pg_catalog.jsonb_array_elements(v_scopes) AS scope
    ), peer AS (
        SELECT readable.network_public_id, readable.workspace_key, readable.network_key,
            peer.direction, peer.peer_workspace_id, peer.peer_network_id, peer.active, peer.waiting
        FROM readable
        JOIN mesh_ops.network_summary_peer AS peer
          ON peer.workspace_id = readable.workspace_key AND peer.network_id = readable.network_key
        WHERE readable.share_read
    ), local_link AS (
        -- Once per pair: from the provider's outgoing row, or from the
        -- consumer's incoming row when the provider's shares cannot be read.
        SELECT peer.network_public_id AS from_id, target.network_public_id AS to_id, peer.active, peer.waiting
        FROM peer
        JOIN readable AS target
          ON target.workspace_key = peer.peer_workspace_id AND target.network_key = peer.peer_network_id
        WHERE peer.direction = 'outgoing' AND peer.peer_workspace_id = peer.workspace_key
        UNION ALL
        SELECT source.network_public_id, peer.network_public_id, peer.active, peer.waiting
        FROM peer
        JOIN readable AS source
          ON source.workspace_key = peer.peer_workspace_id AND source.network_key = peer.peer_network_id
        WHERE peer.direction = 'incoming' AND peer.peer_workspace_id = peer.workspace_key AND NOT source.share_read
    ), hidden AS (
        SELECT 1 FROM peer
        WHERE peer.peer_workspace_id = peer.workspace_key
          AND NOT EXISTS (SELECT 1 FROM readable AS target
              WHERE target.workspace_key = peer.peer_workspace_id AND target.network_key = peer.peer_network_id)
        LIMIT 1
    ), foreign_named AS (
        SELECT peer.*, (
            -- The other Workspace's public ID from one of this Network's own
            -- live share locators, which carry both sides' public IDs.
            SELECT CASE WHEN locator.provider_workspace_id = peer.peer_workspace_id
                        THEN locator.provider_workspace_public_id ELSE locator.consumer_workspace_public_id END
            FROM mesh.share_offer_locator AS locator
            WHERE locator.local_workspace_id = peer.workspace_key AND locator.local_network_id = peer.network_key
              AND locator.state IN ('offered', 'accepted')
              AND (locator.provider_workspace_id = peer.peer_workspace_id
                   OR locator.consumer_workspace_id = peer.peer_workspace_id)
            LIMIT 1) AS peer_workspace_public_id
        FROM peer
        WHERE peer.peer_workspace_id <> peer.workspace_key
        ORDER BY peer.active DESC, peer.waiting DESC, peer.network_public_id, peer.peer_workspace_id
        LIMIT 201
    ), unnamed AS (
        SELECT 1 FROM foreign_named
        LEFT JOIN mesh_ops.tenant_display_identity AS identity
          ON identity.workspace_public_id = foreign_named.peer_workspace_public_id
        WHERE identity.display_code IS NULL
        LIMIT 1
    ), link AS (
        SELECT pg_catalog.jsonb_build_object('kind', 'network', 'id', local_link.from_id) AS from_side,
            pg_catalog.jsonb_build_object('kind', 'network', 'id', local_link.to_id) AS to_side,
            local_link.active, local_link.waiting
        FROM local_link
        UNION ALL
        SELECT CASE WHEN foreign_named.direction = 'outgoing'
                    THEN pg_catalog.jsonb_build_object('kind', 'network', 'id', foreign_named.network_public_id)
                    ELSE pg_catalog.jsonb_build_object('kind', 'workspace', 'display_code', identity.display_code) END,
               CASE WHEN foreign_named.direction = 'outgoing'
                    THEN pg_catalog.jsonb_build_object('kind', 'workspace', 'display_code', identity.display_code)
                    ELSE pg_catalog.jsonb_build_object('kind', 'network', 'id', foreign_named.network_public_id) END,
               foreign_named.active, foreign_named.waiting
        FROM foreign_named
        JOIN mesh_ops.tenant_display_identity AS identity
          ON identity.workspace_public_id = foreign_named.peer_workspace_public_id
    ), bounded AS (
        SELECT * FROM link ORDER BY link.active DESC, link.waiting DESC, link.from_side::TEXT, link.to_side::TEXT
        LIMIT 201
    )
    SELECT pg_catalog.jsonb_build_object(
        'links', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'from', first.from_side, 'to', first.to_side, 'active', first.active, 'waiting', first.waiting))
            FROM (SELECT * FROM bounded LIMIT 200) AS first), '[]'::JSONB),
        'links_partial', (SELECT pg_catalog.count(*) FROM bounded) > 200 OR EXISTS (SELECT 1 FROM hidden)
            OR EXISTS (SELECT 1 FROM unnamed) OR (SELECT pg_catalog.count(*) FROM foreign_named) > 200)
    INTO v_links;
    RETURN v_result || v_links || pg_catalog.jsonb_build_object(
        'workspace_display_code', v_authority -> 'workspace_display_code');
END;
$function$;

-- One Network's summary: the same projection as the list, for this Network
-- alone (so the same permissions), Sites with route.read, and the small
-- figures counted now.
CREATE FUNCTION mesh_ops.read_console_network_summary_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_authority JSONB;
    v_scope JSONB;
    v_summary mesh_ops.network_summary;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network summary read';
    END IF;
    v_authority := mesh_ops.console_summary_authority_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_evaluated_at,
        NULL, p_network_public_id, 1);
    v_scope := v_authority -> 'scopes' -> 0;
    -- An unknown Network, another Workspace's, and one the Session may not
    -- read answer the same.
    IF v_scope IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network summary is not authorized';
    END IF;
    SELECT * INTO v_summary FROM mesh_ops.network_summary AS summary
    WHERE summary.workspace_id = (v_scope ->> 'workspace_key')::BIGINT
      AND summary.network_id = (v_scope ->> 'network_key')::BIGINT;
    IF NOT FOUND THEN
        v_summary := NULL;
    END IF;
    RETURN mesh_ops.console_network_summary_item_internal_v1(v_scope, v_summary,
        mesh_ops.console_network_live_figures_internal_v1((v_scope ->> 'workspace_key')::BIGINT,
            (v_scope ->> 'network_key')::BIGINT, p_evaluated_at));
END;
$function$;

REVOKE ALL ON FUNCTION
    mesh_ops.console_summary_authority_internal_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
        UUID, TIMESTAMPTZ, UUID, UUID, INTEGER),
    mesh_ops.console_network_summary_item_internal_v1(JSONB, mesh_ops.network_summary, JSONB),
    mesh_ops.console_network_live_figures_internal_v1(BIGINT, BIGINT, TIMESTAMPTZ),
    mesh_ops.read_console_network_summaries_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
        UUID, TIMESTAMPTZ, UUID, INTEGER, TEXT),
    mesh_ops.read_console_workspace_overview_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
        UUID, TIMESTAMPTZ),
    mesh_ops.read_console_network_summary_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
        UUID, UUID, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION
    mesh_ops.read_console_network_summaries_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
        UUID, TIMESTAMPTZ, UUID, INTEGER, TEXT),
    mesh_ops.read_console_workspace_overview_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
        UUID, TIMESTAMPTZ),
    mesh_ops.read_console_network_summary_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
        UUID, UUID, TIMESTAMPTZ)
    TO mesh_runtime;
