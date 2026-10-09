-- Schema 118 (R1-64 part D): exporting a Workspace's audit evidence.
--
-- export_workspace_audit_events_v1 returns one chunk of audit record v2
-- documents oldest first, so an export holds whole runs of each stream and
-- a verifier can check sequence and seal links offline. It takes no content
-- filters on purpose: a filtered export would have gaps no verifier could
-- tell apart from deletions. It requires audit.export on the Workspace
-- (every stream in it) or on the Network named (that Network's stream),
-- with the same Session binding and concealment as reading history.

CREATE FUNCTION mesh_ops.export_workspace_audit_events_v1(
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
    p_network_public_id UUID,
    p_since TIMESTAMPTZ,
    p_until TIMESTAMPTZ,
    p_cursor_occurred_at TIMESTAMPTZ,
    p_cursor_event_public_id UUID,
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
    scoped_network_id BIGINT;
    result JSONB;
BEGIN
    IF p_since IS NULL OR p_until IS NULL OR p_since >= p_until
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 500
        OR ((p_cursor_occurred_at IS NULL) <> (p_cursor_event_public_id IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit export query is invalid';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN NULL;
    END IF;
    IF p_network_public_id IS NOT NULL THEN
        SELECT network.id INTO scoped_network_id
        FROM mesh.network AS network
        WHERE network.workspace_id = scoped_workspace_id
          AND network.public_id = p_network_public_id;
        IF scoped_network_id IS NULL THEN
            RETURN NULL;
        END IF;
    END IF;

    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'audit.export', evaluated_at
    );
    IF NOT FOUND THEN
        IF scoped_network_id IS NULL THEN
            RETURN NULL;
        END IF;
        PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'audit.export', evaluated_at
        );
        IF NOT FOUND THEN
            RETURN NULL;
        END IF;
    END IF;

    WITH page AS (
        SELECT event.occurred_at, event.actor_principal_public_id, event.action, event.permission,
            event.result, event.target_kind, event.target_public_id, event.correlation_public_id,
            event.before_semantic_hash, event.after_semantic_hash, event.payload_version, event.payload,
            event.hash_version, event.previous_seal_hash, event.seal_hash, event.payload_canonical,
            identity.public_id AS event_public_id, identity.stream_sequence,
            identity.change_public_id, stream.public_id AS stream_public_id,
            stream.workspace_public_id, stream.network_public_id
        FROM mesh_audit.audit_event AS event
        JOIN mesh_audit.audit_event_identity AS identity
          ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
        JOIN mesh_audit.audit_stream AS stream ON stream.id = identity.stream_id
        WHERE event.workspace_id = scoped_workspace_id
          AND (scoped_network_id IS NULL OR event.network_id = scoped_network_id)
          AND event.occurred_at >= p_since AND event.occurred_at < p_until
          AND (p_cursor_occurred_at IS NULL
              OR (event.occurred_at, identity.public_id) > (p_cursor_occurred_at, p_cursor_event_public_id))
        ORDER BY event.occurred_at, identity.public_id
        LIMIT p_limit + 1
    ), numbered AS (
        SELECT page.*, pg_catalog.row_number() OVER (
            ORDER BY page.occurred_at, page.event_public_id) AS position
        FROM page
    ), shown AS (
        SELECT * FROM numbered WHERE position <= p_limit
    )
    SELECT pg_catalog.jsonb_build_object(
        'records', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'record_version', 2,
                'event_id', shown.event_public_id,
                'event_time', pg_catalog.to_char(shown.occurred_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                'stream_id', shown.stream_public_id,
                'sequence', shown.stream_sequence,
                'workspace_id', COALESCE(shown.workspace_public_id::TEXT, ''),
                'network_id', COALESCE(shown.network_public_id::TEXT, ''),
                'change_id', shown.change_public_id,
                'actor_kind', CASE WHEN shown.actor_principal_public_id IS NULL
                    THEN 'system' ELSE 'principal' END,
                'actor_principal_id', COALESCE(shown.actor_principal_public_id::TEXT, ''),
                'action', shown.action,
                'permission', shown.permission,
                'result', shown.result,
                'target_kind', shown.target_kind,
                'target_id', shown.target_public_id,
                'correlation_id', COALESCE(shown.correlation_public_id::TEXT, ''),
                'before_semantic_hash', COALESCE(pg_catalog.encode(shown.before_semantic_hash, 'hex'), ''),
                'after_semantic_hash', COALESCE(pg_catalog.encode(shown.after_semantic_hash, 'hex'), ''),
                'payload_version', shown.payload_version,
                'payload', shown.payload,
                'payload_canonical', COALESCE(shown.payload_canonical, shown.payload::TEXT),
                'integrity', CASE WHEN shown.hash_version = 2 THEN pg_catalog.jsonb_build_object(
                        'status', 'sealed', 'hash_version', 2,
                        'previous_seal', pg_catalog.encode(shown.previous_seal_hash, 'hex'),
                        'seal', pg_catalog.encode(shown.seal_hash, 'hex'))
                    ELSE pg_catalog.jsonb_build_object('status', 'legacy_unsealed') END
            ) ORDER BY shown.position)
            FROM shown
        ), '[]'::JSONB),
        'has_more', (SELECT pg_catalog.count(*) > p_limit FROM numbered),
        'actors', COALESCE((
            SELECT pg_catalog.jsonb_object_agg(principal.public_id::TEXT, account.display_name)
            FROM mesh.principal AS principal
            JOIN mesh.account AS account
              ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
            WHERE principal.public_id IN (
                    SELECT DISTINCT shown.actor_principal_public_id FROM shown
                    WHERE shown.actor_principal_public_id IS NOT NULL)
              AND EXISTS (
                  SELECT 1 FROM mesh.workspace_membership AS membership
                  WHERE membership.workspace_id = scoped_workspace_id
                    AND membership.deployment_id = principal.deployment_id
                    AND membership.principal_id = principal.id)
        ), '{}'::JSONB)
    ) INTO result;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.export_workspace_audit_events_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.export_workspace_audit_events_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
