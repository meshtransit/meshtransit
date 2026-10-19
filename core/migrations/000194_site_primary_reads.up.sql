-- Schema 194: a Site's read carries the primary Core elected (schema 193),
-- and its primary changes can be read back from the audit history, both
-- with route.read on the Network.

-- One active Site (route.read), as read_site_v1, with its elected primary:
-- NULL before the first election; device_id NULL when no router can serve.
CREATE FUNCTION mesh_ops.read_site_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_site_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_reading JSONB;
    v_primary JSONB;
BEGIN
    v_reading := mesh_ops.read_site_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_site_public_id);
    SELECT pg_catalog.jsonb_build_object(
               'device_id', device.public_id,
               'generation', site_primary.generation,
               'reason', site_primary.reason,
               'elected_at', site_primary.elected_at)
    INTO v_primary
    FROM mesh.site_primary AS site_primary
    JOIN mesh.network_site AS network_site ON network_site.id = site_primary.site_id
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = site_primary.workspace_id AND device.network_id = site_primary.network_id
     AND device.id = site_primary.device_id
    WHERE site_primary.public_id = p_site_public_id
      AND network_site.workspace_id = mesh_ops.current_workspace_id()
      AND network_site.network_id = mesh_ops.current_network_id();
    RETURN v_reading || pg_catalog.jsonb_build_object('primary', v_primary);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_site_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_site_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- One page of a Site's primary changes (route.read), newest first, after the
-- change p_after_event_public_id when given: each the audit event Core
-- recorded with the Site's primary election. A bounded read on the audit
-- index of (Workspace, target, time).
CREATE FUNCTION mesh_ops.list_site_primary_changes_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_site_public_id UUID,
    p_after_event_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_after_at TIMESTAMPTZ;
    v_page JSONB;
    v_count INTEGER;
BEGIN
    IF p_site_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site primary history page is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_site_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    IF NOT EXISTS (SELECT 1 FROM mesh.network_site AS network_site
                   WHERE network_site.workspace_id = v_scope.workspace_id
                     AND network_site.network_id = v_scope.network_id
                     AND network_site.public_id = p_site_public_id AND network_site.state = 'active') THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Site is unavailable';
    END IF;
    IF p_after_event_public_id IS NOT NULL THEN
        SELECT event.occurred_at INTO v_after_at
        FROM mesh_audit.audit_event_identity AS identity
        JOIN mesh_audit.audit_event AS event
          ON event.event_identity_id = identity.id AND event.occurred_at = identity.occurred_at
        WHERE identity.public_id = p_after_event_public_id
          AND event.workspace_id = v_scope.workspace_id AND event.network_id = v_scope.network_id
          AND event.target_public_id = p_site_public_id AND event.target_kind = 'site_primary'
          AND event.action = 'site.primary_changed';
        IF v_after_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site primary history cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'event_id', page.event_public_id,
               'occurred_at', page.occurred_at,
               'device_id', page.payload -> 'device_public_id',
               'previous_device_id', page.payload -> 'previous_device_public_id',
               'reason', page.payload -> 'reason',
               'generation', page.payload -> 'generation'
           ) ORDER BY page.occurred_at DESC, page.event_public_id DESC),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT event.occurred_at, event.payload, identity.public_id AS event_public_id
        FROM mesh_audit.audit_event AS event
        JOIN mesh_audit.audit_event_identity AS identity
          ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
        WHERE event.workspace_id = v_scope.workspace_id AND event.target_public_id = p_site_public_id
          AND event.network_id = v_scope.network_id
          AND event.target_kind = 'site_primary' AND event.action = 'site.primary_changed'
          AND (v_after_at IS NULL
               OR (event.occurred_at, identity.public_id) < (v_after_at, p_after_event_public_id))
        ORDER BY event.occurred_at DESC, identity.public_id DESC
        LIMIT p_limit + 1
    ) AS page;
    RETURN pg_catalog.jsonb_build_object(
        'changes', CASE WHEN v_count > p_limit THEN v_page - p_limit ELSE COALESCE(v_page, '[]'::JSONB) END,
        'has_more', v_count > p_limit
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_site_primary_changes_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_site_primary_changes_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;
