-- Schema 279: deleting a Network, phase 1 (docs/network-delete-design.md
-- §4.1, N1a). The request is synchronous: the Network becomes `deleted`
-- at once, its enrollment keys are revoked and its revision advances, so
-- control closes every map stream and its Devices learn REVOKED. A
-- `mesh_ops.network_deletion` row records the request; the worker of
-- schema 280 revokes the Devices in batches and then frees the prefixes.
-- A Network with a live Trust Contract or a Kubernetes cluster (or a CA
-- not retired yet) is refused with the list of what to end first.

ALTER TABLE mesh.network
    ADD CONSTRAINT network_deleted_at_check CHECK ((state = 'deleted') = (deleted_at IS NOT NULL)) NOT VALID;
ALTER TABLE mesh.network VALIDATE CONSTRAINT network_deleted_at_check;

-- One row per deleted Network: who asked, why, and how far phase 2 is.
CREATE TABLE mesh_ops.network_deletion (
    network_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    deployment_id BIGINT NOT NULL,
    network_public_id UUID NOT NULL UNIQUE,
    requested_at TIMESTAMPTZ NOT NULL,
    requested_by_principal_id BIGINT NOT NULL,
    reason TEXT NOT NULL CHECK (
        pg_catalog.octet_length(reason) BETWEEN 1 AND 512 AND reason = pg_catalog.btrim(reason)),
    devices_total BIGINT NOT NULL CHECK (devices_total >= 0),
    devices_revoked BIGINT NOT NULL DEFAULT 0 CHECK (devices_revoked >= 0),
    claimed_until TIMESTAMPTZ,
    completed_at TIMESTAMPTZ CHECK (completed_at IS NULL OR completed_at >= requested_at),
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT network_deletion_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX network_deletion_pending_idx ON mesh_ops.network_deletion (requested_at, network_id)
    WHERE completed_at IS NULL;
ALTER TABLE mesh_ops.network_deletion ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_deletion FORCE ROW LEVEL SECURITY;
CREATE POLICY network_deletion_migrator_policy ON mesh_ops.network_deletion
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.network_deletion
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- How far a deletion is, as the API shows it.
CREATE FUNCTION mesh_ops.network_deletion_document_internal_v1(p_deletion mesh_ops.network_deletion)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'network_id', p_deletion.network_public_id,
        'state', CASE WHEN p_deletion.completed_at IS NULL THEN 'deleting' ELSE 'deleted' END,
        'requested_at', p_deletion.requested_at,
        'devices_total', p_deletion.devices_total,
        'devices_revoked', p_deletion.devices_revoked,
        'completed_at', p_deletion.completed_at
    ))
$function$;

-- What must end before a Network can go: live Trust Contracts on either
-- side, Kubernetes clusters, and deleted clusters whose CAs are not retired
-- yet (the CA worker must finish them). At most 50 named, with totals.
CREATE FUNCTION mesh_ops.network_deletion_blockers_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    WITH blocker AS (
        SELECT 'trust_contract'::TEXT AS kind, contract.public_id AS id, NULL::TEXT AS name
        FROM mesh.trust_contract AS contract
        WHERE contract.state IN ('activating', 'active')
          AND contract.provider_workspace_id = p_workspace_id AND contract.provider_network_id = p_network_id
        UNION
        SELECT 'trust_contract', contract.public_id, NULL
        FROM mesh.trust_contract AS contract
        WHERE contract.state IN ('activating', 'active')
          AND contract.consumer_workspace_id = p_workspace_id AND contract.consumer_network_id = p_network_id
        UNION ALL
        SELECT 'kubernetes_cluster', cluster.public_id, cluster.name
        FROM mesh.kubernetes_cluster AS cluster
        WHERE cluster.workspace_id = p_workspace_id AND cluster.network_id = p_network_id
          AND cluster.deleted_at IS NULL
        UNION ALL
        SELECT 'kubernetes_ca', cluster.public_id, cluster.name
        FROM mesh.kubernetes_cluster AS cluster
        WHERE cluster.workspace_id = p_workspace_id AND cluster.network_id = p_network_id
          AND cluster.deleted_at IS NOT NULL
          AND (EXISTS (SELECT 1 FROM mesh.kubernetes_cluster_ca AS ca
                       WHERE ca.workspace_id = cluster.workspace_id AND ca.network_id = cluster.network_id
                         AND ca.kubernetes_cluster_id = cluster.id AND ca.state <> 'retired')
               OR EXISTS (SELECT 1 FROM mesh_ops.kubernetes_cluster_ca_schedule AS schedule
                          WHERE schedule.workspace_id = cluster.workspace_id
                            AND schedule.network_id = cluster.network_id
                            AND schedule.kubernetes_cluster_id = cluster.id))
    ),
    named AS (
        SELECT blocker.* FROM blocker ORDER BY blocker.kind, blocker.id LIMIT 50
    )
    SELECT pg_catalog.jsonb_build_object(
        'total', (SELECT pg_catalog.count(*) FROM blocker),
        'trust_contracts', (SELECT pg_catalog.count(*) FROM blocker WHERE blocker.kind = 'trust_contract'),
        'kubernetes_clusters', (SELECT pg_catalog.count(*) FROM blocker WHERE blocker.kind = 'kubernetes_cluster'),
        'kubernetes_cas', (SELECT pg_catalog.count(*) FROM blocker WHERE blocker.kind = 'kubernetes_ca'),
        'items', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                     'kind', named.kind, 'id', named.id, 'name', named.name)) ORDER BY named.kind, named.id)
                 FROM named), '[]'::JSONB)
    )
$function$;

-- The Workspace and Network of this transaction (set_network_scope), in
-- any state, for a Session bound to the Workspace.
CREATE FUNCTION mesh_ops.network_deletion_scope_internal_v1(
    p_session_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT workspace.deployment_id, workspace.id, network.id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = mesh_ops.current_workspace_id() AND network.id = mesh_ops.current_network_id()
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND mesh_ops.session_bound_to_workspace_v1(p_session_public_id, workspace.id)
$function$;

-- Who may delete a Network (design Q3): the Workspace owner, or a
-- built-in role holding network.delete assigned Workspace-wide; one bound
-- to the Network is not enough. network.delete is a Network-scope
-- permission in the catalog, so the Session is checked with network.create
-- (Workspace scope, held by the owner and every Workspace-wide admin), then
-- the Workspace-wide network.delete assignment is looked up and named in
-- the evidence. Works for a Network already deleted, where the Network
-- resolver answers nothing.
CREATE FUNCTION mesh_ops.network_delete_grant_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (role_binding_public_id UUID, role_definition_public_id UUID, binding_authority_generation BIGINT,
    membership_authority_generation BIGINT, workspace_owner_authority_generation BIGINT)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_session RECORD;
BEGIN
    SELECT * INTO v_session FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'network.create', p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF v_session.workspace_owner_authority_generation > 0 THEN
        RETURN QUERY SELECT NULL::UUID, NULL::UUID, 0::BIGINT, v_session.membership_authority_generation,
            v_session.workspace_owner_authority_generation;
        RETURN;
    END IF;
    RETURN QUERY
    SELECT assignment.public_id, role.public_id, assignment.authority_generation,
        v_session.membership_authority_generation, 0::BIGINT
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal ON principal.public_id = p_principal_public_id
    JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.workspace_id = workspace.id AND assignment.principal_id = principal.id
     AND assignment.network_id IS NULL AND assignment.state = 'active'
     AND assignment.valid_from <= p_evaluated_at
     AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
    JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
    JOIN mesh.builtin_role_permission AS granted ON granted.role_key = role.role_key
    JOIN mesh.permission AS permission
      ON permission.id = granted.permission_id AND permission.permission_key = 'network.delete'
    WHERE workspace.public_id = p_workspace_public_id
    ORDER BY assignment.id
    LIMIT 1
    FOR SHARE OF assignment;
END;
$function$;

-- DELETE /api/v1/workspaces/{w}/networks/{n} (design §4.1 phase 1, §4.5).
-- Only the owner or a Workspace-wide network.delete grant may delete; a
-- grant bound to the Network is not enough (network_delete_grant_internal_v1).
-- Outcomes:
--   deleted  the Network is deleted now (phase 2 follows);
--   deleting a repeat while phase 2 runs: nothing changes;
--   blocked  what must end first; nothing changes.
-- P0002 when the deletion has completed (or the Network is unknown),
-- 40001 when the version moved, 42501 when not allowed.
CREATE FUNCTION mesh_ops.delete_network_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_expected_version BIGINT, p_reason TEXT,
    p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_scope RECORD;
    v_grant RECORD;
    v_network mesh.network%ROWTYPE;
    v_deletion mesh_ops.network_deletion%ROWTYPE;
    v_blockers JSONB;
    v_actor BIGINT;
    v_devices BIGINT;
    v_keys INTEGER := 0;
    v_advanced JSONB;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_change_public_id IS NULL OR p_evaluated_at IS NULL OR p_expected_version IS NULL
        OR p_expected_version <= 0
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_reason IS NULL OR pg_catalog.octet_length(p_reason) NOT BETWEEN 1 AND 512
        OR p_reason <> pg_catalog.btrim(p_reason) OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network deletion is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_deletion_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network deletion is not authorized';
    END IF;
    -- Refuse a caller without the grant before taking any lock, so a
    -- member cannot stall Workspace-wide work by repeating the request; the
    -- grant is resolved again under the locks below.
    PERFORM 1 FROM mesh_ops.network_delete_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, v_now);
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network deletion is not authorized';
    END IF;
    -- Workspace-wide changes are serialized by the Workspace row, taken
    -- before the Network revision, as Network creation and member removal do.
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR NO KEY UPDATE;
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    -- NO KEY: no key column changes, and FK inserts that reference the
    -- Network (FOR KEY SHARE) are not blocked by it.
    SELECT * INTO STRICT v_network FROM mesh.network AS network WHERE network.id = v_scope.network_id
    FOR NO KEY UPDATE;

    SELECT * INTO v_grant FROM mesh_ops.network_delete_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network deletion is not authorized';
    END IF;

    IF v_network.state = 'deleted' THEN
        SELECT * INTO v_deletion FROM mesh_ops.network_deletion AS deletion
        WHERE deletion.network_id = v_network.id;
        IF v_deletion.network_id IS NULL OR v_deletion.completed_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Network is unavailable';
        END IF;
        RETURN pg_catalog.jsonb_build_object(
            'outcome', 'deleting',
            'deletion', mesh_ops.network_deletion_document_internal_v1(v_deletion));
    END IF;
    -- No path suspends a Network yet; one that is not active is not deleted
    -- here until its state is understood.
    IF v_network.state <> 'active' THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Network is unavailable';
    END IF;
    IF v_network.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Network version changed';
    END IF;
    v_blockers := mesh_ops.network_deletion_blockers_internal_v1(v_scope.workspace_id, v_scope.network_id);
    IF (v_blockers ->> 'total')::BIGINT > 0 THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'blocked', 'blockers', v_blockers);
    END IF;

    SELECT principal.id INTO STRICT v_actor FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;
    SELECT pg_catalog.count(*) INTO v_devices FROM mesh.device AS device
    WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
      AND device.state NOT IN ('revoked', 'deleted') AND device.deleted_at IS NULL;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.network
    SET state = 'deleted', deleted_at = GREATEST(v_now, created_at),
        authority_generation = authority_generation + 1, version = version + 1,
        updated_at = GREATEST(v_now, updated_at)
    WHERE id = v_network.id
    RETURNING * INTO v_network;

    -- Nobody joins a deleted Network: its keys end now.
    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = GREATEST(v_now, credential.valid_from),
        version = credential.version + 1, updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
      AND credential.state = 'active';
    GET DIAGNOSTICS v_keys = ROW_COUNT;

    INSERT INTO mesh_ops.network_deletion (
        network_id, workspace_id, deployment_id, network_public_id, requested_at,
        requested_by_principal_id, reason, devices_total, updated_at
    ) VALUES (
        v_network.id, v_scope.workspace_id, v_scope.deployment_id, v_network.public_id, v_now,
        v_actor, p_reason, v_devices, v_now
    ) RETURNING * INTO v_deletion;

    -- Control re-reads every map session of the Network and closes it.
    v_advanced := mesh_ops.advance_member_networks_internal_v1(v_scope.workspace_id, ARRAY[v_scope.network_id]);
    -- A share decision checks the Network before it takes the revision lock
    -- and only the sharing revision after it: moving that revision makes a
    -- decision that raced this deletion fail instead of adding a Trust
    -- Contract to a deleted Network.
    UPDATE mesh_ops.network_revision AS revision
    SET sharing_revision = revision.sharing_revision + 1, updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id;

    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'deleted',
        'network', pg_catalog.jsonb_build_object(
            'network_id', v_network.public_id, 'display_name', v_network.display_name,
            'version', v_network.version),
        'deletion', mesh_ops.network_deletion_document_internal_v1(v_deletion),
        'keys_revoked', v_keys,
        'networks', v_advanced,
        'authority', pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
            'binding_id', v_grant.role_binding_public_id,
            'role_id', v_grant.role_definition_public_id,
            'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
            'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
            'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
        ))
    );
END;
$function$;

-- GET /api/v1/workspaces/{w}/networks/{n}: an active Network for a reader
-- with network.read; a Network being deleted, with its progress, for the
-- owner or a Workspace-wide network.delete grant. P0002 once the deletion
-- completed, or when the reader may not see a deleted Network.
CREATE FUNCTION mesh_ops.read_network_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
-- VOLATILE: the permission resolvers lock what they read (FOR SHARE).
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
SET join_collapse_limit = 1
SET from_collapse_limit = 1
SET plan_cache_mode = force_generic_plan
AS $function$
DECLARE
    v_scope RECORD;
    v_network mesh.network%ROWTYPE;
    v_deletion mesh_ops.network_deletion%ROWTYPE;
    v_code TEXT;
BEGIN
    IF p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network read is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_deletion_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Network is unavailable';
    END IF;
    SELECT * INTO STRICT v_network FROM mesh.network AS network WHERE network.id = v_scope.network_id;
    SELECT identity.display_code INTO v_code FROM mesh_ops.tenant_display_identity AS identity
    WHERE identity.network_public_id = v_network.public_id;
    IF v_network.state = 'deleted' THEN
        SELECT * INTO v_deletion FROM mesh_ops.network_deletion AS deletion
        WHERE deletion.network_id = v_network.id;
        IF v_deletion.network_id IS NULL OR v_deletion.completed_at IS NOT NULL
            OR NOT EXISTS (SELECT 1 FROM mesh_ops.network_delete_grant_internal_v1(
                p_session_public_id, p_deployment_public_id, p_principal_public_id,
                p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
                p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
                p_workspace_public_id, p_evaluated_at)) THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Network is unavailable';
        END IF;
        RETURN pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
            'network_id', v_network.public_id, 'display_name', v_network.display_name,
            'display_code', v_code, 'state', 'deleting', 'version', v_network.version,
            'created_at', v_network.created_at,
            'deletion', mesh_ops.network_deletion_document_internal_v1(v_deletion)));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read', p_evaluated_at)) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network read is not authorized';
    END IF;
    RETURN pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'network_id', v_network.public_id, 'display_name', v_network.display_name,
        'display_code', v_code, 'state', v_network.state, 'version', v_network.version,
        'created_at', v_network.created_at));
END;
$function$;

-- Schema 161 told a revoked Device REVOKED; a Device of a deleted Network
-- is told the same from phase 1, before phase 2 reaches it, so it does
-- not register again and again. The keys must still be the Device's
-- current epochs, so an old rotated key learns nothing.
CREATE FUNCTION mesh_ops.map_session_revoked_v2(
    p_machine_key_fingerprint BYTEA,
    p_node_key BYTEA
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.device_machine_key_epoch AS machine
        JOIN mesh.device AS device
          ON device.workspace_id = machine.workspace_id
         AND device.network_id = machine.network_id
         AND device.id = machine.device_id
        JOIN mesh.device_node_key_epoch AS node_key
          ON node_key.workspace_id = device.workspace_id
         AND node_key.network_id = device.network_id
         AND node_key.device_id = device.id
        WHERE p_machine_key_fingerprint IS NOT NULL
          AND pg_catalog.octet_length(p_machine_key_fingerprint) = 32
          AND p_node_key IS NOT NULL
          AND pg_catalog.octet_length(p_node_key) = 32
          AND machine.fingerprint = p_machine_key_fingerprint
          AND machine.epoch = device.current_machine_key_epoch
          AND node_key.public_key = p_node_key
          AND node_key.epoch = device.current_node_key_epoch
          AND ((machine.state = 'revoked' AND node_key.state = 'revoked' AND device.state = 'revoked')
               -- The deletion record, not mesh.network: the definer reads
               -- mesh.network only inside a scope this check never sets.
               OR EXISTS (SELECT 1 FROM mesh_ops.network_deletion AS deletion
                          WHERE deletion.workspace_id = device.workspace_id
                            AND deletion.network_id = device.network_id))
    );
$function$;

REVOKE ALL ON FUNCTION
    mesh_ops.network_deletion_document_internal_v1(mesh_ops.network_deletion),
    mesh_ops.network_deletion_blockers_internal_v1(BIGINT, BIGINT),
    mesh_ops.network_deletion_scope_internal_v1(UUID, UUID, UUID),
    mesh_ops.network_delete_grant_internal_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID,
        TIMESTAMPTZ),
    mesh_ops.delete_network_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
        BIGINT, TEXT, UUID, TIMESTAMPTZ),
    mesh_ops.read_network_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
        TIMESTAMPTZ),
    mesh_ops.map_session_revoked_v2(BYTEA, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION
    mesh_ops.delete_network_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
        BIGINT, TEXT, UUID, TIMESTAMPTZ),
    mesh_ops.read_network_v1(UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
        TIMESTAMPTZ),
    mesh_ops.map_session_revoked_v2(BYTEA, BYTEA)
TO mesh_runtime;
