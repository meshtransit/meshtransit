-- Schema 250 (K1d d1d, docs/k8s-k1d-console-design.md §5, Q133): what an
-- administrator says a cluster's gateway treats as privileged groups and
-- secret-like resources, for meshctl kube audit-check to classify as the
-- gateway does. An administrator types them, never the gateway: a gateway
-- taken over must not choose the parameters that check it. Changing them
-- needs kubernetes_cluster.manage and audit.export (who changes what the
-- check sees must be one who may export it), against the version read.

-- Privileged groups: up to 64 (a cluster's groups), RFC 1123 labels,
-- sorted as Go sorts strings and distinct; none is allowed. A rule's 1 to 16
-- (kubernetes_groups_are_valid_v1) is another limit (review d1d-a H1).
CREATE FUNCTION mesh_ops.kubernetes_privileged_groups_are_valid_v1(p_groups TEXT[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_groups IS NOT NULL AND pg_catalog.cardinality(p_groups) <= 64
        AND (pg_catalog.cardinality(p_groups) = 0
             OR pg_catalog.array_ndims(p_groups) = 1 AND pg_catalog.array_lower(p_groups, 1) = 1)
        AND pg_catalog.array_position(p_groups, NULL) IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.unnest(p_groups) AS listed(name)
            WHERE listed.name !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
        )
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.generate_subscripts(p_groups, 1) AS position(index)
            WHERE position.index > 1
              AND NOT (p_groups[position.index - 1] COLLATE "C" < p_groups[position.index] COLLATE "C")
        )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_privileged_groups_are_valid_v1(TEXT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh.kubernetes_cluster_audit_settings (
    kubernetes_cluster_id BIGINT PRIMARY KEY,
    -- The cluster's public ID: the aggregate its events name.
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    privileged_groups TEXT[] NOT NULL CHECK (mesh_ops.kubernetes_privileged_groups_are_valid_v1(privileged_groups)),
    secret_resources TEXT[] NOT NULL CHECK (
        pg_catalog.cardinality(secret_resources) <= 64
        AND pg_catalog.array_position(secret_resources, NULL) IS NULL
    ),
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by_principal_id BIGINT NOT NULL,
    CONSTRAINT kubernetes_cluster_audit_settings_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE CASCADE
);
CREATE TRIGGER kubernetes_cluster_audit_settings_authority_capture
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_cluster_audit_settings
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_cluster_audit_settings', 'public_id');
ALTER TABLE mesh.kubernetes_cluster_audit_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_cluster_audit_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_cluster_audit_settings_migrator_policy ON mesh.kubernetes_cluster_audit_settings
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_cluster_audit_settings
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Secret-like resources as the chart lists them: resource[.group], lower
-- case, sorted and distinct.
CREATE FUNCTION mesh_ops.kubernetes_secret_resources_are_valid_v1(p_resources TEXT[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_resources IS NOT NULL AND pg_catalog.cardinality(p_resources) <= 64
        AND (pg_catalog.cardinality(p_resources) = 0
             OR pg_catalog.array_ndims(p_resources) = 1 AND pg_catalog.array_lower(p_resources, 1) = 1)
        AND pg_catalog.array_position(p_resources, NULL) IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.unnest(p_resources) AS listed(name)
            WHERE pg_catalog.octet_length(listed.name) NOT BETWEEN 1 AND 253
               OR listed.name !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'
        )
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.generate_subscripts(p_resources, 1) AS position(index)
            WHERE position.index > 1
              AND NOT (p_resources[position.index - 1] COLLATE "C" < p_resources[position.index] COLLATE "C")
        )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_secret_resources_are_valid_v1(TEXT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
ALTER TABLE mesh.kubernetes_cluster_audit_settings ADD CONSTRAINT kubernetes_cluster_audit_settings_resources_check
    CHECK (mesh_ops.kubernetes_secret_resources_are_valid_v1(secret_resources));

CREATE FUNCTION mesh_ops.kubernetes_audit_settings_document_internal_v1(
    p_settings mesh.kubernetes_cluster_audit_settings
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'privileged_groups', pg_catalog.to_jsonb(COALESCE(p_settings.privileged_groups, ARRAY[]::TEXT[])),
        'secret_resources', pg_catalog.to_jsonb(COALESCE(p_settings.secret_resources, ARRAY[]::TEXT[])),
        'version', COALESCE(p_settings.version, 0),
        'updated_at', p_settings.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_audit_settings_document_internal_v1(mesh.kubernetes_cluster_audit_settings)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Any reader of the Network: version 0 and empty lists until set.
CREATE FUNCTION mesh_ops.read_kubernetes_audit_settings_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_settings mesh.kubernetes_cluster_audit_settings%ROWTYPE;
BEGIN
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT * INTO v_settings FROM mesh.kubernetes_cluster_audit_settings AS settings
    WHERE settings.kubernetes_cluster_id = v_cluster.id AND settings.workspace_id = v_cluster.workspace_id
      AND settings.network_id = v_cluster.network_id;
    RETURN mesh_ops.kubernetes_audit_settings_document_internal_v1(v_settings);
END;
$function$;

-- Replaces the settings when p_expected_version is the current one (0
-- before any); the same lists change nothing. Returns what the caller
-- records as the cluster's event.
CREATE FUNCTION mesh_ops.replace_kubernetes_audit_settings_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_expected_version BIGINT, p_privileged_groups TEXT[], p_secret_resources TEXT[], p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_grant RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_before mesh.kubernetes_cluster_audit_settings%ROWTYPE;
    v_after mesh.kubernetes_cluster_audit_settings%ROWTYPE;
    v_export RECORD;
    v_export_scope TEXT := 'workspace';
BEGIN
    IF p_cluster_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 0
        OR p_change_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR NOT mesh_ops.kubernetes_privileged_groups_are_valid_v1(p_privileged_groups)
        OR NOT mesh_ops.kubernetes_secret_resources_are_valid_v1(p_secret_resources) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes audit settings are invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    -- The binding that grants audit.export goes in the event beside the
    -- one that grants manage (review d1d-a M1).
    -- An owner holds it with no binding (review d1d-a N1): the authority
    -- is built as the manage one is, with the owner's generation.
    SELECT granted.role_binding_public_id, granted.role_definition_public_id, granted.binding_authority_generation,
        granted.membership_authority_generation, granted.workspace_owner_authority_generation INTO v_export
    FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, 'audit.export', v_now) AS granted
    LIMIT 1;
    IF NOT FOUND THEN
        v_export_scope := 'network';
        SELECT granted.role_binding_public_id, granted.role_definition_public_id,
            granted.binding_authority_generation, granted.membership_authority_generation,
            granted.workspace_owner_authority_generation INTO v_export
        FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'audit.export', v_now) AS granted
        LIMIT 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit.export required';
        END IF;
    END IF;
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT * INTO v_before FROM mesh.kubernetes_cluster_audit_settings AS settings
    WHERE settings.kubernetes_cluster_id = v_cluster.id FOR UPDATE;
    IF COALESCE(v_before.version, 0) <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Kubernetes audit settings version changed';
    END IF;
    IF v_before.version IS NOT NULL AND v_before.privileged_groups = p_privileged_groups
        AND v_before.secret_resources = p_secret_resources THEN
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id, 'cluster_id', p_cluster_public_id, 'changed', FALSE,
            'settings', mesh_ops.kubernetes_audit_settings_document_internal_v1(v_before));
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.kubernetes_cluster_audit_settings AS settings (
        kubernetes_cluster_id, public_id, workspace_id, network_id, privileged_groups, secret_resources, version,
        updated_at, updated_by_principal_id)
    VALUES (v_cluster.id, v_cluster.public_id, v_cluster.workspace_id, v_cluster.network_id, p_privileged_groups,
        p_secret_resources, 1, v_now, v_grant.actor_id)
    ON CONFLICT (kubernetes_cluster_id) DO UPDATE SET
        privileged_groups = EXCLUDED.privileged_groups, secret_resources = EXCLUDED.secret_resources,
        version = settings.version + 1, updated_at = EXCLUDED.updated_at,
        updated_by_principal_id = EXCLUDED.updated_by_principal_id
    RETURNING * INTO v_after;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'cluster_id', p_cluster_public_id,
        'changed', TRUE,
        'before', CASE WHEN v_before.version IS NULL THEN NULL
                       ELSE mesh_ops.kubernetes_audit_settings_document_internal_v1(v_before) END,
        'settings', mesh_ops.kubernetes_audit_settings_document_internal_v1(v_after),
        'authority', v_grant.authority,
        'export_authority', mesh_ops.enrollment_key_authority_internal_v1(
            v_export.role_binding_public_id, v_export.role_definition_public_id,
            v_export.binding_authority_generation, v_export.membership_authority_generation,
            v_export.workspace_owner_authority_generation) || pg_catalog.jsonb_build_object('scope', v_export_scope)
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_audit_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_audit_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.replace_kubernetes_audit_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, TEXT[], TEXT[], UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.replace_kubernetes_audit_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, TEXT[], TEXT[], UUID
) TO mesh_runtime;
