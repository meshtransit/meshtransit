-- K2d d4b: a Kubernetes cluster's access settings (K2 design §29.1, Q243).
--
-- The contact a gateway names when an access profile refuses a request:
-- who to ask for more access. One set per cluster, version 0 until set;
-- changes need kubernetes_cluster.manage, reads any reader of the cluster.
-- A change advances the Network revision, so the cluster's gateways get
-- the contact in their next map; Go appends its evidence on the Network
-- stream in the same transaction. A change that changes nothing writes
-- nothing.
--
-- Errors: 22023 invalid input, 42501 not authorized, 40001 stale version,
-- P0002 unknown cluster.

CREATE FUNCTION mesh_ops.kubernetes_access_contact_is_valid_v1(p_contact TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    -- As Go's kubecluster.ValidAccessContact: no C0 or C1 control, no
    -- format, line or paragraph separator, no space around it.
    SELECT p_contact IS NOT NULL AND pg_catalog.octet_length(p_contact) <= 256
        AND p_contact !~ '[[:cntrl:]\u0080-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]'
        AND p_contact !~ '^[[:space:]\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]'
        AND p_contact !~ '[[:space:]\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]$'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_access_contact_is_valid_v1(TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh.kubernetes_cluster_access_settings (
    kubernetes_cluster_id BIGINT PRIMARY KEY,
    -- The cluster's public ID: the aggregate its events name.
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    access_contact TEXT NOT NULL CHECK (mesh_ops.kubernetes_access_contact_is_valid_v1(access_contact)),
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by_principal_id BIGINT NOT NULL,
    CONSTRAINT kubernetes_cluster_access_settings_cluster_fk
        FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE CASCADE
);
-- The map reads a Network's contacts on every inventory read.
CREATE INDEX kubernetes_cluster_access_settings_network_idx
    ON mesh.kubernetes_cluster_access_settings (workspace_id, network_id);
CREATE TRIGGER kubernetes_cluster_access_settings_authority_capture
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_cluster_access_settings
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_cluster_access_settings', 'public_id');
ALTER TABLE mesh.kubernetes_cluster_access_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_cluster_access_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_cluster_access_settings_migrator_policy ON mesh.kubernetes_cluster_access_settings
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_cluster_access_settings
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.kubernetes_access_settings_document_internal_v1(
    p_settings mesh.kubernetes_cluster_access_settings
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'access_contact', COALESCE(p_settings.access_contact, ''),
        'version', COALESCE(p_settings.version, 0),
        'updated_at', p_settings.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_access_settings_document_internal_v1(
    mesh.kubernetes_cluster_access_settings
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Any reader of the cluster: version 0 and no contact until set.
CREATE FUNCTION mesh_ops.read_kubernetes_access_settings_v1(
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
    v_settings mesh.kubernetes_cluster_access_settings%ROWTYPE;
BEGIN
    v_cluster := mesh_ops.kubernetes_cluster_reader_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_cluster_public_id);
    SELECT * INTO v_settings FROM mesh.kubernetes_cluster_access_settings AS settings
    WHERE settings.kubernetes_cluster_id = v_cluster.id AND settings.workspace_id = v_cluster.workspace_id
      AND settings.network_id = v_cluster.network_id;
    RETURN mesh_ops.kubernetes_access_settings_document_internal_v1(v_settings);
END;
$function$;

-- Replaces the settings when p_expected_version is the current one (0
-- before any); the same contact changes nothing. A change advances the
-- Network revision. Returns what the caller records as the cluster's event.
CREATE FUNCTION mesh_ops.replace_kubernetes_access_settings_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_expected_version BIGINT, p_access_contact TEXT, p_change_public_id UUID
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
    v_before mesh.kubernetes_cluster_access_settings%ROWTYPE;
    v_after mesh.kubernetes_cluster_access_settings%ROWTYPE;
    v_network_revision BIGINT;
BEGIN
    IF p_cluster_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 0
        OR p_change_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR NOT COALESCE(mesh_ops.kubernetes_access_contact_is_valid_v1(p_access_contact), FALSE) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes access settings are invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    -- Locks in the order the cluster's other writers take them (its group,
    -- its deletion): the cluster, the Network's revision, the settings
    -- (review d4b M1).
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_grant.workspace_id AND revision.network_id = v_grant.network_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes access settings scope is unavailable';
    END IF;
    SELECT * INTO v_before FROM mesh.kubernetes_cluster_access_settings AS settings
    WHERE settings.kubernetes_cluster_id = v_cluster.id FOR UPDATE;
    IF COALESCE(v_before.version, 0) <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Kubernetes access settings version changed';
    END IF;
    IF COALESCE(v_before.access_contact, '') = p_access_contact THEN
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id, 'cluster_id', p_cluster_public_id, 'changed', FALSE,
            'settings', mesh_ops.kubernetes_access_settings_document_internal_v1(v_before));
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.kubernetes_cluster_access_settings AS settings (
        kubernetes_cluster_id, public_id, workspace_id, network_id, access_contact, version, updated_at,
        updated_by_principal_id)
    VALUES (v_cluster.id, v_cluster.public_id, v_cluster.workspace_id, v_cluster.network_id, p_access_contact, 1,
        v_now, v_grant.actor_id)
    ON CONFLICT (kubernetes_cluster_id) DO UPDATE SET
        access_contact = EXCLUDED.access_contact, version = settings.version + 1,
        updated_at = EXCLUDED.updated_at, updated_by_principal_id = EXCLUDED.updated_by_principal_id
    RETURNING * INTO v_after;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1, updated_at = GREATEST(v_now, revision.updated_at)
    WHERE revision.workspace_id = v_grant.workspace_id AND revision.network_id = v_grant.network_id
    RETURNING revision.network_revision INTO v_network_revision;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', v_network_revision,
        'cluster_id', p_cluster_public_id,
        'changed', TRUE,
        'before', CASE WHEN v_before.version IS NULL THEN NULL
                       ELSE mesh_ops.kubernetes_access_settings_document_internal_v1(v_before) END,
        'settings', mesh_ops.kubernetes_access_settings_document_internal_v1(v_after),
        'authority', v_grant.authority
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_access_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_access_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.replace_kubernetes_access_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, TEXT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.replace_kubernetes_access_settings_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, TEXT, UUID
) TO mesh_runtime;

-- Maps read the contacts of the transaction's Network's active clusters, by
-- cluster name; a cluster without one is absent.
CREATE FUNCTION mesh_ops.load_map_network_kubernetes_contacts_v1()
RETURNS TABLE (cluster_name TEXT, access_contact TEXT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace_id BIGINT := mesh_ops.current_workspace_id();
    v_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF v_workspace_id IS NULL OR v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network inventory scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT cluster.name, settings.access_contact
    FROM mesh.kubernetes_cluster_access_settings AS settings
    JOIN mesh.kubernetes_cluster AS cluster
      ON cluster.workspace_id = settings.workspace_id AND cluster.network_id = settings.network_id
     AND cluster.id = settings.kubernetes_cluster_id
    WHERE settings.workspace_id = v_workspace_id AND settings.network_id = v_network_id
      AND cluster.state = 'active' AND settings.access_contact <> ''
    ORDER BY cluster.name;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_kubernetes_contacts_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_kubernetes_contacts_v1() TO mesh_runtime;
