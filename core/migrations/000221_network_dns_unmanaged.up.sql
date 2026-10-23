-- Unmanaged Devices (DNS design D5b): the Devices of up to 16 Device Groups
-- of a Network get no DNS from MeshTransit, for machines that keep a
-- company's DNS or another VPN's. Their maps carry no DNS configuration:
-- the host's DNS stays as it is, and the mesh's names are not answered
-- there.
--
-- A Network's DNS settings are one set of its own, created at version 1
-- with the first change; without one there are no unmanaged Devices,
-- version 0. Changes need dns.manage, reads network.read (the DNS zone
-- authorization, schema 213); a change advances the Network and DNS
-- revisions, so maps are rebuilt, and Go appends its evidence on the Network
-- stream in the same transaction. A change that changes nothing writes
-- nothing. A Device Group the settings name cannot be deleted (MTD07), like
-- one a DNS zone is sent to.
--
-- Errors: 22023 invalid input, 42501 not authorized, 40001 stale version,
-- MTZ04 unknown Device Group.

CREATE TABLE mesh.network_dns_setting (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    unmanaged_group_ids BIGINT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT network_dns_setting_public_id_check
        CHECK (pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7),
    CONSTRAINT network_dns_setting_version_check CHECK (version >= 1),
    CONSTRAINT network_dns_setting_unmanaged_check CHECK (
        pg_catalog.cardinality(unmanaged_group_ids) <= 16
        AND pg_catalog.array_position(unmanaged_group_ids, NULL) IS NULL
    ),
    CONSTRAINT network_dns_setting_time_check CHECK (updated_at >= created_at),
    CONSTRAINT network_dns_setting_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_dns_setting_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_dns_setting_public_id_uidx UNIQUE (public_id),
    CONSTRAINT network_dns_setting_network_uidx UNIQUE (workspace_id, network_id)
);

-- A set only moves forward: one version at a time, on the same Network.
CREATE FUNCTION mesh_ops.enforce_network_dns_setting_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Network DNS settings are never deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Network DNS settings start at version 1';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id <> OLD.network_id
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Network DNS settings change one version at a time';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER network_dns_setting_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.network_dns_setting
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_dns_setting_v1();
CREATE TRIGGER network_dns_setting_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_dns_setting
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_dns_setting', 'public_id');

ALTER TABLE mesh.network_dns_setting ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_dns_setting FORCE ROW LEVEL SECURITY;
CREATE POLICY network_dns_setting_migrator_policy ON mesh.network_dns_setting
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_dns_setting
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_network_dns_setting_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A Device Group the settings name cannot be deleted: its Devices would
-- silently take MeshTransit's DNS again.
CREATE FUNCTION mesh_ops.refuse_deleting_dns_unmanaged_group_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.state = 'deleted' AND OLD.state <> 'deleted' AND EXISTS (
        SELECT 1 FROM mesh.network_dns_setting AS setting
        WHERE setting.workspace_id = OLD.workspace_id AND setting.network_id = OLD.network_id
          AND setting.unmanaged_group_ids @> ARRAY[OLD.id]) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD07', MESSAGE = 'Device Group is used by DNS settings';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER device_group_not_used_by_dns_setting
BEFORE UPDATE OF state ON mesh.device_group
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_deleting_dns_unmanaged_group_v1();
REVOKE ALL ON FUNCTION mesh_ops.refuse_deleting_dns_unmanaged_group_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The settings of the transaction's Network as a document: version (0
-- without a set) and the unmanaged Device Groups, by name.
CREATE FUNCTION mesh_ops.dns_setting_document_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'setting_id', setting.public_id,
        'version', COALESCE(setting.version, 0),
        'unmanaged_groups', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'group_id', device_group.public_id, 'name', device_group.name) ORDER BY device_group.name, device_group.id)
            FROM mesh.device_group AS device_group
            WHERE device_group.id = ANY (setting.unmanaged_group_ids)
              AND device_group.workspace_id = p_workspace_id AND device_group.network_id = p_network_id
        ), '[]'::JSONB))
    FROM (SELECT 1) AS one
    LEFT JOIN mesh.network_dns_setting AS setting
      ON setting.workspace_id = p_workspace_id AND setting.network_id = p_network_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_setting_document_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Reads the Network's DNS settings (network.read).
CREATE FUNCTION mesh_ops.read_dns_setting_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    RETURN mesh_ops.dns_setting_document_internal_v1(v_scope.workspace_id, v_scope.network_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_dns_setting_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_dns_setting_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_runtime;

-- Sets the unmanaged Device Groups (dns.manage) when p_expected_version is
-- still current (0: no set yet). Changes serialize on the Network's revision
-- row and advance the Network and DNS revisions.
CREATE FUNCTION mesh_ops.change_dns_setting_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_expected_version BIGINT,
    p_group_public_ids UUID[], p_change_public_id UUID
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
    v_setting mesh.network_dns_setting%ROWTYPE;
    v_before JSONB;
    v_groups BIGINT[];
    v_network_revision BIGINT;
    v_dns_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_expected_version IS NULL OR p_expected_version < 0 OR p_group_public_ids IS NULL
        OR pg_catalog.cardinality(p_group_public_ids) > 16
        OR pg_catalog.array_position(p_group_public_ids, NULL) IS NOT NULL
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS settings change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'dns.manage'
    );
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DNS settings scope is unavailable';
    END IF;
    SELECT COALESCE(pg_catalog.array_agg(device_group.id ORDER BY device_group.id), '{}') INTO v_groups
    FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.state = 'active' AND device_group.public_id = ANY (p_group_public_ids);
    IF pg_catalog.cardinality(v_groups) <> (SELECT pg_catalog.count(DISTINCT item)
                                            FROM pg_catalog.unnest(p_group_public_ids) AS item) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ04', MESSAGE = 'Device Group is not an active group of this Network';
    END IF;
    SELECT * INTO v_setting FROM mesh.network_dns_setting AS setting
    WHERE setting.workspace_id = v_scope.workspace_id AND setting.network_id = v_scope.network_id
    FOR UPDATE;
    IF COALESCE(v_setting.version, 0) <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'DNS settings version changed';
    END IF;
    v_before := mesh_ops.dns_setting_document_internal_v1(v_scope.workspace_id, v_scope.network_id);
    IF COALESCE(v_setting.unmanaged_group_ids, '{}') = v_groups THEN
        RETURN pg_catalog.jsonb_build_object('setting', v_before, 'changed', FALSE);
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF v_setting.id IS NULL THEN
        INSERT INTO mesh.network_dns_setting (
            public_id, deployment_id, workspace_id, network_id, version, unmanaged_group_ids, created_at, updated_at
        ) VALUES (
            pg_catalog.uuidv7(), v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, 1, v_groups,
            v_now, v_now
        ) RETURNING * INTO v_setting;
    ELSE
        UPDATE mesh.network_dns_setting AS setting
        SET version = setting.version + 1, unmanaged_group_ids = v_groups,
            updated_at = GREATEST(v_now, setting.updated_at)
        WHERE setting.id = v_setting.id
        RETURNING * INTO v_setting;
    END IF;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1, dns_revision = revision.dns_revision + 1,
        updated_at = GREATEST(v_now, revision.updated_at)
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    RETURNING revision.network_revision, revision.dns_revision INTO v_network_revision, v_dns_revision;
    RETURN pg_catalog.jsonb_build_object(
        'setting', mesh_ops.dns_setting_document_internal_v1(v_scope.workspace_id, v_scope.network_id),
        'previous', v_before, 'changed', TRUE,
        'network_revision', v_network_revision, 'dns_revision', v_dns_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_dns_setting_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, UUID[], UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_dns_setting_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, UUID[], UUID
) TO mesh_runtime;

-- Maps read the unmanaged Device Groups of the transaction's Network, by
-- internal reference; none without settings.
CREATE FUNCTION mesh_ops.load_map_network_dns_unmanaged_v1()
RETURNS BIGINT[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
    v_groups BIGINT[];
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS settings scope is unavailable';
    END IF;
    SELECT setting.unmanaged_group_ids INTO v_groups
    FROM mesh.network_dns_setting AS setting
    WHERE setting.workspace_id = scoped_workspace_id AND setting.network_id = scoped_network_id;
    RETURN COALESCE(v_groups, '{}');
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_unmanaged_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_unmanaged_v1()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_dns_unmanaged_v1() TO mesh_runtime;
