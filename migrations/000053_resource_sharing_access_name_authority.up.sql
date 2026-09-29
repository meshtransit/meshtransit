CREATE TABLE mesh.imported_resource_access_name (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    imported_resource_id BIGINT NOT NULL UNIQUE,
    access_name TEXT NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    withdrawn_at TIMESTAMPTZ,
    CONSTRAINT imported_resource_access_name_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT imported_resource_access_name_value_check CHECK (
        pg_catalog.char_length(access_name) BETWEEN 3 AND 253
        AND pg_catalog.octet_length(access_name) = pg_catalog.char_length(access_name)
        AND access_name = pg_catalog.lower(access_name)
        AND access_name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
        AND access_name !~ '^[0-9.]+$'
    ),
    CONSTRAINT imported_resource_access_name_state_check CHECK (
        state IN ('reserved', 'withdrawn')
    ),
    CONSTRAINT imported_resource_access_name_state_shape_check CHECK (
        (state = 'reserved' AND withdrawn_at IS NULL)
        OR (state = 'withdrawn' AND withdrawn_at IS NOT NULL)
    ),
    CONSTRAINT imported_resource_access_name_timestamps_check CHECK (
        updated_at >= created_at
        AND (withdrawn_at IS NULL OR withdrawn_at >= created_at)
    ),
    CONSTRAINT imported_resource_access_name_workspace_fk FOREIGN KEY (
        deployment_id, workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT imported_resource_access_name_network_fk FOREIGN KEY (
        workspace_id, network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT imported_resource_access_name_import_fk FOREIGN KEY (
        workspace_id, network_id, imported_resource_id
    ) REFERENCES mesh.imported_resource (
        workspace_id, network_id, id
    ) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX imported_resource_access_name_current_uidx
    ON mesh.imported_resource_access_name (workspace_id, network_id, access_name)
    WHERE state = 'reserved';
CREATE INDEX imported_resource_access_name_network_state_id_idx
    ON mesh.imported_resource_access_name (workspace_id, network_id, state, id);

CREATE FUNCTION mesh_ops.enforce_imported_resource_access_name_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Imported Resource access name is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'reserved' OR NEW.version <> 1 OR NEW.withdrawn_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid access-name reservation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.imported_resource_id <> NEW.imported_resource_id
        OR OLD.access_name <> NEW.access_name
        OR OLD.created_at <> NEW.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR OLD.state <> 'reserved'
        OR NEW.state <> 'withdrawn' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid access-name transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER imported_resource_access_name_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.imported_resource_access_name
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_imported_resource_access_name_transition();

CREATE TRIGGER imported_resource_access_name_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.imported_resource_access_name
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'imported_resource_access_name', 'public_id'
);

ALTER TABLE mesh.imported_resource_access_name ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.imported_resource_access_name FORCE ROW LEVEL SECURITY;

CREATE POLICY imported_resource_access_name_migrator_policy
    ON mesh.imported_resource_access_name
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY imported_resource_access_name_runtime_policy
    ON mesh.imported_resource_access_name
    FOR SELECT TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );
CREATE POLICY imported_resource_access_name_share_writer_policy
    ON mesh.imported_resource_access_name
    TO mesh_share_writer
    USING (
        workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND network_id = mesh_ops.current_share_consumer_network_id()
    );

CREATE FUNCTION mesh_ops.decide_resource_share_offer_v2(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_consumer_workspace_public_id UUID,
    p_consumer_network_public_id UUID,
    p_offer_public_id UUID,
    p_expected_offer_version BIGINT,
    p_nonce_digest BYTEA,
    p_action TEXT,
    p_contract_public_id UUID,
    p_imported_resource_public_id UUID,
    p_imported_display_name TEXT,
    p_access_name_public_id UUID,
    p_access_name TEXT,
    p_provider_authority_generation BIGINT,
    p_consumer_authority_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    offer_version BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    contract_state TEXT,
    access_name_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_action = 'accept' AND (
        p_access_name_public_id IS NULL OR p_access_name IS NULL
        OR pg_catalog.char_length(p_access_name) NOT BETWEEN 3 AND 253
        OR pg_catalog.octet_length(p_access_name) <> pg_catalog.char_length(p_access_name)
        OR p_access_name <> pg_catalog.lower(p_access_name)
        OR p_access_name !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
        OR p_access_name ~ '^[0-9.]+$'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid consumer access name';
    END IF;
    IF p_action <> 'accept' AND (
        p_access_name_public_id IS NOT NULL OR p_access_name IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unexpected consumer access name';
    END IF;

    SELECT
        decision.provider_network_revision,
        decision.provider_sharing_revision,
        decision.consumer_network_revision,
        decision.consumer_sharing_revision,
        decision.offer_version,
        decision.contract_version,
        decision.imported_resource_version,
        decision.contract_state
    INTO
        provider_network_revision,
        provider_sharing_revision,
        consumer_network_revision,
        consumer_sharing_revision,
        offer_version,
        contract_version,
        imported_resource_version,
        contract_state
    FROM mesh_ops.decide_resource_share_offer_v1(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id,
        p_provider_workspace_public_id,
        p_provider_network_public_id,
        p_consumer_workspace_public_id,
        p_consumer_network_public_id,
        p_offer_public_id,
        p_expected_offer_version,
        p_nonce_digest,
        p_action,
        p_contract_public_id,
        p_imported_resource_public_id,
        p_imported_display_name,
        p_provider_authority_generation,
        p_consumer_authority_generation,
        p_recovery_epoch,
        p_expected_provider_sharing_revision,
        p_expected_consumer_sharing_revision,
        p_occurred_at
    ) AS decision;

    IF p_action = 'accept' THEN
        INSERT INTO mesh.imported_resource_access_name (
            public_id, deployment_id, workspace_id, network_id,
            imported_resource_id, access_name, state, created_at, updated_at
        )
        SELECT
            p_access_name_public_id,
            imported.deployment_id,
            imported.workspace_id,
            imported.network_id,
            imported.id,
            p_access_name,
            'reserved',
            p_occurred_at,
            p_occurred_at
        FROM mesh.imported_resource AS imported
        WHERE imported.public_id = p_imported_resource_public_id
          AND imported.workspace_id = p_consumer_workspace_id
          AND imported.network_id = p_consumer_network_id
          AND imported.state = 'activating'
        RETURNING version INTO access_name_version;
        IF access_name_version IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Imported Resource access-name authority is unavailable';
        END IF;
    ELSE
        access_name_version := 0;
    END IF;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.revoke_resource_share_v2(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_contract_public_id UUID,
    p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    access_name_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    SELECT
        revoked.provider_network_revision,
        revoked.provider_sharing_revision,
        revoked.consumer_network_revision,
        revoked.consumer_sharing_revision,
        revoked.contract_version,
        revoked.imported_resource_version
    INTO
        provider_network_revision,
        provider_sharing_revision,
        consumer_network_revision,
        consumer_sharing_revision,
        contract_version,
        imported_resource_version
    FROM mesh_ops.revoke_resource_share_v1(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id,
        p_contract_public_id,
        p_expected_contract_version,
        p_expected_provider_sharing_revision,
        p_expected_consumer_sharing_revision,
        p_occurred_at
    ) AS revoked;

    UPDATE mesh.imported_resource_access_name AS access_name
    SET state = 'withdrawn',
        version = access_name.version + 1,
        updated_at = p_occurred_at,
        withdrawn_at = p_occurred_at
    FROM mesh.imported_resource AS imported
    JOIN mesh.trust_contract AS contract
      ON contract.id = imported.trust_contract_id
     AND contract.consumer_workspace_id = imported.workspace_id
     AND contract.consumer_network_id = imported.network_id
    WHERE contract.public_id = p_contract_public_id
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id
      AND access_name.imported_resource_id = imported.id
      AND access_name.workspace_id = imported.workspace_id
      AND access_name.network_id = imported.network_id
      AND access_name.state = 'reserved'
    RETURNING access_name.version INTO access_name_version;
    access_name_version := COALESCE(access_name_version, 0);
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON mesh.imported_resource_access_name
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON SEQUENCE mesh.imported_resource_access_name_id_seq
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_imported_resource_access_name_transition()
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v2(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v2(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

GRANT SELECT, INSERT, UPDATE ON mesh.imported_resource_access_name TO mesh_share_writer;
GRANT SELECT ON mesh.imported_resource_access_name TO mesh_runtime;
GRANT USAGE, SELECT ON SEQUENCE mesh.imported_resource_access_name_id_seq TO mesh_share_writer;
