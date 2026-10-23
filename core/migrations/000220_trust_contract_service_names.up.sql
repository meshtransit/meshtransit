-- The service names of a running share (DNS design D3 §19): the provider may
-- change what it suggests while the contract runs, both sides read the
-- current suggestions, and the consumer sees the DNS names of its Network
-- that point at the share.
--
-- An offer's suggestions never change (schema 218). The first time the
-- provider changes them, the contract gets a set of its own, version 1; from
-- then on the set is the suggestion list. Without a set the list is the
-- offer's, version 0. A change never touches the names the consumer made:
-- they are its own DNS names (schema 217).
--
-- The provider's change is audited like every authority write, at the
-- provider Network's current revision: suggestions are no part of any map,
-- so the revision does not advance and no map rebuilds. Go appends the
-- evidence in the same transaction. The writer takes the provider's revision
-- row before the contract row, as every contract writer does.

-- Whether names are service names as offers hold them: canonical DNS names
-- of two labels at least, none an address, none twice.
CREATE FUNCTION mesh_ops.valid_service_names_v1(p_names TEXT[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_names IS NOT NULL
       AND pg_catalog.array_position(p_names, NULL) IS NULL
       AND (SELECT pg_catalog.count(DISTINCT name) FROM pg_catalog.unnest(p_names) AS name)
           = pg_catalog.cardinality(p_names)
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.unnest(p_names) AS name
           WHERE pg_catalog.octet_length(name) NOT BETWEEN 3 AND 253
              OR name !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
              OR name ~ '^[0-9.]+$'
       )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.valid_service_names_v1(TEXT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh.trust_contract_service_name_set (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL,
    deployment_id BIGINT NOT NULL,
    trust_contract_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    names TEXT[] COLLATE "C" NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT trust_contract_service_name_set_public_id_check
        CHECK (pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7),
    CONSTRAINT trust_contract_service_name_set_version_check CHECK (version >= 1),
    CONSTRAINT trust_contract_service_name_set_names_check CHECK (
        pg_catalog.cardinality(names) BETWEEN 0 AND 8 AND mesh_ops.valid_service_names_v1(names)
    ),
    CONSTRAINT trust_contract_service_name_set_time_check CHECK (updated_at >= created_at),
    CONSTRAINT trust_contract_service_name_set_contract_fk FOREIGN KEY (trust_contract_id)
        REFERENCES mesh.trust_contract (id) ON DELETE RESTRICT,
    CONSTRAINT trust_contract_service_name_set_public_id_uidx UNIQUE (public_id),
    CONSTRAINT trust_contract_service_name_set_contract_uidx UNIQUE (trust_contract_id)
);

-- A set only moves forward: one version at a time, on the same contract.
CREATE FUNCTION mesh_ops.enforce_trust_contract_service_name_set_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Contract service names are never deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Contract service names start at version 1';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.trust_contract_id <> OLD.trust_contract_id OR NEW.created_at <> OLD.created_at
        OR NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Contract service names change one version at a time';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER trust_contract_service_name_set_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.trust_contract_service_name_set
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_trust_contract_service_name_set_v1();
CREATE TRIGGER trust_contract_service_name_set_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.trust_contract_service_name_set
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('trust_contract_service_name_set', 'public_id');

ALTER TABLE mesh.trust_contract_service_name_set ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.trust_contract_service_name_set FORCE ROW LEVEL SECURITY;
CREATE POLICY trust_contract_service_name_set_migrator_policy ON mesh.trust_contract_service_name_set
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.trust_contract_service_name_set
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_trust_contract_service_name_set_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The contract of the transaction's Network (provider or consumer side) after
-- one permission check, unlocked: which side the Network is, and the role
-- binding that granted the permission.
CREATE FUNCTION mesh_ops.authorize_contract_service_names_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_contract_public_id UUID, p_permission TEXT
)
RETURNS TABLE (contract_id BIGINT, side TEXT, role_binding_public_id UUID)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_binding UUID;
    v_contract mesh.trust_contract%ROWTYPE;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_contract_public_id IS NULL
        OR p_permission NOT IN ('share.read', 'share.offer') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'contract service names input is invalid';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL OR NOT EXISTS (
        SELECT 1 FROM mesh.workspace AS workspace
        JOIN mesh.network AS network ON network.workspace_id = workspace.id
        WHERE workspace.id = v_workspace AND network.id = v_network
          AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND network.state = 'active' AND network.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'contract service names scope is unavailable';
    END IF;
    SELECT permission.role_binding_public_id INTO v_binding
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, pg_catalog.transaction_timestamp()
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'contract service names are not authorized';
    END IF;
    SELECT * INTO v_contract FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract_public_id
      AND ((contract.provider_workspace_id = v_workspace AND contract.provider_network_id = v_network)
           OR (contract.consumer_workspace_id = v_workspace AND contract.consumer_network_id = v_network));
    IF v_contract.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'trust contract is unavailable';
    END IF;
    RETURN QUERY SELECT v_contract.id,
        CASE WHEN v_contract.provider_network_id = v_network THEN 'provider' ELSE 'consumer' END, v_binding;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_contract_service_names_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The current suggestions of a contract, in order, with their version: the
-- contract's own set, or else its offer's names at version 0.
CREATE FUNCTION mesh_ops.contract_service_names_internal_v1(p_contract_id BIGINT)
RETURNS TABLE (version BIGINT, names TEXT[])
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT name_set.version, name_set.names
    FROM mesh.trust_contract_service_name_set AS name_set
    WHERE name_set.trust_contract_id = p_contract_id
    UNION ALL
    SELECT 0::BIGINT, COALESCE((
        SELECT pg_catalog.array_agg(offered.fqdn ORDER BY offered.ordinal)
        FROM mesh.trust_contract AS contract
        JOIN mesh.share_offer_service_name AS offered ON offered.share_offer_id = contract.share_offer_id
        WHERE contract.id = p_contract_id
    ), '{}'::TEXT[])
    WHERE NOT EXISTS (
        SELECT 1 FROM mesh.trust_contract_service_name_set AS name_set
        WHERE name_set.trust_contract_id = p_contract_id
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.contract_service_names_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One contract's service names for its provider or consumer Network
-- (share.read): the suggestions with their version, the contract's state,
-- and for the consumer the share it imports and, when the session may also
-- read the Network (network.read, as every DNS read), the DNS names of its
-- Network that point at it (at most 100, in name order). The provider never
-- learns the consumer's names.
CREATE FUNCTION mesh_ops.read_contract_service_names_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_contract_public_id UUID
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
    v_contract mesh.trust_contract%ROWTYPE;
    v_current RECORD;
    v_document JSONB;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_contract_service_names_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_contract_public_id, 'share.read'
    );
    SELECT * INTO STRICT v_contract FROM mesh.trust_contract AS contract WHERE contract.id = v_scope.contract_id;
    SELECT * INTO STRICT v_current FROM mesh_ops.contract_service_names_internal_v1(v_contract.id);
    v_document := pg_catalog.jsonb_build_object(
        'contract_id', v_contract.public_id, 'side', v_scope.side, 'state', v_contract.state,
        'expires_at', v_contract.expires_at, 'version', v_current.version,
        'names', pg_catalog.to_jsonb(v_current.names)
    );
    IF v_scope.side = 'consumer' THEN
        PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'network.read', pg_catalog.transaction_timestamp()
        );
        v_document := v_document || pg_catalog.jsonb_build_object(
            'share_id', v_contract.imported_resource_public_id,
            'dns_names', CASE WHEN NOT FOUND THEN '[]'::JSONB ELSE COALESCE((
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'dns_name_id', listed.public_id, 'dns_zone_id', listed.zone_public_id,
                    'fqdn', listed.fqdn) ORDER BY listed.fqdn)
                FROM (
                    SELECT name.public_id, zone.public_id AS zone_public_id, name.fqdn::TEXT AS fqdn
                    FROM mesh.network_dns_name AS name
                    JOIN mesh.network_dns_zone AS zone ON zone.id = name.zone_id
                    WHERE name.workspace_id = v_contract.consumer_workspace_id
                      AND name.network_id = v_contract.consumer_network_id
                      AND name.state = 'active'
                      AND name.share_public_id = v_contract.imported_resource_public_id
                    ORDER BY name.fqdn COLLATE "C"
                    LIMIT 100
                ) AS listed
            ), '[]'::JSONB) END
        );
    END IF;
    RETURN v_document;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_contract_service_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_contract_service_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- The provider replaces a running contract's suggestions (share.offer) when
-- p_expected_version is still theirs (MTZ20 otherwise): the contract active or
-- activating and not past its end (MTZ21 otherwise), Go having checked each
-- name as DNS. The same names write nothing. It returns the set before and
-- after, and the provider Network's current revision for the evidence.
CREATE FUNCTION mesh_ops.replace_contract_service_names_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_contract_public_id UUID,
    p_expected_version BIGINT, p_names TEXT[], p_change_public_id UUID
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
    v_contract mesh.trust_contract%ROWTYPE;
    v_current RECORD;
    v_set mesh.trust_contract_service_name_set%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_network_revision BIGINT;
BEGIN
    IF p_expected_version IS NULL OR p_expected_version < 0 OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_names IS NULL OR pg_catalog.cardinality(p_names) > 8
        OR NOT mesh_ops.valid_service_names_v1(p_names) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'contract service names are invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_contract_service_names_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_contract_public_id, 'share.offer'
    );
    IF v_scope.side <> 'provider' THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'only the provider suggests service names';
    END IF;
    -- The provider's revision row, then the contract row: the order of every
    -- contract writer (a revoke locks both revisions, then the contract).
    SELECT revision.network_revision INTO v_network_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = mesh_ops.current_workspace_id()
      AND revision.network_id = mesh_ops.current_network_id()
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'contract service names scope is unavailable';
    END IF;
    SELECT * INTO STRICT v_contract FROM mesh.trust_contract AS contract
    WHERE contract.id = v_scope.contract_id
    FOR UPDATE;
    IF v_contract.state NOT IN ('activating', 'active') OR v_contract.expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ21', MESSAGE = 'trust contract has ended';
    END IF;
    SELECT * INTO STRICT v_current FROM mesh_ops.contract_service_names_internal_v1(v_contract.id);
    IF v_current.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ20', MESSAGE = 'contract service names changed';
    END IF;
    IF v_current.names = p_names THEN
        RETURN pg_catalog.jsonb_build_object('contract_id', v_contract.public_id, 'changed', FALSE,
            'state', v_contract.state, 'expires_at', v_contract.expires_at,
            'version', v_current.version, 'names', pg_catalog.to_jsonb(v_current.names));
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF v_current.version = 0 THEN
        INSERT INTO mesh.trust_contract_service_name_set (
            public_id, deployment_id, trust_contract_id, version, names, created_at, updated_at
        ) VALUES (
            pg_catalog.uuidv7(), v_contract.deployment_id, v_contract.id, 1, p_names, v_now, v_now
        ) RETURNING * INTO v_set;
    ELSE
        UPDATE mesh.trust_contract_service_name_set AS name_set
        SET version = name_set.version + 1, names = p_names, updated_at = v_now
        WHERE name_set.trust_contract_id = v_contract.id
        RETURNING * INTO v_set;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'contract_id', v_contract.public_id, 'changed', TRUE, 'set_id', v_set.public_id,
        'state', v_contract.state, 'expires_at', v_contract.expires_at,
        'version', v_set.version, 'names', pg_catalog.to_jsonb(v_set.names),
        'previous_version', v_current.version, 'previous_names', pg_catalog.to_jsonb(v_current.names),
        'network_revision', v_network_revision, 'role_binding_id', v_scope.role_binding_public_id
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.replace_contract_service_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, TEXT[], UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.replace_contract_service_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, TEXT[], UUID
) TO mesh_runtime;
