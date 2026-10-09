-- Schema 113 (R1-66): the receiving Network chooses where shared Devices
-- appear.
--
-- A Network may narrow the Resource Alias range for each address family to a
-- prefix inside the Deployment's federation_resource_alias pool (the frame
-- every supported client already allows). Without a row, or with a null
-- prefix, the whole frame is used, which is the behavior before this schema.
-- Other Networks, in any Workspace, may choose the same prefix: Resource
-- Aliases are unique per Network pair, never globally. Consumer Source
-- Aliases live in the provider's space and are not affected.
--
-- Changing a range never renumbers: every alias this Network still retains
-- as the receiving side must stay inside the new prefix. Maps do not change,
-- so no Network revision advances; the evidence names the current one.

CREATE TABLE mesh.network_alias_range (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    family INTEGER NOT NULL,
    prefix CIDR,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT network_alias_range_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_alias_range_prefix_check CHECK (
        family IN (4, 6)
        AND (
            prefix IS NULL
            OR (
                pg_catalog.family(prefix) = family
                AND pg_catalog.masklen(prefix) BETWEEN
                    CASE family WHEN 4 THEN 16 ELSE 96 END
                    AND CASE family WHEN 4 THEN 28 ELSE 124 END
            )
        )
    ),
    CONSTRAINT network_alias_range_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_alias_range_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_alias_range_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_alias_range_family_key UNIQUE (network_id, family)
);

CREATE FUNCTION mesh_ops.enforce_network_alias_range_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Network alias range is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Network alias range';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.family <> NEW.family
        OR OLD.created_at <> NEW.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Network alias range transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER network_alias_range_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.network_alias_range
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_alias_range_transition();
CREATE TRIGGER network_alias_range_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_alias_range
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_alias_range', 'public_id');

ALTER TABLE mesh.network_alias_range ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_alias_range FORCE ROW LEVEL SECURITY;
CREATE POLICY network_alias_range_migrator_policy ON mesh.network_alias_range
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY network_alias_range_runtime_policy ON mesh.network_alias_range
    FOR SELECT TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );
REVOKE ALL ON mesh.network_alias_range FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer,
    mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON SEQUENCE mesh.network_alias_range_id_seq FROM PUBLIC, mesh_runtime, mesh_worker,
    mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT SELECT ON mesh.network_alias_range TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.enforce_network_alias_range_transition()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The chosen prefix of one Network and family, or NULL for the whole frame.
CREATE FUNCTION mesh_ops.network_alias_range_internal_v1(p_network_id BIGINT, p_family INTEGER)
RETURNS CIDR
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT range.prefix
    FROM mesh.network_alias_range AS range
    WHERE range.network_id = p_network_id AND range.family = p_family
$function$;
REVOKE ALL ON FUNCTION mesh_ops.network_alias_range_internal_v1(BIGINT, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Same contract as schema 92. Resource Aliases are now searched inside the
-- receiving Network's chosen range for the pool's family when one is set;
-- Consumer Source Aliases and Networks without a range keep the whole pool.
CREATE OR REPLACE FUNCTION mesh_ops.allocate_network_scoped_alias_v1(
    p_deployment_id BIGINT, p_pool_id BIGINT, p_provider_network_id BIGINT, p_consumer_network_id BIGINT
)
RETURNS INET
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    pool_row mesh.address_pool%ROWTYPE;
    prior_deployment TEXT := pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE);
    search_prefix CIDR;
    chosen_prefix CIDR;
    maximum_offset BIGINT;
    attempt_limit BIGINT;
    candidate INET;
BEGIN
    IF p_deployment_id IS NULL OR p_pool_id IS NULL OR p_provider_network_id IS NULL
        OR p_consumer_network_id IS NULL OR p_provider_network_id = p_consumer_network_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid alias allocation request';
    END IF;
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', p_deployment_id::TEXT, TRUE);
    SELECT pool.* INTO pool_row FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
        AND realm.deployment_id = pool.deployment_id AND realm.kind = 'federation_alias'
        AND realm.state = 'active' AND realm.deleted_at IS NULL
    WHERE pool.id = p_pool_id AND pool.deployment_id = p_deployment_id AND pool.workspace_id IS NULL
      AND pool.purpose IN ('federation_resource_alias', 'federation_consumer_alias')
      AND pool.state = 'active' AND pool.deleted_at IS NULL
    FOR SHARE OF pool;
    IF pool_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'explicit Device alias pool is unavailable';
    END IF;
    IF (pool_row.family = 4 AND pg_catalog.masklen(pool_row.prefix) NOT BETWEEN 8 AND 30)
        OR (pool_row.family = 6 AND pg_catalog.masklen(pool_row.prefix) NOT BETWEEN 67 AND 126)
        OR EXISTS (SELECT 1 FROM (VALUES ('0.0.0.0/8'::CIDR), ('127.0.0.0/8'),
            ('169.254.0.0/16'), ('224.0.0.0/4'), ('240.0.0.0/4'), ('::/128'),
            ('::1/128'), ('::ffff:0:0/96'), ('fe80::/10'), ('ff00::/8')) AS unsafe(prefix)
            WHERE pool_row.prefix && unsafe.prefix)
        OR EXISTS (SELECT 1 FROM mesh.address_pool AS other
            WHERE other.deployment_id = pool_row.deployment_id
              AND other.purpose IN ('node_overlay', 'workspace_service')
              AND other.state IN ('reserved', 'active', 'quarantined')
              AND pool_row.prefix && other.prefix) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device alias pool overlaps an excluded prefix';
    END IF;
    search_prefix := pool_row.prefix;
    IF pool_row.purpose = 'federation_resource_alias' THEN
        chosen_prefix := mesh_ops.network_alias_range_internal_v1(p_consumer_network_id, pool_row.family);
        IF chosen_prefix IS NOT NULL THEN
            IF NOT chosen_prefix <<= pool_row.prefix THEN
                RAISE EXCEPTION USING ERRCODE = 'MT001',
                    MESSAGE = 'Network alias range is outside the Device alias pool';
            END IF;
            search_prefix := chosen_prefix;
        END IF;
    END IF;
    maximum_offset := (1::BIGINT << (CASE pool_row.family WHEN 4 THEN 32 ELSE 128 END
        - pg_catalog.masklen(search_prefix))) - CASE pool_row.family WHEN 4 THEN 2 ELSE 1 END;
    attempt_limit := LEAST(maximum_offset, 65536);
    candidate := NULL;
    FOR candidate_offset IN 1..attempt_limit LOOP
        candidate := pg_catalog.set_masklen(pg_catalog.network(search_prefix) + candidate_offset,
            CASE pool_row.family WHEN 4 THEN 32 ELSE 128 END);
        EXIT WHEN NOT mesh_ops.device_alias_address_retained_v1(pool_row.deployment_id, candidate,
            p_provider_network_id, p_consumer_network_id, NULL, NULL);
        candidate := NULL;
    END LOOP;
    IF candidate IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Device alias candidate window is exhausted';
    END IF;
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    RETURN candidate;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(prior_deployment, ''), TRUE);
    RAISE;
END;
$function$;

-- Resolves the exact Network scope bound by the caller and checks one
-- permission. Runs as the definer, so every query names the scope.
CREATE FUNCTION mesh_ops.authorize_network_alias_range_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT, role_binding_public_id UUID)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_deployment BIGINT;
    v_binding UUID;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network alias range input is invalid';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = v_workspace AND network.id = v_network
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL;
    IF v_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network alias range scope is unavailable';
    END IF;
    SELECT permission.role_binding_public_id INTO v_binding
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network alias range is not authorized';
    END IF;
    RETURN QUERY SELECT v_deployment, v_workspace, v_network, v_binding;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_network_alias_range_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The frame, chosen range and usage per family, plus live incoming shares.
-- The version is 1 plus the sum of row versions; any change advances it.
CREATE FUNCTION mesh_ops.network_alias_range_state_internal_v1(
    p_deployment_id BIGINT, p_network_id BIGINT
)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'version', 1 + COALESCE((
            SELECT pg_catalog.sum(range.version) FROM mesh.network_alias_range AS range
            WHERE range.network_id = p_network_id
        ), 0),
        'families', (
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'family', family.value,
                'frame', (
                    SELECT pool.prefix::TEXT FROM mesh.address_pool AS pool
                    WHERE pool.deployment_id = p_deployment_id AND pool.workspace_id IS NULL
                      AND pool.purpose = 'federation_resource_alias' AND pool.family = family.value
                      AND pool.state = 'active' AND pool.deleted_at IS NULL
                    ORDER BY pool.id LIMIT 1
                ),
                'prefix', mesh_ops.network_alias_range_internal_v1(p_network_id, family.value)::TEXT,
                'retained', (
                    SELECT pg_catalog.count(*) FROM mesh.device_alias_lease AS lease
                    WHERE lease.consumer_network_id = p_network_id AND lease.alias_role = 'resource'
                      AND lease.family = family.value AND lease.state IN ('reserved', 'quarantined')
                ) + (
                    SELECT pg_catalog.count(*) FROM mesh.federation_alias_lease AS lease
                    WHERE lease.consumer_network_id = p_network_id AND lease.family = family.value
                      AND lease.state IN ('reserved', 'active')
                      AND NOT EXISTS (
                          SELECT 1 FROM mesh.device_alias_lease AS adopted
                          WHERE adopted.consumer_network_id = p_network_id
                            AND adopted.alias_role = 'resource'
                            AND adopted.address = lease.resource_alias
                            AND adopted.state IN ('reserved', 'quarantined')
                      )
                )
            ) ORDER BY family.value)
            FROM (VALUES (4), (6)) AS family(value)
        ),
        'live_shares', (
            SELECT pg_catalog.count(*) FROM mesh.private_endpoint AS endpoint
            WHERE endpoint.consumer_network_id = p_network_id
              AND endpoint.provider_network_id <> endpoint.consumer_network_id
              AND endpoint.state = 'provisioning'
        ),
        'share_limit', 256
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.network_alias_range_state_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.read_network_alias_ranges_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_prior TEXT := pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE);
    v_scope RECORD;
    v_state JSONB;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_network_alias_range_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read', p_evaluated_at
    );
    -- Federation alias pools are visible only for the bound Deployment.
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', v_scope.deployment_id::TEXT, TRUE);
    v_state := mesh_ops.network_alias_range_state_internal_v1(v_scope.deployment_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(v_prior, ''), TRUE);
    RETURN v_state;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(v_prior, ''), TRUE);
    RAISE;
END;
$function$;

-- Sets, replaces or clears the range of the requested families. A family not
-- requested stays unchanged; a null prefix returns it to the whole frame.
-- Errors: MTR01 prefix outside the frame, MTR02 a retained alias would fall
-- outside, MTR03 the expected version is stale.
CREATE FUNCTION mesh_ops.set_network_alias_ranges_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_expected_version BIGINT,
    p_set_ipv4 BOOLEAN, p_ipv4_prefix CIDR, p_ipv4_row_public_id UUID,
    p_set_ipv6 BOOLEAN, p_ipv6_prefix CIDR, p_ipv6_row_public_id UUID,
    p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_prior TEXT := pg_catalog.current_setting('mesh.device_alias_deployment_id', TRUE);
    v_scope RECORD;
    v_before JSONB;
    v_after JSONB;
    v_network_revision BIGINT;
    v_current BIGINT;
    v_request RECORD;
    v_frame CIDR;
    v_existing mesh.network_alias_range%ROWTYPE;
    v_changed BOOLEAN := FALSE;
    v_now TIMESTAMPTZ;
BEGIN
    IF p_expected_version IS NULL OR p_expected_version < 1
        OR p_set_ipv4 IS NULL OR p_set_ipv6 IS NULL OR NOT (p_set_ipv4 OR p_set_ipv6)
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_set_ipv4 AND (p_ipv4_row_public_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ipv4_row_public_id), 6) >> 4 <> 7))
        OR (p_set_ipv6 AND (p_ipv6_row_public_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ipv6_row_public_id), 6) >> 4 <> 7)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network alias range request is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_network_alias_range_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.update', p_evaluated_at
    );
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', v_scope.deployment_id::TEXT, TRUE);
    -- Alias allocation holds this lock too, so no alias appears mid-check.
    SELECT revision.network_revision INTO v_network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network alias range scope is unavailable';
    END IF;
    PERFORM range.id FROM mesh.network_alias_range AS range
    WHERE range.network_id = v_scope.network_id ORDER BY range.family FOR UPDATE;
    v_before := mesh_ops.network_alias_range_state_internal_v1(v_scope.deployment_id, v_scope.network_id);
    v_current := (v_before ->> 'version')::BIGINT;
    IF v_current <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MTR03', MESSAGE = 'Network alias range version changed';
    END IF;
    v_now := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    FOR v_request IN
        SELECT * FROM (VALUES
            (4, p_set_ipv4, p_ipv4_prefix, p_ipv4_row_public_id),
            (6, p_set_ipv6, p_ipv6_prefix, p_ipv6_row_public_id)
        ) AS request(family, requested, prefix, row_public_id)
        WHERE request.requested
        ORDER BY request.family
    LOOP
        IF v_request.prefix IS NOT NULL THEN
            IF pg_catalog.family(v_request.prefix) <> v_request.family THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network alias range family is invalid';
            END IF;
            SELECT pool.prefix INTO v_frame FROM mesh.address_pool AS pool
            WHERE pool.deployment_id = v_scope.deployment_id AND pool.workspace_id IS NULL
              AND pool.purpose = 'federation_resource_alias' AND pool.family = v_request.family
              AND pool.state = 'active' AND pool.deleted_at IS NULL
              AND v_request.prefix <<= pool.prefix
            ORDER BY pool.id LIMIT 1;
            IF v_frame IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'MTR01', MESSAGE = 'Network alias range is outside the frame';
            END IF;
            IF EXISTS (
                SELECT 1 FROM mesh.device_alias_lease AS lease
                WHERE lease.consumer_network_id = v_scope.network_id AND lease.alias_role = 'resource'
                  AND lease.family = v_request.family AND lease.state IN ('reserved', 'quarantined')
                  AND NOT lease.address <<= v_request.prefix
            ) OR EXISTS (
                SELECT 1 FROM mesh.federation_alias_lease AS lease
                WHERE lease.consumer_network_id = v_scope.network_id AND lease.family = v_request.family
                  AND lease.state IN ('reserved', 'active')
                  AND NOT lease.resource_alias <<= v_request.prefix
            ) THEN
                RAISE EXCEPTION USING ERRCODE = 'MTR02', MESSAGE = 'Network alias range would exclude a retained alias';
            END IF;
        END IF;
        SELECT * INTO v_existing FROM mesh.network_alias_range AS range
        WHERE range.network_id = v_scope.network_id AND range.family = v_request.family;
        IF v_existing.id IS NULL THEN
            IF v_request.prefix IS NOT NULL THEN
                INSERT INTO mesh.network_alias_range (
                    public_id, deployment_id, workspace_id, network_id, family, prefix,
                    version, created_at, updated_at
                ) VALUES (
                    v_request.row_public_id, v_scope.deployment_id, v_scope.workspace_id,
                    v_scope.network_id, v_request.family, v_request.prefix, 1, v_now, v_now
                );
                v_changed := TRUE;
            END IF;
        ELSIF v_existing.prefix IS DISTINCT FROM v_request.prefix THEN
            UPDATE mesh.network_alias_range
            SET prefix = v_request.prefix, version = version + 1,
                updated_at = GREATEST(v_now, v_existing.updated_at)
            WHERE id = v_existing.id;
            v_changed := TRUE;
        END IF;
    END LOOP;

    v_after := mesh_ops.network_alias_range_state_internal_v1(v_scope.deployment_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(v_prior, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object(
        'changed', v_changed,
        'role_binding_id', v_scope.role_binding_public_id,
        'network_revision', v_network_revision,
        'before', v_before,
        'after', v_after
    );
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.device_alias_deployment_id', COALESCE(v_prior, ''), TRUE);
    RAISE;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_network_alias_ranges_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_alias_ranges_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.set_network_alias_ranges_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BOOLEAN, CIDR, UUID, BOOLEAN, CIDR, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.set_network_alias_ranges_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT,
    BOOLEAN, CIDR, UUID, BOOLEAN, CIDR, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
