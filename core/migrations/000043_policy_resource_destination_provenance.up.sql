ALTER TABLE mesh.compiled_policy_rule
ADD CONSTRAINT compiled_policy_rule_scope_id_unique UNIQUE (
    workspace_id,
    network_id,
    id
);

CREATE TABLE mesh.compiled_policy_resource_destination (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    compiled_policy_rule_id BIGINT NOT NULL,
    destination_resource_id BIGINT NOT NULL,
    resource_version BIGINT NOT NULL CHECK (resource_version > 0),
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    inventory_revision BIGINT NOT NULL CHECK (inventory_revision > 0),
    resource_semantic_hash BYTEA NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT compiled_policy_resource_destination_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_resource_destination_hash_check CHECK (
        pg_catalog.octet_length(resource_semantic_hash) = 32
        AND resource_semantic_hash
            <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT compiled_policy_resource_destination_rule_scope_fk FOREIGN KEY (
        workspace_id,
        network_id,
        compiled_policy_rule_id
    ) REFERENCES mesh.compiled_policy_rule (
        workspace_id,
        network_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_resource_destination_resource_scope_fk FOREIGN KEY (
        workspace_id,
        network_id,
        destination_resource_id
    ) REFERENCES mesh.resource (
        workspace_id,
        network_id,
        id
    ) ON DELETE RESTRICT,
    UNIQUE (compiled_policy_rule_id)
);

CREATE INDEX compiled_policy_resource_destination_resource_idx
ON mesh.compiled_policy_resource_destination (
    workspace_id,
    network_id,
    destination_resource_id,
    compiled_policy_rule_id
);

ALTER TABLE mesh.compiled_policy_resource_destination ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.compiled_policy_resource_destination FORCE ROW LEVEL SECURITY;
CREATE POLICY compiled_policy_resource_destination_migrator_policy
ON mesh.compiled_policy_resource_destination
TO mesh_migrator
USING (TRUE)
WITH CHECK (TRUE);
CREATE POLICY compiled_policy_resource_destination_exact_scope_policy
ON mesh.compiled_policy_resource_destination
TO mesh_runtime
USING (
    workspace_id = mesh_ops.current_workspace_id()
    AND network_id = mesh_ops.current_network_id()
)
WITH CHECK (
    workspace_id = mesh_ops.current_workspace_id()
    AND network_id = mesh_ops.current_network_id()
);

CREATE TRIGGER compiled_policy_resource_destination_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.compiled_policy_resource_destination
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'compiled_policy_resource_destination',
    'public_id'
);
CREATE TRIGGER compiled_policy_resource_destination_immutable
BEFORE UPDATE OR DELETE ON mesh.compiled_policy_resource_destination
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

CREATE FUNCTION mesh_ops.attach_policy_resource_destinations(
    p_release_public_id UUID,
    p_created_at TIMESTAMPTZ,
    p_rules JSONB
)
RETURNS TABLE (attached_count INTEGER)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    release_internal_id BIGINT;
    expected_count INTEGER;
    valid_count INTEGER;
    inserted_count INTEGER;
BEGIN
    BEGIN
        scoped_workspace_id := NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT;
        scoped_network_id := NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'transaction Network scope is unavailable';
    END;

    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(p_release_public_id),
            6
        ) >> 4 <> 7
        OR p_created_at IS NULL
        OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) > 10000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy Resource destination input is invalid';
    END IF;

    SELECT release.id
    INTO release_internal_id
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace_id
      AND release.network_id = scoped_network_id
      AND release.public_id = p_release_public_id
      AND release.state = 'active'
    FOR KEY SHARE;
    IF release_internal_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'active Policy Release is unavailable';
    END IF;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_public_id UUID,
            destination_resource_version BIGINT,
            destination_target_generation BIGINT,
            destination_inventory_revision BIGINT,
            destination_resource_semantic_hash TEXT
        )
    )
    SELECT
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_resource_public_id IS NOT NULL
               OR rule.destination_resource_version IS NOT NULL
               OR rule.destination_target_generation IS NOT NULL
               OR rule.destination_inventory_revision IS NOT NULL
               OR rule.destination_resource_semantic_hash IS NOT NULL
        )::INTEGER,
        pg_catalog.count(*) FILTER (
            WHERE rule.destination_resource_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_resource_public_id),
                    6
                  ) >> 4 = 7
              AND rule.projection_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.projection_public_id),
                    6
                  ) >> 4 = 7
              AND rule.access_rule_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.access_rule_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_node_public_id IS NOT NULL
              AND pg_catalog.get_byte(
                    pg_catalog.uuid_send(rule.destination_node_public_id),
                    6
                  ) >> 4 = 7
              AND rule.destination_resource_version > 0
              AND rule.destination_target_generation > 0
              AND rule.destination_inventory_revision > 0
              AND rule.destination_resource_semantic_hash
                    ~ '^[0-9a-f]{64}$'
        )::INTEGER
    INTO expected_count, valid_count
    FROM input_rule AS rule;

    IF expected_count IS NULL OR valid_count IS NULL
        OR expected_count = 0
        OR expected_count <> valid_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'policy Resource destination shape is invalid';
    END IF;

    PERFORM resource.id
    FROM mesh.resource AS resource
    JOIN (
        SELECT DISTINCT
            rule.destination_resource_public_id,
            rule.destination_resource_version,
            rule.destination_target_generation,
            rule.destination_inventory_revision,
            rule.destination_resource_semantic_hash
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            destination_resource_public_id UUID,
            destination_resource_version BIGINT,
            destination_target_generation BIGINT,
            destination_inventory_revision BIGINT,
            destination_resource_semantic_hash TEXT
        )
        WHERE rule.destination_resource_public_id IS NOT NULL
    ) AS input_resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = input_resource.destination_resource_public_id
     AND resource.version = input_resource.destination_resource_version
     AND resource.target_generation = input_resource.destination_target_generation
     AND resource.inventory_revision = input_resource.destination_inventory_revision
     AND resource.semantic_hash = pg_catalog.decode(
            input_resource.destination_resource_semantic_hash,
            'hex'
         )
     AND resource.state = 'active'
    ORDER BY resource.id
    FOR KEY SHARE OF resource;

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID,
            access_rule_public_id UUID,
            destination_node_public_id UUID,
            destination_resource_public_id UUID,
            destination_resource_version BIGINT,
            destination_target_generation BIGINT,
            destination_inventory_revision BIGINT,
            destination_resource_semantic_hash TEXT
        )
        WHERE rule.destination_resource_public_id IS NOT NULL
    ),
    resolved AS (
        SELECT
            compiled.id AS compiled_policy_rule_id,
            compiled.public_id AS compiled_policy_rule_public_id,
            resource.id AS resource_id,
            input_rule.destination_resource_version AS resource_version,
            input_rule.destination_target_generation AS target_generation,
            input_rule.destination_inventory_revision AS inventory_revision,
            resource.semantic_hash AS resource_semantic_hash
        FROM input_rule
        JOIN mesh.compiled_policy_rule AS compiled
          ON compiled.workspace_id = scoped_workspace_id
         AND compiled.network_id = scoped_network_id
         AND compiled.policy_release_id = release_internal_id
         AND compiled.public_id = input_rule.projection_public_id
         AND compiled.access_rule_public_id = input_rule.access_rule_public_id
        JOIN mesh.device AS destination
          ON destination.workspace_id = scoped_workspace_id
         AND destination.network_id = scoped_network_id
         AND destination.id = compiled.destination_device_id
         AND destination.public_id = input_rule.destination_node_public_id
         AND destination.state = 'active'
        JOIN mesh.resource AS resource
          ON resource.workspace_id = scoped_workspace_id
         AND resource.network_id = scoped_network_id
         AND resource.public_id = input_rule.destination_resource_public_id
         AND resource.version = input_rule.destination_resource_version
         AND resource.target_generation = input_rule.destination_target_generation
         AND resource.inventory_revision = input_rule.destination_inventory_revision
         AND resource.semantic_hash = pg_catalog.decode(
                input_rule.destination_resource_semantic_hash,
                'hex'
             )
         AND resource.state = 'active'
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = scoped_workspace_id
         AND target.network_id = scoped_network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.device_id = compiled.destination_device_id
         AND target.state = 'active'
    )
    INSERT INTO mesh.compiled_policy_resource_destination (
        public_id,
        workspace_id,
        network_id,
        compiled_policy_rule_id,
        destination_resource_id,
        resource_version,
        target_generation,
        inventory_revision,
        resource_semantic_hash,
        created_at
    )
    SELECT
        resolved.compiled_policy_rule_public_id,
        scoped_workspace_id,
        scoped_network_id,
        resolved.compiled_policy_rule_id,
        resolved.resource_id,
        resolved.resource_version,
        resolved.target_generation,
        resolved.inventory_revision,
        resolved.resource_semantic_hash,
        p_created_at
    FROM resolved
    ORDER BY resolved.compiled_policy_rule_id;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count <> expected_count THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'policy Resource destination changed';
    END IF;

    attached_count := inserted_count;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON mesh.compiled_policy_resource_destination
FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT SELECT ON mesh.compiled_policy_resource_destination TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.attach_policy_resource_destinations(
    UUID,
    TIMESTAMPTZ,
    JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_resource_destinations(
    UUID,
    TIMESTAMPTZ,
    JSONB
) FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_resource_destinations(
    UUID,
    TIMESTAMPTZ,
    JSONB
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
