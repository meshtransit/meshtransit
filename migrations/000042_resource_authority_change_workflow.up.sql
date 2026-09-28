INSERT INTO mesh.permission (
    permission_key,
    description,
    risk_class,
    allowed_scope_kinds,
    catalog_version
) VALUES
    ('resource.transfer', 'Transfer Resource ownership or custody', 'privileged', ARRAY['network'], 1),
    ('resource_group.transfer', 'Transfer Resource Group ownership or custody', 'privileged', ARRAY['network'], 1);

CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    authority_field_changes INTEGER;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource authority is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'resource_device_target' THEN
        IF OLD.public_id <> NEW.public_id
            OR OLD.workspace_id <> NEW.workspace_id
            OR OLD.network_id <> NEW.network_id
            OR OLD.resource_id <> NEW.resource_id
            OR OLD.device_id <> NEW.device_id
            OR OLD.target_generation <> NEW.target_generation
            OR OLD.bound_by_principal_id <> NEW.bound_by_principal_id
            OR OLD.bound_at <> NEW.bound_at
            OR OLD.created_at <> NEW.created_at
            OR OLD.state <> 'active'
            OR NEW.state <> 'superseded'
            OR NEW.version <> OLD.version + 1
            OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource target transition';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME IN ('resource_group_version', 'resource_group_version_member') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'immutable Resource authority cannot change';
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.display_name <> NEW.display_name
        OR OLD.name_key <> NEW.name_key
        OR OLD.created_at <> NEW.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR NEW.activated_network_revision <= OLD.activated_network_revision
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource authority transition';
    END IF;
    authority_field_changes :=
        (OLD.owner_principal_id <> NEW.owner_principal_id)::INTEGER +
        (OLD.custodian_principal_id <> NEW.custodian_principal_id)::INTEGER;
    IF TG_TABLE_NAME = 'resource' THEN
        IF OLD.kind <> NEW.kind
            OR OLD.provenance_kind <> NEW.provenance_kind
            OR OLD.provenance_principal_id <> NEW.provenance_principal_id
            OR OLD.provenance_at <> NEW.provenance_at
            OR NEW.inventory_revision <= OLD.inventory_revision THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource transition';
        END IF;
        IF authority_field_changes = 1 THEN
            IF OLD.state <> NEW.state
                OR OLD.target_generation <> NEW.target_generation
                OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
                OR OLD.semantic_hash = NEW.semantic_hash THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource authority change';
            END IF;
        ELSIF authority_field_changes <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource authority change';
        ELSIF OLD.state <> NEW.state THEN
            IF OLD.semantic_hash <> NEW.semantic_hash
                OR OLD.target_generation <> NEW.target_generation
                OR NOT (
                    (OLD.state = 'active' AND NEW.state IN ('suspended', 'deleted'))
                    OR (OLD.state = 'suspended' AND NEW.state IN ('active', 'deleted'))
                )
                OR (NEW.state = 'deleted' AND (
                    NEW.deleted_at IS NULL OR NEW.deleted_at <> NEW.updated_at
                ))
                OR (NEW.state <> 'deleted' AND NEW.deleted_at IS NOT NULL) THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource lifecycle transition';
            END IF;
        ELSIF NEW.target_generation = OLD.target_generation + 1 THEN
            IF NEW.semantic_hash = OLD.semantic_hash
                OR NEW.deleted_at IS NOT NULL THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource rebind transition';
            END IF;
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'resource_group' THEN
        IF NEW.group_revision <= OLD.group_revision THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group revision';
        END IF;
        IF authority_field_changes = 1 THEN
            IF OLD.state <> NEW.state
                OR OLD.active_definition_version <> NEW.active_definition_version
                OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
                OR OLD.semantic_hash = NEW.semantic_hash THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group authority change';
            END IF;
        ELSIF authority_field_changes <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group authority change';
        ELSIF OLD.state <> NEW.state THEN
            IF OLD.semantic_hash <> NEW.semantic_hash
                OR OLD.active_definition_version <> NEW.active_definition_version
                OR NOT (
                    (OLD.state = 'active' AND NEW.state IN ('suspended', 'deleted'))
                    OR (OLD.state = 'suspended' AND NEW.state IN ('active', 'deleted'))
                )
                OR (NEW.state = 'deleted' AND (
                    NEW.deleted_at IS NULL OR NEW.deleted_at <> NEW.updated_at
                ))
                OR (NEW.state <> 'deleted' AND NEW.deleted_at IS NOT NULL) THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group lifecycle transition';
            END IF;
        ELSIF NEW.active_definition_version = OLD.active_definition_version + 1 THEN
            IF NEW.semantic_hash = OLD.semantic_hash
                OR NEW.deleted_at IS NOT NULL THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group replacement';
            END IF;
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource trigger configuration';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_resource_authority_transition() FROM PUBLIC;

CREATE TABLE mesh.resource_authority_change_request (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    subject_kind TEXT NOT NULL,
    resource_id BIGINT,
    resource_group_id BIGINT,
    action TEXT NOT NULL,
    expected_subject_version BIGINT NOT NULL CHECK (expected_subject_version > 0),
    current_owner_principal_id BIGINT NOT NULL,
    current_custodian_principal_id BIGINT NOT NULL,
    proposed_owner_principal_id BIGINT NOT NULL,
    proposed_custodian_principal_id BIGINT NOT NULL,
    target_principal_id BIGINT NOT NULL,
    requested_by_principal_id BIGINT NOT NULL,
    requested_by_account_session_id BIGINT NOT NULL,
    impact_hash BYTEA NOT NULL,
    required_confirmations SMALLINT NOT NULL DEFAULT 1,
    confirmation_count SMALLINT NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    applied_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT resource_authority_change_request_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_authority_change_request_subject_check CHECK (
        (subject_kind = 'resource' AND resource_id IS NOT NULL AND resource_group_id IS NULL)
        OR
        (subject_kind = 'resource_group' AND resource_id IS NULL AND resource_group_id IS NOT NULL)
    ),
    CONSTRAINT resource_authority_change_request_action_check CHECK (
        action IN ('owner_transfer', 'custodian_delegation')
    ),
    CONSTRAINT resource_authority_change_request_authority_check CHECK (
        (
            action = 'owner_transfer'
            AND proposed_owner_principal_id = target_principal_id
            AND proposed_owner_principal_id <> current_owner_principal_id
            AND proposed_custodian_principal_id = current_custodian_principal_id
        )
        OR
        (
            action = 'custodian_delegation'
            AND proposed_custodian_principal_id = target_principal_id
            AND proposed_custodian_principal_id <> current_custodian_principal_id
            AND proposed_owner_principal_id = current_owner_principal_id
        )
    ),
    CONSTRAINT resource_authority_change_request_requester_check CHECK (
        requested_by_principal_id = current_owner_principal_id
        AND target_principal_id <> requested_by_principal_id
    ),
    CONSTRAINT resource_authority_change_request_impact_hash_check CHECK (
        pg_catalog.octet_length(impact_hash) = 32
        AND impact_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT resource_authority_change_request_quorum_check CHECK (
        required_confirmations = 1
        AND confirmation_count BETWEEN 0 AND required_confirmations
    ),
    CONSTRAINT resource_authority_change_request_state_check CHECK (
        (state = 'pending' AND confirmation_count = 0 AND applied_at IS NULL)
        OR
        (state = 'applied' AND confirmation_count = 1 AND applied_at IS NOT NULL)
    ),
    CONSTRAINT resource_authority_change_request_timestamps_check CHECK (
        updated_at >= created_at
        AND expires_at = created_at + INTERVAL '10 minutes'
        AND (applied_at IS NULL OR (applied_at >= created_at AND applied_at < expires_at))
    ),
    CONSTRAINT resource_authority_change_request_workspace_fk FOREIGN KEY (
        deployment_id, workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_network_fk FOREIGN KEY (
        workspace_id, network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_resource_fk FOREIGN KEY (
        workspace_id, network_id, resource_id
    ) REFERENCES mesh.resource (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_group_fk FOREIGN KEY (
        workspace_id, network_id, resource_group_id
    ) REFERENCES mesh.resource_group (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_owner_fk FOREIGN KEY (
        deployment_id, current_owner_principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_custodian_fk FOREIGN KEY (
        deployment_id, current_custodian_principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_proposed_owner_fk FOREIGN KEY (
        deployment_id, proposed_owner_principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_proposed_custodian_fk FOREIGN KEY (
        deployment_id, proposed_custodian_principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_target_fk FOREIGN KEY (
        deployment_id, target_principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_requester_fk FOREIGN KEY (
        deployment_id, requested_by_principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_change_request_session_fk FOREIGN KEY (
        deployment_id, requested_by_principal_id, requested_by_account_session_id
    ) REFERENCES mesh.account_session (
        deployment_id, principal_id, id
    ) ON DELETE RESTRICT,
    UNIQUE (deployment_id, id),
    UNIQUE (workspace_id, network_id, id)
);

CREATE INDEX resource_authority_change_request_resource_state_idx
ON mesh.resource_authority_change_request (
    workspace_id, network_id, resource_id, state, expires_at, id
) WHERE subject_kind = 'resource';

CREATE INDEX resource_authority_change_request_group_state_idx
ON mesh.resource_authority_change_request (
    workspace_id, network_id, resource_group_id, state, expires_at, id
) WHERE subject_kind = 'resource_group';

CREATE TABLE mesh.resource_authority_step_up_evidence (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    request_id BIGINT NOT NULL,
    account_session_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    evidence_role TEXT NOT NULL,
    operation_semantic_hash BYTEA NOT NULL,
    authentication_time TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT resource_authority_step_up_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_authority_step_up_role_check CHECK (
        evidence_role IN ('requester', 'confirmer')
    ),
    CONSTRAINT resource_authority_step_up_hash_check CHECK (
        pg_catalog.octet_length(operation_semantic_hash) = 32
        AND operation_semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT resource_authority_step_up_freshness_check CHECK (
        authentication_time <= created_at
        AND authentication_time > created_at - INTERVAL '5 minutes'
    ),
    CONSTRAINT resource_authority_step_up_request_fk FOREIGN KEY (
        workspace_id, network_id, request_id
    ) REFERENCES mesh.resource_authority_change_request (
        workspace_id, network_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_step_up_session_fk FOREIGN KEY (
        deployment_id, principal_id, account_session_id
    ) REFERENCES mesh.account_session (
        deployment_id, principal_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT resource_authority_step_up_principal_fk FOREIGN KEY (
        deployment_id, principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (account_session_id),
    UNIQUE (request_id, evidence_role),
    UNIQUE (request_id, principal_id)
);

CREATE FUNCTION mesh_ops.enforce_resource_authority_change_workflow()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource authority change evidence is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'resource_authority_step_up_evidence' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource authority step-up evidence is immutable';
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.subject_kind <> NEW.subject_kind
        OR OLD.resource_id IS DISTINCT FROM NEW.resource_id
        OR OLD.resource_group_id IS DISTINCT FROM NEW.resource_group_id
        OR OLD.action <> NEW.action
        OR OLD.expected_subject_version <> NEW.expected_subject_version
        OR OLD.current_owner_principal_id <> NEW.current_owner_principal_id
        OR OLD.current_custodian_principal_id <> NEW.current_custodian_principal_id
        OR OLD.proposed_owner_principal_id <> NEW.proposed_owner_principal_id
        OR OLD.proposed_custodian_principal_id <> NEW.proposed_custodian_principal_id
        OR OLD.target_principal_id <> NEW.target_principal_id
        OR OLD.requested_by_principal_id <> NEW.requested_by_principal_id
        OR OLD.requested_by_account_session_id <> NEW.requested_by_account_session_id
        OR OLD.impact_hash <> NEW.impact_hash
        OR OLD.required_confirmations <> NEW.required_confirmations
        OR OLD.expires_at <> NEW.expires_at
        OR OLD.created_at <> NEW.created_at
        OR OLD.state <> 'pending'
        OR NEW.state <> 'applied'
        OR OLD.confirmation_count <> 0
        OR NEW.confirmation_count <> 1
        OR OLD.applied_at IS NOT NULL
        OR NEW.applied_at IS NULL
        OR NEW.applied_at <> NEW.updated_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource authority change request transition';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_resource_authority_change_workflow() FROM PUBLIC;

CREATE TRIGGER resource_authority_change_request_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_authority_change_request
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_authority_change_workflow();

CREATE TRIGGER resource_authority_step_up_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_authority_step_up_evidence
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_authority_change_workflow();

CREATE TRIGGER resource_authority_change_request_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_authority_change_request
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'resource_authority_change_request',
    'public_id'
);

CREATE TRIGGER resource_authority_step_up_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_authority_step_up_evidence
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'resource_authority_step_up_evidence',
    'public_id'
);

ALTER TABLE mesh.resource_authority_change_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_authority_change_request FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_authority_change_request_migrator_policy
ON mesh.resource_authority_change_request
USING (CURRENT_USER = 'mesh_migrator')
WITH CHECK (CURRENT_USER = 'mesh_migrator');

ALTER TABLE mesh.resource_authority_step_up_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_authority_step_up_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_authority_step_up_migrator_policy
ON mesh.resource_authority_step_up_evidence
USING (CURRENT_USER = 'mesh_migrator')
WITH CHECK (CURRENT_USER = 'mesh_migrator');

CREATE FUNCTION mesh_ops.resource_authority_change_resource_impact_v1(
    p_resource_public_id UUID,
    p_action TEXT,
    p_target_principal_public_id UUID
)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    resource_state TEXT,
    resource_version BIGINT,
    semantic_hash BYTEA,
    device_public_id UUID,
    target_generation BIGINT,
    target_principal_public_id UUID
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_target_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_principal_public_id), 6) >> 4 <> 7
        OR p_action NOT IN ('owner_transfer', 'custodian_delegation') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource authority change impact input';
    END IF;
    RETURN QUERY
    SELECT resource.display_name,
           owner.public_id,
           custodian.public_id,
           resource.state,
           resource.version,
           resource.semantic_hash,
           device.public_id,
           resource.target_generation,
           target_principal.public_id
    FROM mesh.resource AS resource
    JOIN mesh.principal AS owner ON owner.id = resource.owner_principal_id
    JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = resource.target_generation
     AND target.state = 'active'
    JOIN mesh.device AS device
      ON device.workspace_id = target.workspace_id
     AND device.network_id = target.network_id
     AND device.id = target.device_id
    JOIN mesh.workspace AS workspace ON workspace.id = resource.workspace_id
    JOIN mesh.principal AS target_principal
      ON target_principal.deployment_id = workspace.deployment_id
     AND target_principal.public_id = p_target_principal_public_id
     AND target_principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = target_principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE resource.workspace_id = scoped_workspace_id
      AND resource.network_id = scoped_network_id
      AND resource.public_id = p_resource_public_id
      AND resource.kind = 'device'
    FOR SHARE OF resource, owner, custodian, target, device, workspace, target_principal, membership;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resource_authority_change_resource_impact_v1(UUID, TEXT, UUID)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.preview_resource_authority_change_v1(UUID, TEXT, UUID)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    resource_state TEXT,
    resource_version BIGINT,
    semantic_hash BYTEA,
    device_public_id UUID,
    target_generation BIGINT,
    target_principal_public_id UUID
)
LANGUAGE SQL
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
SELECT * FROM mesh_ops.resource_authority_change_resource_impact_v1($1, $2, $3);
$function$;

CREATE FUNCTION mesh_ops.lock_resource_authority_change_v1(UUID, TEXT, UUID)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    resource_state TEXT,
    resource_version BIGINT,
    semantic_hash BYTEA,
    device_public_id UUID,
    target_generation BIGINT,
    target_principal_public_id UUID
)
LANGUAGE SQL
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
SELECT * FROM mesh_ops.resource_authority_change_resource_impact_v1($1, $2, $3);
$function$;

CREATE FUNCTION mesh_ops.resource_authority_change_group_impact_v1(
    p_group_public_id UUID,
    p_action TEXT,
    p_target_principal_public_id UUID
)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_state TEXT,
    group_version BIGINT,
    definition_version BIGINT,
    semantic_hash BYTEA,
    members JSONB,
    target_principal_public_id UUID
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    current_group_id BIGINT;
    target_principal_id BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL OR p_target_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_principal_public_id), 6) >> 4 <> 7
        OR p_action NOT IN ('owner_transfer', 'custodian_delegation') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group authority change impact input';
    END IF;
    SELECT resource_group.id INTO current_group_id
    FROM mesh.resource_group AS resource_group
    WHERE resource_group.workspace_id = scoped_workspace_id
      AND resource_group.network_id = scoped_network_id
      AND resource_group.public_id = p_group_public_id
    FOR SHARE;
    IF current_group_id IS NULL THEN
        RETURN;
    END IF;
    SELECT principal.id INTO target_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_target_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE workspace.id = scoped_workspace_id
    FOR SHARE OF workspace, principal, membership;
    IF target_principal_id IS NULL THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT resource_group.display_name,
           owner.public_id,
           custodian.public_id,
           resource_group.state,
           resource_group.version,
           resource_group.active_definition_version,
           resource_group.semantic_hash,
           pg_catalog.jsonb_agg(
               pg_catalog.jsonb_build_object(
                   'resource_public_id', resource.public_id,
                   'resource_version', member.resource_version,
                   'target_generation', member.target_generation
               ) ORDER BY member.ordinal
           ),
           p_target_principal_public_id
    FROM mesh.resource_group AS resource_group
    JOIN mesh.principal AS owner ON owner.id = resource_group.owner_principal_id
    JOIN mesh.principal AS custodian ON custodian.id = resource_group.custodian_principal_id
    JOIN mesh.resource_group_version AS version
      ON version.workspace_id = resource_group.workspace_id
     AND version.network_id = resource_group.network_id
     AND version.resource_group_id = resource_group.id
     AND version.definition_version = resource_group.active_definition_version
     AND version.semantic_hash = resource_group.semantic_hash
    JOIN mesh.resource_group_version_member AS member
      ON member.workspace_id = version.workspace_id
     AND member.network_id = version.network_id
     AND member.resource_group_id = version.resource_group_id
     AND member.resource_group_version_id = version.id
    JOIN mesh.resource AS resource
      ON resource.workspace_id = member.workspace_id
     AND resource.network_id = member.network_id
     AND resource.id = member.resource_id
    WHERE resource_group.id = current_group_id
    GROUP BY resource_group.display_name, owner.public_id, custodian.public_id,
             resource_group.state, resource_group.version,
             resource_group.active_definition_version, resource_group.semantic_hash;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resource_authority_change_group_impact_v1(UUID, TEXT, UUID)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.preview_resource_group_authority_change_v1(UUID, TEXT, UUID)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_state TEXT,
    group_version BIGINT,
    definition_version BIGINT,
    semantic_hash BYTEA,
    members JSONB,
    target_principal_public_id UUID
)
LANGUAGE SQL
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
SELECT * FROM mesh_ops.resource_authority_change_group_impact_v1($1, $2, $3);
$function$;

CREATE FUNCTION mesh_ops.lock_resource_group_authority_change_v1(UUID, TEXT, UUID)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_state TEXT,
    group_version BIGINT,
    definition_version BIGINT,
    semantic_hash BYTEA,
    members JSONB,
    target_principal_public_id UUID
)
LANGUAGE SQL
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
SELECT * FROM mesh_ops.resource_authority_change_group_impact_v1($1, $2, $3);
$function$;

CREATE FUNCTION mesh_ops.require_resource_authority_step_up_v1(
    p_account_session_public_id UUID,
    p_principal_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    account_session_id BIGINT,
    principal_id BIGINT,
    authentication_time TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    IF p_account_session_public_id IS NULL OR p_principal_public_id IS NULL
        OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_account_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource authority step-up input';
    END IF;
    RETURN QUERY
    SELECT session.id, session.principal_id, session.authentication_time
    FROM mesh.account_session AS session
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
     AND principal.public_id = p_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_identity_provider AS routing
      ON routing.deployment_id = session.deployment_id
     AND routing.workspace_id = scoped_workspace_id
     AND routing.identity_provider_id = session.identity_provider_id
     AND routing.identity_provider_client_id = session.identity_provider_client_id
     AND routing.state = 'active'
    WHERE session.public_id = p_account_session_public_id
      AND session.login_workspace_id = scoped_workspace_id
      AND session.state = 'active'
      AND session.authentication_time <= p_evaluated_at
      AND session.authentication_time > p_evaluated_at - INTERVAL '5 minutes'
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND routing.minimum_assurance IS NOT NULL
      AND session.acr = routing.minimum_assurance
      AND NOT EXISTS (
          SELECT 1
          FROM mesh.resource_authority_step_up_evidence AS evidence
          WHERE evidence.account_session_id = session.id
      )
    FOR UPDATE OF session;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.require_resource_authority_step_up_v1(UUID, UUID, TIMESTAMPTZ)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.request_resource_authority_change_v1(
    p_request_public_id UUID,
    p_step_up_evidence_public_id UUID,
    p_subject_kind TEXT,
    p_subject_public_id UUID,
    p_action TEXT,
    p_expected_subject_version BIGINT,
    p_target_principal_public_id UUID,
    p_actor_principal_public_id UUID,
    p_actor_account_session_public_id UUID,
    p_impact_hash BYTEA,
    p_occurred_at TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    subsystem_revision BIGINT,
    request_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    scoped_deployment_id BIGINT;
    subject_resource_id BIGINT;
    subject_group_id BIGINT;
    subject_version BIGINT;
    subject_state TEXT;
    current_owner_id BIGINT;
    current_custodian_id BIGINT;
    proposed_owner_id BIGINT;
    proposed_custodian_id BIGINT;
    target_principal_id BIGINT;
    actor_principal_id BIGINT;
    actor_session_id BIGINT;
    actor_authentication_time TIMESTAMPTZ;
    current_network_revision BIGINT;
    current_subsystem_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_subsystem_revision BIGINT;
    inserted_request_id BIGINT;
    inserted_request_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_request_public_id IS NULL OR p_step_up_evidence_public_id IS NULL
        OR p_subject_public_id IS NULL OR p_target_principal_public_id IS NULL
        OR p_actor_principal_public_id IS NULL OR p_actor_account_session_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_step_up_evidence_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_account_session_public_id), 6) >> 4 <> 7
        OR p_subject_kind NOT IN ('resource', 'resource_group')
        OR p_action NOT IN ('owner_transfer', 'custodian_delegation')
        OR p_expected_subject_version IS NULL OR p_expected_subject_version <= 0
        OR p_impact_hash IS NULL OR pg_catalog.octet_length(p_impact_hash) <> 32
        OR p_impact_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL OR p_expires_at IS NULL
        OR p_expires_at <> p_occurred_at + INTERVAL '10 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource authority change request input';
    END IF;
    SELECT workspace.deployment_id INTO scoped_deployment_id
    FROM mesh.workspace AS workspace
    WHERE workspace.id = scoped_workspace_id AND workspace.state = 'active'
    FOR SHARE;
    IF scoped_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource authority change scope is unavailable';
    END IF;
    SELECT step_up.account_session_id, step_up.principal_id, step_up.authentication_time
    INTO actor_session_id, actor_principal_id, actor_authentication_time
    FROM mesh_ops.require_resource_authority_step_up_v1(
        p_actor_account_session_public_id,
        p_actor_principal_public_id,
        p_occurred_at
    ) AS step_up;
    IF actor_session_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT007', MESSAGE = 'fresh step-up evidence is required';
    END IF;
    SELECT principal.id INTO target_principal_id
    FROM mesh.principal AS principal
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = scoped_deployment_id
     AND membership.workspace_id = scoped_workspace_id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= p_occurred_at
     AND (membership.expires_at IS NULL OR membership.expires_at > p_occurred_at)
    WHERE principal.deployment_id = scoped_deployment_id
      AND principal.public_id = p_target_principal_public_id
      AND principal.state = 'active'
    FOR SHARE OF principal, membership;
    IF target_principal_id IS NULL OR target_principal_id = actor_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Resource authority target is unavailable';
    END IF;
    SELECT revision.network_revision,
           CASE WHEN p_subject_kind = 'resource'
                THEN revision.inventory_revision ELSE revision.group_revision END
    INTO current_network_revision, current_subsystem_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF p_subject_kind = 'resource' THEN
        SELECT resource.id, resource.version, resource.state,
               resource.owner_principal_id, resource.custodian_principal_id
        INTO subject_resource_id, subject_version, subject_state,
             current_owner_id, current_custodian_id
        FROM mesh.resource AS resource
        WHERE resource.workspace_id = scoped_workspace_id
          AND resource.network_id = scoped_network_id
          AND resource.public_id = p_subject_public_id
          AND resource.kind = 'device'
        FOR UPDATE;
    ELSE
        SELECT resource_group.id, resource_group.version, resource_group.state,
               resource_group.owner_principal_id, resource_group.custodian_principal_id
        INTO subject_group_id, subject_version, subject_state,
             current_owner_id, current_custodian_id
        FROM mesh.resource_group AS resource_group
        WHERE resource_group.workspace_id = scoped_workspace_id
          AND resource_group.network_id = scoped_network_id
          AND resource_group.public_id = p_subject_public_id
        FOR UPDATE;
    END IF;
    IF subject_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource authority is unavailable';
    END IF;
    IF subject_version <> p_expected_subject_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority version changed';
    END IF;
    IF subject_state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource authority cannot change';
    END IF;
    IF current_owner_id <> actor_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'only the current owner can request authority change';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM mesh.resource_authority_change_request AS request
        WHERE request.workspace_id = scoped_workspace_id
          AND request.network_id = scoped_network_id
          AND request.state = 'pending'
          AND request.expires_at > p_occurred_at
          AND (
              (p_subject_kind = 'resource' AND request.resource_id = subject_resource_id)
              OR
              (p_subject_kind = 'resource_group' AND request.resource_group_id = subject_group_id)
          )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Resource authority change is already pending';
    END IF;
    proposed_owner_id := CASE WHEN p_action = 'owner_transfer'
                              THEN target_principal_id ELSE current_owner_id END;
    proposed_custodian_id := CASE WHEN p_action = 'custodian_delegation'
                                  THEN target_principal_id ELSE current_custodian_id END;
    IF proposed_owner_id = current_owner_id AND proposed_custodian_id = current_custodian_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Resource authority is unchanged';
    END IF;
    IF p_subject_kind = 'resource' THEN
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            inventory_revision = revision.inventory_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.inventory_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.inventory_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
    ELSE
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.group_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.group_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
    END IF;
    IF advanced_network_revision IS NULL OR advanced_subsystem_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource authority revision changed';
    END IF;
    INSERT INTO mesh.resource_authority_change_request (
        public_id, deployment_id, workspace_id, network_id, subject_kind,
        resource_id, resource_group_id, action, expected_subject_version,
        current_owner_principal_id, current_custodian_principal_id,
        proposed_owner_principal_id, proposed_custodian_principal_id,
        target_principal_id, requested_by_principal_id,
        requested_by_account_session_id, impact_hash,
        required_confirmations, confirmation_count, state,
        expires_at, created_at, updated_at
    ) VALUES (
        p_request_public_id, scoped_deployment_id, scoped_workspace_id, scoped_network_id,
        p_subject_kind, subject_resource_id, subject_group_id, p_action,
        p_expected_subject_version, current_owner_id, current_custodian_id,
        proposed_owner_id, proposed_custodian_id, target_principal_id,
        actor_principal_id, actor_session_id, p_impact_hash,
        1, 0, 'pending', p_expires_at, p_occurred_at, p_occurred_at
    ) RETURNING id, version INTO inserted_request_id, inserted_request_version;
    INSERT INTO mesh.resource_authority_step_up_evidence (
        public_id, deployment_id, workspace_id, network_id, request_id,
        account_session_id, principal_id, evidence_role,
        operation_semantic_hash, authentication_time, created_at
    ) VALUES (
        p_step_up_evidence_public_id, scoped_deployment_id, scoped_workspace_id,
        scoped_network_id, inserted_request_id, actor_session_id, actor_principal_id,
        'requester', p_impact_hash, actor_authentication_time, p_occurred_at
    );
    network_revision := advanced_network_revision;
    subsystem_revision := advanced_subsystem_revision;
    request_version := inserted_request_version;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.request_resource_authority_change_v1(
    UUID, UUID, TEXT, UUID, TEXT, BIGINT, UUID, UUID, UUID, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC;

CREATE FUNCTION mesh_ops.lock_resource_authority_change_request_v1(
    p_request_public_id UUID
)
RETURNS TABLE (
    subject_kind TEXT,
    subject_public_id UUID,
    action TEXT,
    target_principal_public_id UUID,
    expected_subject_version BIGINT,
    impact_hash BYTEA,
    request_version BIGINT,
    request_state TEXT,
    expires_at TIMESTAMPTZ,
    requester_session_public_id UUID,
    requester_deployment_public_id UUID,
    requester_principal_public_id UUID,
    requester_identity_subject_public_id UUID,
    requester_login_workspace_public_id UUID,
    requester_authentication_time TIMESTAMPTZ,
    requester_acr TEXT,
    requester_amr TEXT[],
    requester_session_version BIGINT,
    requester_principal_generation BIGINT,
    requester_account_generation BIGINT,
    requester_provider_generation BIGINT,
    requester_recovery_epoch BIGINT,
    requester_idle_expires_at TIMESTAMPTZ,
    requester_absolute_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_request_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource authority change request identity';
    END IF;
    RETURN QUERY
    SELECT request.subject_kind,
           CASE WHEN request.subject_kind = 'resource'
                THEN resource.public_id ELSE resource_group.public_id END,
           request.action,
           target_principal.public_id,
           request.expected_subject_version,
           request.impact_hash,
           request.version,
           request.state,
           request.expires_at,
           session.public_id,
           deployment.installation_public_id,
           requester.public_id,
           subject.public_id,
           workspace.public_id,
           session.authentication_time,
           session.acr,
           session.amr,
           session.version,
           session.principal_authority_generation,
           session.account_session_generation,
           session.provider_generation,
           session.deployment_recovery_epoch,
           session.idle_expires_at,
           session.absolute_expires_at
    FROM mesh.resource_authority_change_request AS request
    JOIN mesh.deployment AS deployment ON deployment.id = request.deployment_id
    JOIN mesh.workspace AS workspace ON workspace.id = request.workspace_id
    JOIN mesh.principal AS requester ON requester.id = request.requested_by_principal_id
    JOIN mesh.principal AS target_principal ON target_principal.id = request.target_principal_id
    JOIN mesh.account_session AS session ON session.id = request.requested_by_account_session_id
    JOIN mesh.identity_subject AS subject ON subject.id = session.identity_subject_id
    LEFT JOIN mesh.resource AS resource ON resource.id = request.resource_id
    LEFT JOIN mesh.resource_group AS resource_group ON resource_group.id = request.resource_group_id
    WHERE request.workspace_id = scoped_workspace_id
      AND request.network_id = scoped_network_id
      AND request.public_id = p_request_public_id
    FOR UPDATE OF request;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lock_resource_authority_change_request_v1(UUID) FROM PUBLIC;

CREATE FUNCTION mesh_ops.confirm_resource_authority_change_v1(
    p_step_up_evidence_public_id UUID,
    p_request_public_id UUID,
    p_expected_request_version BIGINT,
    p_actor_principal_public_id UUID,
    p_actor_account_session_public_id UUID,
    p_impact_hash BYTEA,
    p_proposed_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    subsystem_revision BIGINT,
    subject_version BIGINT,
    request_version BIGINT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    semantic_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    request_row mesh.resource_authority_change_request%ROWTYPE;
    actor_session_id BIGINT;
    actor_principal_id BIGINT;
    actor_authentication_time TIMESTAMPTZ;
    current_subject_version BIGINT;
    current_subject_state TEXT;
    current_owner_id BIGINT;
    current_custodian_id BIGINT;
    current_semantic_hash BYTEA;
    current_network_revision BIGINT;
    current_subsystem_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_subsystem_revision BIGINT;
    advanced_subject_version BIGINT;
    advanced_request_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_step_up_evidence_public_id IS NULL OR p_request_public_id IS NULL
        OR p_actor_principal_public_id IS NULL OR p_actor_account_session_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_step_up_evidence_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_account_session_public_id), 6) >> 4 <> 7
        OR p_expected_request_version IS NULL OR p_expected_request_version <= 0
        OR p_impact_hash IS NULL OR pg_catalog.octet_length(p_impact_hash) <> 32
        OR p_proposed_semantic_hash IS NULL OR pg_catalog.octet_length(p_proposed_semantic_hash) <> 32
        OR p_impact_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_proposed_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource authority confirmation input';
    END IF;
    SELECT request.* INTO request_row
    FROM mesh.resource_authority_change_request AS request
    WHERE request.workspace_id = scoped_workspace_id
      AND request.network_id = scoped_network_id
      AND request.public_id = p_request_public_id
    FOR UPDATE;
    IF request_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource authority change request is unavailable';
    END IF;
    IF request_row.version <> p_expected_request_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority change request version changed';
    END IF;
    IF request_row.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource authority change request is not pending';
    END IF;
    IF p_occurred_at >= request_row.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MT008', MESSAGE = 'Resource authority change request expired';
    END IF;
    IF request_row.impact_hash <> p_impact_hash THEN
        RAISE EXCEPTION USING ERRCODE = 'MT006', MESSAGE = 'Resource authority change impact changed';
    END IF;
    SELECT step_up.account_session_id, step_up.principal_id, step_up.authentication_time
    INTO actor_session_id, actor_principal_id, actor_authentication_time
    FROM mesh_ops.require_resource_authority_step_up_v1(
        p_actor_account_session_public_id,
        p_actor_principal_public_id,
        p_occurred_at
    ) AS step_up;
    IF actor_session_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT007', MESSAGE = 'fresh step-up evidence is required';
    END IF;
    IF actor_principal_id <> request_row.target_principal_id
        OR actor_principal_id = request_row.requested_by_principal_id
        OR actor_session_id = request_row.requested_by_account_session_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'independent confirmation is required';
    END IF;
    SELECT revision.network_revision,
           CASE WHEN request_row.subject_kind = 'resource'
                THEN revision.inventory_revision ELSE revision.group_revision END
    INTO current_network_revision, current_subsystem_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF request_row.subject_kind = 'resource' THEN
        SELECT resource.version, resource.state, resource.owner_principal_id,
               resource.custodian_principal_id, resource.semantic_hash
        INTO current_subject_version, current_subject_state, current_owner_id,
             current_custodian_id, current_semantic_hash
        FROM mesh.resource AS resource
        WHERE resource.workspace_id = scoped_workspace_id
          AND resource.network_id = scoped_network_id
          AND resource.id = request_row.resource_id
        FOR UPDATE;
    ELSE
        SELECT resource_group.version, resource_group.state,
               resource_group.owner_principal_id, resource_group.custodian_principal_id,
               resource_group.semantic_hash
        INTO current_subject_version, current_subject_state, current_owner_id,
             current_custodian_id, current_semantic_hash
        FROM mesh.resource_group AS resource_group
        WHERE resource_group.workspace_id = scoped_workspace_id
          AND resource_group.network_id = scoped_network_id
          AND resource_group.id = request_row.resource_group_id
        FOR UPDATE;
    END IF;
    IF current_subject_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource authority is unavailable';
    END IF;
    IF current_subject_version <> request_row.expected_subject_version
        OR current_owner_id <> request_row.current_owner_principal_id
        OR current_custodian_id <> request_row.current_custodian_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority changed';
    END IF;
    IF current_subject_state = 'deleted' OR current_semantic_hash = p_proposed_semantic_hash THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource authority cannot change';
    END IF;
    IF request_row.subject_kind = 'resource' THEN
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            inventory_revision = revision.inventory_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.inventory_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.inventory_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
        UPDATE mesh.resource AS resource
        SET owner_principal_id = request_row.proposed_owner_principal_id,
            custodian_principal_id = request_row.proposed_custodian_principal_id,
            semantic_hash = p_proposed_semantic_hash,
            activated_network_revision = advanced_network_revision,
            inventory_revision = advanced_subsystem_revision,
            version = resource.version + 1,
            updated_at = p_occurred_at
        WHERE resource.id = request_row.resource_id
          AND resource.version = request_row.expected_subject_version
        RETURNING resource.version INTO advanced_subject_version;
    ELSE
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.group_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.group_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
        UPDATE mesh.resource_group AS resource_group
        SET owner_principal_id = request_row.proposed_owner_principal_id,
            custodian_principal_id = request_row.proposed_custodian_principal_id,
            semantic_hash = p_proposed_semantic_hash,
            activated_network_revision = advanced_network_revision,
            group_revision = advanced_subsystem_revision,
            version = resource_group.version + 1,
            updated_at = p_occurred_at
        WHERE resource_group.id = request_row.resource_group_id
          AND resource_group.version = request_row.expected_subject_version
        RETURNING resource_group.version INTO advanced_subject_version;
    END IF;
    IF advanced_network_revision IS NULL OR advanced_subsystem_revision IS NULL
        OR advanced_subject_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource authority revision changed';
    END IF;
    INSERT INTO mesh.resource_authority_step_up_evidence (
        public_id, deployment_id, workspace_id, network_id, request_id,
        account_session_id, principal_id, evidence_role,
        operation_semantic_hash, authentication_time, created_at
    ) VALUES (
        p_step_up_evidence_public_id, request_row.deployment_id, scoped_workspace_id,
        scoped_network_id, request_row.id, actor_session_id, actor_principal_id,
        'confirmer', p_impact_hash, actor_authentication_time, p_occurred_at
    );
    UPDATE mesh.resource_authority_change_request AS request
    SET confirmation_count = 1,
        state = 'applied',
        applied_at = p_occurred_at,
        version = request.version + 1,
        updated_at = p_occurred_at
    WHERE request.id = request_row.id
      AND request.version = p_expected_request_version
      AND request.state = 'pending'
    RETURNING request.version INTO advanced_request_version;
    IF advanced_request_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority request changed';
    END IF;
    network_revision := advanced_network_revision;
    subsystem_revision := advanced_subsystem_revision;
    subject_version := advanced_subject_version;
    request_version := advanced_request_version;
    SELECT owner.public_id, custodian.public_id
    INTO owner_principal_public_id, custodian_principal_public_id
    FROM mesh.principal AS owner
    JOIN mesh.principal AS custodian
      ON custodian.id = request_row.proposed_custodian_principal_id
    WHERE owner.id = request_row.proposed_owner_principal_id;
    semantic_hash := p_proposed_semantic_hash;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.confirm_resource_authority_change_v1(
    UUID, UUID, BIGINT, UUID, UUID, BYTEA, BYTEA, TIMESTAMPTZ
) FROM PUBLIC;

REVOKE ALL ON mesh.resource_authority_change_request, mesh.resource_authority_step_up_evidence
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

REVOKE ALL ON SEQUENCE mesh.resource_authority_change_request_id_seq,
                       mesh.resource_authority_step_up_evidence_id_seq
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.preview_resource_authority_change_v1(UUID, TEXT, UUID)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_authority_change_v1(UUID, TEXT, UUID)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.preview_resource_group_authority_change_v1(UUID, TEXT, UUID)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_group_authority_change_v1(UUID, TEXT, UUID)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.request_resource_authority_change_v1(
    UUID, UUID, TEXT, UUID, TEXT, BIGINT, UUID, UUID, UUID, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_authority_change_request_v1(UUID)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.confirm_resource_authority_change_v1(
    UUID, UUID, BIGINT, UUID, UUID, BYTEA, BYTEA, TIMESTAMPTZ
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
