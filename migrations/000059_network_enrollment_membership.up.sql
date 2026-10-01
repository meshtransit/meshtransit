CREATE TABLE mesh.network_membership (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    workspace_membership_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT network_membership_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_membership_state_check CHECK (
        state IN ('active', 'suspended', 'revoked')
    ),
    CONSTRAINT network_membership_validity_check CHECK (
        expires_at IS NULL OR expires_at > valid_from
    ),
    CONSTRAINT network_membership_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_membership_network_scope_fk FOREIGN KEY (
        workspace_id,
        network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_membership_workspace_member_fk FOREIGN KEY (
        deployment_id,
        workspace_id,
        principal_id,
        workspace_membership_id
    ) REFERENCES mesh.workspace_membership (
        deployment_id,
        workspace_id,
        principal_id,
        id
    ) ON DELETE RESTRICT,
    UNIQUE (deployment_id, workspace_id, network_id, principal_id, id)
);

CREATE UNIQUE INDEX network_membership_current_uidx
    ON mesh.network_membership (deployment_id, workspace_id, network_id, principal_id)
    WHERE state <> 'revoked';
CREATE INDEX network_membership_principal_choice_idx
    ON mesh.network_membership (deployment_id, principal_id, state, workspace_id, network_id)
    WHERE state = 'active';
CREATE INDEX network_membership_network_state_idx
    ON mesh.network_membership (workspace_id, network_id, state, principal_id);

CREATE FUNCTION mesh_ops.enforce_network_membership_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Network membership authority is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.principal_id <> NEW.principal_id
        OR OLD.workspace_membership_id <> NEW.workspace_membership_id
        OR OLD.valid_from <> NEW.valid_from
        OR NEW.version <> OLD.version + 1
        OR NEW.authority_generation <> OLD.authority_generation + 1
        OR NEW.updated_at < OLD.updated_at
        OR OLD.state = 'revoked' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid Network membership transition';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_network_membership_transition() FROM PUBLIC;

CREATE TRIGGER network_membership_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.network_membership
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_membership_transition();

CREATE TRIGGER network_membership_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_membership
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'network_membership',
    'public_id'
);

ALTER TABLE mesh.network_membership ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_membership FORCE ROW LEVEL SECURITY;
CREATE POLICY network_membership_migrator_policy ON mesh.network_membership
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY network_membership_exact_scope_policy ON mesh.network_membership
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

REVOKE ALL ON TABLE mesh.network_membership
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
