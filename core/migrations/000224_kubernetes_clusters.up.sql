-- Schema 224: Kubernetes clusters whose gateways join a Network (K1 design
-- §3, §4.1; K1a1 plan §2). A cluster owns one enrollment profile of kind
-- kubernetes_gateway; its join keys are enrollment credentials of that
-- profile, presented as mtk1.<id>.<secret>. A replica that presents a key
-- opens a request, which holds no Device; an administrator approves it by
-- the code the replica prints, which consumes one use of the key; the
-- replica's session then completes it, which creates a Workspace-owned
-- Device of kind kubernetes_gateway that never expires.
--
-- The ordinary registration functions never accept a join key: the intake
-- scope and both credential locks skip profiles of another kind, so an
-- older Core on this schema refuses join keys too.
--
-- A gateway Device's identity, owner, name and expiry never change, it is
-- never suspended, and no Device Group, tag, alias, share, route, exit, Site
-- or DNS label refers to it; triggers enforce this whichever role writes.
-- Only functions owned by mesh_migrator create gateway Devices, gateway
-- profiles and join keys.
--
-- Errors: 22023 invalid input, 42501 not authorized, P0002 unknown cluster or
-- request, 40001 stale version, MTL01 a gateway Device cannot take part (the
-- code Device lifecycle stores already answer as a conflict),
-- MTK02 the request is not pending, MTK03 too many requests are waiting,
-- MTK04 the key or the request is not usable, MTK05 the cluster still has
-- replicas or requests, MTK06 the keys are already in use.
--
-- Rollback: older binaries read none of the new columns; their registration
-- functions are replaced here in place with the same signatures and refuse
-- join keys.

INSERT INTO mesh.permission (permission_key, description, risk_class, allowed_scope_kinds, catalog_version)
VALUES
    ('kubernetes_cluster.manage',
     'Create and delete the Kubernetes clusters of a Network and issue their join keys',
     'privileged', ARRAY['network'], 1),
    ('kubernetes_cluster.approve',
     'Approve a replica''s request to join a Kubernetes cluster',
     'privileged', ARRAY['network'], 1);

INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT grant_row.role_key, permission.id
FROM (VALUES
    ('admin', 'kubernetes_cluster.manage'),
    ('admin', 'kubernetes_cluster.approve'),
    ('network_admin', 'kubernetes_cluster.manage'),
    ('network_admin', 'kubernetes_cluster.approve')
) AS grant_row(role_key, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key = grant_row.permission_key
ON CONFLICT DO NOTHING;

CREATE TABLE mesh.kubernetes_cluster (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_by_principal_id BIGINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT kubernetes_cluster_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_cluster_name_check CHECK (
        pg_catalog.octet_length(name) BETWEEN 1 AND 60
        AND name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    ),
    CONSTRAINT kubernetes_cluster_description_check CHECK (
        description IS NULL OR (
            pg_catalog.char_length(description) BETWEEN 1 AND 128
            AND description = pg_catalog.btrim(description)
            AND description !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT kubernetes_cluster_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL) OR (state = 'deleted' AND deleted_at IS NOT NULL)
    ),
    CONSTRAINT kubernetes_cluster_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT kubernetes_cluster_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_cluster_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_cluster_creator_fk FOREIGN KEY (created_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX kubernetes_cluster_active_name_uidx
    ON mesh.kubernetes_cluster (workspace_id, network_id, name)
    WHERE state = 'active';

CREATE FUNCTION mesh_ops.enforce_kubernetes_cluster_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Kubernetes clusters are deleted by state, never removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid new Kubernetes cluster';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id <> OLD.network_id
        OR NEW.name <> OLD.name OR NEW.created_by_principal_id <> OLD.created_by_principal_id
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes cluster transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER kubernetes_cluster_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.kubernetes_cluster
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_kubernetes_cluster_transition_v1();
CREATE TRIGGER kubernetes_cluster_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_cluster
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_cluster', 'public_id');

ALTER TABLE mesh.kubernetes_cluster ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_cluster FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_cluster_migrator_policy ON mesh.kubernetes_cluster
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_cluster
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_kubernetes_cluster_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A cluster's enrollment profile: Workspace-owned gateway Devices that never
-- expire, enrolled only by key, never interactively, advertising nothing.
ALTER TABLE mesh.enrollment_profile
    ADD COLUMN device_kind TEXT NOT NULL DEFAULT 'standard',
    ADD COLUMN kubernetes_cluster_id BIGINT;
ALTER TABLE mesh.enrollment_profile
    ADD CONSTRAINT enrollment_profile_device_kind_check CHECK (
        device_kind IN ('standard', 'kubernetes_gateway')
        AND (device_kind = 'kubernetes_gateway') = (kubernetes_cluster_id IS NOT NULL)
        AND (device_kind = 'standard' OR (
            NOT interactive_authorization_enabled AND NOT route_advertisement_allowed
            AND ephemeral_mode = 'persistent' AND credential_use_policy = 'bounded'
        ))
    ) NOT VALID,
    ADD CONSTRAINT enrollment_profile_kubernetes_cluster_fk FOREIGN KEY (
        workspace_id, network_id, kubernetes_cluster_id
    ) REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID;
ALTER TABLE mesh.enrollment_profile VALIDATE CONSTRAINT enrollment_profile_device_kind_check;
ALTER TABLE mesh.enrollment_profile VALIDATE CONSTRAINT enrollment_profile_kubernetes_cluster_fk;
CREATE UNIQUE INDEX enrollment_profile_kubernetes_cluster_uidx
    ON mesh.enrollment_profile (kubernetes_cluster_id)
    WHERE kubernetes_cluster_id IS NOT NULL AND deleted_at IS NULL;

-- Gateway Devices: one per (cluster, ordinal) among the Devices not deleted.
ALTER TABLE mesh.device
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'standard',
    ADD COLUMN kubernetes_cluster_id BIGINT,
    ADD COLUMN kubernetes_ordinal SMALLINT;
ALTER TABLE mesh.device
    ADD CONSTRAINT device_kind_check CHECK (
        kind IN ('standard', 'kubernetes_gateway')
        AND (kind = 'kubernetes_gateway') = (kubernetes_cluster_id IS NOT NULL)
        AND (kubernetes_cluster_id IS NULL) = (kubernetes_ordinal IS NULL)
        AND (kubernetes_ordinal IS NULL OR kubernetes_ordinal BETWEEN 0 AND 63)
        AND (kind = 'standard' OR (ownership = 'workspace' AND NOT is_ephemeral
            AND suspended_reason IS NULL AND handover_principal_id IS NULL AND hostname_locked))
    ) NOT VALID,
    ADD CONSTRAINT device_kubernetes_cluster_fk FOREIGN KEY (
        workspace_id, network_id, kubernetes_cluster_id
    ) REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID;
ALTER TABLE mesh.device VALIDATE CONSTRAINT device_kind_check;
ALTER TABLE mesh.device VALIDATE CONSTRAINT device_kubernetes_cluster_fk;
CREATE UNIQUE INDEX device_kubernetes_ordinal_uidx
    ON mesh.device (kubernetes_cluster_id, kubernetes_ordinal)
    WHERE kubernetes_cluster_id IS NOT NULL AND deleted_at IS NULL;

-- Whether a profile is not a standard one, read as the owner: NULL when it
-- does not exist, which the writer guard treats as a gateway profile.
CREATE FUNCTION mesh_ops.enrollment_profile_is_gateway_internal_v1(p_profile_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT profile.device_kind <> 'standard' FROM mesh.enrollment_profile AS profile WHERE profile.id = p_profile_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enrollment_profile_is_gateway_internal_v1(BIGINT)
    FROM PUBLIC, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.enrollment_profile_is_gateway_internal_v1(BIGINT)
    TO mesh_runtime, mesh_worker;

-- Only a function owned by mesh_migrator creates a gateway profile, a
-- credential on one, or a gateway Device: mesh_runtime may insert profiles,
-- credentials and Devices of its own for ordinary registration. The guard
-- runs as the writer (SECURITY INVOKER), so CURRENT_USER is mesh_migrator
-- only inside the migrator's own functions.
CREATE FUNCTION mesh_ops.enforce_kubernetes_gateway_writer_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_gateway BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'enrollment_credential' THEN
        v_gateway := COALESCE(mesh_ops.enrollment_profile_is_gateway_internal_v1(NEW.enrollment_profile_id), TRUE);
    ELSIF TG_TABLE_NAME = 'enrollment_profile' THEN
        v_gateway := NEW.device_kind <> 'standard'
            OR (TG_OP = 'UPDATE' AND OLD.device_kind <> 'standard');
    ELSE
        v_gateway := NEW.kind <> 'standard';
    END IF;
    IF v_gateway AND CURRENT_USER <> 'mesh_migrator' THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'Kubernetes gateway enrollment is written only by its functions';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_kubernetes_gateway_writer_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER enrollment_profile_kubernetes_writer
BEFORE INSERT OR UPDATE ON mesh.enrollment_profile
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_kubernetes_gateway_writer_v1();
CREATE TRIGGER enrollment_credential_kubernetes_writer
BEFORE INSERT OR UPDATE ON mesh.enrollment_credential
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_kubernetes_gateway_writer_v1();
CREATE TRIGGER device_kubernetes_writer
BEFORE INSERT ON mesh.device
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_kubernetes_gateway_writer_v1();

-- A gateway Device keeps its identity, owner, name and expiry. It is never
-- suspended or handed over; it is revoked or deleted, and a revoked one may
-- be deleted. Everything else (key epochs, session generation) moves as for
-- any Device.
CREATE FUNCTION mesh_ops.enforce_kubernetes_gateway_device_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.kubernetes_cluster_id IS DISTINCT FROM OLD.kubernetes_cluster_id
        OR NEW.kubernetes_ordinal IS DISTINCT FROM OLD.kubernetes_ordinal
        OR NEW.public_id <> OLD.public_id OR NEW.workspace_id <> OLD.workspace_id
        OR NEW.network_id <> OLD.network_id OR NEW.enrollment_profile_id <> OLD.enrollment_profile_id
        OR NEW.owner_principal_id IS DISTINCT FROM OLD.owner_principal_id
        OR NEW.custodian_principal_id IS DISTINCT FROM OLD.custodian_principal_id
        OR NEW.ownership <> OLD.ownership
        OR NEW.hostname <> OLD.hostname OR NEW.hostname_locked <> OLD.hostname_locked
        -- A revoked Device's name is released for others (registration).
        OR (NEW.hostname_key <> OLD.hostname_key AND OLD.state = 'active' AND NEW.state = 'active')
        OR NEW.is_ephemeral <> OLD.is_ephemeral OR NEW.expires_at <> OLD.expires_at
        OR NEW.suspended_reason IS NOT NULL OR NEW.handover_principal_id IS NOT NULL
        OR NEW.created_at <> OLD.created_at
        OR NOT (NEW.state = OLD.state
            OR (OLD.state = 'active' AND NEW.state IN ('revoked', 'deleted'))
            OR (OLD.state = 'revoked' AND NEW.state = 'deleted')) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01',
            MESSAGE = 'a Kubernetes gateway Device is only revoked or deleted';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_kubernetes_gateway_device_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER device_kubernetes_gateway_lifecycle
BEFORE UPDATE ON mesh.device
FOR EACH ROW
WHEN (OLD.kind = 'kubernetes_gateway' OR NEW.kind = 'kubernetes_gateway')
EXECUTE FUNCTION mesh_ops.enforce_kubernetes_gateway_device_v1();

-- Refuses a row that names a gateway Device in any of the columns given as
-- trigger arguments: internal IDs (or arrays of them), or public IDs for
-- columns named *public_id. It reads mesh.device as its owner, so row security of the
-- writer cannot hide a gateway from it.
CREATE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_row JSONB := pg_catalog.to_jsonb(NEW);
    v_column TEXT;
    v_value JSONB;
BEGIN
    FOREACH v_column IN ARRAY TG_ARGV LOOP
        -- A misspelt column would let every row through: refuse instead.
        IF NOT v_row ? v_column THEN
            RAISE EXCEPTION USING ERRCODE = '42703',
                MESSAGE = 'Kubernetes gateway guard names an unknown column ' || v_column;
        END IF;
        v_value := v_row -> v_column;
        CONTINUE WHEN pg_catalog.jsonb_typeof(v_value) = 'null';
        IF pg_catalog.jsonb_typeof(v_value) = 'array' THEN
            PERFORM 1 FROM mesh.device AS device
            WHERE device.kind = 'kubernetes_gateway'
              AND device.id IN (SELECT element::BIGINT FROM pg_catalog.jsonb_array_elements_text(v_value) AS element);
        ELSIF v_column LIKE '%public_id' THEN
            PERFORM 1 FROM mesh.device AS device
            WHERE device.public_id = (v_value #>> '{}')::UUID AND device.kind = 'kubernetes_gateway';
        ELSE
            PERFORM 1 FROM mesh.device AS device
            WHERE device.id = (v_value #>> '{}')::BIGINT AND device.kind = 'kubernetes_gateway';
        END IF;
        IF FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01',
                MESSAGE = 'a Kubernetes gateway Device cannot be used here';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Every table that refers to a Device, except: key epochs, address leases,
-- pending registrations and credential uses (a gateway has them like any
-- Device); the alias client version (what its client supports, reported on
-- every map open); compiled Policy (publication refuses gateways from K1a2
-- on); and history, telemetry and change logs that only record what
-- happened.
CREATE TRIGGER device_alias_client_readiness_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_alias_client_readiness
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1(
    'consumer_device_id', 'provider_device_id');
CREATE TRIGGER network_dns_name_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.network_dns_name
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_public_id');
CREATE TRIGGER exit_pool_serving_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.exit_pool_serving
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_ids');
CREATE TRIGGER device_alias_lease_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_alias_lease
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('owner_device_id');
CREATE TRIGGER device_dns_label_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_dns_label
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER device_exit_offer_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_exit_offer
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER device_group_member_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_group_member
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER device_route_advertisement_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_route_advertisement
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER device_tag_assignment_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.device_tag_assignment
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER direct_device_endpoint_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.direct_device_endpoint
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('target_device_id');
CREATE TRIGGER exit_pool_primary_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.exit_pool_primary
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER network_exit_node_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.network_exit_node
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER network_site_router_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.network_site_router
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER private_endpoint_route_intent_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh_ops.private_endpoint_route_intent
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('target_device_public_id');
CREATE TRIGGER private_endpoint_readiness_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.private_endpoint_readiness
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('target_device_public_id');
CREATE TRIGGER resource_device_target_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.resource_device_target
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');
CREATE TRIGGER site_primary_kubernetes_gateway
BEFORE INSERT OR UPDATE ON mesh.site_primary
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('device_id');

-- A replica's request to join a cluster. It holds no Device: the Device is
-- created only when the replica's session completes an approved request.
-- The nonce Core chose binds the code the replica prints; the reported
-- document is what the pod says about itself, for display only. A request
-- past its deadline is moved to expired by the next function that touches
-- its keys, key or cluster.
CREATE TABLE mesh.kubernetes_replica_request (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    enrollment_credential_id BIGINT NOT NULL,
    machine_key BYTEA NOT NULL,
    machine_key_fingerprint BYTEA NOT NULL,
    node_key BYTEA NOT NULL,
    node_key_fingerprint BYTEA NOT NULL,
    hostname TEXT NOT NULL,
    request_nonce BYTEA NOT NULL,
    reported JSONB NOT NULL DEFAULT '{}'::JSONB,
    state TEXT NOT NULL DEFAULT 'pending',
    failed_code_attempts SMALLINT NOT NULL DEFAULT 0,
    approved_by_principal_id BIGINT,
    approved_at TIMESTAMPTZ,
    completion_deadline TIMESTAMPTZ,
    reserved_ordinal SMALLINT,
    reserved_hostname TEXT,
    device_id BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_replica_request_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_replica_request_keys_check CHECK (
        pg_catalog.octet_length(machine_key) = 32
        AND machine_key <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND pg_catalog.octet_length(machine_key_fingerprint) = 32
        AND pg_catalog.octet_length(node_key) = 32
        AND node_key <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND node_key <> machine_key
        AND pg_catalog.octet_length(node_key_fingerprint) = 32
    ),
    CONSTRAINT kubernetes_replica_request_hostname_check CHECK (
        pg_catalog.char_length(hostname) BETWEEN 1 AND 253 AND hostname = pg_catalog.btrim(hostname)
    ),
    CONSTRAINT kubernetes_replica_request_nonce_check CHECK (
        pg_catalog.octet_length(request_nonce) = 32
        AND request_nonce <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT kubernetes_replica_request_reported_check CHECK (
        -- Core accepts at most 2 KiB of JSON; its jsonb text may be longer.
        pg_catalog.jsonb_typeof(reported) = 'object' AND pg_catalog.octet_length(reported::TEXT) <= 4096
    ),
    CONSTRAINT kubernetes_replica_request_state_check CHECK (
        state IN ('pending', 'approved', 'completed', 'rejected', 'cancelled', 'expired')
        AND failed_code_attempts BETWEEN 0 AND 5
        AND (failed_code_attempts < 5 OR state = 'cancelled')
        AND (approved_at IS NULL) = (approved_by_principal_id IS NULL)
        AND (approved_at IS NULL) = (completion_deadline IS NULL)
        AND (approved_at IS NULL) = (reserved_ordinal IS NULL)
        AND (approved_at IS NULL) = (reserved_hostname IS NULL)
        AND (state NOT IN ('approved', 'completed') OR approved_at IS NOT NULL)
        AND (state NOT IN ('pending', 'rejected') OR approved_at IS NULL)
        AND (state = 'completed') = (device_id IS NOT NULL)
        AND (reserved_ordinal IS NULL OR reserved_ordinal BETWEEN 0 AND 63)
    ),
    CONSTRAINT kubernetes_replica_request_timestamps_check CHECK (
        expires_at > created_at AND updated_at >= created_at
        AND (approved_at IS NULL OR (approved_at >= created_at AND completion_deadline > approved_at))
    ),
    CONSTRAINT kubernetes_replica_request_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_replica_request_credential_fk FOREIGN KEY (workspace_id, network_id, enrollment_credential_id)
        REFERENCES mesh.enrollment_credential (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_replica_request_approver_fk FOREIGN KEY (approved_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_replica_request_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

-- Live requests (waiting or approved) hold their keys.
CREATE UNIQUE INDEX kubernetes_replica_request_live_machine_uidx
    ON mesh.kubernetes_replica_request (machine_key_fingerprint) WHERE state IN ('pending', 'approved');
CREATE UNIQUE INDEX kubernetes_replica_request_live_node_uidx
    ON mesh.kubernetes_replica_request (node_key) WHERE state IN ('pending', 'approved');
-- An ordinal is reserved by at most one approved request of a cluster.
CREATE UNIQUE INDEX kubernetes_replica_request_approved_ordinal_uidx
    ON mesh.kubernetes_replica_request (kubernetes_cluster_id, reserved_ordinal) WHERE state = 'approved';
CREATE INDEX kubernetes_replica_request_credential_idx
    ON mesh.kubernetes_replica_request (enrollment_credential_id) WHERE state IN ('pending', 'approved');
CREATE INDEX kubernetes_replica_request_cluster_idx
    ON mesh.kubernetes_replica_request (kubernetes_cluster_id, created_at DESC);

CREATE FUNCTION mesh_ops.enforce_kubernetes_replica_request_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'replica requests are never removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.version <> 1 OR NEW.failed_code_attempts <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid new replica request';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.workspace_id <> OLD.workspace_id
        OR NEW.network_id <> OLD.network_id OR NEW.kubernetes_cluster_id <> OLD.kubernetes_cluster_id
        OR NEW.enrollment_credential_id <> OLD.enrollment_credential_id
        OR NEW.machine_key <> OLD.machine_key OR NEW.node_key <> OLD.node_key
        OR NEW.node_key_fingerprint <> OLD.node_key_fingerprint OR NEW.hostname <> OLD.hostname
        OR NEW.machine_key_fingerprint <> OLD.machine_key_fingerprint OR NEW.reported <> OLD.reported
        -- What an approval set never changes afterwards.
        OR (OLD.approved_at IS NOT NULL AND (
            NEW.approved_at IS DISTINCT FROM OLD.approved_at
            OR NEW.approved_by_principal_id IS DISTINCT FROM OLD.approved_by_principal_id
            OR NEW.completion_deadline IS DISTINCT FROM OLD.completion_deadline
            OR NEW.reserved_ordinal IS DISTINCT FROM OLD.reserved_ordinal
            OR NEW.reserved_hostname IS DISTINCT FROM OLD.reserved_hostname))
        -- A request expires only past its deadline.
        OR (NEW.state = 'expired' AND OLD.state = 'pending'
            AND OLD.expires_at > pg_catalog.transaction_timestamp())
        OR (NEW.state = 'expired' AND OLD.state = 'approved'
            AND OLD.completion_deadline > pg_catalog.transaction_timestamp())
        OR NEW.request_nonce <> OLD.request_nonce OR NEW.expires_at <> OLD.expires_at
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR NEW.failed_code_attempts < OLD.failed_code_attempts
        OR NOT (
            (OLD.state = 'pending' AND NEW.state IN ('pending', 'approved', 'rejected', 'cancelled', 'expired'))
            OR (OLD.state = 'approved' AND NEW.state IN ('completed', 'cancelled', 'expired'))
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid replica request transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER kubernetes_replica_request_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.kubernetes_replica_request
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_kubernetes_replica_request_transition_v1();
CREATE TRIGGER kubernetes_replica_request_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_replica_request
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_replica_request', 'public_id');

ALTER TABLE mesh.kubernetes_replica_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_replica_request FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_replica_request_migrator_policy ON mesh.kubernetes_replica_request
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_replica_request
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_kubernetes_replica_request_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Opening a request looks for its keys among other registrations.
CREATE INDEX pending_registration_live_node_key_idx
    ON mesh.pending_registration (requested_node_key) WHERE state IN ('pending', 'authorized');
CREATE INDEX pending_registration_live_machine_idx
    ON mesh.pending_registration (machine_key_fingerprint) WHERE state IN ('pending', 'authorized');
CREATE INDEX browser_registration_intent_live_node_key_idx
    ON mesh.browser_registration_intent (requested_node_key) WHERE state IN ('pending', 'approved');

-- A gateway's key use names its request instead of a pending registration.
ALTER TABLE mesh.enrollment_credential_use
    ALTER COLUMN pending_registration_id DROP NOT NULL,
    ADD COLUMN kubernetes_replica_request_id BIGINT;
ALTER TABLE mesh.enrollment_credential_use
    ADD CONSTRAINT enrollment_credential_use_origin_check CHECK (
        (pending_registration_id IS NULL) <> (kubernetes_replica_request_id IS NULL)
    ) NOT VALID,
    ADD CONSTRAINT enrollment_credential_use_kubernetes_request_fk FOREIGN KEY (
        workspace_id, network_id, kubernetes_replica_request_id
    ) REFERENCES mesh.kubernetes_replica_request (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID;
ALTER TABLE mesh.enrollment_credential_use VALIDATE CONSTRAINT enrollment_credential_use_origin_check;
ALTER TABLE mesh.enrollment_credential_use VALIDATE CONSTRAINT enrollment_credential_use_kubernetes_request_fk;
CREATE UNIQUE INDEX enrollment_credential_use_kubernetes_request_uidx
    ON mesh.enrollment_credential_use (kubernetes_replica_request_id)
    WHERE kubernetes_replica_request_id IS NOT NULL;

-- The ordinary registration path never accepts a join key: the intake
-- scope and both credential locks skip credentials of a gateway profile, as
-- if they did not exist. Same signatures, so older binaries on this schema
-- refuse join keys too.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_registration_intake_scope(p_credential_public_id uuid)
 RETURNS TABLE(deployment_public_id uuid, workspace_public_id uuid, network_public_id uuid, recovery_epoch bigint)
 LANGUAGE plpgsql
 STABLE PARALLEL SAFE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    previous_credential_public_id TEXT;
BEGIN
    previous_credential_public_id := pg_catalog.current_setting(
        'mesh.registration_intake_credential_public_id',
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.registration_intake_credential_public_id',
        COALESCE(p_credential_public_id::TEXT, ''),
        TRUE
    );

    RETURN QUERY
    SELECT
        deployment.installation_public_id,
        workspace.public_id,
        network.public_id,
        deployment.recovery_epoch
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.network AS network
      ON network.workspace_id = credential.workspace_id
     AND network.id = credential.network_id
    JOIN mesh.workspace AS workspace
      ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    WHERE credential.public_id = p_credential_public_id
      AND NOT EXISTS (
          SELECT 1 FROM mesh.enrollment_profile AS gateway_profile
          WHERE gateway_profile.id = credential.enrollment_profile_id
            AND gateway_profile.device_kind <> 'standard'
      )
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL;

    PERFORM pg_catalog.set_config(
        'mesh.registration_intake_credential_public_id',
        COALESCE(previous_credential_public_id, ''),
        TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.registration_intake_credential_public_id',
            COALESCE(previous_credential_public_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.lock_registration_credential(p_credential_public_id uuid)
 RETURNS TABLE(credential_internal_id bigint, profile_internal_id bigint, issuer_internal_id bigint, issuer_public_id text, credential_state text, use_limit_kind text, max_uses bigint, used_count bigint, issued_recovery_epoch bigint, valid_from timestamp with time zone, expires_at timestamp with time zone, credential_version bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
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

    RETURN QUERY
    SELECT
        credential.id,
        credential.enrollment_profile_id,
        credential.issuer_principal_id,
        principal.public_id::TEXT,
        credential.state,
        credential.use_limit_kind,
        credential.max_uses,
        credential.used_count,
        credential.issued_recovery_epoch,
        credential.valid_from,
        credential.expires_at,
        credential.version
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.principal AS principal ON principal.id = credential.issuer_principal_id
    WHERE credential.workspace_id = scoped_workspace_id
      AND credential.network_id = scoped_network_id
      AND credential.public_id = p_credential_public_id
      AND NOT EXISTS (
          SELECT 1 FROM mesh.enrollment_profile AS gateway_profile
          WHERE gateway_profile.id = credential.enrollment_profile_id
            AND gateway_profile.device_kind <> 'standard'
      )
    FOR UPDATE OF credential;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'scoped enrollment credential is unavailable';
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.lock_registration_credential_v2(p_credential_public_id uuid)
 RETURNS TABLE(credential_internal_id bigint, profile_internal_id bigint, issuer_internal_id bigint, issuer_public_id text, credential_state text, use_limit_kind text, max_uses bigint, used_count bigint, issued_recovery_epoch bigint, valid_from timestamp with time zone, expires_at timestamp with time zone, credential_version bigint, device_lifetime_seconds bigint, device_never_expires boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT credential.id, credential.enrollment_profile_id, credential.issuer_principal_id,
        principal.public_id::TEXT, credential.state, credential.use_limit_kind, credential.max_uses,
        credential.used_count, credential.issued_recovery_epoch, credential.valid_from,
        credential.expires_at, credential.version, credential.device_lifetime_seconds,
        credential.device_never_expires
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.principal AS principal ON principal.id = credential.issuer_principal_id
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id
      AND NOT EXISTS (
          SELECT 1 FROM mesh.enrollment_profile AS gateway_profile
          WHERE gateway_profile.id = credential.enrollment_profile_id
            AND gateway_profile.device_kind <> 'standard'
      )
    FOR UPDATE OF credential;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'scoped enrollment credential is unavailable';
    END IF;
END;
$function$;

-- The caller's grant of one permission in the Network: the scope, the
-- acting account and the authority for the audit record. Raises 42501.
CREATE FUNCTION mesh_ops.kubernetes_cluster_grant_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT, actor_id BIGINT, authority JSONB)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_grant RECORD;
    v_actor BIGINT;
BEGIN
    IF p_permission NOT IN ('network.read', 'kubernetes_cluster.manage', 'kubernetes_cluster.approve')
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: scope';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, pg_catalog.transaction_timestamp()
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: permission';
    END IF;
    SELECT principal.id INTO v_actor FROM mesh.principal AS principal
    JOIN mesh.deployment AS deployment ON deployment.id = principal.deployment_id
    WHERE principal.deployment_id = v_scope.deployment_id AND principal.public_id = p_principal_public_id
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND deployment.recovery_epoch = p_deployment_recovery_epoch;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes cluster action is not authorized: actor';
    END IF;
    RETURN QUERY SELECT v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, v_actor,
        mesh_ops.enrollment_key_authority_internal_v1(
            v_grant.role_binding_public_id, v_grant.role_definition_public_id,
            v_grant.binding_authority_generation, v_grant.membership_authority_generation,
            v_grant.workspace_owner_authority_generation);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_grant_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.kubernetes_cluster_document_internal_v1(p_cluster mesh.kubernetes_cluster)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'cluster_id', p_cluster.public_id,
        'name', p_cluster.name,
        'description', p_cluster.description,
        'state', p_cluster.state,
        'version', p_cluster.version,
        'created_by_principal_id', creator.public_id,
        'created_at', p_cluster.created_at,
        'updated_at', p_cluster.updated_at,
        'replicas', (
            SELECT pg_catalog.count(*) FROM mesh.device AS device
            WHERE device.workspace_id = p_cluster.workspace_id AND device.network_id = p_cluster.network_id
              AND device.kubernetes_cluster_id = p_cluster.id AND device.deleted_at IS NULL
              AND device.state = 'active'
        )
    )
    FROM mesh.principal AS creator
    WHERE creator.id = p_cluster.created_by_principal_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_document_internal_v1(mesh.kubernetes_cluster)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A request as the API shows it: never the nonce. The state is derived on
-- the transaction clock for a waiting or approved request past its deadline.
CREATE FUNCTION mesh_ops.kubernetes_replica_request_document_internal_v1(
    p_request mesh.kubernetes_replica_request
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'request_id', p_request.public_id,
        'cluster_id', cluster.public_id,
        'key_id', credential.public_id,
        'machine_key_fingerprint', pg_catalog.encode(p_request.machine_key_fingerprint, 'hex'),
        'node_key_fingerprint', pg_catalog.encode(p_request.node_key_fingerprint, 'hex'),
        'hostname', p_request.hostname,
        'reported', p_request.reported,
        'state', CASE
            WHEN p_request.state = 'pending'
                 AND p_request.expires_at <= pg_catalog.transaction_timestamp() THEN 'expired'
            WHEN p_request.state = 'approved'
                 AND p_request.completion_deadline <= pg_catalog.transaction_timestamp() THEN 'expired'
            ELSE p_request.state
        END,
        'failed_code_attempts', p_request.failed_code_attempts,
        'approved_by_principal_id', approver.public_id,
        'approved_at', p_request.approved_at,
        'completion_deadline', p_request.completion_deadline,
        'reserved_ordinal', p_request.reserved_ordinal,
        'reserved_hostname', p_request.reserved_hostname,
        'device_id', device.public_id,
        'expires_at', p_request.expires_at,
        'version', p_request.version,
        'created_at', p_request.created_at,
        'updated_at', p_request.updated_at
    )
    FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.enrollment_credential AS credential ON credential.id = p_request.enrollment_credential_id
    LEFT JOIN mesh.principal AS approver ON approver.id = p_request.approved_by_principal_id
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = p_request.workspace_id AND device.network_id = p_request.network_id
     AND device.id = p_request.device_id
    WHERE cluster.id = p_request.kubernetes_cluster_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_replica_request_document_internal_v1(mesh.kubernetes_replica_request)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Moves the waiting and approved requests past their deadlines to expired:
-- of one key, one cluster, or holding one of two keys. They then no longer
-- hold their keys, ordinals or queue places.
CREATE FUNCTION mesh_ops.expire_kubernetes_replica_requests_internal_v1(
    p_credential_id BIGINT, p_cluster_id BIGINT, p_machine_fingerprint BYTEA, p_node_key BYTEA
)
RETURNS VOID
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'expired', version = request.version + 1,
        updated_at = GREATEST(pg_catalog.transaction_timestamp(), request.updated_at)
    WHERE request.state IN ('pending', 'approved')
      AND ((request.state = 'pending' AND request.expires_at <= pg_catalog.transaction_timestamp())
        OR (request.state = 'approved' AND request.completion_deadline <= pg_catalog.transaction_timestamp()))
      AND (request.enrollment_credential_id = p_credential_id
        OR request.kubernetes_cluster_id = p_cluster_id
        OR request.machine_key_fingerprint = p_machine_fingerprint
        OR request.node_key = p_node_key)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.expire_kubernetes_replica_requests_internal_v1(BIGINT, BIGINT, BYTEA, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.kubernetes_network_revision_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS BIGINT
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT revision.network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_workspace_id AND revision.network_id = p_network_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_network_revision_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates a cluster and its enrollment profile (kubernetes_cluster.manage).
-- At most p_cluster_limit active clusters per Network (MTK07).
CREATE FUNCTION mesh_ops.create_kubernetes_cluster_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_name TEXT, p_description TEXT, p_cluster_limit INTEGER, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_count BIGINT;
    v_constraint TEXT;
BEGIN
    IF p_cluster_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_cluster_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_name IS NULL OR p_cluster_limit IS NULL OR p_cluster_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    -- Clusters of one Network serialize on its revision row.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_grant.workspace_id AND revision.network_id = v_grant.network_id
    FOR UPDATE;
    SELECT pg_catalog.count(*) INTO v_count FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.state = 'active';
    IF v_count >= p_cluster_limit THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK07', MESSAGE = 'the Network has the most Kubernetes clusters it may have';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    BEGIN
        INSERT INTO mesh.kubernetes_cluster (
            public_id, deployment_id, workspace_id, network_id, name, description, created_by_principal_id,
            created_at, updated_at
        ) VALUES (
            p_cluster_public_id, v_grant.deployment_id, v_grant.workspace_id, v_grant.network_id, p_name,
            NULLIF(p_description, ''), v_grant.actor_id, v_now, v_now
        ) RETURNING * INTO v_cluster;
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
        IF v_constraint = 'kubernetes_cluster_active_name_uidx' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK08',
                MESSAGE = 'the Network already has a Kubernetes cluster of this name';
        END IF;
        RAISE;
    END;
    INSERT INTO mesh.enrollment_profile (
        public_id, workspace_id, network_id, created_by_principal_id, display_name, name_key,
        node_lifetime_seconds, ephemeral_mode, route_advertisement_allowed, credential_use_policy,
        credential_max_uses, state, interactive_authorization_enabled, device_never_expires,
        device_kind, kubernetes_cluster_id, created_at, updated_at
    ) VALUES (
        pg_catalog.uuidv7(), v_grant.workspace_id, v_grant.network_id, v_grant.actor_id,
        'Kubernetes cluster ' || p_name, 'kubernetes-cluster:' || p_cluster_public_id::TEXT,
        15552000, 'persistent', FALSE, 'bounded', 8, 'active', FALSE, TRUE,
        'kubernetes_gateway', v_cluster.id, v_now, v_now
    );
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'authority', v_grant.authority
    );
END;
$function$;

-- Deletes a cluster that has no replica left and no request waiting or
-- approved (MTK05); its profile is deleted and its keys revoked.
CREATE FUNCTION mesh_ops.delete_kubernetes_cluster_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_expected_version BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_cluster%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    SELECT * INTO v_before FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    IF p_expected_version IS NOT NULL AND p_expected_version <> v_before.version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'the Kubernetes cluster changed';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    -- Lock order: cluster (above), then keys, then requests.
    PERFORM 1 FROM mesh.enrollment_credential AS credential
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    WHERE profile.kubernetes_cluster_id = v_before.id
    ORDER BY credential.id
    FOR UPDATE OF credential;
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(NULL, v_before.id, NULL, NULL);
    IF EXISTS (
        SELECT 1 FROM mesh.device AS device
        WHERE device.workspace_id = v_grant.workspace_id AND device.network_id = v_grant.network_id
          AND device.kubernetes_cluster_id = v_before.id AND device.deleted_at IS NULL
    ) OR EXISTS (
        SELECT 1 FROM mesh.kubernetes_replica_request AS request
        WHERE request.kubernetes_cluster_id = v_before.id AND request.state IN ('pending', 'approved')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK05', MESSAGE = 'the Kubernetes cluster still has replicas or requests';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = v_now, version = credential.version + 1,
        updated_at = GREATEST(v_now, credential.updated_at)
    FROM mesh.enrollment_profile AS profile
    WHERE profile.kubernetes_cluster_id = v_before.id AND credential.enrollment_profile_id = profile.id
      AND credential.state = 'active';
    UPDATE mesh.enrollment_profile AS profile
    SET state = 'deleted', deleted_at = v_now, version = profile.version + 1,
        updated_at = GREATEST(v_now, profile.updated_at)
    WHERE profile.kubernetes_cluster_id = v_before.id AND profile.deleted_at IS NULL;
    UPDATE mesh.kubernetes_cluster AS cluster
    SET state = 'deleted', deleted_at = v_now, version = cluster.version + 1,
        updated_at = GREATEST(v_now, cluster.updated_at)
    WHERE cluster.id = v_before.id
    RETURNING * INTO v_cluster;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_cluster_document_internal_v1(v_before),
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'authority', v_grant.authority
    );
END;
$function$;

-- The Network's active clusters by name, at most p_limit (network.read).
CREATE FUNCTION mesh_ops.list_kubernetes_clusters_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'clusters', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_cluster_document_internal_v1(listed) ORDER BY listed.name)
            FROM (
                SELECT cluster.* FROM mesh.kubernetes_cluster AS cluster
                WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
                  AND cluster.state = 'active'
                ORDER BY cluster.name
                LIMIT p_limit
            ) AS listed
        ), '[]'::JSONB)
    );
END;
$function$;

-- Issues a join key for an active cluster (kubernetes_cluster.manage):
-- 5 minutes to an hour, 1 to 8 uses; at most 16 usable keys per cluster
-- (MTK07). Devices it enrolls never expire.
CREATE FUNCTION mesh_ops.issue_kubernetes_join_key_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_key_public_id UUID,
    p_digest_key_id TEXT, p_token_digest BYTEA, p_token_fingerprint BYTEA,
    p_key_lifetime_seconds BIGINT, p_uses BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_profile BIGINT;
    v_usable BIGINT;
    v_credential mesh.enrollment_credential%ROWTYPE;
BEGIN
    IF p_key_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_key_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_cluster_public_id IS NULL OR p_digest_key_id IS NULL OR p_token_digest IS NULL
        OR p_token_fingerprint IS NULL
        OR p_key_lifetime_seconds IS NULL OR p_key_lifetime_seconds NOT BETWEEN 300 AND 3600
        OR p_uses IS NULL OR p_uses NOT BETWEEN 1 AND 8 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'join key request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT profile.id INTO STRICT v_profile FROM mesh.enrollment_profile AS profile
    WHERE profile.kubernetes_cluster_id = v_cluster.id AND profile.deleted_at IS NULL
      AND profile.state = 'active' AND profile.device_kind = 'kubernetes_gateway';
    SELECT pg_catalog.count(*) INTO v_usable FROM mesh.enrollment_credential AS credential
    WHERE credential.workspace_id = v_grant.workspace_id AND credential.network_id = v_grant.network_id
      AND credential.enrollment_profile_id = v_profile AND credential.state = 'active'
      AND credential.deleted_at IS NULL AND credential.used_count < credential.max_uses
      AND credential.expires_at > v_now;
    IF v_usable >= 16 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK07', MESSAGE = 'the Kubernetes cluster already has 16 usable join keys';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.enrollment_credential (
        public_id, workspace_id, network_id, enrollment_profile_id, issuer_principal_id,
        digest_algorithm, digest_key_id, token_digest, token_fingerprint, issued_recovery_epoch,
        use_limit_kind, max_uses, used_count, valid_from, expires_at, state,
        device_lifetime_seconds, device_never_expires, description, created_at, updated_at
    ) VALUES (
        p_key_public_id, v_grant.workspace_id, v_grant.network_id, v_profile, v_grant.actor_id,
        'hmac-sha256-v1', p_digest_key_id, p_token_digest, p_token_fingerprint, p_deployment_recovery_epoch,
        'bounded', p_uses, 0, v_now, v_now + pg_catalog.make_interval(secs => p_key_lifetime_seconds), 'active',
        NULL, TRUE, NULL, v_now, v_now
    )
    RETURNING * INTO v_credential;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'key', mesh_ops.kubernetes_join_key_document_internal_v1(v_credential),
        'authority', v_grant.authority
    );
END;
$function$;

-- A join key as the API shows it, never its digest.
CREATE FUNCTION mesh_ops.kubernetes_join_key_document_internal_v1(p_credential mesh.enrollment_credential)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'key_id', p_credential.public_id,
        'issued_by_principal_id', issuer.public_id,
        'created_at', p_credential.valid_from,
        'expires_at', p_credential.expires_at,
        'revoked_at', p_credential.revoked_at,
        'uses', p_credential.max_uses,
        'used', p_credential.used_count,
        'version', p_credential.version,
        'state', CASE
            WHEN p_credential.state = 'revoked' THEN 'revoked'
            WHEN p_credential.used_count >= p_credential.max_uses THEN 'used'
            WHEN p_credential.expires_at <= pg_catalog.transaction_timestamp() THEN 'expired'
            ELSE 'active'
        END
    )
    FROM mesh.principal AS issuer
    WHERE issuer.id = p_credential.issuer_principal_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_join_key_document_internal_v1(mesh.enrollment_credential)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Revokes a join key (kubernetes_cluster.manage) and cancels its waiting and
-- approved requests: an approved request no longer completes.
CREATE FUNCTION mesh_ops.revoke_kubernetes_join_key_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID, p_key_public_id UUID,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.enrollment_credential%ROWTYPE;
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_cancelled BIGINT;
BEGIN
    IF p_cluster_public_id IS NULL OR p_key_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'join key request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.manage');
    -- Lock order: cluster, then key, then requests.
    PERFORM 1 FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id
    FOR UPDATE;
    SELECT credential.* INTO v_before FROM mesh.enrollment_credential AS credential
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = profile.kubernetes_cluster_id
    WHERE credential.workspace_id = v_grant.workspace_id AND credential.network_id = v_grant.network_id
      AND credential.public_id = p_key_public_id AND cluster.public_id = p_cluster_public_id
      AND profile.device_kind = 'kubernetes_gateway'
    FOR UPDATE OF credential;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown join key';
    END IF;
    IF v_before.state <> 'active' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK04', MESSAGE = 'the join key is already revoked';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = v_now, version = credential.version + 1,
        updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.id = v_before.id
    RETURNING * INTO v_credential;
    WITH cancelled AS (
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1,
            updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.enrollment_credential_id = v_before.id AND request.state IN ('pending', 'approved')
        RETURNING 1
    )
    SELECT pg_catalog.count(*) INTO v_cancelled FROM cancelled;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'cluster_id', p_cluster_public_id,
        'before', mesh_ops.kubernetes_join_key_document_internal_v1(v_before),
        'key', mesh_ops.kubernetes_join_key_document_internal_v1(v_credential),
        'cancelled_requests', v_cancelled,
        'authority', v_grant.authority
    );
END;
$function$;

-- One cluster with its keys, newest first (at most p_key_limit), its
-- replicas by ordinal and its latest requests (at most p_request_limit):
-- network.read sees the cluster and replicas; keys and requests need
-- kubernetes_cluster.manage or kubernetes_cluster.approve.
CREATE FUNCTION mesh_ops.read_kubernetes_cluster_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_key_limit INTEGER, p_request_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_manager BOOLEAN;
BEGIN
    IF p_cluster_public_id IS NULL OR p_key_limit IS NULL OR p_key_limit NOT BETWEEN 1 AND 256
        OR p_request_limit IS NULL OR p_request_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes cluster request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'network.read');
    v_manager := EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'kubernetes_cluster.manage',
            pg_catalog.transaction_timestamp()))
        OR EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'kubernetes_cluster.approve',
            pg_catalog.transaction_timestamp()));
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'cluster', mesh_ops.kubernetes_cluster_document_internal_v1(v_cluster),
        'replicas', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'device_id', device.public_id, 'name', device.hostname,
                'ordinal', device.kubernetes_ordinal, 'state', device.state,
                'created_at', device.created_at
            ) ORDER BY device.kubernetes_ordinal, device.id)
            FROM mesh.device AS device
            WHERE device.workspace_id = v_grant.workspace_id AND device.network_id = v_grant.network_id
              AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
        ), '[]'::JSONB),
        'keys', CASE WHEN v_manager THEN COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_join_key_document_internal_v1(listed)
                ORDER BY listed.valid_from DESC, listed.id DESC)
            FROM (
                SELECT credential.* FROM mesh.enrollment_credential AS credential
                JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
                WHERE profile.kubernetes_cluster_id = v_cluster.id
                ORDER BY credential.valid_from DESC, credential.id DESC
                LIMIT p_key_limit
            ) AS listed
        ), '[]'::JSONB) END,
        'requests', CASE WHEN v_manager THEN COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.kubernetes_replica_request_document_internal_v1(listed)
                ORDER BY listed.created_at DESC, listed.id DESC)
            FROM (
                SELECT request.* FROM mesh.kubernetes_replica_request AS request
                WHERE request.kubernetes_cluster_id = v_cluster.id
                ORDER BY request.created_at DESC, request.id DESC
                LIMIT p_request_limit
            ) AS listed
        ), '[]'::JSONB) END
    );
END;
$function$;

-- The Network of a join key, for a replica's session before it has a scope:
-- only keys of a gateway profile of an active cluster, in an active
-- Network, Workspace and deployment.
CREATE FUNCTION mesh_ops.resolve_kubernetes_join_scope_v1(p_credential_public_id UUID)
RETURNS TABLE (
    deployment_public_id UUID, workspace_public_id UUID, network_public_id UUID, recovery_epoch BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_previous TEXT := pg_catalog.current_setting('mesh.registration_intake_credential_public_id', TRUE);
BEGIN
    -- The Workspace and Network rows are readable for this credential only
    -- (the intake scope policies of schema 13).
    PERFORM pg_catalog.set_config('mesh.registration_intake_credential_public_id',
        COALESCE(p_credential_public_id::TEXT, ''), TRUE);
    RETURN QUERY
    SELECT deployment.installation_public_id, workspace.public_id, network.public_id, deployment.recovery_epoch
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = profile.kubernetes_cluster_id
    JOIN mesh.network AS network
      ON network.workspace_id = credential.workspace_id AND network.id = credential.network_id
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE credential.public_id = p_credential_public_id
      AND profile.device_kind = 'kubernetes_gateway' AND profile.deleted_at IS NULL
      AND cluster.state = 'active'
      AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL;
    PERFORM pg_catalog.set_config('mesh.registration_intake_credential_public_id', COALESCE(v_previous, ''), TRUE);
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.registration_intake_credential_public_id',
            COALESCE(v_previous, ''), TRUE);
        RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.resolve_kubernetes_join_scope_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_kubernetes_join_scope_v1(UUID) TO mesh_runtime;

-- Locks a join key of the transaction's Network and returns what Go checks
-- the presented secret against. Unknown keys raise 23503, as for
-- enrollment keys.
CREATE FUNCTION mesh_ops.lock_kubernetes_join_key_v1(p_credential_public_id UUID)
RETURNS TABLE (
    digest_algorithm TEXT, digest_key_id TEXT, token_digest BYTEA, credential_state TEXT,
    issued_recovery_epoch BIGINT, valid_from TIMESTAMPTZ, expires_at TIMESTAMPTZ,
    max_uses BIGINT, used_count BIGINT, cluster_public_id UUID
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_cluster BIGINT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    -- Lock order: cluster, then key, then requests.
    SELECT profile.kubernetes_cluster_id INTO v_cluster
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id AND profile.device_kind = 'kubernetes_gateway';
    PERFORM 1 FROM mesh.kubernetes_cluster AS cluster WHERE cluster.id = v_cluster FOR SHARE;
    RETURN QUERY
    SELECT credential.digest_algorithm, credential.digest_key_id, credential.token_digest, credential.state,
        credential.issued_recovery_epoch, credential.valid_from, credential.expires_at,
        credential.max_uses, credential.used_count, cluster.public_id
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = profile.kubernetes_cluster_id
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id
      AND profile.device_kind = 'kubernetes_gateway' AND cluster.state = 'active'
    FOR UPDATE OF credential;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'scoped join key is unavailable';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_kubernetes_join_key_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_kubernetes_join_key_v1(UUID) TO mesh_runtime;

-- Opens a request for a replica whose join key Go has just verified in this
-- transaction (the key is locked). The key must be usable and of the
-- deployment's recovery epoch (MTK04); the machine key must never have been
-- any Device's and the node key never any Device's or another registration's
-- (MTK06); at most twice the key's uses may wait (MTK03). The same machine
-- key and node key on the same key get their open request back
-- (created = false).
CREATE FUNCTION mesh_ops.open_kubernetes_replica_request_v1(
    p_credential_public_id UUID, p_request_public_id UUID, p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA, p_node_key BYTEA, p_node_key_fingerprint BYTEA, p_hostname TEXT,
    p_reported JSONB, p_request_nonce BYTEA, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_epoch BIGINT;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_waiting BIGINT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_credential_public_id IS NULL OR p_request_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR p_machine_key IS NULL OR p_machine_key_fingerprint IS NULL OR p_node_key IS NULL
        OR p_node_key_fingerprint IS NULL
        OR p_hostname IS NULL OR p_reported IS NULL OR p_request_nonce IS NULL
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT credential.* INTO v_credential FROM mesh.enrollment_credential AS credential
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id
    FOR UPDATE;
    SELECT cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.enrollment_profile AS profile ON profile.kubernetes_cluster_id = cluster.id
    WHERE profile.id = v_credential.enrollment_profile_id AND profile.device_kind = 'kubernetes_gateway'
      AND profile.deleted_at IS NULL AND cluster.state = 'active';
    SELECT deployment.recovery_epoch INTO v_epoch FROM mesh.workspace AS workspace
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE workspace.id = v_workspace;
    IF v_credential.id IS NULL OR v_cluster.id IS NULL OR v_credential.state <> 'active'
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch
        OR v_credential.valid_from > v_now OR v_credential.expires_at <= v_now
        OR v_credential.used_count >= v_credential.max_uses THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK04', MESSAGE = 'the join key is not usable';
    END IF;
    -- Past-deadline requests of this key, or holding these keys under
    -- another key, are moved to expired first. Those other requests are
    -- taken out of the usual lock order; a deadlock with another key's
    -- approval is possible only over two stale rows, and PostgreSQL resolves
    -- it (40P01, a conflict the caller retries).
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(
        v_credential.id, NULL, p_machine_key_fingerprint, p_node_key);

    SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
    WHERE request.machine_key_fingerprint = p_machine_key_fingerprint
      AND request.state IN ('pending', 'approved');
    IF FOUND THEN
        IF v_request.node_key <> p_node_key OR v_request.enrollment_credential_id <> v_credential.id
            OR v_request.machine_key <> p_machine_key THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK06', MESSAGE = 'the keys are already in use';
        END IF;
        RETURN pg_catalog.jsonb_build_object(
            'created', FALSE,
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
            'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
        );
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.device_machine_key_epoch AS epoch
               WHERE epoch.fingerprint = p_machine_key_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh.device_node_key_epoch AS epoch WHERE epoch.public_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS request
                   WHERE request.node_key = p_node_key AND request.state IN ('pending', 'approved'))
        OR EXISTS (SELECT 1 FROM mesh.pending_registration AS pending
                   WHERE pending.state IN ('pending', 'authorized') AND pending.requested_node_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.pending_registration AS pending
                   WHERE pending.state IN ('pending', 'authorized')
                     AND pending.machine_key_fingerprint = p_machine_key_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh.browser_registration_intent AS intent
                   WHERE intent.state IN ('pending', 'approved') AND intent.requested_node_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.browser_registration_intent AS intent
                   JOIN mesh.workspace AS workspace ON workspace.deployment_id = intent.deployment_id
                   WHERE workspace.id = v_workspace AND intent.state IN ('pending', 'approved')
                     AND intent.machine_key_fingerprint = p_machine_key_fingerprint) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK06', MESSAGE = 'the keys are already in use';
    END IF;
    SELECT pg_catalog.count(*) INTO v_waiting FROM mesh.kubernetes_replica_request AS request
    WHERE request.enrollment_credential_id = v_credential.id AND request.state = 'pending';
    IF v_waiting >= 2 * v_credential.max_uses THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK03', MESSAGE = 'too many replicas are waiting for this join key';
    END IF;
    INSERT INTO mesh.kubernetes_replica_request (
        public_id, workspace_id, network_id, kubernetes_cluster_id, enrollment_credential_id,
        machine_key, machine_key_fingerprint, node_key, node_key_fingerprint, hostname, request_nonce, reported,
        expires_at, created_at, updated_at
    ) VALUES (
        p_request_public_id, v_workspace, v_network, v_cluster.id, v_credential.id,
        p_machine_key, p_machine_key_fingerprint, p_node_key, p_node_key_fingerprint, p_hostname, p_request_nonce,
        p_reported,
        v_credential.expires_at, v_now, v_now
    ) RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'created', TRUE,
        'key_issuer_principal_id', (SELECT issuer.public_id FROM mesh.principal AS issuer
                                    WHERE issuer.id = v_credential.issuer_principal_id),
        'network_id', (SELECT network.public_id FROM mesh.network AS network
                       WHERE network.workspace_id = v_workspace AND network.id = v_network),
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_workspace, v_network),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.open_kubernetes_replica_request_v1(
    UUID, UUID, BYTEA, BYTEA, BYTEA, BYTEA, TEXT, JSONB, BYTEA, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.open_kubernetes_replica_request_v1(
    UUID, UUID, BYTEA, BYTEA, BYTEA, BYTEA, TEXT, JSONB, BYTEA, UUID
) TO mesh_runtime;

-- Locks a request of an active cluster for an administrator's decision
-- (kubernetes_cluster.approve) after moving it to expired if it is past its
-- deadline. Returns its keys and nonce, from which Go computes the code.
CREATE FUNCTION mesh_ops.lock_kubernetes_replica_request_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_cluster_public_id UUID, p_request_public_id UUID
)
RETURNS mesh.kubernetes_replica_request
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_cluster BIGINT;
    v_credential BIGINT;
BEGIN
    -- Lock order: cluster, then key, then request; the request is read
    -- again under its lock.
    SELECT request.kubernetes_cluster_id, request.enrollment_credential_id INTO v_cluster, v_credential
    FROM mesh.kubernetes_replica_request AS request
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = request.kubernetes_cluster_id
    WHERE request.workspace_id = p_workspace_id AND request.network_id = p_network_id
      AND request.public_id = p_request_public_id AND cluster.public_id = p_cluster_public_id;
    PERFORM 1 FROM mesh.kubernetes_cluster AS cluster WHERE cluster.id = v_cluster AND cluster.state = 'active'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown replica request';
    END IF;
    PERFORM 1 FROM mesh.enrollment_credential AS credential WHERE credential.id = v_credential FOR UPDATE;
    SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
    WHERE request.workspace_id = p_workspace_id AND request.network_id = p_network_id
      AND request.public_id = p_request_public_id AND request.kubernetes_cluster_id = v_cluster
      AND request.enrollment_credential_id = v_credential
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown replica request';
    END IF;
    IF (v_request.state = 'pending' AND v_request.expires_at <= pg_catalog.transaction_timestamp())
        OR (v_request.state = 'approved'
            AND v_request.completion_deadline <= pg_catalog.transaction_timestamp()) THEN
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'expired', version = request.version + 1,
            updated_at = GREATEST(pg_catalog.transaction_timestamp(), request.updated_at)
        WHERE request.id = v_request.id
        RETURNING * INTO v_request;
    END IF;
    RETURN v_request;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_kubernetes_replica_request_internal_v1(BIGINT, BIGINT, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.lock_kubernetes_replica_request_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    -- Moving a request past its deadline to expired is a change too.
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    v_request := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    RETURN pg_catalog.jsonb_build_object(
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'machine_key', pg_catalog.encode(v_request.machine_key, 'hex'),
        'node_key', pg_catalog.encode(v_request.node_key, 'hex'),
        'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
    );
END;
$function$;

-- Approves a waiting request (kubernetes_cluster.approve) after Go matched
-- the code in this transaction. The key is checked again under its lock:
-- revoked (also by offboarding its issuer), expired, used up or of an older
-- recovery epoch cancels the request instead (outcome = cancelled, nothing
-- consumed). Otherwise one use is consumed, the lowest free ordinal and the
-- name <cluster>-<ordinal> are reserved, and the replica has 15 minutes to
-- complete. A request that is no longer waiting raises MTK02; a cluster with
-- 64 replicas raises MTK07.
CREATE FUNCTION mesh_ops.approve_kubernetes_replica_request_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_code BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_epoch BIGINT;
    v_digest BYTEA;
    v_ordinal SMALLINT;
    v_hostname TEXT;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_before := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    IF v_before.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    SELECT cluster.* INTO STRICT v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.id = v_before.kubernetes_cluster_id;
    -- The code is checked here too, not only by Core: the first 50 bits of
    -- SHA-256(label || 0x00 || machine key || node key || cluster ID || nonce)
    -- (shared/kubejoin).
    v_digest := pg_catalog.sha256(pg_catalog.convert_to('meshtransit/kube-join-code/v1', 'UTF8')
        || pg_catalog.decode('00', 'hex') || v_before.machine_key || v_before.node_key
        || pg_catalog.uuid_send(v_cluster.public_id) || v_before.request_nonce);
    IF p_code IS DISTINCT FROM (
        (pg_catalog.get_byte(v_digest, 0)::BIGINT << 42) | (pg_catalog.get_byte(v_digest, 1)::BIGINT << 34)
        | (pg_catalog.get_byte(v_digest, 2)::BIGINT << 26) | (pg_catalog.get_byte(v_digest, 3)::BIGINT << 18)
        | (pg_catalog.get_byte(v_digest, 4)::BIGINT << 10) | (pg_catalog.get_byte(v_digest, 5)::BIGINT << 2)
        | (pg_catalog.get_byte(v_digest, 6)::BIGINT >> 6)) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK09', MESSAGE = 'the code does not match the request';
    END IF;
    SELECT credential.* INTO v_credential FROM mesh.enrollment_credential AS credential
    WHERE credential.id = v_before.enrollment_credential_id;
    SELECT deployment.recovery_epoch INTO v_epoch FROM mesh.deployment AS deployment
    WHERE deployment.id = v_grant.deployment_id;
    IF v_credential.state <> 'active' OR v_credential.expires_at <= v_now OR v_credential.valid_from > v_now
        OR v_credential.used_count >= v_credential.max_uses
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch THEN
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.id = v_before.id
        RETURNING * INTO v_request;
        RETURN pg_catalog.jsonb_build_object(
            'outcome', 'cancelled',
            'network_id', p_network_public_id,
            'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
                v_grant.workspace_id, v_grant.network_id),
            'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
            'authority', v_grant.authority
        );
    END IF;
    -- Ordinals of one cluster are reserved under its row lock, taken above.
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(NULL, v_cluster.id, NULL, NULL);
    SELECT candidate.ordinal INTO v_ordinal
    FROM pg_catalog.generate_series(0, 63) AS candidate(ordinal)
    WHERE NOT EXISTS (
        SELECT 1 FROM mesh.device AS device
        WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
          AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
          AND device.kubernetes_ordinal = candidate.ordinal
    ) AND NOT EXISTS (
        SELECT 1 FROM mesh.kubernetes_replica_request AS request
        WHERE request.kubernetes_cluster_id = v_cluster.id AND request.state = 'approved'
          AND request.reserved_ordinal = candidate.ordinal
    )
    ORDER BY candidate.ordinal
    LIMIT 1;
    IF v_ordinal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK07', MESSAGE = 'the Kubernetes cluster has 64 replicas';
    END IF;
    v_hostname := v_cluster.name || '-' || v_ordinal::TEXT;
    UPDATE mesh.enrollment_credential AS credential
    SET used_count = credential.used_count + 1, version = credential.version + 1,
        updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.id = v_credential.id;
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'approved', approved_by_principal_id = v_grant.actor_id, approved_at = v_now,
        completion_deadline = v_now + INTERVAL '15 minutes', reserved_ordinal = v_ordinal,
        reserved_hostname = v_hostname, version = request.version + 1,
        updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'approved',
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

-- Counts a wrong code on a waiting request (kubernetes_cluster.approve); the
-- fifth cancels it. A request that is no longer waiting raises MTK02.
CREATE FUNCTION mesh_ops.record_kubernetes_join_code_failure_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_before := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    IF v_before.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_replica_request AS request
    SET failed_code_attempts = request.failed_code_attempts + 1,
        state = CASE WHEN request.failed_code_attempts + 1 >= 5 THEN 'cancelled' ELSE request.state END,
        version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

-- Rejects a waiting request (kubernetes_cluster.approve). A request that is
-- no longer waiting raises MTK02.
CREATE FUNCTION mesh_ops.reject_kubernetes_replica_request_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_before := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    IF v_before.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'rejected', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

-- The management functions take an account Session and authorize it.
REVOKE ALL ON FUNCTION mesh_ops.create_kubernetes_cluster_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, TEXT, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.create_kubernetes_cluster_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TEXT, TEXT, INTEGER, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.delete_kubernetes_cluster_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.delete_kubernetes_cluster_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_clusters_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_clusters_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_cluster_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_cluster_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.issue_kubernetes_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, TEXT, BYTEA, BYTEA, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.issue_kubernetes_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, TEXT, BYTEA, BYTEA, BIGINT, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.revoke_kubernetes_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_kubernetes_join_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.lock_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.approve_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.approve_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_join_code_failure_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_join_code_failure_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.reject_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.reject_kubernetes_replica_request_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
