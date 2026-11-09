-- Schema 280: deleting a Network, phase 2 (docs/network-delete-design.md
-- §4.1, N1b). The worker takes one unfinished deletion at a time
-- (FOR UPDATE SKIP LOCKED, so replicas never share one; a stuck one does
-- not hold the others back), revokes up to a
-- batch of its Devices in one transaction with one evidence record, and
-- once none is left revokes its memberships and roles, drops its pending
-- Resource removals and holds its prefixes for 24 hours. Network creation
-- releases held prefixes past their quarantine, under the Workspace lock it
-- already takes, before it checks for overlaps.

-- Holding and releasing prefixes: inside this transaction's Workspace,
-- with the release switched on by the two functions that do it.
CREATE POLICY network_prefix_deletion_hold_release ON mesh.network_prefix
    FOR UPDATE TO mesh_migrator
    USING (workspace_id = mesh_ops.current_workspace_id()
           AND pg_catalog.current_setting('mesh.network_prefix_release', TRUE) = 'on')
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id()
           AND pg_catalog.current_setting('mesh.network_prefix_release', TRUE) = 'on');

CREATE OR REPLACE FUNCTION mesh_ops.create_network_v2(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_display_name text, p_ipv4_prefix cidr, p_ipv6_prefix cidr, p_ipv4_prefix_public_id uuid, p_ipv6_prefix_public_id uuid, p_membership_public_id uuid, p_enrollment_profile_public_id uuid, p_change_public_id uuid)
 RETURNS TABLE(network_public_id uuid, network_display_code text, network_version bigint, network_created_at timestamp with time zone, network_ipv4_prefix cidr, network_ipv6_prefix cidr, replayed boolean, actor_binding_public_id uuid, actor_role_public_id uuid, actor_binding_generation bigint, actor_membership_generation bigint, actor_owner_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    actor RECORD;
    actor_principal_id BIGINT;
    actor_membership_id BIGINT;
    deployment_internal_id BIGINT;
    existing mesh.network%ROWTYPE;
    pool_v4 mesh.address_pool%ROWTYPE;
    pool_v6 mesh.address_pool%ROWTYPE;
    created_network_id BIGINT;
    evaluated_at TIMESTAMPTZ;
    assigned_ipv6 CIDR;
    existing_ipv6 CIDR;
    pool_hex TEXT;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_network_public_id, p_ipv4_prefix_public_id,
        p_ipv6_prefix_public_id, p_membership_public_id, p_enrollment_profile_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
        END IF;
    END LOOP;
    IF p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR pg_catalog.btrim(p_display_name) <> p_display_name
        OR p_ipv4_prefix IS NULL OR pg_catalog.family(p_ipv4_prefix) <> 4
        OR pg_catalog.masklen(p_ipv4_prefix) NOT BETWEEN 16 AND 28
        OR NOT (p_ipv4_prefix <<= '100.64.0.0/10'::CIDR)
        OR (p_ipv6_prefix IS NOT NULL AND (pg_catalog.family(p_ipv6_prefix) <> 6
            OR pg_catalog.masklen(p_ipv6_prefix) NOT BETWEEN 56 AND 112)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    -- Network creation in one Workspace is serialized by its row lock.
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR NO KEY UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'network.create', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT principal.id, membership.id INTO STRICT actor_principal_id, actor_membership_id
    FROM mesh.principal AS principal
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = principal.deployment_id
     AND membership.workspace_id = scoped_workspace_id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
    WHERE principal.public_id = p_principal_public_id;

    SELECT * INTO existing FROM mesh.network AS network
    WHERE network.workspace_id = scoped_workspace_id AND network.public_id = p_network_public_id;
    IF FOUND THEN
        SELECT prefix.prefix INTO existing_ipv6 FROM mesh.network_prefix AS prefix
        WHERE prefix.network_id = existing.id AND prefix.family = 6 AND prefix.state = 'active';
        IF existing.display_name <> p_display_name OR NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS prefix
            WHERE prefix.network_id = existing.id AND prefix.prefix = p_ipv4_prefix AND prefix.state = 'active'
        ) OR (p_ipv6_prefix IS NOT NULL AND existing_ipv6 IS DISTINCT FROM p_ipv6_prefix) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Network ID was used for another request';
        END IF;
        PERFORM pg_catalog.set_config('mesh.network_id', existing.id::TEXT, TRUE);
        RETURN QUERY
        SELECT existing.public_id, identity.display_code, existing.version, existing.created_at,
            p_ipv4_prefix, existing_ipv6, TRUE,
            actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
            actor.membership_authority_generation, actor.workspace_owner_authority_generation
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE identity.network_public_id = existing.public_id;
        RETURN;
    END IF;

    SELECT pool.* INTO pool_v4 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 4
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND p_ipv4_prefix <<= pool.prefix;
    SELECT pool.* INTO pool_v6 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 6
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND (p_ipv6_prefix IS NULL OR p_ipv6_prefix <<= pool.prefix)
    ORDER BY pool.id
    LIMIT 1;
    IF pool_v4.id IS NULL OR pool_v6.id IS NULL OR pool_v4.address_realm_id <> pool_v6.address_realm_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Network prefix is outside the Workspace address pools';
    END IF;
    -- Schema 280: ranges of deleted Networks held past their quarantine are
    -- released here, under the Workspace lock this function holds, before
    -- the overlap check and the IPv6 assignment, as Device leases are.
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_prefix_release', 'on', TRUE);
    UPDATE mesh.network_prefix AS prefix
    SET state = 'released', quarantine_until = NULL, version = prefix.version + 1,
        updated_at = GREATEST(evaluated_at, prefix.updated_at)
    WHERE prefix.workspace_id = scoped_workspace_id AND prefix.state = 'quarantined'
      AND prefix.quarantine_until <= evaluated_at;
    PERFORM pg_catalog.set_config('mesh.network_prefix_release', '', TRUE);
    assigned_ipv6 := p_ipv6_prefix;
    IF assigned_ipv6 IS NULL THEN
        -- First free /64 of the /48 pool: the pool's 48-bit routing prefix
        -- plus a 16-bit subnet ID, skipping any overlap in the realm.
        IF pg_catalog.masklen(pool_v6.prefix) <> 48 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Workspace IPv6 pool cannot assign /64 ranges';
        END IF;
        pool_hex := pg_catalog.encode(pg_catalog.substr(
            pg_catalog.inet_send(pg_catalog.network(pool_v6.prefix)), 5, 6), 'hex');
        SELECT candidate.prefix INTO assigned_ipv6
        FROM pg_catalog.generate_series(0, 65535) AS subnet(id)
        CROSS JOIN LATERAL (
            SELECT (pg_catalog.substr(pool_hex, 1, 4) || ':' || pg_catalog.substr(pool_hex, 5, 4)
                || ':' || pg_catalog.substr(pool_hex, 9, 4) || ':'
                || pg_catalog.lpad(pg_catalog.to_hex(subnet.id), 4, '0') || '::/64')::CIDR AS prefix
        ) AS candidate
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS used
            WHERE used.address_realm_id = pool_v6.address_realm_id
              AND used.state IN ('reserved', 'active', 'quarantined')
              AND used.prefix && candidate.prefix
        )
        ORDER BY subnet.id
        LIMIT 1;
        IF assigned_ipv6 IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Workspace IPv6 pool is exhausted';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.network_prefix AS prefix
        WHERE prefix.address_realm_id = pool_v4.address_realm_id
          AND prefix.state IN ('reserved', 'active', 'quarantined')
          AND (prefix.prefix && p_ipv4_prefix OR prefix.prefix && assigned_ipv6)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23P01', MESSAGE = 'network_prefix_overlap';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT pg_catalog.nextval(pg_catalog.pg_get_serial_sequence('mesh.network', 'id')) INTO created_network_id;
    PERFORM pg_catalog.set_config('mesh.network_id', created_network_id::TEXT, TRUE);
    INSERT INTO mesh.network (id, public_id, workspace_id, display_name, name_key, node_limit, state)
    OVERRIDING SYSTEM VALUE
    VALUES (created_network_id, p_network_public_id, scoped_workspace_id, p_display_name,
        pg_catalog.lower(p_display_name), 1000, 'active');
    INSERT INTO mesh_ops.network_revision (workspace_id, network_id) VALUES (scoped_workspace_id, created_network_id);
    INSERT INTO mesh.network_prefix (
        public_id, workspace_id, network_id, address_realm_id, address_pool_id, prefix, family, state
    ) VALUES
        (p_ipv4_prefix_public_id, scoped_workspace_id, created_network_id, pool_v4.address_realm_id, pool_v4.id,
            p_ipv4_prefix, 4, 'active'),
        (p_ipv6_prefix_public_id, scoped_workspace_id, created_network_id, pool_v6.address_realm_id, pool_v6.id,
            assigned_ipv6, 6, 'active');
    INSERT INTO mesh.network_membership (
        public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id, state, valid_from
    ) VALUES (
        p_membership_public_id, deployment_internal_id, scoped_workspace_id, created_network_id,
        actor_principal_id, actor_membership_id, 'active', evaluated_at
    );
    INSERT INTO mesh.enrollment_profile (
        public_id, workspace_id, network_id, created_by_principal_id, display_name, name_key,
        node_lifetime_seconds, ephemeral_mode, credential_use_policy, state, interactive_authorization_enabled
    ) VALUES (
        p_enrollment_profile_public_id, scoped_workspace_id, created_network_id, actor_principal_id,
        'Interactive login', 'interactive-login', 2592000, 'persistent', 'unlimited', 'active', TRUE
    );
    INSERT INTO mesh_audit.audit_stream (deployment_id, workspace_id, network_id, scope_kind)
    VALUES (deployment_internal_id, scoped_workspace_id, created_network_id, 'network');

    RETURN QUERY
    SELECT network.public_id, identity.display_code, network.version, network.created_at,
        p_ipv4_prefix, assigned_ipv6, FALSE,
        actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
        actor.membership_authority_generation, actor.workspace_owner_authority_generation
    FROM mesh.network AS network
    JOIN mesh_ops.tenant_display_identity AS identity ON identity.network_public_id = network.public_id
    WHERE network.id = created_network_id;
END;
$function$
;


-- The evidence a step described, for finalize in the same transaction.
-- Only the migrator reaches it, so a worker session cannot swap it.
CREATE TABLE mesh_ops.network_deletion_proof (
    transaction_id BIGINT PRIMARY KEY,
    change_public_id UUID NOT NULL,
    proof JSONB NOT NULL
);
ALTER TABLE mesh_ops.network_deletion_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_deletion_proof FORCE ROW LEVEL SECURITY;
CREATE POLICY network_deletion_proof_migrator_policy ON mesh_ops.network_deletion_proof
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.network_deletion_proof
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- How long phase 2 holds a deleted Network's prefixes once it completes.
CREATE FUNCTION mesh_ops.network_prefix_hold_v1()
RETURNS INTERVAL
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$ SELECT INTERVAL '24 hours' $function$;

-- One step for one deletion, its row locked by the caller: revokes up to
-- p_batch Devices under the Network's revision lock, and finishes the
-- deletion once none is left. MTN03 when every Device left is locked by
-- another writer (nothing changed).
CREATE FUNCTION mesh_ops.network_deletion_step_internal_v1(
    p_deletion mesh_ops.network_deletion, p_change UUID, p_batch INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_deletion mesh_ops.network_deletion%ROWTYPE := p_deletion;
    v_network mesh.network%ROWTYPE;
    v_device RECORD;
    v_revoked INTEGER := 0;
    v_left BOOLEAN;
    v_memberships INTEGER := 0;
    v_bindings INTEGER := 0;
    v_assignments INTEGER := 0;
    v_removals INTEGER := 0;
    v_prefixes INTEGER := 0;
    v_advanced JSONB;
    v_head RECORD;
    v_audit JSONB;
    v_outbox JSONB;
BEGIN
    -- The deleted Network's scope, as set_network_scope gives a request.
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_deletion.workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', v_deletion.network_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    SELECT * INTO STRICT v_network FROM mesh.network AS network
    WHERE network.workspace_id = v_deletion.workspace_id AND network.id = v_deletion.network_id;
    IF v_network.state <> 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'a Network being deleted is not deleted';
    END IF;
    -- The revision, then rows, as every writer of the Network.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_deletion.workspace_id AND revision.network_id = v_deletion.network_id
    FOR UPDATE;

    FOR v_device IN
        SELECT device.id FROM mesh.device AS device
        WHERE device.workspace_id = v_deletion.workspace_id AND device.network_id = v_deletion.network_id
          AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
        ORDER BY device.id
        LIMIT p_batch
        FOR UPDATE SKIP LOCKED
    LOOP
        PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'network deleted', v_now);
        v_revoked := v_revoked + 1;
    END LOOP;
    -- Any Device still unrevoked, locked ones included.
    v_left := EXISTS (
        SELECT 1 FROM mesh.device AS device
        WHERE device.workspace_id = v_deletion.workspace_id AND device.network_id = v_deletion.network_id
          AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL);
    IF v_revoked = 0 AND v_left THEN
        -- Every Device left is held by another writer: give the locks back
        -- (the caller rolls this back to its savepoint) and try later.
        RAISE EXCEPTION USING ERRCODE = 'MTN03', MESSAGE = 'every Device left is locked';
    END IF;

    IF NOT v_left THEN
        UPDATE mesh.network_membership AS membership
        SET state = 'revoked', authority_generation = membership.authority_generation + 1,
            version = membership.version + 1, updated_at = GREATEST(v_now, membership.updated_at)
        WHERE membership.workspace_id = v_deletion.workspace_id AND membership.network_id = v_deletion.network_id
          AND membership.state <> 'revoked';
        GET DIAGNOSTICS v_memberships = ROW_COUNT;
        UPDATE mesh.role_binding AS binding
        SET state = 'revoked', authority_generation = binding.authority_generation + 1,
            version = binding.version + 1, updated_at = GREATEST(v_now, binding.updated_at)
        WHERE binding.workspace_id = v_deletion.workspace_id AND binding.network_id = v_deletion.network_id
          AND binding.state <> 'revoked';
        GET DIAGNOSTICS v_bindings = ROW_COUNT;
        UPDATE mesh.workspace_role_assignment AS assignment
        SET state = 'revoked', revoked_at = GREATEST(v_now, assignment.created_at),
            authority_generation = assignment.authority_generation + 1, version = assignment.version + 1,
            updated_at = GREATEST(v_now, assignment.updated_at)
        WHERE assignment.workspace_id = v_deletion.workspace_id AND assignment.network_id = v_deletion.network_id
          AND assignment.state = 'active';
        GET DIAGNOSTICS v_assignments = ROW_COUNT;
        -- Nobody edits a deleted Network's policy again: a Resource removal
        -- waiting for it would retry for ever (schema 185).
        DELETE FROM mesh_ops.resource_device_removal AS removal
        WHERE removal.workspace_id = v_deletion.workspace_id AND removal.network_id = v_deletion.network_id;
        GET DIAGNOSTICS v_removals = ROW_COUNT;
        PERFORM pg_catalog.set_config('mesh.network_prefix_release', 'on', TRUE);
        UPDATE mesh.network_prefix AS prefix
        SET state = 'quarantined', quarantine_until = v_now + mesh_ops.network_prefix_hold_v1(),
            version = prefix.version + 1, updated_at = GREATEST(v_now, prefix.updated_at)
        WHERE prefix.workspace_id = v_deletion.workspace_id AND prefix.network_id = v_deletion.network_id
          AND prefix.state IN ('reserved', 'active');
        GET DIAGNOSTICS v_prefixes = ROW_COUNT;
        PERFORM pg_catalog.set_config('mesh.network_prefix_release', '', TRUE);
    END IF;
    UPDATE mesh_ops.network_deletion AS deletion
    SET devices_revoked = deletion.devices_revoked + v_revoked,
        completed_at = CASE WHEN v_left THEN NULL ELSE v_now END,
        claimed_until = NULL,
        updated_at = GREATEST(v_now, deletion.updated_at)
    WHERE deletion.network_id = v_deletion.network_id
    RETURNING * INTO v_deletion;

    -- The step changed the Network's Devices: advance its revision, so the
    -- outbox event carries a new one.
    v_advanced := mesh_ops.advance_member_networks_internal_v1(v_deletion.workspace_id,
        ARRAY[v_deletion.network_id]);
    SELECT * INTO STRICT v_head FROM mesh_audit.lock_network_stream_head();
    v_audit := pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'network_id', v_network.public_id,
        'devices_revoked', v_revoked,
        'deletion', mesh_ops.network_deletion_document_internal_v1(v_deletion),
        'memberships_revoked', CASE WHEN v_left THEN NULL ELSE v_memberships END,
        'roles_revoked', CASE WHEN v_left THEN NULL ELSE v_bindings + v_assignments END,
        'resource_removals_dropped', CASE WHEN v_left THEN NULL ELSE v_removals END,
        'prefixes_held', CASE WHEN v_left THEN NULL ELSE v_prefixes END,
        'prefixes_held_until', CASE WHEN v_left THEN NULL ELSE v_now + mesh_ops.network_prefix_hold_v1() END));
    v_outbox := pg_catalog.jsonb_build_object(
        'network_id', v_network.public_id, 'aggregate_kind', 'network', 'aggregate_id', v_network.public_id,
        'network_revision', (v_advanced -> 0 ->> 'network_revision')::BIGINT,
        'group_revision', (v_advanced -> 0 ->> 'group_revision')::BIGINT);
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE,
        'completed', NOT v_left,
        'change_id', p_change,
        'network_id', v_network.public_id,
        'aggregate_version', v_network.version,
        'action', CASE WHEN v_left THEN 'network.devices_revoked' ELSE 'network.delete_completed' END,
        'stream_id', v_head.stream_internal_id,
        'sequence', v_head.next_sequence,
        'previous_hash', pg_catalog.encode(v_head.latest_event_hash, 'hex'),
        'network_revision', (v_advanced -> 0 ->> 'network_revision')::BIGINT,
        'audit_payload', v_audit::TEXT,
        'outbox_payload', v_outbox::TEXT);
END;
$function$;

-- One step of phase 2: tries the unfinished deletions of this Deployment
-- oldest first (rows other replicas hold are skipped) and returns the
-- evidence of the first that changes. A deletion whose step fails, or whose
-- Devices are all locked, does not hold the others back: it is rolled back
-- to a savepoint and the next one is tried. A failed one is counted and
-- left alone for five minutes (claimed_until), so it does not run again
-- before every step; every answer carries the count.
CREATE FUNCTION mesh_ops.prepare_network_deletion_step_v1(p_deployment UUID, p_change UUID, p_batch INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment BIGINT;
    v_deletion mesh_ops.network_deletion%ROWTYPE;
    v_proof JSONB;
    v_failed INTEGER := 0;
BEGIN
    IF NOT pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
        OR p_deployment IS NULL OR p_change IS NULL OR p_batch IS NULL OR p_batch NOT BETWEEN 1 AND 2000
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network deletion step is invalid';
    END IF;
    SELECT deployment.id INTO v_deployment FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment;
    IF v_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network deletion step is invalid';
    END IF;
    FOR v_deletion IN
        SELECT * FROM mesh_ops.network_deletion AS deletion
        WHERE deletion.deployment_id = v_deployment AND deletion.completed_at IS NULL
          AND (deletion.claimed_until IS NULL OR deletion.claimed_until <= pg_catalog.transaction_timestamp())
        ORDER BY deletion.requested_at, deletion.network_id
        LIMIT 16
        FOR UPDATE SKIP LOCKED
    LOOP
        v_proof := NULL;
        BEGIN
            v_proof := mesh_ops.network_deletion_step_internal_v1(v_deletion, p_change, p_batch);
        EXCEPTION
            WHEN SQLSTATE 'MTN03' THEN
                NULL;
            WHEN OTHERS THEN
                v_failed := v_failed + 1;
                UPDATE mesh_ops.network_deletion AS deletion
                SET claimed_until = pg_catalog.transaction_timestamp() + INTERVAL '5 minutes'
                WHERE deletion.network_id = v_deletion.network_id;
        END;
        IF v_proof IS NOT NULL THEN
            v_proof := v_proof || pg_catalog.jsonb_build_object('failed', v_failed);
            INSERT INTO mesh_ops.network_deletion_proof (transaction_id, change_public_id, proof)
            VALUES ((pg_catalog.pg_current_xact_id()::TEXT)::BIGINT, p_change, v_proof);
            RETURN v_proof;
        END IF;
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('changed', FALSE, 'failed', v_failed);
END;
$function$;

-- Appends the one event prepare_network_deletion_step_v1 kept for this
-- transaction, with the hash the worker computed, as the system actor.
CREATE FUNCTION mesh_ops.finalize_network_deletion_step_v1(p_change UUID, p_event JSONB)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_proof JSONB;
    v_sequence BIGINT;
BEGIN
    DELETE FROM mesh_ops.network_deletion_proof AS kept
    WHERE kept.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      AND kept.change_public_id = p_change
    RETURNING kept.proof INTO v_proof;
    IF NOT pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
        OR v_proof IS NULL OR p_change IS NULL OR p_event IS NULL
        OR pg_catalog.jsonb_typeof(p_event) <> 'object'
        OR v_proof ->> 'change_id' IS DISTINCT FROM p_change::TEXT
        OR p_event ->> 'stream_id' IS DISTINCT FROM v_proof ->> 'stream_id'
        OR p_event ->> 'sequence' IS DISTINCT FROM v_proof ->> 'sequence'
        OR p_event ->> 'previous_hash' IS DISTINCT FROM v_proof ->> 'previous_hash'
        OR p_event ->> 'audit_payload' IS DISTINCT FROM v_proof ->> 'audit_payload'
        OR p_event ->> 'outbox_payload' IS DISTINCT FROM v_proof ->> 'outbox_payload'
        OR p_event ->> 'event_id' IS NULL OR p_event ->> 'outbox_id' IS NULL
        OR p_event ->> 'event_hash' !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Network deletion evidence mismatch';
    END IF;
    v_sequence := mesh_audit.append_authority_evidence(
        (v_proof ->> 'stream_id')::BIGINT,
        (p_event ->> 'event_id')::UUID,
        (p_event ->> 'outbox_id')::UUID,
        (v_proof ->> 'sequence')::BIGINT,
        pg_catalog.decode(v_proof ->> 'previous_hash', 'hex'),
        pg_catalog.decode(p_event ->> 'event_hash', 'hex'),
        'network',
        (v_proof ->> 'network_id')::UUID,
        (v_proof ->> 'aggregate_version')::BIGINT,
        (v_proof ->> 'network_revision')::BIGINT,
        NULL::UUID,
        v_proof ->> 'action',
        'system.reconcile',
        NULL::UUID,
        NULL::BYTEA,
        NULL::BYTEA,
        (v_proof ->> 'audit_payload')::JSONB,
        'network.revision.advanced',
        (v_proof ->> 'outbox_payload')::JSONB
    );
    IF v_sequence <> (v_proof ->> 'sequence')::BIGINT THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Network deletion evidence changed';
    END IF;
    RETURN v_sequence;
END;
$function$;

-- How many deletions wait, and the oldest, for the worker's metrics.
CREATE FUNCTION mesh_ops.network_deletion_lag_v1(p_deployment UUID)
RETURNS TABLE (pending BIGINT, oldest_requested_at TIMESTAMPTZ)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*), pg_catalog.min(deletion.requested_at)
    FROM mesh_ops.network_deletion AS deletion
    JOIN mesh.deployment AS deployment ON deployment.id = deletion.deployment_id
    WHERE deployment.installation_public_id = p_deployment AND deletion.completed_at IS NULL
      AND pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
$function$;

REVOKE ALL ON FUNCTION
    mesh_ops.network_deletion_step_internal_v1(mesh_ops.network_deletion, UUID, INTEGER),
    mesh_ops.network_prefix_hold_v1(),
    mesh_ops.prepare_network_deletion_step_v1(UUID, UUID, INTEGER),
    mesh_ops.finalize_network_deletion_step_v1(UUID, JSONB),
    mesh_ops.network_deletion_lag_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION
    mesh_ops.prepare_network_deletion_step_v1(UUID, UUID, INTEGER),
    mesh_ops.finalize_network_deletion_step_v1(UUID, JSONB),
    mesh_ops.network_deletion_lag_v1(UUID)
TO mesh_worker;
