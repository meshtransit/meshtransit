-- DNS names that point at a share (DNS design D3a): a name of the
-- consumer Network answers with the alias of a share the Network imports,
-- so a provider's web app opens under its real name.
--
-- An address name now has one of three targets: a Device of the Network,
-- fixed addresses, or a share (the imported resource's public ID). The name
-- keeps a share that has ended, like a Device that has gone, and answers
-- nothing then; a new share target must be one the Network consumes now.
--
-- A Core that does not know shares (a rollback) never reads or writes one
-- by name: the v1 readers, the v1 map reader and change_dns_names_v1 leave
-- share names out (a change to one finds no such name, MTZ0F), and v1
-- documents keep their keys. Its zone writes still treat them as names of
-- the zone: they count in name_count and the limits, move with adopt_names,
-- and go when it deletes a zone with its names. The v2 functions serve every
-- target. One body serves both, behind a flag.
--
-- Errors, beside schema 215's: MTZ10 a share no name may point at now (not
-- imported by the Network, or its contract no longer runs).

ALTER TABLE mesh.network_dns_name ADD COLUMN share_public_id UUID;
-- The new check only widens the old one: added NOT VALID and validated
-- apart, the scan runs without blocking writes.
ALTER TABLE mesh.network_dns_name DROP CONSTRAINT network_dns_name_target_check;
ALTER TABLE mesh.network_dns_name ADD CONSTRAINT network_dns_name_target_check CHECK (
    (kind = 'address' AND cname IS NULL AND (
        (device_public_id IS NOT NULL AND addresses IS NULL AND share_public_id IS NULL)
        OR (device_public_id IS NULL AND share_public_id IS NULL
            AND mesh_ops.dns_name_addresses_valid_internal_v1(addresses))
        OR (device_public_id IS NULL AND addresses IS NULL AND share_public_id IS NOT NULL)))
    OR (kind = 'cname' AND device_public_id IS NULL AND addresses IS NULL AND share_public_id IS NULL
        AND cname IS NOT NULL AND cname <> fqdn AND pg_catalog.octet_length(cname) BETWEEN 1 AND 253
        AND cname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
) NOT VALID;
ALTER TABLE mesh.network_dns_name VALIDATE CONSTRAINT network_dns_name_target_check;
ALTER TABLE mesh.network_dns_name ADD CONSTRAINT network_dns_name_share_check CHECK (
    share_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(share_public_id), 6) >> 4 = 7
);
CREATE INDEX network_dns_name_share_idx
    ON mesh.network_dns_name (workspace_id, network_id, share_public_id)
    WHERE share_public_id IS NOT NULL AND state = 'active';

-- Whether a share can become a name's target now: one this Network imports,
-- whose contract is active (or activating) and not past its expiry.
CREATE FUNCTION mesh_ops.dns_share_target_live_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT,
    p_share_public_id UUID, p_at TIMESTAMPTZ)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.imported_resource AS imported
        JOIN mesh.trust_contract AS contract ON contract.id = imported.trust_contract_id
        WHERE imported.workspace_id = p_workspace_id AND imported.network_id = p_network_id
          AND imported.public_id = p_share_public_id
          AND imported.state IN ('activating', 'active')
          AND contract.consumer_workspace_id = p_workspace_id AND contract.consumer_network_id = p_network_id
          AND contract.state IN ('activating', 'active') AND contract.expires_at > p_at)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_share_target_live_internal_v1(BIGINT, BIGINT, UUID, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A name as the API shows it; share_aware adds the share target (its ID,
-- name, contract and whether it still runs). Without it the document is
-- exactly schema 215's.
CREATE FUNCTION mesh_ops.dns_name_document_internal_v2(p_name mesh.network_dns_name, p_share_aware BOOLEAN)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT CASE WHEN NOT p_share_aware THEN mesh_ops.dns_name_document_internal_v1(p_name)
        ELSE mesh_ops.dns_name_document_internal_v1(p_name) || pg_catalog.jsonb_build_object(
            'share_id', p_name.share_public_id,
            'share_name', (SELECT imported.display_name FROM mesh.imported_resource AS imported
                           WHERE imported.workspace_id = p_name.workspace_id
                             AND imported.network_id = p_name.network_id
                             AND imported.public_id = p_name.share_public_id),
            'contract_id', (SELECT contract.public_id FROM mesh.trust_contract AS contract
                            WHERE contract.imported_resource_public_id = p_name.share_public_id
                              AND contract.consumer_workspace_id = p_name.workspace_id
                              AND contract.consumer_network_id = p_name.network_id),
            'share_state', CASE WHEN p_name.share_public_id IS NULL THEN NULL
                                WHEN mesh_ops.dns_share_target_live_internal_v1(p_name.workspace_id,
                                    p_name.network_id, p_name.share_public_id, pg_catalog.now()) THEN 'active'
                                ELSE 'ended' END)
        END
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_name_document_internal_v2(mesh.network_dns_name, BOOLEAN)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The target of one name operation; share_aware also reads share_id, which
-- a Core that does not know shares never sends.
CREATE FUNCTION mesh_ops.dns_name_target_internal_v2(p_item JSONB, p_share_aware BOOLEAN,
    OUT kind TEXT, OUT device_public_id UUID, OUT addresses INET[], OUT cname TEXT, OUT share_public_id UUID)
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    SELECT target.kind, target.device_public_id, target.addresses, target.cname
    INTO kind, device_public_id, addresses, cname
    FROM mesh_ops.dns_name_target_internal_v1(p_item) AS target;
    IF p_item ? 'share_id' THEN
        IF NOT p_share_aware THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name target is invalid';
        END IF;
        share_public_id := (p_item ->> 'share_id')::UUID;
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_name_target_internal_v2(JSONB, BOOLEAN)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates, changes and deletes names of one zone (dns.manage); see
-- change_dns_names_v1 in schema 215. share_aware lets a target be a share.
CREATE FUNCTION mesh_ops.change_dns_names_internal_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_operations JSONB,
    p_zone_name_limit INTEGER, p_network_name_limit INTEGER, p_host_name_limit INTEGER,
    p_change_public_id UUID, p_share_aware BOOLEAN
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_zone mesh.network_dns_zone%ROWTYPE;
    v_name mesh.network_dns_name%ROWTYPE;
    v_item JSONB;
    v_index INTEGER;
    v_pass TEXT;
    v_seen UUID[] := '{}';
    v_name_id UUID;
    v_target RECORD;
    v_fqdn TEXT;
    v_before JSONB;
    v_results JSONB := '[]'::JSONB;
    v_changed BOOLEAN := FALSE;
    v_zone_before BIGINT;
    v_network_before BIGINT;
    v_hosted_before BIGINT;
    v_constraint TEXT;
    v_network_revision BIGINT;
    v_dns_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_zone_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_operations IS NULL OR pg_catalog.jsonb_typeof(p_operations) <> 'array'
        OR pg_catalog.jsonb_array_length(p_operations) NOT BETWEEN 1 AND 100
        OR p_zone_name_limit IS NULL OR p_zone_name_limit NOT BETWEEN 1 AND 2000
        OR p_network_name_limit IS NULL OR p_network_name_limit NOT BETWEEN 1 AND 10000
        OR p_host_name_limit IS NULL OR p_host_name_limit NOT BETWEEN 0 AND 2000 OR p_share_aware IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name change is invalid';
    END IF;
    -- Each operation names one name, once, with what its kind needs.
    FOR v_item, v_index IN
        SELECT entry.item, (entry.ordinal - 1)::INTEGER
        FROM pg_catalog.jsonb_array_elements(p_operations) WITH ORDINALITY AS entry (item, ordinal)
    LOOP
        BEGIN
            v_name_id := (v_item ->> 'name_id')::UUID;
        EXCEPTION WHEN invalid_text_representation THEN
            v_name_id := NULL;
        END;
        IF pg_catalog.jsonb_typeof(v_item) <> 'object' OR v_name_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(v_name_id), 6) >> 4 <> 7 OR v_name_id = ANY (v_seen)
            OR (v_item ->> 'op') IS NULL OR (v_item ->> 'op') NOT IN ('create', 'update', 'delete')
            OR ((v_item ->> 'op') = 'create' AND ((v_item ->> 'label') IS NULL
                OR (v_item ->> 'label') !~ '^(@|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*)$'))
            OR ((v_item ->> 'op') <> 'create'
                AND (COALESCE(pg_catalog.jsonb_typeof(v_item -> 'expected_version'), '') <> 'number'
                     OR (v_item ->> 'expected_version')::NUMERIC NOT BETWEEN 1 AND 9223372036854775807))
            OR ((v_item ->> 'op') <> 'delete' AND COALESCE(v_item ->> 'kind', '') NOT IN ('address', 'cname')) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name operation is invalid',
                DETAIL = v_index::TEXT;
        END IF;
        v_seen := v_seen || v_name_id;
    END LOOP;
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DNS name scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_zone := mesh_ops.dns_name_zone_internal_v1(v_scope.workspace_id, v_scope.network_id, p_zone_public_id);
    SELECT COALESCE((SELECT counted.name_count FROM mesh.network_dns_zone_name_count AS counted
                     WHERE counted.zone_id = v_zone.id), 0) INTO v_zone_before;
    SELECT COALESCE(pg_catalog.sum(counted.name_count), 0) INTO v_network_before
    FROM mesh.network_dns_zone_name_count AS counted
    WHERE counted.workspace_id = v_scope.workspace_id AND counted.network_id = v_scope.network_id;
    v_hosted_before := mesh_ops.dns_host_name_count_internal_v1(v_scope.workspace_id, v_scope.network_id);

    FOREACH v_pass IN ARRAY ARRAY['delete', 'update', 'create'] LOOP
        FOR v_item, v_index IN
            SELECT entry.item, (entry.ordinal - 1)::INTEGER
            FROM pg_catalog.jsonb_array_elements(p_operations) WITH ORDINALITY AS entry (item, ordinal)
            WHERE entry.item ->> 'op' = v_pass
            ORDER BY entry.ordinal
        LOOP
            v_name_id := (v_item ->> 'name_id')::UUID;
            v_before := NULL;
            IF v_pass <> 'create' THEN
                SELECT * INTO v_name FROM mesh.network_dns_name AS name
                WHERE name.zone_id = v_zone.id AND name.public_id = v_name_id AND name.state = 'active'
                  AND (p_share_aware OR name.share_public_id IS NULL)
                FOR UPDATE;
                IF v_name.id IS NULL THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTZ0F', MESSAGE = 'DNS name is unavailable',
                        DETAIL = v_index::TEXT;
                END IF;
                IF v_name.version <> (v_item ->> 'expected_version')::BIGINT THEN
                    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'DNS name version changed',
                        DETAIL = v_index::TEXT;
                END IF;
                v_before := mesh_ops.dns_name_document_internal_v2(v_name, p_share_aware);
            END IF;
            IF v_pass <> 'delete' THEN
                BEGIN
                    SELECT * INTO v_target FROM mesh_ops.dns_name_target_internal_v2(v_item, p_share_aware);
                EXCEPTION WHEN invalid_text_representation OR data_exception THEN
                    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name target is invalid',
                        DETAIL = v_index::TEXT;
                END;
                v_fqdn := CASE WHEN v_pass = 'update' THEN v_name.fqdn
                               WHEN v_item ->> 'label' = '@' THEN v_zone.domain
                               ELSE (v_item ->> 'label') || '.' || v_zone.domain END;
                -- An update to what is stored writes nothing, even when its
                -- Device has gone since.
                IF v_pass = 'update' AND v_name.kind = v_target.kind
                    AND v_name.device_public_id IS NOT DISTINCT FROM v_target.device_public_id
                    AND v_name.addresses IS NOT DISTINCT FROM v_target.addresses
                    AND v_name.cname IS NOT DISTINCT FROM v_target.cname
                    AND v_name.share_public_id IS NOT DISTINCT FROM v_target.share_public_id THEN
                    v_results := v_results || pg_catalog.jsonb_build_object('index', v_index, 'operation', v_pass,
                        'name', v_before, 'previous', v_before, 'changed', FALSE);
                    CONTINUE;
                END IF;
                IF v_target.cname = v_fqdn THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTZ0D', MESSAGE = 'A CNAME cannot point at its own name',
                        DETAIL = v_index::TEXT;
                END IF;
                IF v_target.device_public_id IS NOT NULL
                    -- A CASE in an IF condition goes in parentheses: plpgsql
                    -- ends the condition at the first THEN outside them.
                    AND v_target.device_public_id IS DISTINCT FROM (CASE WHEN v_pass = 'update'
                                                                      THEN v_name.device_public_id END)
                    AND NOT EXISTS (
                    SELECT 1 FROM mesh.device AS device
                    WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
                      AND device.public_id = v_target.device_public_id AND device.deleted_at IS NULL
                      AND device.state = 'active') THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTZ0B', MESSAGE = 'Device cannot be a DNS name target',
                        DETAIL = v_index::TEXT;
                END IF;
                -- A new target share is one this Network consumes now; a
                -- name keeps a share that has ended since.
                IF v_target.share_public_id IS NOT NULL
                    AND v_target.share_public_id IS DISTINCT FROM (CASE WHEN v_pass = 'update'
                                                                     THEN v_name.share_public_id END)
                    AND NOT mesh_ops.dns_share_target_live_internal_v1(v_scope.workspace_id, v_scope.network_id,
                        v_target.share_public_id, v_now) THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTZ10', MESSAGE = 'Share cannot be a DNS name target',
                        DETAIL = v_index::TEXT;
                END IF;
            END IF;
            BEGIN
                IF v_pass = 'delete' THEN
                    UPDATE mesh.network_dns_name AS name
                    SET state = 'deleted', deleted_at = GREATEST(v_now, name.updated_at),
                        version = name.version + 1, updated_at = GREATEST(v_now, name.updated_at)
                    WHERE name.id = v_name.id
                    RETURNING * INTO v_name;
                ELSIF v_pass = 'update' THEN
                    UPDATE mesh.network_dns_name AS name
                    SET kind = v_target.kind, device_public_id = v_target.device_public_id,
                        addresses = v_target.addresses, cname = v_target.cname,
                        share_public_id = v_target.share_public_id,
                        version = name.version + 1, updated_at = GREATEST(v_now, name.updated_at)
                    WHERE name.id = v_name.id
                    RETURNING * INTO v_name;
                ELSE
                    INSERT INTO mesh.network_dns_name (
                        public_id, deployment_id, workspace_id, network_id, zone_id, fqdn, kind,
                        device_public_id, addresses, cname, share_public_id, created_at, updated_at
                    ) VALUES (
                        v_name_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, v_zone.id,
                        v_fqdn, v_target.kind, v_target.device_public_id, v_target.addresses, v_target.cname,
                        v_target.share_public_id, v_now, v_now
                    ) RETURNING * INTO v_name;
                END IF;
            EXCEPTION
                WHEN unique_violation THEN
                    GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
                    IF v_constraint = 'network_dns_name_active_fqdn_uidx' THEN
                        RAISE EXCEPTION USING ERRCODE = 'MTZ08', MESSAGE = 'DNS name is taken',
                            DETAIL = v_index::TEXT;
                    END IF;
                    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name operation is invalid',
                        DETAIL = v_index::TEXT;
                WHEN check_violation OR not_null_violation THEN
                    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name target is invalid',
                        DETAIL = v_index::TEXT;
            END;
            IF v_name.state = 'active' THEN
                IF mesh_ops.dns_longest_zone_internal_v1(v_scope.workspace_id, v_scope.network_id, v_name.fqdn)
                    <> v_zone.id THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTZ09', MESSAGE = 'A longer DNS zone holds the name',
                        DETAIL = v_index::TEXT;
                END IF;
                IF v_name.kind = 'cname' AND v_name.fqdn = v_zone.domain THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTZ0C', MESSAGE = 'A CNAME cannot be the zone''s own domain',
                        DETAIL = v_index::TEXT;
                END IF;
            END IF;
            v_changed := TRUE;
            v_results := v_results || pg_catalog.jsonb_build_object('index', v_index, 'operation', v_pass,
                'name', mesh_ops.dns_name_document_internal_v2(v_name, p_share_aware), 'previous', v_before,
                'changed', TRUE);
        END LOOP;
    END LOOP;
    SELECT pg_catalog.jsonb_agg(result ORDER BY (result ->> 'index')::INTEGER) INTO v_results
    FROM pg_catalog.jsonb_array_elements(v_results) AS result;
    IF NOT v_changed THEN
        RETURN pg_catalog.jsonb_build_object('results', v_results, 'changed', FALSE,
            'role_binding_id', v_scope.role_binding_public_id);
    END IF;

    -- Limits: a count over its limit fails only when this change raised it.
    IF (SELECT counted.name_count FROM mesh.network_dns_zone_name_count AS counted
        WHERE counted.zone_id = v_zone.id) > GREATEST(p_zone_name_limit, v_zone_before)
        OR (SELECT pg_catalog.sum(counted.name_count) FROM mesh.network_dns_zone_name_count AS counted
            WHERE counted.workspace_id = v_scope.workspace_id AND counted.network_id = v_scope.network_id)
           > GREATEST(p_network_name_limit, v_network_before)
        OR mesh_ops.dns_host_name_count_internal_v1(v_scope.workspace_id, v_scope.network_id)
           > GREATEST(p_host_name_limit, v_hosted_before) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ0A', MESSAGE = 'DNS name limit reached';
    END IF;
    -- CNAME chains among the Network's own names: none loops, none is longer
    -- than 8.
    IF EXISTS (
        WITH RECURSIVE chain (target, depth) AS (
            SELECT name.cname, 1
            FROM mesh.network_dns_name AS name
            WHERE name.workspace_id = v_scope.workspace_id AND name.network_id = v_scope.network_id
              AND name.state = 'active' AND name.kind = 'cname'
            UNION ALL
            SELECT next.cname, chain.depth + 1
            FROM chain
            JOIN mesh.network_dns_name AS next
              ON next.workspace_id = v_scope.workspace_id AND next.network_id = v_scope.network_id
             AND next.state = 'active' AND next.kind = 'cname' AND next.fqdn = chain.target
            WHERE chain.depth < 9
        )
        SELECT 1 FROM chain WHERE depth >= 9) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ0D', MESSAGE = 'A CNAME chain loops or is longer than 8';
    END IF;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1, dns_revision = revision.dns_revision + 1,
        updated_at = GREATEST(v_now, revision.updated_at)
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    RETURNING revision.network_revision, revision.dns_revision INTO v_network_revision, v_dns_revision;
    RETURN pg_catalog.jsonb_build_object(
        'results', v_results, 'changed', TRUE,
        'network_revision', v_network_revision, 'dns_revision', v_dns_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_dns_names_internal_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB,
    INTEGER, INTEGER, INTEGER, UUID, BOOLEAN
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- schema 215's change_dns_names_v1, for a Core that does not know shares.
CREATE OR REPLACE FUNCTION mesh_ops.change_dns_names_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_operations JSONB,
    p_zone_name_limit INTEGER, p_network_name_limit INTEGER, p_host_name_limit INTEGER,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.change_dns_names_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, p_operations,
        p_zone_name_limit, p_network_name_limit, p_host_name_limit, p_change_public_id, FALSE)
$function$;

-- Every target, a share too.
CREATE FUNCTION mesh_ops.change_dns_names_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_operations JSONB,
    p_zone_name_limit INTEGER, p_network_name_limit INTEGER, p_host_name_limit INTEGER,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.change_dns_names_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, p_operations,
        p_zone_name_limit, p_network_name_limit, p_host_name_limit, p_change_public_id, TRUE)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_dns_names_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB,
    INTEGER, INTEGER, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_dns_names_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB,
    INTEGER, INTEGER, INTEGER, UUID
) TO mesh_runtime;

-- One page of a zone's names (network.read); see list_dns_names_v1.
CREATE FUNCTION mesh_ops.list_dns_names_internal_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_after_name_public_id UUID,
    p_prefix TEXT, p_limit INTEGER, p_share_aware BOOLEAN
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_zone mesh.network_dns_zone%ROWTYPE;
    v_after_fqdn TEXT;
    v_page JSONB;
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR p_share_aware IS NULL
        OR (p_prefix IS NOT NULL AND p_prefix !~ '^[a-z0-9.-]{1,253}$') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name page is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    v_zone := mesh_ops.dns_name_zone_internal_v1(v_scope.workspace_id, v_scope.network_id, p_zone_public_id);
    IF p_after_name_public_id IS NOT NULL THEN
        SELECT name.fqdn INTO v_after_fqdn FROM mesh.network_dns_name AS name
        WHERE name.workspace_id = v_scope.workspace_id AND name.network_id = v_scope.network_id
          AND name.public_id = p_after_name_public_id;
        IF v_after_fqdn IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name page cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(mesh_ops.dns_name_document_internal_v2(page, p_share_aware)
               ORDER BY page.fqdn, page.public_id),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT * FROM mesh.network_dns_name AS name
        WHERE name.zone_id = v_zone.id AND name.state = 'active'
          AND (p_share_aware OR name.share_public_id IS NULL)
          AND (v_after_fqdn IS NULL OR (name.fqdn, name.public_id) > (v_after_fqdn, p_after_name_public_id))
          AND (p_prefix IS NULL OR name.fqdn LIKE p_prefix || '%')
        ORDER BY name.fqdn, name.public_id
        LIMIT p_limit + 1
    ) AS page;
    RETURN pg_catalog.jsonb_build_object(
        'names', CASE WHEN v_count > p_limit THEN v_page - p_limit ELSE COALESCE(v_page, '[]'::JSONB) END,
        'has_more', v_count > p_limit,
        'zone', mesh_ops.dns_zone_document_internal_v2(v_zone)
    ) || mesh_ops.dns_zone_abilities_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_dns_names_internal_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, TEXT, INTEGER, BOOLEAN
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.list_dns_names_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_after_name_public_id UUID,
    p_prefix TEXT, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.list_dns_names_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, p_after_name_public_id,
        p_prefix, p_limit, FALSE)
$function$;

CREATE FUNCTION mesh_ops.list_dns_names_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_after_name_public_id UUID,
    p_prefix TEXT, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.list_dns_names_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, p_after_name_public_id,
        p_prefix, p_limit, TRUE)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_dns_names_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, TEXT, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_dns_names_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, TEXT, INTEGER
) TO mesh_runtime;

-- One active name of a zone (network.read); see read_dns_name_v1.
CREATE FUNCTION mesh_ops.read_dns_name_internal_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_name_public_id UUID,
    p_share_aware BOOLEAN
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_zone mesh.network_dns_zone%ROWTYPE;
    v_name mesh.network_dns_name%ROWTYPE;
BEGIN
    IF p_share_aware IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name read is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    v_zone := mesh_ops.dns_name_zone_internal_v1(v_scope.workspace_id, v_scope.network_id, p_zone_public_id);
    SELECT * INTO v_name FROM mesh.network_dns_name AS name
    WHERE name.zone_id = v_zone.id AND name.public_id = p_name_public_id AND name.state = 'active'
      AND (p_share_aware OR name.share_public_id IS NULL);
    IF v_name.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ0F', MESSAGE = 'DNS name is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('name', mesh_ops.dns_name_document_internal_v2(v_name, p_share_aware))
        || mesh_ops.dns_zone_abilities_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_dns_name_internal_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, BOOLEAN
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.read_dns_name_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_name_public_id UUID
)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.read_dns_name_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, p_name_public_id, FALSE)
$function$;

CREATE FUNCTION mesh_ops.read_dns_name_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_name_public_id UUID
)
RETURNS JSONB
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.read_dns_name_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, p_name_public_id, TRUE)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_dns_name_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_dns_name_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;

-- Schema 216's map reader leaves share names out until maps carry them
-- (DNS design D3b): their rows have no address target it could read.
CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_dns_names_v1(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    fqdn TEXT,
    kind TEXT,
    device_id BIGINT,
    device_public_id TEXT,
    addresses TEXT[],
    cname TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS name request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS name scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT name.zone_id, name.fqdn::TEXT, name.kind, COALESCE(device.id, 0),
           COALESCE(name.device_public_id::TEXT, ''),
           COALESCE(ARRAY(SELECT pg_catalog.host(item.address)
                          FROM pg_catalog.unnest(name.addresses) WITH ORDINALITY AS item (address, ordinal)
                          ORDER BY item.ordinal), '{}'::TEXT[]),
           COALESCE(name.cname::TEXT, '')
    FROM mesh.network_dns_name AS name
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = name.workspace_id AND device.network_id = name.network_id
     AND device.public_id = name.device_public_id AND device.deleted_at IS NULL
    WHERE name.workspace_id = scoped_workspace_id
      AND name.network_id = scoped_network_id
      AND name.state = 'active'
      AND name.share_public_id IS NULL
    ORDER BY name.fqdn
    LIMIT p_limit;
END;
$function$;
