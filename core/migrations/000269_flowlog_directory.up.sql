-- The connection log receiver's directory (connection logs design §16d,
-- C59–C62, s4c2a): what names a record's endpoints and checks a reporter's
-- role. Its revision is the Network's own (network_revision); no trigger
-- of this schema writes on a map change.

-- Owner pseudonyms, one per Workspace membership (C60): a random UUID the
-- receiver puts in records instead of the person. A revoked membership loses
-- it, a new one gets a new one; a suspension keeps it. Derived data: the
-- membership change it follows is the audited one.
CREATE TABLE mesh.connection_log_owner_pseudonym (
    membership_id BIGINT PRIMARY KEY REFERENCES mesh.workspace_membership (id) ON DELETE CASCADE,
    workspace_id BIGINT NOT NULL,
    pseudonym UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE mesh.connection_log_owner_pseudonym ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.connection_log_owner_pseudonym FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_log_owner_pseudonym_migrator_policy ON mesh.connection_log_owner_pseudonym
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.connection_log_owner_pseudonym
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.track_connection_log_owner_pseudonym_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.state = 'revoked' THEN
        DELETE FROM mesh.connection_log_owner_pseudonym AS pseudonym WHERE pseudonym.membership_id = NEW.id;
    ELSE
        INSERT INTO mesh.connection_log_owner_pseudonym (membership_id, workspace_id, pseudonym, created_at)
        VALUES (NEW.id, NEW.workspace_id, pg_catalog.gen_random_uuid(), pg_catalog.transaction_timestamp())
        ON CONFLICT (membership_id) DO NOTHING;
    END IF;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.track_connection_log_owner_pseudonym_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER workspace_membership_connection_log_pseudonym
AFTER INSERT OR UPDATE OF state ON mesh.workspace_membership
FOR EACH ROW EXECUTE FUNCTION mesh_ops.track_connection_log_owner_pseudonym_v1();

INSERT INTO mesh.connection_log_owner_pseudonym (membership_id, workspace_id, pseudonym, created_at)
SELECT membership.id, membership.workspace_id, pg_catalog.gen_random_uuid(), pg_catalog.transaction_timestamp()
FROM mesh.workspace_membership AS membership
WHERE membership.state <> 'revoked';

-- What the reader sees: rows of Networks with a destination, and the
-- deployment's alias pools (no tenant's). Policies compare the guarded row's
-- own columns with a sub-select's (as in schema 268).
CREATE POLICY connection_log_owner_pseudonym_flowlog_read ON mesh.connection_log_owner_pseudonym
    FOR SELECT TO mesh_flowlog_reader
    USING (workspace_id IN (SELECT logged.workspace_id FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.connection_log_owner_pseudonym TO mesh_flowlog_reader;
CREATE POLICY workspace_membership_flowlog_read ON mesh.workspace_membership
    FOR SELECT TO mesh_flowlog_reader
    USING (workspace_id IN (SELECT logged.workspace_id FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.workspace_membership TO mesh_flowlog_reader;
CREATE POLICY address_pool_flowlog_read ON mesh.address_pool
    FOR SELECT TO mesh_flowlog_reader
    USING (workspace_id IS NULL AND purpose IN ('federation_resource_alias', 'federation_consumer_alias'));
GRANT SELECT ON mesh.address_pool TO mesh_flowlog_reader;

CREATE POLICY node_address_lease_flowlog_read ON mesh.node_address_lease
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.node_address_lease TO mesh_flowlog_reader;
CREATE POLICY network_prefix_flowlog_read ON mesh.network_prefix
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.network_prefix TO mesh_flowlog_reader;
CREATE POLICY device_tag_flowlog_read ON mesh.device_tag
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.device_tag TO mesh_flowlog_reader;
CREATE POLICY device_tag_assignment_flowlog_read ON mesh.device_tag_assignment
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.device_tag_assignment TO mesh_flowlog_reader;
CREATE POLICY device_group_flowlog_read ON mesh.device_group
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.device_group TO mesh_flowlog_reader;
CREATE POLICY device_group_member_flowlog_read ON mesh.device_group_member
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.device_group_member TO mesh_flowlog_reader;
CREATE POLICY network_site_flowlog_read ON mesh.network_site
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.network_site TO mesh_flowlog_reader;
CREATE POLICY network_site_router_flowlog_read ON mesh.network_site_router
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.network_site_router TO mesh_flowlog_reader;
CREATE POLICY network_exit_pool_flowlog_read ON mesh.network_exit_pool
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.network_exit_pool TO mesh_flowlog_reader;
CREATE POLICY network_exit_node_flowlog_read ON mesh.network_exit_node
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.network_exit_node TO mesh_flowlog_reader;

-- The Network part of the directory (C61): revision, prefixes, the
-- deployment's alias pools, Sites with routers, Exit Pools with candidates,
-- tag and group names, and how many Devices the pages will list. NULL: no
-- such Network, or no destination.
CREATE FUNCTION mesh_ops.flowlog_directory_network_v1(p_workspace_public_id UUID, p_network_public_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace BIGINT;
    v_network BIGINT;
BEGIN
    SELECT settings.workspace_id, settings.network_id INTO v_workspace, v_network
    FROM mesh.network_connection_log AS settings
    JOIN mesh.workspace AS workspace ON workspace.id = settings.workspace_id
    WHERE settings.public_id = p_network_public_id AND workspace.public_id = p_workspace_public_id
      AND settings.credential_id IS NOT NULL;
    IF v_network IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'revision', (SELECT revision.network_revision FROM mesh_ops.network_revision AS revision
                     WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network),
        'built_at', v_now,
        'mesh_prefixes', COALESCE((SELECT pg_catalog.jsonb_agg(prefix.prefix::TEXT ORDER BY prefix.prefix)
            FROM mesh.network_prefix AS prefix
            WHERE prefix.workspace_id = v_workspace AND prefix.network_id = v_network
              AND prefix.state = 'active' AND prefix.deleted_at IS NULL), '[]'::JSONB),
        'alias_prefixes', COALESCE((SELECT pg_catalog.jsonb_agg(pool.prefix::TEXT ORDER BY pool.prefix)
            FROM mesh.address_pool AS pool
            WHERE pool.workspace_id IS NULL AND pool.state = 'active' AND pool.deleted_at IS NULL
              AND pool.purpose IN ('federation_resource_alias', 'federation_consumer_alias')), '[]'::JSONB),
        'sites', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'id', site.public_id,
                'prefixes', (SELECT COALESCE(pg_catalog.jsonb_agg(member::TEXT ORDER BY member), '[]'::JSONB)
                             FROM pg_catalog.unnest(site.prefixes) AS member),
                'routers', COALESCE((SELECT pg_catalog.jsonb_agg(device.public_id ORDER BY device.public_id)
                    FROM mesh.network_site_router AS router
                    JOIN mesh.device AS device ON device.workspace_id = router.workspace_id
                     AND device.network_id = router.network_id AND device.id = router.device_id
                    WHERE router.site_id = site.id), '[]'::JSONB))
            ORDER BY site.public_id)
            FROM mesh.network_site AS site
            WHERE site.workspace_id = v_workspace AND site.network_id = v_network
              AND site.state = 'active' AND site.deleted_at IS NULL), '[]'::JSONB),
        'exit_pools', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'id', pool.public_id,
                'candidates', COALESCE((SELECT pg_catalog.jsonb_agg(device.public_id ORDER BY device.public_id)
                    FROM mesh.network_exit_node AS candidate
                    JOIN mesh.device AS device ON device.workspace_id = candidate.workspace_id
                     AND device.network_id = candidate.network_id AND device.id = candidate.device_id
                    WHERE candidate.pool_id = pool.id), '[]'::JSONB))
            ORDER BY pool.public_id)
            FROM mesh.network_exit_pool AS pool
            WHERE pool.workspace_id = v_workspace AND pool.network_id = v_network
              AND pool.state = 'active' AND pool.deleted_at IS NULL), '[]'::JSONB),
        'tags', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', tag.public_id, 'name', tag.name)
                ORDER BY tag.public_id)
            FROM mesh.device_tag AS tag
            WHERE tag.workspace_id = v_workspace AND tag.network_id = v_network AND tag.deleted_at IS NULL),
            '[]'::JSONB),
        'groups', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', grouped.public_id,
                'name', grouped.name) ORDER BY grouped.public_id)
            FROM mesh.device_group AS grouped
            WHERE grouped.workspace_id = v_workspace AND grouped.network_id = v_network
              AND grouped.deleted_at IS NULL), '[]'::JSONB),
        'devices', (SELECT pg_catalog.count(*) FROM mesh.device AS device
            WHERE device.workspace_id = v_workspace AND device.network_id = v_network
              AND (device.deleted_at IS NULL OR device.deleted_at >= v_now - INTERVAL '25 hours'))
    );
END;
$function$;

-- One page of the directory's Devices after p_after (C61), by public ID: the
-- live ones and, as tombstones, those deleted in the last 25 hours. A
-- Device's state counts its expiry; its owner is a membership's pseudonym,
-- or unlinked. At most 64 tags and 64 groups each, flagged when cut.
CREATE FUNCTION mesh_ops.flowlog_directory_devices_v1(p_workspace_public_id UUID, p_network_public_id UUID,
    p_after UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace BIGINT;
    v_network BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid connection log directory page';
    END IF;
    SELECT settings.workspace_id, settings.network_id INTO v_workspace, v_network
    FROM mesh.network_connection_log AS settings
    JOIN mesh.workspace AS workspace ON workspace.id = settings.workspace_id
    WHERE settings.public_id = p_network_public_id AND workspace.public_id = p_workspace_public_id
      AND settings.credential_id IS NOT NULL;
    IF v_network IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN COALESCE((SELECT pg_catalog.jsonb_agg(listed.document ORDER BY listed.public_id) FROM (
        SELECT device.public_id, CASE WHEN device.deleted_at IS NOT NULL THEN
            pg_catalog.jsonb_build_object('id', device.public_id, 'kind', device.kind, 'state', 'deleted',
                'owner_kind', device.ownership, 'pseudonym', owner.pseudonym)
        ELSE pg_catalog.jsonb_build_object(
            'id', device.public_id, 'kind', device.kind, 'hostname', device.hostname,
            'state', CASE WHEN device.state = 'active' AND device.expires_at <= v_now THEN 'expired'
                          ELSE device.state END,
            'owner_kind', device.ownership, 'pseudonym', owner.pseudonym,
            'addresses', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.host(lease.address) ORDER BY lease.address)
                FROM mesh.node_address_lease AS lease
                WHERE lease.workspace_id = device.workspace_id AND lease.network_id = device.network_id
                  AND lease.device_id = device.id AND lease.state = 'active'), '[]'::JSONB),
            'tags', COALESCE((SELECT pg_catalog.jsonb_agg(tagged.public_id ORDER BY tagged.public_id) FROM (
                SELECT tag.public_id FROM mesh.device_tag_assignment AS assignment
                JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
                WHERE assignment.workspace_id = device.workspace_id AND assignment.network_id = device.network_id
                  AND assignment.device_id = device.id AND tag.deleted_at IS NULL
                ORDER BY tag.public_id LIMIT 64) AS tagged), '[]'::JSONB),
            'groups', COALESCE((SELECT pg_catalog.jsonb_agg(grouped.public_id ORDER BY grouped.public_id) FROM (
                SELECT device_group.public_id FROM mesh.device_group_member AS member
                JOIN mesh.device_group AS device_group ON device_group.id = member.device_group_id
                WHERE member.workspace_id = device.workspace_id AND member.network_id = device.network_id
                  AND member.device_id = device.id AND device_group.deleted_at IS NULL
                ORDER BY device_group.public_id LIMIT 64) AS grouped), '[]'::JSONB),
            -- Counted as listed: live names only (review s4c2a L1).
            'truncated', (SELECT pg_catalog.count(*) FROM mesh.device_tag_assignment AS assignment
                          JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
                          WHERE assignment.workspace_id = device.workspace_id
                            AND assignment.network_id = device.network_id AND assignment.device_id = device.id
                            AND tag.deleted_at IS NULL) > 64
                OR (SELECT pg_catalog.count(*) FROM mesh.device_group_member AS member
                    JOIN mesh.device_group AS device_group ON device_group.id = member.device_group_id
                    WHERE member.workspace_id = device.workspace_id AND member.network_id = device.network_id
                      AND member.device_id = device.id AND device_group.deleted_at IS NULL) > 64)
        END AS document
        FROM mesh.device AS device
        LEFT JOIN LATERAL (
            -- A member Device's owner: the current membership's pseudonym.
            SELECT pseudonym.pseudonym FROM mesh.workspace_membership AS membership
            JOIN mesh.connection_log_owner_pseudonym AS pseudonym ON pseudonym.membership_id = membership.id
            WHERE device.ownership = 'member' AND membership.workspace_id = device.workspace_id
              AND membership.principal_id = device.owner_principal_id AND membership.state <> 'revoked'
              AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
            ORDER BY membership.id DESC LIMIT 1
        ) AS owner ON TRUE
        WHERE device.workspace_id = v_workspace AND device.network_id = v_network
          AND (device.deleted_at IS NULL OR device.deleted_at >= v_now - INTERVAL '25 hours')
          AND (p_after IS NULL OR device.public_id > p_after)
        ORDER BY device.public_id
        LIMIT p_limit) AS listed), '[]'::JSONB);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.flowlog_directory_network_v1(UUID, UUID),
    mesh_ops.flowlog_directory_devices_v1(UUID, UUID, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
