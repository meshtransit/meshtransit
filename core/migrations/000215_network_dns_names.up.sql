-- Network DNS names (DNS design D2a): names an administrator sets inside a
-- Network's DNS zones, and what a zone answers for the names it does not
-- hold.
--
-- A zone now says what its other names get (other_names): forward (D1, ask
-- the zone's resolvers), nxdomain (no such name, answered on the Device) or
-- host (the host's own DNS). Only a forward zone has resolvers; the others
-- keep none and fail open, and never the root. A zone on the Internet is
-- never nxdomain: it would take the whole domain away from every Device it
-- is sent to.
--
-- A name is one row of mesh.network_dns_name in the longest active zone
-- that covers it, never the root: an address name points at one Device of
-- the Network (its mesh addresses) or at 1 to 8 fixed addresses, a cname
-- name at one other name. Its target lives in its row so a CHECK keeps
-- every rule of one name. A zone's own domain (@) is never a CNAME. Fixed
-- addresses stay out of the overlay frame and the loopback, link-local,
-- multicast and reserved ranges; Go checks the rest (the mesh suffix,
-- special-use names, chains). A deferred trigger keeps every active name in
-- the longest active zone that covers it, whichever Core writes.
--
-- Schema 213 functions keep working for a Core that does not know names (a
-- rollback): change_dns_zone_v1 sees forward zones only, refuses to delete
-- a zone that holds names and to create one that would take names from
-- another (MTZ01, which that Core shows as a conflict); the zone readers and
-- the map readers of schema 214 return forward zones only. The v2 functions
-- below serve every kind.
--
-- Errors, beside schema 213's: MTZ07 the zone holds names (or would take
-- names from another zone), MTZ08 the name is taken, MTZ09 a longer zone
-- holds the name, MTZ0A a name limit, MTZ0B the target Device cannot be a
-- target, MTZ0C a CNAME at the zone's own domain, MTZ0D a CNAME chain that
-- loops or is longer than 8, MTZ0E nxdomain on a domain on the Internet,
-- MTZ0F an unknown or deleted name of the zone. A
-- name change that fails on one operation names its position (from 0) in
-- the error detail.

-- Zone kinds: the resolver check now depends on what other names get.
ALTER TABLE mesh.network_dns_zone DROP CONSTRAINT network_dns_zone_other_names_check;
ALTER TABLE mesh.network_dns_zone DROP CONSTRAINT network_dns_zone_resolvers_check;
ALTER TABLE mesh.network_dns_zone ADD CONSTRAINT network_dns_zone_other_names_check CHECK (
    (other_names = 'forward' AND mesh_ops.dns_zone_resolvers_valid_internal_v1(resolvers))
    OR (other_names IN ('nxdomain', 'host') AND resolvers = '[]'::JSONB AND failure_mode = 'open'
        AND domain <> '.' AND (other_names = 'host' OR public_class = 'private'))
);

-- Fixed addresses of a name: 1 to 8 distinct host addresses, none in the
-- overlay frame (100.64.0.0/10, 198.18.0.0/15, fd00::/8) or a range no
-- answer may name (this network, loopback, link-local, multicast, reserved,
-- unspecified, IPv4-mapped).
CREATE FUNCTION mesh_ops.dns_name_addresses_valid_internal_v1(p_addresses INET[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_addresses IS NOT NULL
        AND pg_catalog.cardinality(p_addresses) BETWEEN 1 AND 8
        AND pg_catalog.array_position(p_addresses, NULL) IS NULL
        AND (SELECT pg_catalog.count(DISTINCT address) FROM pg_catalog.unnest(p_addresses) AS address)
            = pg_catalog.cardinality(p_addresses)
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.unnest(p_addresses) AS address
            WHERE pg_catalog.masklen(address) <> CASE pg_catalog.family(address) WHEN 4 THEN 32 ELSE 128 END
               OR address <<= ANY (ARRAY[
                   '0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
                   '100.64.0.0/10', '198.18.0.0/15',
                   '::/128', '::1/128', '::ffff:0:0/96', 'fe80::/10', 'ff00::/8', 'fd00::/8'
               ]::INET[]))
$function$;

CREATE TABLE mesh.network_dns_name (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    zone_id BIGINT NOT NULL,
    fqdn TEXT COLLATE "C" NOT NULL,
    kind TEXT NOT NULL,
    -- One Device of the Network by public ID: the name keeps it when the
    -- Device is removed, and answers nothing then.
    device_public_id UUID,
    addresses INET[],
    cname TEXT COLLATE "C",
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT network_dns_name_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_dns_name_fqdn_check CHECK (
        pg_catalog.octet_length(fqdn) BETWEEN 1 AND 253
        AND fqdn ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
    ),
    CONSTRAINT network_dns_name_target_check CHECK (
        (kind = 'address' AND cname IS NULL AND (
            (device_public_id IS NOT NULL AND addresses IS NULL)
            OR (device_public_id IS NULL AND mesh_ops.dns_name_addresses_valid_internal_v1(addresses))))
        OR (kind = 'cname' AND device_public_id IS NULL AND addresses IS NULL AND cname IS NOT NULL
            AND cname <> fqdn AND pg_catalog.octet_length(cname) BETWEEN 1 AND 253
            AND cname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
    ),
    CONSTRAINT network_dns_name_device_check CHECK (
        device_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(device_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_dns_name_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL) OR (state = 'deleted' AND deleted_at IS NOT NULL)
    ),
    CONSTRAINT network_dns_name_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_dns_name_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_dns_name_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_dns_name_zone_fk FOREIGN KEY (workspace_id, network_id, zone_id)
        REFERENCES mesh.network_dns_zone (workspace_id, network_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX network_dns_name_active_fqdn_uidx
    ON mesh.network_dns_name (workspace_id, network_id, fqdn)
    WHERE state = 'active';
-- A zone's names in name order (pages, counts) and the names that point at
-- one Device.
CREATE INDEX network_dns_name_zone_idx
    ON mesh.network_dns_name (zone_id, fqdn, public_id)
    WHERE state = 'active';
CREATE INDEX network_dns_name_device_idx
    ON mesh.network_dns_name (workspace_id, network_id, device_public_id)
    WHERE state = 'active' AND device_public_id IS NOT NULL;

CREATE FUNCTION mesh_ops.enforce_network_dns_name_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'DNS names are deleted by state, never removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid new DNS name';
        END IF;
        RETURN NEW;
    END IF;
    -- The zone changes only when a longer zone takes the name.
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id <> OLD.network_id
        OR NEW.fqdn <> OLD.fqdn OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid DNS name transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER network_dns_name_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.network_dns_name
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_dns_name_transition_v1();
CREATE TRIGGER network_dns_name_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_dns_name
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_dns_name', 'public_id');

ALTER TABLE mesh.network_dns_name ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_dns_name FORCE ROW LEVEL SECURITY;
CREATE POLICY network_dns_name_migrator_policy ON mesh.network_dns_name
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_dns_name
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.dns_name_addresses_valid_internal_v1(INET[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_network_dns_name_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- How many active names each zone holds, kept by a trigger: a separate row,
-- so a name change never touches the zone row (its version and ETag) or its
-- audit.
CREATE TABLE mesh.network_dns_zone_name_count (
    zone_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    name_count INTEGER NOT NULL CHECK (name_count >= 0),
    CONSTRAINT network_dns_zone_name_count_zone_fk FOREIGN KEY (workspace_id, network_id, zone_id)
        REFERENCES mesh.network_dns_zone (workspace_id, network_id, id) ON DELETE RESTRICT
);
CREATE INDEX network_dns_zone_name_count_network_idx
    ON mesh.network_dns_zone_name_count (workspace_id, network_id);

ALTER TABLE mesh.network_dns_zone_name_count ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_dns_zone_name_count FORCE ROW LEVEL SECURITY;
CREATE POLICY network_dns_zone_name_count_migrator_policy ON mesh.network_dns_zone_name_count
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_dns_zone_name_count
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.count_network_dns_names_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.state = NEW.state AND OLD.zone_id = NEW.zone_id THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.state = 'active' THEN
        UPDATE mesh.network_dns_zone_name_count SET name_count = name_count - 1 WHERE zone_id = OLD.zone_id;
    END IF;
    IF NEW.state = 'active' THEN
        INSERT INTO mesh.network_dns_zone_name_count (zone_id, workspace_id, network_id, name_count)
        VALUES (NEW.zone_id, NEW.workspace_id, NEW.network_id, 1)
        ON CONFLICT (zone_id) DO UPDATE
        SET name_count = mesh.network_dns_zone_name_count.name_count + 1;
    END IF;
    RETURN NULL;
END;
$function$;
CREATE TRIGGER network_dns_name_count
AFTER INSERT OR UPDATE ON mesh.network_dns_name
FOR EACH ROW EXECUTE FUNCTION mesh_ops.count_network_dns_names_v1();
REVOKE ALL ON FUNCTION mesh_ops.count_network_dns_names_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The longest active zone of a Network that covers a name, never the root.
CREATE FUNCTION mesh_ops.dns_longest_zone_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT, p_fqdn TEXT)
RETURNS BIGINT
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT zone.id
    FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = p_workspace_id AND zone.network_id = p_network_id AND zone.state = 'active'
      AND zone.domain = ANY (ARRAY(
          SELECT pg_catalog.array_to_string(labels.part[suffix.first:], '.')
          FROM (SELECT pg_catalog.string_to_array(p_fqdn, '.') AS part) AS labels
          CROSS JOIN LATERAL pg_catalog.generate_subscripts(labels.part, 1) AS suffix (first)))
    ORDER BY pg_catalog.length(zone.domain) DESC
    LIMIT 1
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_longest_zone_internal_v1(BIGINT, BIGINT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether a name is where it belongs: deleted, or active in the longest
-- active zone that covers it, and no CNAME at that zone's own domain.
CREATE FUNCTION mesh_ops.dns_name_placed_internal_v1(p_name_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT name.state = 'deleted' OR (
        zone.state = 'active'
        AND mesh_ops.dns_longest_zone_internal_v1(name.workspace_id, name.network_id, name.fqdn) = zone.id
        AND (name.kind = 'address' OR name.fqdn <> zone.domain))
    FROM mesh.network_dns_name AS name
    JOIN mesh.network_dns_zone AS zone ON zone.id = name.zone_id
    WHERE name.id = p_name_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_name_placed_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Checked at commit, after every write of the transaction: a name changed,
-- or a zone created or deleted, leaves every name of the Network in place.
CREATE FUNCTION mesh_ops.check_network_dns_names_placed_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_TABLE_NAME = 'network_dns_name' THEN
        IF NOT COALESCE(mesh_ops.dns_name_placed_internal_v1(NEW.id), FALSE) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'DNS name is not in its longest zone';
        END IF;
        RETURN NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.network_dns_name AS name
        WHERE name.workspace_id = NEW.workspace_id AND name.network_id = NEW.network_id
          AND name.state = 'active'
          AND (name.zone_id = NEW.id OR (NEW.domain <> '.'
               AND (name.fqdn = NEW.domain OR pg_catalog.right(name.fqdn, pg_catalog.length(NEW.domain) + 1)
                    = '.' || NEW.domain)))
          AND NOT COALESCE(mesh_ops.dns_name_placed_internal_v1(name.id), FALSE)) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'DNS zone leaves names outside their longest zone';
    END IF;
    RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER network_dns_name_placed
AFTER INSERT OR UPDATE ON mesh.network_dns_name
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.check_network_dns_names_placed_v1();
CREATE CONSTRAINT TRIGGER network_dns_zone_names_placed
AFTER INSERT OR UPDATE OF state ON mesh.network_dns_zone
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.check_network_dns_names_placed_v1();
REVOKE ALL ON FUNCTION mesh_ops.check_network_dns_names_placed_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One zone of any kind, with its resolvers ([] when it has none) and how
-- many names it holds.
CREATE FUNCTION mesh_ops.dns_zone_document_internal_v2(p_zone mesh.network_dns_zone)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT document || pg_catalog.jsonb_build_object(
        'resolvers', CASE WHEN pg_catalog.jsonb_typeof(document -> 'resolvers') = 'array'
                          THEN document -> 'resolvers' ELSE '[]'::JSONB END,
        'name_count', COALESCE((SELECT counted.name_count FROM mesh.network_dns_zone_name_count AS counted
                                WHERE counted.zone_id = p_zone.id), 0))
    FROM (SELECT mesh_ops.dns_zone_document_internal_v1(p_zone) AS document) AS zone_document
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_zone_document_internal_v2(mesh.network_dns_zone)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Schema 213's readers return forward zones only: the Core that reads them
-- knows no other kind.
CREATE OR REPLACE FUNCTION mesh_ops.list_dns_zones_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_zone_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN mesh_ops.list_dns_zones_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_after_zone_public_id, p_limit, TRUE);
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.read_dns_zone_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN mesh_ops.read_dns_zone_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, TRUE);
END;
$function$;

-- One page of the Network's active zones in domain order; p_legacy keeps
-- to forward zones and schema 213's document.
CREATE FUNCTION mesh_ops.list_dns_zones_internal_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_zone_public_id UUID, p_limit INTEGER,
    p_legacy BOOLEAN
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_after_domain TEXT;
    v_page JSONB;
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR p_legacy IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone page is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    IF p_after_zone_public_id IS NOT NULL THEN
        SELECT zone.domain INTO v_after_domain FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
          AND zone.public_id = p_after_zone_public_id;
        IF v_after_domain IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone page cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(CASE WHEN p_legacy THEN mesh_ops.dns_zone_document_internal_v1(page)
                                     ELSE mesh_ops.dns_zone_document_internal_v2(page) END
               ORDER BY page.domain COLLATE "C", page.public_id),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT * FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
          AND zone.state = 'active' AND (NOT p_legacy OR zone.other_names = 'forward')
          AND (v_after_domain IS NULL
               OR (zone.domain COLLATE "C", zone.public_id) > (v_after_domain COLLATE "C", p_after_zone_public_id))
        ORDER BY zone.domain COLLATE "C", zone.public_id
        LIMIT p_limit + 1
    ) AS page;
    RETURN pg_catalog.jsonb_build_object(
        'zones', CASE WHEN v_count > p_limit THEN v_page - p_limit ELSE COALESCE(v_page, '[]'::JSONB) END,
        'has_more', v_count > p_limit,
        'workspace_code', (SELECT identity.display_code FROM mesh_ops.tenant_display_identity AS identity
                           WHERE identity.workspace_public_id = p_workspace_public_id),
        'network_code', (SELECT identity.display_code FROM mesh_ops.tenant_display_identity AS identity
                         WHERE identity.network_public_id = p_network_public_id)
    ) || mesh_ops.dns_zone_abilities_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_dns_zones_internal_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, BOOLEAN
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One active zone; p_legacy keeps to forward zones.
CREATE FUNCTION mesh_ops.read_dns_zone_internal_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_legacy BOOLEAN
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
BEGIN
    IF p_legacy IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone read is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    SELECT * INTO v_zone FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
      AND zone.public_id = p_zone_public_id AND zone.state = 'active'
      AND (NOT p_legacy OR zone.other_names = 'forward');
    IF v_zone.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'DNS zone is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('zone', CASE WHEN p_legacy
            THEN mesh_ops.dns_zone_document_internal_v1(v_zone)
            ELSE mesh_ops.dns_zone_document_internal_v2(v_zone) END)
        || mesh_ops.dns_zone_abilities_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_dns_zone_internal_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BOOLEAN
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.list_dns_zones_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_zone_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN mesh_ops.list_dns_zones_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_after_zone_public_id, p_limit, FALSE);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_dns_zones_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_dns_zones_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;

CREATE FUNCTION mesh_ops.read_dns_zone_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN mesh_ops.read_dns_zone_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_zone_public_id, FALSE);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_dns_zone_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_dns_zone_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- Names in zones of kind host across the Network: their names are each a
-- domain the host routes to its resolver.
CREATE FUNCTION mesh_ops.dns_host_name_count_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS BIGINT
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE(pg_catalog.sum(counted.name_count), 0)::BIGINT
    FROM mesh.network_dns_zone_name_count AS counted
    JOIN mesh.network_dns_zone AS zone ON zone.id = counted.zone_id
    WHERE counted.workspace_id = p_workspace_id AND counted.network_id = p_network_id
      AND zone.state = 'active' AND zone.other_names = 'host'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_host_name_count_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates, changes or deletes a zone (dns.manage), schema 213's rules plus
-- the zone kinds and its names. A new zone that would take names from a
-- shorter zone takes them only with p_with_names (else MTZ07); a zone that
-- holds names is deleted only with p_with_names, and its names with it.
-- p_legacy is schema 213's caller: forward zones only, no names moved or
-- deleted (MTZ01), its document. p_host_name_limit bounds the names in
-- zones of kind host across the Network.
CREATE FUNCTION mesh_ops.change_dns_zone_internal_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_zone_public_id UUID, p_expected_version BIGINT, p_domain TEXT, p_other_names TEXT, p_failure_mode TEXT,
    p_resolvers JSONB, p_group_public_ids UUID[], p_search_position INTEGER, p_public_class TEXT,
    p_public_list_version TEXT, p_public_confirmed BOOLEAN, p_zone_limit INTEGER, p_search_limit INTEGER,
    p_consumer_limit INTEGER, p_host_name_limit INTEGER, p_with_names BOOLEAN, p_legacy BOOLEAN,
    p_change_public_id UUID
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
    v_before JSONB;
    v_groups BIGINT[] := '{}';
    v_item JSONB;
    v_device mesh.device%ROWTYPE;
    v_constraint TEXT;
    v_network_revision BIGINT;
    v_dns_revision BIGINT;
    v_names BIGINT[] := '{}';
    v_hosted_before BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_zone_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_zone_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_with_names IS NULL OR p_legacy IS NULL OR (p_legacy AND p_with_names)
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_domain IS NULL OR p_failure_mode IS NULL OR p_resolvers IS NULL
            OR p_other_names IS NULL OR p_other_names NOT IN ('forward', 'nxdomain', 'host')
            OR (p_legacy AND p_other_names <> 'forward')
            OR p_group_public_ids IS NULL OR pg_catalog.cardinality(p_group_public_ids) > 16
            OR p_public_class IS NULL OR p_public_list_version IS NULL OR p_public_confirmed IS NULL
            OR p_search_limit IS NULL OR p_search_limit NOT BETWEEN 0 AND 16
            OR p_consumer_limit IS NULL OR p_consumer_limit NOT BETWEEN 1 AND 100000
            OR p_host_name_limit IS NULL OR p_host_name_limit NOT BETWEEN 0 AND 2000))
        OR (p_operation = 'create' AND (p_zone_limit IS NULL OR p_zone_limit NOT BETWEEN 1 AND 1000)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone change is invalid';
    END IF;
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DNS zone scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_hosted_before := mesh_ops.dns_host_name_count_internal_v1(v_scope.workspace_id, v_scope.network_id);

    IF p_operation <> 'create' THEN
        SELECT * INTO v_zone FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
          AND zone.public_id = p_zone_public_id AND zone.state = 'active'
          AND (NOT p_legacy OR zone.other_names = 'forward')
        FOR UPDATE;
        IF v_zone.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'DNS zone is unavailable';
        END IF;
        IF v_zone.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'DNS zone version changed';
        END IF;
        v_before := CASE WHEN p_legacy THEN mesh_ops.dns_zone_document_internal_v1(v_zone)
                         ELSE mesh_ops.dns_zone_document_internal_v2(v_zone) END;
    END IF;

    IF p_operation = 'update' AND v_zone.domain = p_domain AND v_zone.other_names = p_other_names
        AND v_zone.failure_mode = p_failure_mode
        AND v_zone.resolvers = p_resolvers AND v_zone.search_position IS NOT DISTINCT FROM p_search_position
        AND v_zone.public_confirmed = p_public_confirmed AND v_zone.public_class = p_public_class
        AND v_zone.public_list_version = p_public_list_version
        AND v_zone.distribution_group_ids = COALESCE((
            SELECT pg_catalog.array_agg(device_group.id ORDER BY device_group.id)
            FROM mesh.device_group AS device_group
            WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
              AND device_group.state = 'active' AND device_group.public_id = ANY (p_group_public_ids)), '{}')
        AND pg_catalog.cardinality(v_zone.distribution_group_ids) = (
            SELECT pg_catalog.count(DISTINCT item) FROM pg_catalog.unnest(p_group_public_ids) AS item) THEN
        RETURN pg_catalog.jsonb_build_object(
            'zone', v_before, 'previous', v_before, 'changed', FALSE, 'names', 0,
            'role_binding_id', v_scope.role_binding_public_id);
    END IF;

    IF p_operation <> 'delete' THEN
        IF p_operation = 'update' AND (p_domain <> v_zone.domain OR p_public_class <> v_zone.public_class
            OR p_public_list_version <> v_zone.public_list_version) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'A DNS zone domain never changes';
        END IF;
        IF p_other_names = 'nxdomain' AND p_public_class <> 'private' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ0E', MESSAGE = 'A DNS zone on the Internet is never nxdomain';
        END IF;
        SELECT pg_catalog.array_agg(device_group.id ORDER BY device_group.id) INTO v_groups
        FROM mesh.device_group AS device_group
        WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
          AND device_group.state = 'active' AND device_group.public_id = ANY (p_group_public_ids);
        v_groups := COALESCE(v_groups, '{}');
        IF pg_catalog.cardinality(v_groups) <> (SELECT pg_catalog.count(DISTINCT item)
                                                FROM pg_catalog.unnest(p_group_public_ids) AS item) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ04', MESSAGE = 'Device Group is not an active group of this Network';
        END IF;
        IF (p_other_names = 'forward' AND NOT mesh_ops.dns_zone_resolvers_valid_internal_v1(p_resolvers))
            OR (p_other_names <> 'forward' AND (p_resolvers <> '[]'::JSONB OR p_failure_mode <> 'open'
                                                OR p_domain = '.')) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone resolvers are invalid';
        END IF;
        FOR v_item IN SELECT item FROM pg_catalog.jsonb_array_elements(p_resolvers) AS item
                      WHERE item ? 'device_id' LOOP
            SELECT * INTO v_device FROM mesh.device AS device
            WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
              AND device.public_id = (v_item ->> 'device_id')::UUID AND device.deleted_at IS NULL
            FOR SHARE;
            IF v_device.id IS NULL OR v_device.state <> 'active' OR v_device.ownership <> 'workspace'
                OR EXISTS (SELECT 1 FROM mesh.network_exit_node AS exit_node
                           WHERE exit_node.device_id = v_device.id) THEN
                RAISE EXCEPTION USING ERRCODE = 'MTZ03', MESSAGE = 'Device cannot be a DNS resolver';
            END IF;
            IF mesh_ops.dns_resolver_consumers_internal_v1(v_scope.workspace_id, v_scope.network_id,
                v_item ->> 'device_id', v_zone.id, v_groups) > p_consumer_limit THEN
                RAISE EXCEPTION USING ERRCODE = 'MTZ06',
                    MESSAGE = 'a DNS resolver Device would serve more Devices than a map holds';
            END IF;
        END LOOP;
        IF p_search_position IS NOT NULL AND (
            SELECT pg_catalog.count(*) FROM mesh.network_dns_zone AS zone
            WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
              AND zone.state = 'active' AND zone.search_position IS NOT NULL
              AND zone.id IS DISTINCT FROM v_zone.id) >= p_search_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ05', MESSAGE = 'Network already has the maximum search domains';
        END IF;
    END IF;

    IF p_operation = 'create' THEN
        IF p_domain <> '.' AND (SELECT pg_catalog.count(*) FROM mesh.network_dns_zone AS zone
            WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
              AND zone.state = 'active' AND zone.domain <> '.') >= p_zone_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ02', MESSAGE = 'Network already has the maximum DNS zones';
        END IF;
        -- Names the new zone covers that a shorter zone holds now.
        IF p_domain <> '.' THEN
            SELECT COALESCE(pg_catalog.array_agg(name.id ORDER BY name.id), '{}') INTO v_names
            FROM mesh.network_dns_name AS name
            JOIN mesh.network_dns_zone AS holder ON holder.id = name.zone_id
            WHERE name.workspace_id = v_scope.workspace_id AND name.network_id = v_scope.network_id
              AND name.state = 'active'
              AND (name.fqdn = p_domain
                   OR pg_catalog.right(name.fqdn, pg_catalog.length(p_domain) + 1) = '.' || p_domain)
              AND pg_catalog.length(holder.domain) < pg_catalog.length(p_domain);
        END IF;
        IF pg_catalog.cardinality(v_names) > 0 AND NOT p_with_names THEN
            RAISE EXCEPTION USING ERRCODE = CASE WHEN p_legacy THEN 'MTZ01' ELSE 'MTZ07' END,
                MESSAGE = 'DNS zone would take names another zone holds';
        END IF;
        BEGIN
            INSERT INTO mesh.network_dns_zone (
                public_id, deployment_id, workspace_id, network_id, domain, other_names, failure_mode, resolvers,
                distribution_group_ids, search_position, public_class, public_list_version, public_confirmed,
                created_at, updated_at
            ) VALUES (
                p_zone_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, p_domain,
                p_other_names, p_failure_mode, p_resolvers, v_groups, p_search_position, p_public_class,
                p_public_list_version, p_public_confirmed, v_now, v_now
            ) RETURNING * INTO v_zone;
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_dns_zone_active_domain_uidx' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTZ01', MESSAGE = 'DNS zone domain is taken';
            END IF;
            RAISE;
        END;
        IF EXISTS (SELECT 1 FROM mesh.network_dns_name AS name
                   WHERE name.id = ANY (v_names) AND name.fqdn = p_domain AND name.kind = 'cname') THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ0C', MESSAGE = 'A CNAME would be the zone''s own domain';
        END IF;
        UPDATE mesh.network_dns_name AS name
        SET zone_id = v_zone.id, version = name.version + 1, updated_at = GREATEST(v_now, name.updated_at)
        WHERE name.id = ANY (v_names);
    ELSIF p_operation = 'update' THEN
        UPDATE mesh.network_dns_zone
        SET other_names = p_other_names, failure_mode = p_failure_mode, resolvers = p_resolvers,
            distribution_group_ids = v_groups, search_position = p_search_position,
            public_confirmed = p_public_confirmed, version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_zone.id
        RETURNING * INTO v_zone;
    ELSE
        SELECT COALESCE(pg_catalog.array_agg(name.id ORDER BY name.id), '{}') INTO v_names
        FROM mesh.network_dns_name AS name
        WHERE name.zone_id = v_zone.id AND name.state = 'active';
        IF pg_catalog.cardinality(v_names) > 0 AND NOT p_with_names THEN
            RAISE EXCEPTION USING ERRCODE = CASE WHEN p_legacy THEN 'MTZ01' ELSE 'MTZ07' END,
                MESSAGE = 'DNS zone holds names';
        END IF;
        UPDATE mesh.network_dns_name AS name
        SET state = 'deleted', deleted_at = GREATEST(v_now, name.updated_at), version = name.version + 1,
            updated_at = GREATEST(v_now, name.updated_at)
        WHERE name.id = ANY (v_names);
        UPDATE mesh.network_dns_zone
        SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at),
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_zone.id
        RETURNING * INTO v_zone;
    END IF;
    IF mesh_ops.dns_host_name_count_internal_v1(v_scope.workspace_id, v_scope.network_id)
        > GREATEST(p_host_name_limit, v_hosted_before) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ0A', MESSAGE = 'Network already has the most names in host zones';
    END IF;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1, dns_revision = revision.dns_revision + 1,
        updated_at = GREATEST(v_now, revision.updated_at)
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    RETURNING revision.network_revision, revision.dns_revision INTO v_network_revision, v_dns_revision;
    RETURN pg_catalog.jsonb_build_object(
        'zone', CASE WHEN p_legacy THEN mesh_ops.dns_zone_document_internal_v1(v_zone)
                     ELSE mesh_ops.dns_zone_document_internal_v2(v_zone) END,
        'previous', v_before, 'changed', TRUE, 'names', pg_catalog.cardinality(v_names),
        'network_revision', v_network_revision, 'dns_revision', v_dns_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_dns_zone_internal_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, TEXT, TEXT, JSONB, UUID[], INTEGER, TEXT, TEXT, BOOLEAN, INTEGER, INTEGER, INTEGER,
    INTEGER, BOOLEAN, BOOLEAN, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Schema 213's change: forward zones only, and never a name moved or
-- deleted.
CREATE OR REPLACE FUNCTION mesh_ops.change_dns_zone_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_zone_public_id UUID, p_expected_version BIGINT, p_domain TEXT, p_failure_mode TEXT,
    p_resolvers JSONB, p_group_public_ids UUID[], p_search_position INTEGER, p_public_class TEXT,
    p_public_list_version TEXT, p_public_confirmed BOOLEAN, p_zone_limit INTEGER, p_search_limit INTEGER,
    p_consumer_limit INTEGER, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    v_result := mesh_ops.change_dns_zone_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_operation, p_zone_public_id, p_expected_version, p_domain,
        CASE WHEN p_operation = 'delete' THEN NULL ELSE 'forward' END, p_failure_mode, p_resolvers,
        p_group_public_ids, p_search_position, p_public_class, p_public_list_version, p_public_confirmed,
        p_zone_limit, p_search_limit, p_consumer_limit, CASE WHEN p_operation = 'delete' THEN NULL ELSE 0 END,
        FALSE, TRUE, p_change_public_id);
    RETURN v_result - 'names';
END;
$function$;

-- Schema 215's change: every zone kind, and names moved with p_with_names.
CREATE FUNCTION mesh_ops.change_dns_zone_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_zone_public_id UUID, p_expected_version BIGINT, p_domain TEXT, p_other_names TEXT, p_failure_mode TEXT,
    p_resolvers JSONB, p_group_public_ids UUID[], p_search_position INTEGER, p_public_class TEXT,
    p_public_list_version TEXT, p_public_confirmed BOOLEAN, p_zone_limit INTEGER, p_search_limit INTEGER,
    p_consumer_limit INTEGER, p_host_name_limit INTEGER, p_with_names BOOLEAN, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN mesh_ops.change_dns_zone_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_operation, p_zone_public_id, p_expected_version, p_domain,
        p_other_names, p_failure_mode, p_resolvers, p_group_public_ids, p_search_position, p_public_class,
        p_public_list_version, p_public_confirmed, p_zone_limit, p_search_limit, p_consumer_limit,
        p_host_name_limit, p_with_names, FALSE, p_change_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_dns_zone_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, TEXT, TEXT, JSONB, UUID[], INTEGER, TEXT, TEXT, BOOLEAN, INTEGER, INTEGER, INTEGER,
    INTEGER, BOOLEAN, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_dns_zone_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, TEXT, TEXT, JSONB, UUID[], INTEGER, TEXT, TEXT, BOOLEAN, INTEGER, INTEGER, INTEGER,
    INTEGER, BOOLEAN, UUID
) TO mesh_runtime;

-- Schema 214's map readers keep to forward zones: the Core that reads them
-- knows no other kind.
CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_dns_zones_v1(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    domain TEXT,
    failure_mode TEXT,
    group_ids BIGINT[],
    search_position INTEGER
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
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1025 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS zone request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS zone scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT zone.id, zone.domain, zone.failure_mode, zone.distribution_group_ids,
           COALESCE(zone.search_position, 0)
    FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = scoped_workspace_id
      AND zone.network_id = scoped_network_id
      AND zone.state = 'active'
      AND zone.other_names = 'forward'
    ORDER BY zone.domain COLLATE "C"
    LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_dns_resolvers_v1(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    resolver_position INTEGER,
    device_id BIGINT,
    device_public_id TEXT,
    address TEXT,
    port INTEGER,
    eligible BOOLEAN
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
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 4101 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS resolver request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS resolver scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT zone.id, resolver.position::INTEGER, COALESCE(device.id, 0),
           COALESCE(resolver.item ->> 'device_id', ''), COALESCE(resolver.item ->> 'address', ''),
           (resolver.item ->> 'port')::INTEGER,
           COALESCE(device.state = 'active' AND device.ownership = 'workspace', FALSE)
    FROM mesh.network_dns_zone AS zone
    CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(zone.resolvers) WITH ORDINALITY AS resolver (item, position)
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = zone.workspace_id AND device.network_id = zone.network_id
     AND device.public_id = (resolver.item ->> 'device_id')::UUID AND device.deleted_at IS NULL
    WHERE zone.workspace_id = scoped_workspace_id
      AND zone.network_id = scoped_network_id
      AND zone.state = 'active'
      AND zone.other_names = 'forward'
    ORDER BY zone.id, resolver.position
    LIMIT p_limit;
END;
$function$;

-- One name: its zone, its label in the zone (@ for the zone's own domain),
-- its target and, for a Device, the Device's name and state (removed once
-- it is gone).
CREATE FUNCTION mesh_ops.dns_name_document_internal_v1(p_name mesh.network_dns_name)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'name_id', p_name.public_id,
        'zone_id', zone.public_id,
        'fqdn', p_name.fqdn,
        'label', CASE WHEN p_name.fqdn = zone.domain THEN '@'
                      ELSE pg_catalog.left(p_name.fqdn,
                               pg_catalog.length(p_name.fqdn) - pg_catalog.length(zone.domain) - 1) END,
        'kind', p_name.kind,
        'device_id', p_name.device_public_id,
        'device_name', device.hostname,
        'device_state', CASE WHEN p_name.device_public_id IS NULL THEN NULL
                             WHEN device.id IS NULL OR device.deleted_at IS NOT NULL THEN 'removed'
                             ELSE device.state END,
        'addresses', (SELECT pg_catalog.jsonb_agg(pg_catalog.host(item.address) ORDER BY item.ordinal)
                      FROM pg_catalog.unnest(p_name.addresses) WITH ORDINALITY AS item (address, ordinal)),
        'cname', p_name.cname,
        'state', p_name.state,
        'version', p_name.version,
        'created_at', p_name.created_at,
        'updated_at', p_name.updated_at
    )
    FROM mesh.network_dns_zone AS zone
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = p_name.workspace_id AND device.network_id = p_name.network_id
     AND device.public_id = p_name.device_public_id
    WHERE zone.id = p_name.zone_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_name_document_internal_v1(mesh.network_dns_name)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The active zone a name request is about, in the authorized scope.
CREATE FUNCTION mesh_ops.dns_name_zone_internal_v1(p_scope_workspace_id BIGINT, p_scope_network_id BIGINT,
    p_zone_public_id UUID)
RETURNS mesh.network_dns_zone
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_zone mesh.network_dns_zone%ROWTYPE;
BEGIN
    SELECT * INTO v_zone FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = p_scope_workspace_id AND zone.network_id = p_scope_network_id
      AND zone.public_id = p_zone_public_id AND zone.state = 'active' AND zone.domain <> '.';
    IF v_zone.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'DNS zone is unavailable';
    END IF;
    RETURN v_zone;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_name_zone_internal_v1(BIGINT, BIGINT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One page of a zone's active names in name order (network.read), after the
-- name p_after_name_public_id when given, those starting with p_prefix
-- when given.
CREATE FUNCTION mesh_ops.list_dns_names_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_after_name_public_id UUID,
    p_prefix TEXT, p_limit INTEGER
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
    v_zone mesh.network_dns_zone%ROWTYPE;
    v_after_fqdn TEXT;
    v_page JSONB;
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
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
    SELECT pg_catalog.jsonb_agg(mesh_ops.dns_name_document_internal_v1(page)
               ORDER BY page.fqdn, page.public_id),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT * FROM mesh.network_dns_name AS name
        WHERE name.zone_id = v_zone.id AND name.state = 'active'
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
REVOKE ALL ON FUNCTION mesh_ops.list_dns_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, TEXT, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_dns_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, TEXT, INTEGER
) TO mesh_runtime;

-- One active name of a zone (network.read).
CREATE FUNCTION mesh_ops.read_dns_name_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_name_public_id UUID
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
    v_zone mesh.network_dns_zone%ROWTYPE;
    v_name mesh.network_dns_name%ROWTYPE;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    v_zone := mesh_ops.dns_name_zone_internal_v1(v_scope.workspace_id, v_scope.network_id, p_zone_public_id);
    SELECT * INTO v_name FROM mesh.network_dns_name AS name
    WHERE name.zone_id = v_zone.id AND name.public_id = p_name_public_id AND name.state = 'active';
    IF v_name.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTZ0F', MESSAGE = 'DNS name is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('name', mesh_ops.dns_name_document_internal_v1(v_name))
        || mesh_ops.dns_zone_abilities_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_dns_name_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_dns_name_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID
) TO mesh_runtime;

-- The target of one name operation, read from its JSON: a Device, fixed
-- addresses (canonical text) or a CNAME; NULLs for what it is not.
CREATE FUNCTION mesh_ops.dns_name_target_internal_v1(p_item JSONB,
    OUT kind TEXT, OUT device_public_id UUID, OUT addresses INET[], OUT cname TEXT)
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    kind := p_item ->> 'kind';
    IF p_item ? 'device_id' THEN
        device_public_id := (p_item ->> 'device_id')::UUID;
    END IF;
    IF p_item ? 'addresses' THEN
        IF pg_catalog.jsonb_typeof(p_item -> 'addresses') <> 'array' OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_item -> 'addresses') AS item
            WHERE pg_catalog.jsonb_typeof(item) <> 'string' OR item #>> '{}' !~ '^[0-9a-f.:]{2,39}$'
               OR pg_catalog.host((item #>> '{}')::INET) <> item #>> '{}') THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name addresses are invalid';
        END IF;
        addresses := ARRAY(SELECT (entry.item #>> '{}')::INET
                           FROM pg_catalog.jsonb_array_elements(p_item -> 'addresses') WITH ORDINALITY
                                AS entry (item, ordinal)
                           ORDER BY entry.ordinal);
    END IF;
    cname := p_item ->> 'cname';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_name_target_internal_v1(JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates, changes and deletes names of one zone (dns.manage): 1 to 100
-- operations, each on its own name, applied deletes first, then updates,
-- then creates, so the checks see the zone as the request leaves it. A
-- create gives the name's label (@ for the zone's own domain), an update
-- or a delete the name and its expected version; creates and updates give
-- the kind and target. A new target Device is an active Device of the
-- Network; a name keeps a Device that has gone since.
-- The limits are names per zone, per Network and in zones of kind host
-- across the Network; a change that only lowers a count never fails on
-- one. An update that changes nothing writes nothing; a request that
-- changes nothing returns changed = false. Changes serialize on the
-- Network's revision row and advance the Network and DNS revisions once.
CREATE FUNCTION mesh_ops.change_dns_names_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID, p_operations JSONB,
    p_zone_name_limit INTEGER, p_network_name_limit INTEGER, p_host_name_limit INTEGER,
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
        OR p_host_name_limit IS NULL OR p_host_name_limit NOT BETWEEN 0 AND 2000 THEN
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
                FOR UPDATE;
                IF v_name.id IS NULL THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTZ0F', MESSAGE = 'DNS name is unavailable',
                        DETAIL = v_index::TEXT;
                END IF;
                IF v_name.version <> (v_item ->> 'expected_version')::BIGINT THEN
                    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'DNS name version changed',
                        DETAIL = v_index::TEXT;
                END IF;
                v_before := mesh_ops.dns_name_document_internal_v1(v_name);
            END IF;
            IF v_pass <> 'delete' THEN
                BEGIN
                    SELECT * INTO v_target FROM mesh_ops.dns_name_target_internal_v1(v_item);
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
                    AND v_name.cname IS NOT DISTINCT FROM v_target.cname THEN
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
                        version = name.version + 1, updated_at = GREATEST(v_now, name.updated_at)
                    WHERE name.id = v_name.id
                    RETURNING * INTO v_name;
                ELSE
                    INSERT INTO mesh.network_dns_name (
                        public_id, deployment_id, workspace_id, network_id, zone_id, fqdn, kind,
                        device_public_id, addresses, cname, created_at, updated_at
                    ) VALUES (
                        v_name_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, v_zone.id,
                        v_fqdn, v_target.kind, v_target.device_public_id, v_target.addresses, v_target.cname,
                        v_now, v_now
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
                'name', mesh_ops.dns_name_document_internal_v1(v_name), 'previous', v_before, 'changed', TRUE);
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
REVOKE ALL ON FUNCTION mesh_ops.change_dns_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB,
    INTEGER, INTEGER, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_dns_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB,
    INTEGER, INTEGER, INTEGER, UUID
) TO mesh_runtime;
