-- Schema 157: registration finds a prefix's lowest free address from a
-- stored floor instead of reading every live lease of the prefix.
--
-- Registration gives a new Device the lowest address of the prefix that no
-- live lease holds. Finding it read every live lease of the prefix, O(N) per
-- registration (13 ms per prefix at 100,000 Devices). Each prefix now keeps a
-- floor (registration_address_floor) with this invariant:
--
--   every address from the prefix's first host up to, but not including, the
--   floor is held by a lease that is active for a Device that is not revoked,
--   or quarantined.
--
-- Below the floor the only free addresses are therefore those whose
-- quarantine has ended, which the quarantine index finds directly. At and
-- above the floor the allocator walks the live leases in address order from
-- the floor, which is normally free itself. After allocating, the allocator
-- raises the floor past the addresses it saw settled; it holds the prefix's
-- allocator lock and the floor row lock while it does so.
--
-- A live lease that stops being live, moves, or is deleted lowers the floor
-- (trigger on node_address_lease). A lease that becomes live, or a floor that
-- is lower than it could be, keeps the invariant: a low floor only makes the
-- next walk longer. A missing floor row means the prefix's first host.
--
-- A Device revoked since schema 143 has its leases quarantined in the same
-- transaction, which keeps them settled; revocation does not read leases
-- here. A lease still active for a Device revoked before schema 143 is not
-- settled: the backfill below and the allocator's walk keep the floor at or
-- below it. Were a future writer to revoke a Device without quarantining its
-- lease below the floor, that address would only wait for the floor to come
-- down again before reuse; no address is ever leased twice.
--
-- The floor never decides whether an address may be leased: the live-address
-- unique index stays the final arbiter.

CREATE TABLE mesh_ops.registration_address_floor (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    network_prefix_id BIGINT NOT NULL,
    -- The prefix the floor was computed for; a floor for another prefix
    -- value is ignored.
    prefix CIDR NOT NULL,
    floor_address INET NOT NULL,
    PRIMARY KEY (network_prefix_id),
    CONSTRAINT registration_address_floor_prefix_fk FOREIGN KEY (workspace_id, network_id, network_prefix_id)
        REFERENCES mesh.network_prefix (workspace_id, network_id, id) ON DELETE CASCADE,
    CONSTRAINT registration_address_floor_address_check CHECK (
        pg_catalog.family(floor_address) = pg_catalog.family(prefix)
        AND pg_catalog.masklen(floor_address) = CASE pg_catalog.family(prefix) WHEN 4 THEN 32 ELSE 128 END
    )
);

ALTER TABLE mesh_ops.registration_address_floor ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.registration_address_floor FORCE ROW LEVEL SECURITY;
CREATE POLICY registration_address_floor_migrator_policy ON mesh_ops.registration_address_floor
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
-- The registering transaction reads and writes the floors of its own
-- Network's prefixes, for the prefix value they hold.
CREATE POLICY registration_address_floor_exact_scope_policy ON mesh_ops.registration_address_floor
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
        AND EXISTS (
            SELECT 1
            FROM mesh.network_prefix AS network_prefix
            WHERE network_prefix.workspace_id = registration_address_floor.workspace_id
              AND network_prefix.network_id = registration_address_floor.network_id
              AND network_prefix.id = registration_address_floor.network_prefix_id
              AND network_prefix.prefix = registration_address_floor.prefix
        )
    );
GRANT SELECT, INSERT, UPDATE ON mesh_ops.registration_address_floor TO mesh_runtime;

-- The allocator walks a prefix's live leases in address order, and finds the
-- leases whose quarantine has ended below the floor.
CREATE INDEX node_address_lease_prefix_live_address_idx
    ON mesh.node_address_lease (network_prefix_id, address)
    WHERE state IN ('active', 'quarantined');
CREATE INDEX node_address_lease_prefix_quarantine_address_idx
    ON mesh.node_address_lease (network_prefix_id, address) INCLUDE (quarantine_until)
    WHERE state = 'quarantined';

-- A live lease stopped being live, moved or was deleted: its address may be
-- free now, so the floor of its prefix goes no higher than it.
CREATE FUNCTION mesh_ops.lower_registration_address_floor_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    UPDATE mesh_ops.registration_address_floor AS address_floor
    SET floor_address = OLD.address
    WHERE address_floor.network_prefix_id = OLD.network_prefix_id
      AND address_floor.floor_address > OLD.address;
    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lower_registration_address_floor_v1() FROM PUBLIC;

CREATE TRIGGER node_address_lease_registration_floor_update
AFTER UPDATE ON mesh.node_address_lease
FOR EACH ROW
WHEN (OLD.state IN ('active', 'quarantined')
    AND (NEW.state NOT IN ('active', 'quarantined')
        OR (NEW.network_prefix_id, NEW.address, NEW.device_id)
            IS DISTINCT FROM (OLD.network_prefix_id, OLD.address, OLD.device_id)))
EXECUTE FUNCTION mesh_ops.lower_registration_address_floor_v1();
CREATE TRIGGER node_address_lease_registration_floor_delete
AFTER DELETE ON mesh.node_address_lease
FOR EACH ROW
WHEN (OLD.state IN ('active', 'quarantined'))
EXECUTE FUNCTION mesh_ops.lower_registration_address_floor_v1();

-- Every prefix starts at the lowest address no settled lease holds. The
-- trigger above exists already and blocks lease writers until this commits,
-- so no release is missed between the read and the floor.
WITH settled AS (
    -- Each live lease that is not active for a revoked Device, with the
    -- address after it (none for the last address of a family, which never
    -- holds a mesh host) and the next settled address of its prefix.
    SELECT
        lease.network_prefix_id,
        lease.address,
        CASE WHEN pg_catalog.host(lease.address) IN (
            '255.255.255.255', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        ) THEN NULL ELSE lease.address + 1 END AS successor,
        pg_catalog.lead(lease.address) OVER (
            PARTITION BY lease.network_prefix_id ORDER BY lease.address
        ) AS next_address
    FROM mesh.node_address_lease AS lease
    LEFT JOIN mesh.device AS device
      ON device.id = lease.device_id AND device.state = 'revoked'
    WHERE lease.state IN ('active', 'quarantined')
      AND NOT (lease.state = 'active' AND device.id IS NOT NULL)
), bounds AS (
    SELECT
        network_prefix.workspace_id,
        network_prefix.network_id,
        network_prefix.id,
        network_prefix.prefix,
        pg_catalog.set_masklen(
            pg_catalog.network(network_prefix.prefix)::INET + 1,
            CASE pg_catalog.family(network_prefix.prefix) WHEN 4 THEN 32 ELSE 128 END
        ) AS first_host
    FROM mesh.network_prefix AS network_prefix
)
INSERT INTO mesh_ops.registration_address_floor (
    workspace_id, network_id, network_prefix_id, prefix, floor_address
)
SELECT
    bounds.workspace_id,
    bounds.network_id,
    bounds.id,
    bounds.prefix,
    CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM settled
            WHERE settled.network_prefix_id = bounds.id AND settled.address = bounds.first_host
        ) THEN bounds.first_host
        -- The first host is settled: the floor is the address after the
        -- first settled lease whose successor is not settled.
        ELSE COALESCE((
            SELECT pg_catalog.min(settled.successor)
            FROM settled
            WHERE settled.network_prefix_id = bounds.id
              AND settled.address >= bounds.first_host
              AND settled.successor IS NOT NULL
              AND settled.next_address IS DISTINCT FROM settled.successor
        ), bounds.first_host)
    END
FROM bounds;
