-- Schema 196: Sites may use IPv6 unique local prefixes (fc00::/7).
--
-- Until now every prefix in fd00::/8, the client overlay frame, was refused,
-- which kept a LAN's or VPC's own unique local prefix out of Sites. Only the
-- addresses the mesh itself uses are reserved now: fd00::/48 (the router
-- self-test address fd00:: lives there) and, checked when a Site is written,
-- the Workspace's overlay pools and the deployment's Device alias pools. A
-- prefix that overlaps one is refused with MTS09. Clients also leave out a
-- Site prefix that overlaps the /48 of a mesh address they hold.
--
-- The validators keep their names: the CHECK constraints and functions that
-- call them see the looser rule at once, and every row they accepted before
-- still passes.

CREATE OR REPLACE FUNCTION mesh_ops.site_prefixes_valid_internal_v1(p_prefixes CIDR[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.cardinality(p_prefixes) BETWEEN 1 AND 1024
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.unnest(p_prefixes) AS prefix
           WHERE prefix IS NULL
              OR (pg_catalog.family(prefix) = 4 AND pg_catalog.masklen(prefix) < 8)
              OR (pg_catalog.family(prefix) = 6 AND pg_catalog.masklen(prefix) < 32)
              OR prefix && '100.64.0.0/10'::CIDR OR prefix && '198.18.0.0/15'::CIDR
              OR prefix && 'fd00::/48'::CIDR)
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.advertised_prefixes_valid_internal_v1(p_prefixes CIDR[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.cardinality(p_prefixes) <= 256
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.unnest(p_prefixes) AS prefix
           WHERE prefix IS NULL
              OR (pg_catalog.family(prefix) = 4 AND pg_catalog.masklen(prefix) < 8)
              OR (pg_catalog.family(prefix) = 6 AND pg_catalog.masklen(prefix) < 32)
              OR prefix && '100.64.0.0/10'::CIDR OR prefix && '198.18.0.0/15'::CIDR
              OR prefix && 'fd00::/48'::CIDR)
$function$;

-- A Site's prefixes never overlap an address pool the mesh hands out in its
-- Workspace (node overlay) or the deployment (Device aliases).
CREATE FUNCTION mesh_ops.enforce_network_site_pools_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    -- The deployment's alias pools are read through the policy below, bound
    -- to this check only; the Workspace's own pools through its scope.
    PERFORM pg_catalog.set_config('mesh.site_pool_check_deployment_id', NEW.deployment_id::TEXT, TRUE);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(NEW.prefixes) AS site_prefix(prefix)
        JOIN mesh.address_pool AS pool ON pool.deployment_id = NEW.deployment_id
        WHERE pool.deleted_at IS NULL
          AND pool.purpose IN ('node_overlay', 'federation_resource_alias', 'federation_consumer_alias')
          AND (pool.workspace_id = NEW.workspace_id OR pool.workspace_id IS NULL)
          AND pool.prefix && site_prefix.prefix
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTS09', MESSAGE = 'a Site prefix overlaps a mesh address pool';
    END IF;
    PERFORM pg_catalog.set_config('mesh.site_pool_check_deployment_id', '', TRUE);
    RETURN NEW;
END;
$function$;

CREATE POLICY address_pool_site_check_read ON mesh.address_pool FOR SELECT TO mesh_migrator
    USING (workspace_id IS NULL AND purpose IN ('federation_resource_alias', 'federation_consumer_alias')
           AND deployment_id = NULLIF(
               pg_catalog.current_setting('mesh.site_pool_check_deployment_id', TRUE), '')::BIGINT);

CREATE TRIGGER network_site_pools
BEFORE INSERT OR UPDATE OF prefixes ON mesh.network_site
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_site_pools_v1();

REVOKE ALL ON FUNCTION mesh_ops.enforce_network_site_pools_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
