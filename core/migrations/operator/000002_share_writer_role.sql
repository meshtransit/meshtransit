-- Run as database operator before the first migration: the migrator refuses to run without this role
-- (it was created by hand before; this step makes "migrate operator apply" enough). Never grant role membership.
-- Safe to run again: an existing role keeps its members and gets the same attributes.
DO $role$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mesh_share_writer') THEN
        CREATE ROLE mesh_share_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE mesh_share_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$role$;
