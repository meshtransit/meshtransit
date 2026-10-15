-- Run as the database operator before migration 80; never grant membership.
-- Safe to run again: an existing role keeps its members and gets the same attributes.
DO $role$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mesh_direct_map_reader') THEN
        CREATE ROLE mesh_direct_map_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE mesh_direct_map_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$role$;
