-- Run as database operator before migration 270. Never grant role membership.
-- Safe to run again: an existing role keeps its members and gets the same attributes.
DO $role$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mesh_flowlog_status_writer') THEN
        CREATE ROLE mesh_flowlog_status_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE mesh_flowlog_status_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$role$;
