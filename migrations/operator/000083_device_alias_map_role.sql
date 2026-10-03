-- Run as database operator before migration 83. Never grant role membership.
CREATE ROLE mesh_device_alias_map_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
