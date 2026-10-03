-- Run as database operator before migration 85. Never grant role membership.
CREATE ROLE mesh_device_alias_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
