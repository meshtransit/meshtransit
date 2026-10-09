-- Run as database operator before migration 82. Never grant role membership.
CREATE ROLE mesh_device_alias_observer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
