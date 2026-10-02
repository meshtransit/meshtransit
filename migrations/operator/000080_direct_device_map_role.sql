-- Run as the database operator before migration 80; never grant membership.
CREATE ROLE mesh_direct_map_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
