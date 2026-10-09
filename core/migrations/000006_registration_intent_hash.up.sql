ALTER TABLE mesh.pending_registration
    ADD COLUMN request_hash BYTEA;

-- Rows created before semantic hashing cannot be reconstructed safely because
-- the original requested hostname and Node key were not retained. Bind them to
-- a deterministic non-matching legacy marker so replay fails closed.
UPDATE mesh.pending_registration
SET request_hash = pg_catalog.uuid_send(public_id) || pg_catalog.uuid_send(public_id)
WHERE request_hash IS NULL;

ALTER TABLE mesh.pending_registration
    ALTER COLUMN request_hash SET NOT NULL,
    ADD CONSTRAINT pending_registration_request_hash_check CHECK (
        pg_catalog.octet_length(request_hash) = 32
        AND request_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    );
