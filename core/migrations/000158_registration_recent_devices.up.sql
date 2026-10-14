-- Schema 158: count a person's recent sign-in Devices by index.
--
-- A browser sign-in refuses a new Device for a person who already added 20
-- to the Network within a day (H3). It counts them under the Network's
-- revision lock, so the count must not grow with the Network: with only the
-- (workspace, network, state, created_at) index, a generic plan walked every
-- Device the Network gained that day and filtered by person (2,020 rows for
-- one person with none in a 2,000-Device test). This index names the
-- person, the Network and the time directly. Only sign-in Devices are
-- counted, so the index leaves out enrollment-key ones.

CREATE INDEX device_registered_principal_recent_idx
    ON mesh.device (registered_by_principal_id, workspace_id, network_id, created_at)
    WHERE registered_by_kind = 'principal';
