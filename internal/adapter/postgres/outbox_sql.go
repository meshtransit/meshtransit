package postgres

const claimNetworkRevisionsSQL = `WITH candidates AS MATERIALIZED (
    SELECT event.id
    FROM mesh_ops.outbox_event AS event
    WHERE event.completed_at IS NULL
      AND event.workspace_id IS NOT NULL
      AND event.network_id IS NOT NULL
      AND event.network_revision IS NOT NULL
      AND event.available_at <= pg_catalog.clock_timestamp()
      AND (
          event.state = 'pending'
          OR (
              event.state = 'claimed'
              AND event.claim_expires_at <= pg_catalog.clock_timestamp()
          )
      )
    ORDER BY event.available_at, event.id
    FOR UPDATE SKIP LOCKED
    LIMIT $1
)
UPDATE mesh_ops.outbox_event AS event
SET state = 'claimed',
    claim_token = $2::UUID,
    claimed_by = $3,
    claimed_at = pg_catalog.clock_timestamp(),
    claim_expires_at = pg_catalog.clock_timestamp()
        + ($4::BIGINT * INTERVAL '1 millisecond'),
    completed_at = NULL,
    attempt_count = event.attempt_count + 1,
    last_error_class = NULL
FROM candidates
WHERE event.id = candidates.id
RETURNING
    event.id,
    event.workspace_id,
    event.network_id,
    event.network_revision,
    event.attempt_count,
    event.claimed_at`

const setOutboxScopeSQL = `SELECT
    pg_catalog.set_config('mesh.workspace_id', $1, TRUE),
    pg_catalog.set_config('mesh.network_id', $2, TRUE)`

const loadCurrentNetworkRevisionSQL = `SELECT
    network.public_id::TEXT,
    revision.network_revision
FROM mesh.network AS network
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = network.workspace_id
 AND revision.network_id = network.id
WHERE network.workspace_id = $1
  AND network.id = $2`

const markRevisionDeliveredSQL = `WITH delivered AS MATERIALIZED (
    UPDATE mesh_ops.outbox_event AS event
    SET state = 'delivered',
        completed_at = pg_catalog.clock_timestamp(),
        last_error_class = NULL
    WHERE event.id = $1
      AND event.state = 'claimed'
      AND event.claim_token = $2::UUID
      AND event.claimed_by = $3
      AND event.claim_expires_at > pg_catalog.clock_timestamp()
    RETURNING event.id, event.attempt_count
)
INSERT INTO mesh_ops.outbox_attempt (
    outbox_event_id,
    attempt_number,
    worker_id,
    started_at,
    finished_at,
    result,
    error_class,
    next_retry_at
)
SELECT
    delivered.id,
    delivered.attempt_count,
    $3,
    $4,
    pg_catalog.clock_timestamp(),
    'delivered',
    NULL,
    NULL
FROM delivered
`

const retryNetworkRevisionSQL = `WITH retried AS MATERIALIZED (
    UPDATE mesh_ops.outbox_event AS event
    SET state = 'pending',
        available_at = pg_catalog.clock_timestamp()
            + ($5::BIGINT * INTERVAL '1 millisecond'),
        claim_token = NULL,
        claimed_by = NULL,
        claimed_at = NULL,
        claim_expires_at = NULL,
        completed_at = NULL,
        last_error_class = NULL
    WHERE event.id = $1
      AND event.state = 'claimed'
      AND event.claim_token = $2::UUID
      AND event.claimed_by = $3
      AND event.claim_expires_at > pg_catalog.clock_timestamp()
    RETURNING event.id, event.attempt_count, event.available_at
)
INSERT INTO mesh_ops.outbox_attempt (
    outbox_event_id,
    attempt_number,
    worker_id,
    started_at,
    finished_at,
    result,
    error_class,
    next_retry_at
)
SELECT
    retried.id,
    retried.attempt_count,
    $3,
    $4,
    pg_catalog.clock_timestamp(),
    'retry',
    $6,
    retried.available_at
FROM retried
`
