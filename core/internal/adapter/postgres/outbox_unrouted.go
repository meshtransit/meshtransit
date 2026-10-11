package postgres

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/domain/outbox/unrouted"
)

// retireUnroutedEventsSQL closes pending events without a Network scope.
// They satisfy the terminal state shape: one claim instant, an expiry just
// after it, completion at the same instant and error class no_consumer.
const retireUnroutedEventsSQL = `WITH instant AS (
    SELECT pg_catalog.clock_timestamp() AS at
),
candidates AS MATERIALIZED (
    SELECT event.id
    FROM mesh_ops.outbox_event AS event
    WHERE event.completed_at IS NULL
      AND event.network_id IS NULL
      AND event.state = 'pending'
      AND event.available_at <= pg_catalog.clock_timestamp()
    ORDER BY event.available_at, event.id
    FOR UPDATE SKIP LOCKED
    LIMIT $1
)
UPDATE mesh_ops.outbox_event AS event
SET state = 'terminal',
    claim_token = $2::UUID,
    claimed_by = $3,
    claimed_at = instant.at,
    claim_expires_at = instant.at + INTERVAL '1 millisecond',
    completed_at = instant.at,
    attempt_count = event.attempt_count + 1,
    last_error_class = 'no_consumer'
FROM candidates, instant
WHERE event.id = candidates.id`

var _ unrouted.Store = (*OutboxStore)(nil)

// RetireUnroutedEvents marks up to limit unconsumed pending events terminal
// and reports how many it closed.
func (store *OutboxStore) RetireUnroutedEvents(ctx context.Context, workerID string, limit int) (retired int, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || store.newToken == nil ||
		!validOutboxWorkerID(workerID) || limit <= 0 || limit > maxOutboxBatchSize {
		return 0, ErrInvalidOutboxStore
	}
	token, err := store.newToken()
	if err != nil {
		return 0, errors.Join(ErrFinishOutbox, fmt.Errorf("generate claim token: %w", err))
	}
	tag, err := store.database.Exec(ctx, retireUnroutedEventsSQL, limit, token, workerID)
	if err != nil {
		return 0, errors.Join(ErrFinishOutbox, err)
	}
	return int(tag.RowsAffected()), nil
}
