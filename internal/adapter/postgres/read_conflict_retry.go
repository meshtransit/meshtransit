package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// readConflictBackoff spaces the reruns of a read-only transaction. Its length
// plus one bounds the attempts.
var readConflictBackoff = [...]time.Duration{20 * time.Millisecond, 60 * time.Millisecond}

// retryReadConflict reruns a complete read-only transaction when PostgreSQL
// reports a serialization failure, a deadlock or a lock timeout. Console reads
// take FOR SHARE locks on revision rows that a concurrent publish or worker
// briefly updates; a fresh snapshot then reads the committed state. Writes are
// never retried here, and any other error returns at once.
func retryReadConflict[T any](ctx context.Context, read func() (T, error)) (T, error) {
	for attempt := 0; ; attempt++ {
		value, err := read()
		if err == nil || attempt >= len(readConflictBackoff) || !readConflict(err) {
			return value, err
		}
		timer := time.NewTimer(readConflictBackoff[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return value, err
		case <-timer.C:
		}
	}
}

func readConflict(err error) bool {
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return false
	}
	switch databaseError.Code {
	case "40001", "40P01", "55P03":
		return true
	default:
		return false
	}
}
