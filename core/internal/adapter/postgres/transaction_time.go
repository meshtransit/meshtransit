package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/adapter/postgres/dbclock"
)

// ErrTransactionTime classifies a failed or unusable read of the database
// clock for one unit of work.
var ErrTransactionTime = dbclock.ErrTransactionTime

// transactionTimeSQL reads the instant the current transaction started, on the
// database clock (see package dbclock).
const transactionTimeSQL = dbclock.TransactionTimeSQL

// readTransactionTime returns the database clock's time for this unit of
// work; see package dbclock for the rule it serves.
func readTransactionTime[R dbclock.Row](
	ctx context.Context,
	queryRow func(context.Context, string, ...any) R,
) (time.Time, error) {
	return dbclock.Read(ctx, queryRow)
}
