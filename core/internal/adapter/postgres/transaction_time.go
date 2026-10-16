package postgres

import (
	"context"
	"errors"
	"time"
)

// ErrTransactionTime classifies a failed or unusable read of the database
// clock for one unit of work.
var ErrTransactionTime = errors.New("read postgres transaction time")

// transactionTimeSQL reads the instant the current transaction started, on the
// database clock. It is the same value SQL's own transaction_timestamp() and
// now() return for the rest of the transaction.
const transactionTimeSQL = `SELECT pg_catalog.transaction_timestamp()`

// rowScanner is the Scan half of every row type the stores' transaction
// abstractions return.
type rowScanner interface {
	Scan(...any) error
}

// readTransactionTime returns the database clock's time for this unit of
// work. The database clock is the single source of truth for every persisted
// timestamp and every comparison with persisted state (expiry, leases,
// created, updated, withdrawn and revoked times, state transitions): a store
// reads it inside the transaction that writes or compares, and passes it to
// every statement of that transaction, so they all agree with each other and
// with times SQL stamps itself. This host's clock only bounds local timeouts
// and backoff.
func readTransactionTime[R rowScanner](
	ctx context.Context,
	queryRow func(context.Context, string, ...any) R,
) (time.Time, error) {
	if ctx == nil || queryRow == nil {
		return time.Time{}, ErrTransactionTime
	}
	var at time.Time
	if err := queryRow(ctx, transactionTimeSQL).Scan(&at); err != nil {
		return time.Time{}, errors.Join(ErrTransactionTime, err)
	}
	if at.IsZero() {
		return time.Time{}, ErrTransactionTime
	}
	return at.UTC(), nil
}
