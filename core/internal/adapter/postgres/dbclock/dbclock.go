// Package dbclock reads the database clock for one unit of work.
//
// The database clock is the single source of truth for every persisted
// timestamp and every comparison with persisted state (expiry, leases,
// created, updated, withdrawn and revoked times, state transitions). A store
// reads it inside the transaction that writes or compares, and passes it to
// every statement of that transaction, so they all agree with each other and
// with times SQL stamps itself. The MeshCore host clock only bounds local
// timeouts and backoff.
package dbclock

import (
	"context"
	"errors"
	"time"
)

// ErrTransactionTime classifies a failed or unusable read of the database
// clock for one unit of work.
var ErrTransactionTime = errors.New("read postgres transaction time")

// TransactionTimeSQL reads the instant the current transaction started, on
// the database clock. It is the same value SQL's own transaction_timestamp()
// and now() return for the rest of the transaction.
const TransactionTimeSQL = `SELECT pg_catalog.transaction_timestamp()`

// Row is the Scan half of every row type the stores' transaction
// abstractions return.
type Row interface {
	Scan(...any) error
}

// Read returns the database clock's time for the transaction queryRow runs in.
func Read[R Row](
	ctx context.Context,
	queryRow func(context.Context, string, ...any) R,
) (time.Time, error) {
	if ctx == nil || queryRow == nil {
		return time.Time{}, ErrTransactionTime
	}
	var at time.Time
	if err := queryRow(ctx, TransactionTimeSQL).Scan(&at); err != nil {
		return time.Time{}, errors.Join(ErrTransactionTime, err)
	}
	if at.IsZero() {
		return time.Time{}, ErrTransactionTime
	}
	return at.UTC(), nil
}
