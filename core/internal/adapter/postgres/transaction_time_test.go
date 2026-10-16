package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

type transactionTimeRow struct {
	at  time.Time
	err error
}

func (row transactionTimeRow) Scan(values ...any) error {
	if row.err != nil {
		return row.err
	}
	*values[0].(*time.Time) = row.at
	return nil
}

func TestReadTransactionTimeReadsTheDatabaseClock(t *testing.T) {
	t.Parallel()
	at := time.Date(2030, 1, 2, 10, 4, 5, 6000, time.FixedZone("UTC+7", 7*60*60))
	var query string
	got, err := readTransactionTime(t.Context(), func(_ context.Context, sql string, _ ...any) transactionTimeRow {
		query = sql
		return transactionTimeRow{at: at}
	})
	if err != nil || !got.Equal(at) || got.Location() != time.UTC {
		t.Fatalf("readTransactionTime() = %v, %v; want %v in UTC", got, err, at)
	}
	if query != `SELECT pg_catalog.transaction_timestamp()` {
		t.Fatalf("readTransactionTime() query = %q", query)
	}
	failure := errors.New("connection reset")
	if _, err := readTransactionTime(t.Context(), func(context.Context, string, ...any) transactionTimeRow {
		return transactionTimeRow{err: failure}
	}); !errors.Is(err, failure) || !errors.Is(err, ErrTransactionTime) {
		t.Fatalf("readTransactionTime() failure = %v", err)
	}
	if _, err := readTransactionTime(t.Context(), func(context.Context, string, ...any) transactionTimeRow {
		return transactionTimeRow{}
	}); !errors.Is(err, ErrTransactionTime) {
		t.Fatalf("readTransactionTime() zero time = %v", err)
	}
	if _, err := readTransactionTime[transactionTimeRow](t.Context(), nil); !errors.Is(err, ErrTransactionTime) {
		t.Fatalf("readTransactionTime() without a transaction = %v", err)
	}
}
