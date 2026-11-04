package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/retention"
)

// retentionDatabase answers every call with count or answer and records
// the arguments it was given.
type retentionDatabase struct {
	fakeOutboxDatabase
	count  int
	answer string
	args   []any
}

func (database *retentionDatabase) QueryRow(_ context.Context, _ string, arguments ...any) outboxRow {
	database.args = arguments
	return fakeOutboxRow{scan: func(destinations ...any) error {
		switch target := destinations[0].(type) {
		case *int:
			*target = database.count
		case *string:
			*target = database.answer
		}
		return nil
	}}
}

func TestRetentionStoreReadsBoundedAnswers(t *testing.T) {
	t.Parallel()
	database := &retentionDatabase{count: 7}
	store := &RetentionStore{database: database}
	if removed, err := store.PruneIdempotency(t.Context(), 24*time.Hour, 100); err != nil || removed != 7 {
		t.Fatalf("idempotency = %d, %v", removed, err)
	}
	if database.args[0] != 86400 || database.args[1] != 100 {
		t.Fatalf("idempotency arguments = %v, want grace in seconds and the limit", database.args)
	}
	database.answer = `{"events": 3, "attempts": 5}`
	if removed, err := store.PruneOutbox(t.Context(), 7, 30, 100); err != nil || removed.Events != 3 ||
		removed.Attempts != 5 {
		t.Fatalf("outbox = %+v, %v", removed, err)
	}
	database.answer = `{"defaults": 0, "identities": 4, "mutations": 2}`
	if removed, err := store.PruneAudit(t.Context(), 12, 100); err != nil ||
		removed.Identities != 4 || removed.Mutations != 2 {
		t.Fatalf("audit = %+v, %v", removed, err)
	}
}

func TestRetentionStoreRefusesBadInputAndAnswers(t *testing.T) {
	t.Parallel()
	database := &retentionDatabase{}
	store := &RetentionStore{database: database}
	for name, call := range map[string]func() error{
		"grace under an hour": func() error { _, err := store.PruneIdempotency(t.Context(), time.Minute, 10); return err },
		"batch over 5000":     func() error { _, err := store.PruneIdempotency(t.Context(), time.Hour, 5001); return err },
		"terminal first":      func() error { _, err := store.PruneOutbox(t.Context(), 7, 3, 10); return err },
		"no months":           func() error { _, err := store.PruneAudit(t.Context(), 0, 10); return err },
	} {
		if err := call(); !errors.Is(err, ErrInvalidRetentionStore) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, answer := range map[string]string{
		"outbox without attempts": `{"events": 1}`,
		"outbox over the limit":   `{"events": 11, "attempts": 0}`,
		"not JSON":                `removed`,
	} {
		database.answer = answer
		if _, err := store.PruneOutbox(t.Context(), 7, 30, 10); !errors.Is(err, ErrInvalidRetentionStore) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, answer := range map[string]string{
		"audit without mutations": `{"defaults": 0, "identities": 0}`,
		"audit negative":          `{"defaults": -1, "identities": 0, "mutations": 0}`,
		"audit over the limit":    `{"defaults": 0, "identities": 11, "mutations": 0}`,
	} {
		database.answer = answer
		if _, err := store.PruneAudit(t.Context(), 12, 10); !errors.Is(err, ErrInvalidRetentionStore) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	database.count = 11
	if _, err := store.PruneIdempotency(t.Context(), time.Hour, 10); !errors.Is(err, ErrInvalidRetentionStore) {
		t.Errorf("idempotency over the limit: err = %v", err)
	}
	if _, err := NewRetentionStore(nil); !errors.Is(err, ErrInvalidRetentionStore) {
		t.Errorf("nil pool: err = %v", err)
	}
}

// A lock not taken in time is busy; a missing or refused function is not
// ready; anything else keeps no class.
func TestRetentionFailureClassifiesPostgresErrors(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]error{
		"55P03": retention.ErrBusy, "42883": retention.ErrNotReady, "42501": retention.ErrNotReady,
		"23514": retention.ErrNotReady,
	} {
		err := retentionFailure("prune", &pgconn.PgError{Code: code})
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", code, err, want)
		}
	}
	err := retentionFailure("prune", &pgconn.PgError{Code: "23503"})
	if errors.Is(err, retention.ErrBusy) || errors.Is(err, retention.ErrNotReady) {
		t.Errorf("foreign key failure classed as %v", err)
	}
}
