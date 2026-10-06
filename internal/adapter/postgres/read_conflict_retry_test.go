package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRetryReadConflictRerunsOnlyLockConflicts(t *testing.T) {
	t.Parallel()
	errOther := errors.New("other")
	for _, test := range []struct {
		name      string
		failures  []error
		wantCalls int
		wantErr   bool
	}{
		{name: "success", wantCalls: 1},
		{name: "serialization then success", failures: []error{&pgconn.PgError{Code: "40001"}}, wantCalls: 2},
		{name: "wrapped lock timeout then success",
			failures:  []error{fmt.Errorf("read: %w", &pgconn.PgError{Code: "55P03"}), &pgconn.PgError{Code: "40P01"}},
			wantCalls: 3},
		{name: "bounded attempts", wantCalls: 3, wantErr: true, failures: []error{
			&pgconn.PgError{Code: "40001"}, &pgconn.PgError{Code: "40001"},
			&pgconn.PgError{Code: "40001"}, &pgconn.PgError{Code: "40001"},
		}},
		{name: "permission denied is final", failures: []error{&pgconn.PgError{Code: "42501"}}, wantCalls: 1, wantErr: true},
		{name: "plain error is final", failures: []error{errOther}, wantCalls: 1, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			value, err := retryReadConflict(context.Background(), func() (int, error) {
				calls++
				if calls <= len(test.failures) {
					return 0, test.failures[calls-1]
				}
				return 7, nil
			})
			if calls != test.wantCalls || (err != nil) != test.wantErr || (!test.wantErr && value != 7) {
				t.Fatalf("calls=%d value=%d err=%v", calls, value, err)
			}
		})
	}
}

func TestRetryReadConflictStopsWhenCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := retryReadConflict(ctx, func() (int, error) {
		calls++
		return 0, &pgconn.PgError{Code: "40001"}
	})
	if calls != 1 || err == nil {
		t.Fatalf("canceled retry calls=%d err=%v", calls, err)
	}
}
