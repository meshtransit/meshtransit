package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthCreationClockRequiresCompletedReadOnlyUnit(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"success", "zero", "query", "configure", "commit", "cleanup", "cancel", "begin"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			at := time.Date(2026, 10, 3, 12, 0, 0, 123456000, time.UTC)
			transaction := newFakeAuthTransactionDatabaseTransaction()
			failure := errors.New("synthetic creation clock failure")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			row := authTransactionTestRow{scan: func(values ...any) error {
				*values[0].(*time.Time) = at
				if name == "zero" {
					*values[0].(*time.Time) = time.Time{}
				}
				if name == "cancel" {
					cancel()
				}
				return nil
			}}
			database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
			switch name {
			case "query", "cleanup":
				row = authTransactionTestRow{err: failure}
			case "configure":
				transaction.execErrors[configureAuthTransactionSQL] = []error{failure}
			case "commit":
				transaction.commitErr = failure
			case "begin":
				database.beginErr = failure
			}
			if name == "cleanup" {
				transaction.rollbackErr = failure
			}
			transaction.enqueueRow(authClaimClockSQL, row)
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := store.CreationTime(ctx)
			if name == "success" {
				if err != nil || !got.Equal(at) || transaction.commitCalls != 1 || transaction.rollbackCalls != 0 {
					t.Fatal("DB time escaped an incomplete read", err)
				}
			} else if err == nil || !got.IsZero() {
				t.Fatal("failed read released creation time")
			}
			if len(database.readOnly) != 1 || !database.readOnly[0] {
				t.Fatal("creation clock opened a write unit")
			}
			if name != "success" && name != "begin" && transaction.rollbackCalls != 1 {
				t.Fatal("failed read leaked its unit")
			}
			if name == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("creation clock lost cancellation")
			}
		})
	}
}

func TestAuthCreationClockRejectsAbsentOrCanceledContextBeforeBegin(t *testing.T) {
	t.Parallel()
	database := &fakeAuthTransactionDatabase{}
	store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var absent context.Context
	if at, err := store.CreationTime(absent); err == nil || !at.IsZero() {
		t.Fatal("absent context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if at, err := store.CreationTime(ctx); !errors.Is(err, context.Canceled) || !at.IsZero() {
		t.Fatal("canceled context accepted")
	}
	if len(database.readOnly) != 0 {
		t.Fatal("invalid clock request reached DB")
	}
}
