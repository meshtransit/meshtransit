package postgres

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"
)

// partitionDatabase answers ensure with created and maintain with answer,
// or fails the call whose SQL holds failOn.
type partitionDatabase struct {
	fakeOutboxDatabase
	created int
	answer  string
	failOn  string
}

func (database *partitionDatabase) QueryRow(_ context.Context, query string, _ ...any) outboxRow {
	if database.failOn != "" && strings.Contains(query, database.failOn) {
		return fakeOutboxRow{scan: func(...any) error { return errors.New("55P03") }}
	}
	return fakeOutboxRow{scan: func(destinations ...any) error {
		switch target := destinations[0].(type) {
		case *int:
			*target = database.created
		case *string:
			*target = database.answer
		}
		return nil
	}}
}

func testPartitionStore(database outboxDatabase) *KubernetesOperationPartitionStore {
	return &KubernetesOperationPartitionStore{database: database, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now: func() time.Time { return time.Unix(1_800_000_000, 0) }, started: 1_799_990_000}
}

// Only a whole pass moves the gauges: before one they read NaN; a failed
// maintain or an answer out of form leaves them as they were.
func TestKubernetesOperationPartitionStorePasses(t *testing.T) {
	t.Parallel()
	database := &partitionDatabase{created: 2, answer: `{"ahead": 3, "dropped": ["kubernetes_operation_2024_01"]}`}
	store := testPartitionStore(database)
	if !math.IsNaN(store.Ahead()) || store.CheckedAt() != 1_799_990_000 {
		t.Fatalf("gauges before any pass: ahead %v, checked %v", store.Ahead(), store.CheckedAt())
	}
	if created, err := store.EnsurePartitions(t.Context(), 3); err != nil || created != 2 || store.Ahead() != 3 ||
		store.CheckedAt() != 1_800_000_000 || store.Dropped() != 1 {
		t.Fatalf("a pass: %d, %v, ahead %v, checked %v, dropped %d", created, err, store.Ahead(), store.CheckedAt(),
			store.Dropped())
	}
	store.now = func() time.Time { return time.Unix(1_800_003_600, 0) }
	for _, test := range []struct {
		name   string
		change func()
	}{
		{"maintain failed", func() { database.failOn = "maintain" }},
		{"no ahead", func() { database.failOn, database.answer = "", `{"dropped": []}` }},
		{"out of form", func() { database.failOn, database.answer = "", `{"ahead": 1, "more": 1}` }},
		{"ensure failed", func() { database.failOn = "ensure" }},
	} {
		name := test.name
		test.change()
		if _, err := store.EnsurePartitions(t.Context(), 3); err == nil {
			t.Fatalf("%s: no error", name)
		}
		if store.Ahead() != 3 || store.CheckedAt() != 1_800_000_000 {
			t.Fatalf("%s moved the gauges: ahead %v, checked %v", name, store.Ahead(), store.CheckedAt())
		}
	}
	if _, err := (&KubernetesOperationPartitionStore{}).EnsurePartitions(t.Context(), 3); err == nil {
		t.Fatal("a store without a database ran")
	}
}
