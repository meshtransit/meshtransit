//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"math"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

// assertKubernetesOperationPartitions: the worker keeps the months ahead
// and reads how far ahead every table holds (K1b0 §4, §8).
func assertKubernetesOperationPartitions(ctx context.Context, t *testing.T, workerPool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesOperationPartitionStore(workerPool,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !math.IsNaN(store.Ahead()) {
		t.Fatalf("Ahead() = %v before any pass", store.Ahead())
	}
	if _, err := store.EnsurePartitions(ctx, 3); err != nil {
		t.Fatalf("EnsurePartitions() error = %v", err)
	}
	created, err := store.EnsurePartitions(ctx, 3)
	if err != nil || created != 0 || store.Ahead() != 3 || store.Dropped() != 0 {
		t.Fatalf("a second pass: created %d, ahead %v, dropped %d, %v", created, store.Ahead(), store.Dropped(), err)
	}
	if _, err := postgresadapter.NewKubernetesOperationPartitionStore(nil, slog.Default()); err == nil {
		t.Fatal("no pool was taken")
	}
}
