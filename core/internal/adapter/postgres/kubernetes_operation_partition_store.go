package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/audit/partitions"
)

const (
	ensureKubernetesOperationPartitionsSQL   = `SELECT mesh_ops.ensure_kubernetes_operation_partitions_v1($1::INTEGER)`
	maintainKubernetesOperationPartitionsSQL = `SELECT mesh_ops.maintain_kubernetes_operation_partitions_v1(
    $1::INTEGER)::TEXT`
	// KubernetesOperationKeepMonths is how long operations are kept (K1b0
	// §7): the partitions of months that ended before are dropped.
	KubernetesOperationKeepMonths = 13
)

// ErrInvalidKubernetesOperationPartitionStore reports unsafe construction
// or input.
var ErrInvalidKubernetesOperationPartitionStore = errors.New("invalid postgres Kubernetes operation partition store")

// KubernetesOperationPartitionStore keeps the monthly partitions of
// Kubernetes operations, outcomes and denials through the worker pool
// (schema 245): created ahead, dropped past KubernetesOperationKeepMonths.
// The tables have no DEFAULT partition, so a missing month refuses writes:
// Ahead and CheckedAt are what to alert on.
type KubernetesOperationPartitionStore struct {
	database outboxDatabase
	logger   *slog.Logger
	now      func() time.Time
	// ahead is valid once checked is set: a gauge read before the first
	// pass shows nothing rather than a month missing (review b0c M1).
	ahead   atomic.Int64
	checked atomic.Int64 // Unix seconds of the last whole pass; 0: none yet
	dropped atomic.Uint64
	// started stands for the last pass until one is whole, so passes that
	// fail from a restart on still age the check (review b0c re-review M1).
	started int64
}

var _ partitions.Store = (*KubernetesOperationPartitionStore)(nil)

// NewKubernetesOperationPartitionStore rejects non-worker pools.
func NewKubernetesOperationPartitionStore(pool *Pool, logger *slog.Logger) (*KubernetesOperationPartitionStore,
	error,
) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil || logger == nil {
		return nil, ErrInvalidKubernetesOperationPartitionStore
	}
	return &KubernetesOperationPartitionStore{database: pool.outboxDatabase, logger: logger, now: time.Now,
		started: time.Now().Unix()}, nil
}

// EnsurePartitions creates the months ahead, then drops the expired ones,
// logging each, and reads how many months ahead every table holds. A lock
// not taken in time (55P03) fails the pass, retried at the next one; only a
// whole pass moves CheckedAt.
func (store *KubernetesOperationPartitionStore) EnsurePartitions(ctx context.Context, monthsAhead int) (int, error) {
	if ctx == nil || store == nil || store.database == nil || monthsAhead < 1 || monthsAhead > 36 {
		return 0, ErrInvalidKubernetesOperationPartitionStore
	}
	var created int
	if err := store.database.QueryRow(ctx, ensureKubernetesOperationPartitionsSQL, monthsAhead).Scan(
		&created); err != nil {
		return 0, fmt.Errorf("ensure Kubernetes operation partitions: %w", err)
	}
	if created < 0 {
		return 0, ErrInvalidKubernetesOperationPartitionStore
	}
	var answer string
	if err := store.database.QueryRow(ctx, maintainKubernetesOperationPartitionsSQL,
		KubernetesOperationKeepMonths).Scan(&answer); err != nil {
		return created, fmt.Errorf("maintain Kubernetes operation partitions: %w", err)
	}
	var maintained struct {
		Ahead   *int64   `json:"ahead"`
		Dropped []string `json:"dropped"`
	}
	if err := decodeStrictJSON(answer, 64<<10, &maintained); err != nil || maintained.Ahead == nil {
		return created, fmt.Errorf("decode Kubernetes operation partition maintenance: %w",
			errors.Join(ErrInvalidKubernetesOperationPartitionStore, err))
	}
	// Dropping a month of records is logged by name (review b0c M3).
	for _, name := range maintained.Dropped {
		store.logger.InfoContext(ctx, "Kubernetes operation partition dropped past retention",
			"partition", name, "keep_months", KubernetesOperationKeepMonths)
	}
	store.dropped.Add(uint64(len(maintained.Dropped)))
	store.ahead.Store(*maintained.Ahead)
	store.checked.Store(store.now().Unix())
	return created, nil
}

// Ahead returns how many months ahead of this one every table held at the
// last whole pass, -1 when this month's was missing; NaN before any.
func (store *KubernetesOperationPartitionStore) Ahead() float64 {
	if store.checked.Load() == 0 {
		return math.NaN()
	}
	return float64(store.ahead.Load())
}

// CheckedAt returns the Unix time of the last whole pass, or the store's
// creation before any: passes that keep failing leave it behind (review
// b0c H1).
func (store *KubernetesOperationPartitionStore) CheckedAt() float64 {
	if checked := store.checked.Load(); checked != 0 {
		return float64(checked)
	}
	return float64(store.started)
}

// Dropped returns how many expired partitions the passes dropped.
func (store *KubernetesOperationPartitionStore) Dropped() uint64 { return store.dropped.Load() }
