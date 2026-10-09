package postgres

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/audit/partitions"
)

// ErrInvalidAuditPartitionStore reports unsafe construction or input.
var ErrInvalidAuditPartitionStore = errors.New("invalid postgres audit partition store")

const ensureAuditPartitionsSQL = `SELECT mesh_ops.ensure_audit_event_partitions_v1($1::INTEGER)`

// AuditPartitionStore creates monthly audit partitions through the worker
// pool; the definer function owns the DDL and its row-level security.
type AuditPartitionStore struct{ database outboxDatabase }

var _ partitions.Store = (*AuditPartitionStore)(nil)

// NewAuditPartitionStore rejects non-worker pools before any effect.
func NewAuditPartitionStore(pool *Pool) (*AuditPartitionStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidAuditPartitionStore
	}
	return &AuditPartitionStore{database: pool.outboxDatabase}, nil
}

// EnsurePartitions runs one bounded call and reports the partitions created.
func (store *AuditPartitionStore) EnsurePartitions(ctx context.Context, monthsAhead int) (int, error) {
	if ctx == nil || store == nil || store.database == nil || monthsAhead < 1 || monthsAhead > 36 {
		return 0, ErrInvalidAuditPartitionStore
	}
	var created int
	if err := store.database.QueryRow(ctx, ensureAuditPartitionsSQL, monthsAhead).Scan(&created); err != nil {
		return 0, err
	}
	if created < 0 {
		return 0, ErrInvalidAuditPartitionStore
	}
	return created, nil
}
