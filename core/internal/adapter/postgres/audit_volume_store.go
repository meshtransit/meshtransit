package postgres

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/domain/auditvolume"
)

// ErrInvalidAuditVolumeStore reports unsafe construction or answers.
var ErrInvalidAuditVolumeStore = errors.New("invalid postgres audit volume store")

// deploymentAuditEventsSQL sums every Deployment stream (schema 275).
const deploymentAuditEventsSQL = `SELECT mesh_ops.deployment_audit_events_v1()`

// AuditVolumeStore reads the Deployment streams' event count through the
// worker pool.
type AuditVolumeStore struct{ database outboxDatabase }

var _ auditvolume.Reader = (*AuditVolumeStore)(nil)

// NewAuditVolumeStore rejects non-worker pools before any effect.
func NewAuditVolumeStore(pool *Pool) (*AuditVolumeStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidAuditVolumeStore
	}
	return &AuditVolumeStore{database: pool.outboxDatabase}, nil
}

// DeploymentEvents returns the events every Deployment stream holds.
func (store *AuditVolumeStore) DeploymentEvents(ctx context.Context) (int64, error) {
	if ctx == nil || store == nil || store.database == nil {
		return 0, ErrInvalidAuditVolumeStore
	}
	var events int64
	if err := store.database.QueryRow(ctx, deploymentAuditEventsSQL).Scan(&events); err != nil {
		return 0, fmt.Errorf("read Deployment audit events: %w", err)
	}
	if events < 0 {
		return 0, ErrInvalidAuditVolumeStore
	}
	return events, nil
}
