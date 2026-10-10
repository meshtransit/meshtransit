package postgres

import (
	"context"
	"errors"
	"time"
)

const acceptMTCPTimestampSQL = `SELECT mesh_ops.accept_mtcp_timestamp_v1($1::BYTEA, $2::BYTEA, $3::BIGINT)`

// ErrMTCPTimestamp classifies an unavailable MTCP timestamp check.
var ErrMTCPTimestamp = errors.New("postgres: MTCP timestamp check unavailable")

// MTCPTimestampStore keeps the last accepted MTCP ClientHello timestamp of
// machine keys bound to an active Device (schema 137).
type MTCPTimestampStore struct {
	database resourceAuthorityDatabase
	metrics  *postgresPoolMetrics
}

// NewMTCPTimestampStore accepts only the runtime-authenticated pool.
func NewMTCPTimestampStore(pool *Pool) (*MTCPTimestampStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil {
		return nil, ErrMTCPTimestamp
	}
	return &MTCPTimestampStore{database: pool.resourceAuthorityDatabase, metrics: pool.metrics}, nil
}

// AcceptTimestamp reports whether timestampMS is newer than the stored one
// for the machine key fingerprint. Keys without an active Device for nodeKey
// are accepted: the caller's per-replica cache decides for them.
func (store *MTCPTimestampStore) AcceptTimestamp(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
	timestampMS int64) (_ bool, resultErr error) {
	if store == nil || store.database == nil || ctx == nil || timestampMS <= 0 ||
		(len(nodeKey) != 0 && len(nodeKey) != 32) {
		return false, ErrMTCPTimestamp
	}
	startedAt := time.Now()
	defer func() {
		if store.metrics != nil {
			store.metrics.observeOperation(postgresOperationMTCPTimestamp, time.Since(startedAt), resultErr)
		}
	}()
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return false, errors.Join(ErrMTCPTimestamp, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	var accepted bool
	if err := transaction.QueryRow(ctx, acceptMTCPTimestampSQL, machineFingerprint[:], nodeKey, timestampMS).
		Scan(&accepted); err != nil {
		return false, errors.Join(ErrMTCPTimestamp, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrMTCPTimestamp, err)
	}
	return accepted, nil
}
