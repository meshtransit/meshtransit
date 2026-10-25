package postgres

import (
	"context"
	"errors"
	"time"
)

const acceptMTCPTimestampSQL = `SELECT accepted, gateway, machine_state, node_current
FROM mesh_ops.accept_mtcp_timestamp_v2($1::BYTEA, $2::BYTEA, $3::BIGINT)`

const commitMTCPGatewayTimestampSQL = `SELECT mesh_ops.commit_mtcp_gateway_timestamp_v1($1::BYTEA, $2::BYTEA, $3::BIGINT)`

// MTCPTimestampCheck is what schema 226 says about a handshake's keys.
type MTCPTimestampCheck struct {
	Accepted bool
	// Gateway: the machine key belongs, or belonged, to a Kubernetes
	// gateway; its timestamp was compared, not written.
	Gateway bool
	// MachineState is current, retired or unbound.
	MachineState string
	NodeCurrent  bool
}

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
// for the machine key fingerprint, and what the keys are. Keys without an
// active Device for nodeKey are accepted: the caller's per-replica cache
// decides for them. A gateway's timestamp is compared, not written.
func (store *MTCPTimestampStore) AcceptTimestamp(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
	timestampMS int64) (MTCPTimestampCheck, error) {
	if len(nodeKey) != 0 && len(nodeKey) != 32 {
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
	var check MTCPTimestampCheck
	err := store.run(ctx, timestampMS, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, acceptMTCPTimestampSQL, machineFingerprint[:], nodeKey, timestampMS).
			Scan(&check.Accepted, &check.Gateway, &check.MachineState, &check.NodeCurrent)
	})
	if err != nil {
		return MTCPTimestampCheck{}, err
	}
	switch check.MachineState {
	case "current", "retired", "unbound":
		return check, nil
	default:
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
}

// CommitGatewayTimestamp records a gateway's timestamp after its session
// proved its node key: false when the keys are no longer the gateway's
// current ones or the timestamp is not newer.
func (store *MTCPTimestampStore) CommitGatewayTimestamp(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64) (bool, error) {
	if len(nodeKey) != 32 {
		return false, ErrMTCPTimestamp
	}
	var committed bool
	err := store.run(ctx, timestampMS, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, commitMTCPGatewayTimestampSQL, machineFingerprint[:], nodeKey,
			timestampMS).Scan(&committed)
	})
	return committed, err
}

func (store *MTCPTimestampStore) run(ctx context.Context, timestampMS int64,
	statement func(resourceAuthorityDatabaseTransaction) error) (resultErr error) {
	if store == nil || store.database == nil || ctx == nil || timestampMS <= 0 {
		return ErrMTCPTimestamp
	}
	startedAt := time.Now()
	defer func() {
		if store.metrics != nil {
			store.metrics.observeOperation(postgresOperationMTCPTimestamp, time.Since(startedAt), resultErr)
		}
	}()
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return errors.Join(ErrMTCPTimestamp, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if err := statement(transaction); err != nil {
		return errors.Join(ErrMTCPTimestamp, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrMTCPTimestamp, err)
	}
	return nil
}
