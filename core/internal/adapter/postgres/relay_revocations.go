package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const readRelayRevocationsSQL = `SELECT pg_catalog.jsonb_build_object(
    'nodes', COALESCE(pg_catalog.jsonb_agg(pg_catalog.encode(revoked.value, 'hex'))
        FILTER (WHERE revoked.kind = 'node'), '[]'::JSONB),
    'trust_contracts', COALESCE(pg_catalog.jsonb_agg(pg_catalog.encode(revoked.value, 'hex'))
        FILTER (WHERE revoked.kind = 'trust_contract'), '[]'::JSONB)
)::TEXT
FROM mesh_ops.relay_revocations_v1($1::TIMESTAMPTZ) AS revoked`

// maxRelayRevocations bounds one read; a relay state cannot carry more.
const maxRelayRevocations = 1 << 20

// ErrRelayRevocations classifies an unavailable or malformed revocation read.
var ErrRelayRevocations = errors.New("postgres: relay revocations unavailable")

// RelayRevocations lists what relays must stop honouring: node keys of ended
// key epochs and of inactive Devices, and ended Trust Contracts (schema 135).
type RelayRevocations struct {
	NodeKeys       [][32]byte
	TrustContracts [][16]byte
}

// RelayRevocationStore reads relay revocations with the runtime pool.
type RelayRevocationStore struct {
	database resourceAuthorityDatabase
	metrics  *postgresPoolMetrics
}

// NewRelayRevocationStore accepts only the runtime-authenticated pool.
func NewRelayRevocationStore(pool *Pool) (*RelayRevocationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil {
		return nil, ErrRelayRevocations
	}
	return &RelayRevocationStore{database: pool.resourceAuthorityDatabase, metrics: pool.metrics}, nil
}

// maxRelayRevocationLookback is the furthest back relay_revocations_v1 reads.
const maxRelayRevocationLookback = time.Hour

// ReadRelayRevocations returns what ended within lookback before the
// database clock's now: revocation times are the database clock's.
func (store *RelayRevocationStore) ReadRelayRevocations(ctx context.Context, lookback time.Duration) (_ RelayRevocations, resultErr error) {
	if store == nil || store.database == nil || ctx == nil ||
		lookback <= 0 || lookback > maxRelayRevocationLookback {
		return RelayRevocations{}, ErrRelayRevocations
	}
	startedAt := time.Now()
	defer func() {
		if store.metrics != nil {
			store.metrics.observeOperation(postgresOperationRelayRevocations, time.Since(startedAt), resultErr)
		}
	}()
	transaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return RelayRevocations{}, errors.Join(ErrRelayRevocations, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	now, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return RelayRevocations{}, errors.Join(ErrRelayRevocations, err)
	}
	since := now.Add(-lookback)
	var encoded string
	if err := transaction.QueryRow(ctx, readRelayRevocationsSQL, since).Scan(&encoded); err != nil {
		return RelayRevocations{}, errors.Join(ErrRelayRevocations, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return RelayRevocations{}, errors.Join(ErrRelayRevocations, err)
	}
	return decodeRelayRevocations(encoded)
}

func decodeRelayRevocations(encoded string) (RelayRevocations, error) {
	var wire struct {
		Nodes          []string `json:"nodes"`
		TrustContracts []string `json:"trust_contracts"`
	}
	if err := json.Unmarshal([]byte(encoded), &wire); err != nil {
		return RelayRevocations{}, errors.Join(ErrRelayRevocations, err)
	}
	if len(wire.Nodes)+len(wire.TrustContracts) > maxRelayRevocations {
		return RelayRevocations{}, fmt.Errorf("%w: too many entries", ErrRelayRevocations)
	}
	result := RelayRevocations{
		NodeKeys:       make([][32]byte, len(wire.Nodes)),
		TrustContracts: make([][16]byte, len(wire.TrustContracts)),
	}
	for i, value := range wire.Nodes {
		if !decodeFixedHex(result.NodeKeys[i][:], value) {
			return RelayRevocations{}, fmt.Errorf("%w: node key", ErrRelayRevocations)
		}
	}
	for i, value := range wire.TrustContracts {
		if !decodeFixedHex(result.TrustContracts[i][:], value) {
			return RelayRevocations{}, fmt.Errorf("%w: Trust Contract ID", ErrRelayRevocations)
		}
	}
	return result, nil
}

func decodeFixedHex(dst []byte, value string) bool {
	if len(value) != 2*len(dst) {
		return false
	}
	_, err := hex.Decode(dst, []byte(value))
	return err == nil
}
