package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

// ErrInvalidAuthExpiryStore indicates invalid worker isolation, metadata or bounds.
var ErrInvalidAuthExpiryStore = errors.New("invalid postgres browser expiry store")

const listAuthExpirySQL = `SELECT mesh_ops.list_due_oidc_browser_v1($1::UUID, $2::INTEGER)`
const expireAuthSQL = `SELECT transaction_version, transaction_consumed_at, expired_at,
    stream_internal_id, next_sequence, latest_event_hash
FROM mesh_ops.expire_oidc_browser_v1($1::UUID,$2::UUID,$3::BIGINT,
    $4::TIMESTAMPTZ,$5::TIMESTAMPTZ,$6::TIMESTAMPTZ,$7::BYTEA)`
const appendAuthExpirySQL = `SELECT mesh_ops.append_oidc_expiry_evidence_v1(
    $1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::UUID,$6::BIGINT,
    $7::BYTEA,$8::BYTEA,$9::BYTEA,$10::BYTEA,$11::JSONB)`

// AuthExpiryStore exposes only no-grant cleanup through the worker pool.
// It is deliberately separate from the runtime-only AuthTransactionStore.
type AuthExpiryStore struct {
	database authTransactionDatabase
	options  AuthTransactionOptions
	metrics  *postgresPoolMetrics
}

var (
	_ oidcauth.ExpiryCandidates   = (*AuthExpiryStore)(nil)
	_ oidcauth.ExpiryTransactions = (*AuthExpiryStore)(nil)
)

// NewAuthExpiryStore requires an initialized worker pool and finite SQL bounds.
func NewAuthExpiryStore(pool *Pool, options AuthTransactionOptions) (*AuthExpiryStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.authTransactionDatabase == nil ||
		!validAuthTransactionOptions(options) {
		return nil, ErrInvalidAuthExpiryStore
	}
	return &AuthExpiryStore{database: pool.authTransactionDatabase, options: options, metrics: pool.metrics}, nil
}

func (store *AuthExpiryStore) begin(
	ctx context.Context,
	readOnly bool,
) (result authTransactionDatabaseTransaction, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAuthTransactionOptions(store.options) {
		return nil, ErrInvalidAuthExpiryStore
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, ctx.Err())
	}
	database, beginErr := store.database.Begin(ctx, readOnly)
	if database == nil {
		return nil, errors.Join(ErrBeginAuthTransaction, classifyAuthExpiryError(ctx, beginErr))
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
		defer cancel()
		if err := database.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, ErrRollbackAuthTransaction, classifyAuthExpiryError(cleanup, err))
		}
		resultErr = errors.Join(resultErr, cleanup.Err(), ctx.Err())
	}()
	if beginErr != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, classifyAuthExpiryError(ctx, beginErr))
	}
	setup := &AuthTransactionStore{options: store.options}
	if err := setup.configure(ctx, database); err != nil {
		return nil, classifyAuthExpiryError(ctx, err)
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, ctx.Err())
	}
	owned = true
	return database, nil
}

// ListDue owns a bounded READ ONLY unit and returns no PKCE/digests or current Route.
// Read completion and joined rollback precede releasing any hint batch.
func (store *AuthExpiryStore) ListDue(
	ctx context.Context,
	dep deployment.ID,
	limit int,
) (result []oidcauth.ExpirySnapshot, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationAuthExpiryList, startedAt, resultErr) }()
	if ctx == nil || store == nil || !publicid.ID(dep).IsValid() || limit < 1 || limit > 128 {
		return nil, ErrInvalidAuthExpiryStore
	}
	ctx, cancel := context.WithTimeout(ctx, min(store.options.StatementTimeout, 30*time.Second))
	defer cancel()
	database, err := store.begin(ctx, true)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
		defer cleanupCancel()
		if err := database.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			result, resultErr = nil, errors.Join(resultErr, ErrRollbackAuthTransaction, classifyAuthExpiryError(cleanup, err))
		}
		if cleanup.Err() != nil {
			result, resultErr = nil, errors.Join(resultErr, cleanup.Err())
		}
	}()
	var raw []byte
	if err := database.QueryRow(
		ctx,
		listAuthExpirySQL,
		dep.String(),
		limit,
	).Scan(&raw); err != nil {
		return nil, classifyAuthExpiryError(ctx, err)
	}
	batch, err := decodeAuthExpiryBatch(raw, dep, limit)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(ErrAuthTransactionEvidence, ctx.Err())
	}
	if err := database.Commit(ctx); err != nil {
		return nil, classifyAuthExpiryError(ctx, err)
	}
	committed = true
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return batch, nil
}

type authExpiryCandidateRow struct {
	DeploymentID  string     `json:"deployment_public_id"`
	TransactionID string     `json:"transaction_public_id"`
	State         string     `json:"state"`
	Version       int64      `json:"version"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	ConsumedAt    *time.Time `json:"consumed_at"`
	BindingHash   string     `json:"binding_hash"`
}

func decodeAuthExpiryBatch(raw []byte, dep deployment.ID, limit int) ([]oidcauth.ExpirySnapshot, error) {
	if !publicid.ID(dep).IsValid() || limit < 1 || limit > 128 || len(raw) < 2 || len(raw) > limit*1024 {
		return nil, ErrAuthTransactionEvidence
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var rows []authExpiryCandidateRow
	if err := decoder.Decode(&rows); err != nil || rows == nil || len(rows) > limit {
		return nil, ErrAuthTransactionEvidence
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrAuthTransactionEvidence
	}
	batch := make([]oidcauth.ExpirySnapshot, 0, len(rows))
	seen := make(map[publicid.ID]struct{}, len(rows))
	for _, row := range rows {
		id, err := publicid.Parse(row.TransactionID)
		if err != nil || row.DeploymentID != dep.String() || len(row.BindingHash) != 64 {
			return nil, ErrAuthTransactionEvidence
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, ErrAuthTransactionEvidence
		}
		seen[id] = struct{}{}
		var hash [32]byte
		if _, err := hex.Decode(hash[:], []byte(row.BindingHash)); err != nil {
			return nil, ErrAuthTransactionEvidence
		}
		params := oidcauth.ExpirySnapshotParams{
			DeploymentID: dep, TransactionID: oidcauth.TransactionID(id), State: row.State, Version: row.Version,
			CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, SemanticHash: hash,
		}
		if row.ConsumedAt != nil {
			params.ConsumedAt = *row.ConsumedAt
		}
		snapshot, err := oidcauth.NewExpirySnapshot(params)
		if err != nil {
			return nil, ErrAuthTransactionEvidence
		}
		if len(batch) > 0 && snapshot.ExpiresAt().Before(batch[len(batch)-1].ExpiresAt()) {
			return nil, ErrAuthTransactionEvidence
		}
		batch = append(batch, snapshot)
	}
	return batch, nil
}

// BeginExpiry opens one no-grant READ COMMITTED unit for the exact assignment.
func (store *AuthExpiryStore) BeginExpiry(
	ctx context.Context,
	dep deployment.ID,
) (result oidcauth.ExpiryTransaction, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationAuthExpiryBegin, startedAt, resultErr) }()
	if !publicid.ID(dep).IsValid() {
		return nil, ErrInvalidAuthExpiryStore
	}
	database, err := store.begin(ctx, false)
	if err != nil {
		return nil, err
	}
	return newAuthExpiryTransaction(database, dep, store.metrics), nil
}

func (store *AuthExpiryStore) observe(operation postgresOperation, startedAt time.Time, err error) {
	if store != nil {
		store.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
