package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing/target"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

const resolveShareTargetSQL = `SELECT workspace_public_id::TEXT, network_public_id::TEXT,
 workspace_display_code, network_display_code
FROM mesh_ops.resolve_share_target_v1(` + sessionArguments + `,$10::UUID,$11::UUID,$12::TEXT)`

// ShareTargetStore resolves share consumer Networks by display code.
type ShareTargetStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewShareTargetStore uses the runtime pool.
func NewShareTargetStore(pool *Pool, options AccountSessionOptions) (*ShareTargetStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, target.ErrInvalid
	}
	return &ShareTargetStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// shareTargetError maps the schema 105 error classes; anything else is uncertain.
func shareTargetError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return target.ErrNotFound
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "42501", "23503":
			return target.ErrForbidden
		case "22023":
			return target.ErrInvalid
		}
	}
	return errors.Join(target.ErrUnavailable, err)
}

// Resolve reads one target in a read-only transaction that is rolled back.
func (store *ShareTargetStore) Resolve(ctx context.Context, query target.Query) (_ target.Target, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !query.IsValid() {
		return target.Target{}, target.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return target.Target{}, target.ErrUnavailable
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return target.Target{}, errors.Join(target.ErrUnavailable, err)
	}
	args := append(sessionQueryArguments(query.Session), query.Provider.WorkspaceID().String(),
		query.Provider.NetworkID().String(), query.NetworkCode.String())
	var workspaceText, networkText, workspaceCode, networkCode string
	if err := tx.QueryRow(ctx, resolveShareTargetSQL, args...).Scan(&workspaceText, &networkText, &workspaceCode,
		&networkCode); err != nil {
		return target.Target{}, shareTargetError(err)
	}
	workspaceID, workspaceErr := workspace.ParseID(workspaceText)
	networkID, networkErr := network.ParseID(networkText)
	wsCode, wsCodeErr := identity.ParseDisplayCode(workspaceCode)
	netCode, netCodeErr := identity.ParseDisplayCode(networkCode)
	if errors.Join(workspaceErr, networkErr, wsCodeErr, netCodeErr) != nil {
		return target.Target{}, target.ErrInvalid
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return target.Target{}, target.ErrInvalid
	}
	return target.Target{Scope: scope, WorkspaceCode: wsCode, NetworkCode: netCode}, nil
}
