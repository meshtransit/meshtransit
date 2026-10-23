package mapsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
)

// loadNetworkRevisionSQL reads the installed scope's Network revision.
const loadNetworkRevisionSQL = `SELECT revision.network_revision
FROM mesh_ops.network_revision AS revision
WHERE revision.workspace_id = mesh_ops.current_workspace_id()
  AND revision.network_id = mesh_ops.current_network_id()`

var _ appmapsession.NetworkRevisionReader = (*Store)(nil)

// NetworkRevision implements NetworkRevisionReader: one short read-only
// transaction in the Network's exact scope, bound like a snapshot read.
func (store *Store) NetworkRevision(ctx context.Context, scope network.Scope) (_ int64, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() {
		return 0, ErrSnapshotEvidence
	}
	startedAt := time.Now()
	defer func() {
		store.observer.ObserveMapSession(OperationReadNetworkRevision, time.Since(startedAt), resultErr)
	}()
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return 0, errors.Join(ErrLoadSnapshot, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollback(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return 0, errors.Join(ErrLoadSnapshot, fmt.Errorf("configure revision read: %w", err))
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(ctx, setScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return 0, errors.Join(ErrLoadSnapshot, fmt.Errorf("set revision scope: %w", err))
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return 0, ErrSnapshotEvidence
	}
	var revision int64
	if err := transaction.QueryRow(ctx, loadNetworkRevisionSQL).Scan(&revision); err != nil {
		return 0, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network revision: %w", err))
	}
	if revision <= 0 {
		return 0, ErrSnapshotEvidence
	}
	if err := transaction.Commit(ctx); err != nil {
		return 0, errors.Join(ErrLoadSnapshot, fmt.Errorf("commit revision read: %w", err))
	}
	committed = true
	return revision, nil
}
