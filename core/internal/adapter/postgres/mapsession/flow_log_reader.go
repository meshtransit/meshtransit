package mapsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
)

// loadFlowLogSQL reads the installed scope's connection log setting
// (schema 267); no row is no logging.
const loadFlowLogSQL = `SELECT enabled, forwarded, window_s, provider FROM mesh_ops.read_connection_log_ticket_v2()`

var _ appmapsession.FlowLogReader = (*Store)(nil)

// ReadFlowLog implements FlowLogReader in one short read-only transaction
// in the Network's exact scope, bound like a revision read. Streams share
// it through appmapsession.FlowLogCache.
func (store *Store) ReadFlowLog(ctx context.Context, scope network.Scope) (_ appmapsession.FlowLogSettings,
	resultErr error,
) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() {
		return appmapsession.FlowLogSettings{}, ErrSnapshotEvidence
	}
	startedAt := time.Now()
	defer func() {
		store.observer.ObserveMapSession(OperationReadFlowLog, time.Since(startedAt), resultErr)
	}()
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return appmapsession.FlowLogSettings{}, errors.Join(ErrLoadSnapshot, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollback(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return appmapsession.FlowLogSettings{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("configure flow log read: %w", err))
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(ctx, setScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return appmapsession.FlowLogSettings{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("set flow log scope: %w", err))
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return appmapsession.FlowLogSettings{}, ErrSnapshotEvidence
	}
	var settings appmapsession.FlowLogSettings
	var window int32
	var provider *string
	err = transaction.QueryRow(ctx, loadFlowLogSQL).Scan(&settings.Enabled, &settings.Forwarded, &window, &provider)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		settings = appmapsession.FlowLogSettings{}
	case err != nil:
		return appmapsession.FlowLogSettings{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("read flow log: %w", err))
	case window < 60 || window > 300:
		return appmapsession.FlowLogSettings{}, ErrSnapshotEvidence
	default:
		settings.WindowSeconds = int(window)
		if provider != nil {
			settings.Provider = *provider
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return appmapsession.FlowLogSettings{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("commit flow log read: %w", err))
	}
	committed = true
	return settings, nil
}
