package mapsession

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// revisionShareAge is how long one read of a Network's revision answers
// the exit node streams of that Network on this replica: they poll every
// few seconds, so their reads coalesce into about one per Network
// (TD-CORE-90).
const revisionShareAge = time.Second

// maxRevisionReads bounds the Networks whose last read is remembered.
const maxRevisionReads = 4096

// revisionReads shares a Network's revision read between streams.
type revisionReads struct {
	mu      sync.Mutex
	entries map[network.Scope]*revisionRead
}

// revisionRead is one read; done closes when revision and err are set.
type revisionRead struct {
	done     chan struct{}
	revision int64
	err      error
	at       time.Time
}

// NetworkRevision implements NetworkRevisionReader: a read made for
// another stream of the Network within revisionShareAge, or being made,
// answers; otherwise one short read-only transaction in the Network's exact
// scope, bound like a snapshot read.
func (store *Store) NetworkRevision(ctx context.Context, scope network.Scope) (int64, error) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() {
		return 0, ErrSnapshotEvidence
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	reads := &store.revisions
	now := time.Now()
	reads.mu.Lock()
	read, ok := reads.entries[scope]
	if !ok || (!read.at.IsZero() && now.Sub(read.at) >= revisionShareAge) {
		if reads.entries == nil || (!ok && len(reads.entries) >= maxRevisionReads) {
			reads.entries = make(map[network.Scope]*revisionRead)
		}
		read = &revisionRead{done: make(chan struct{})}
		reads.entries[scope] = read
		// The read is every waiting stream's, the first caller's too: it runs
		// on its own deadline, and a caller that gives up only stops waiting.
		go store.shareRevisionRead(reads, scope, read)
	}
	reads.mu.Unlock()
	select {
	case <-read.done:
		return read.revision, read.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// shareRevisionRead makes read, then answers every stream waiting on it.
func (store *Store) shareRevisionRead(reads *revisionReads, scope network.Scope, read *revisionRead) {
	readCtx, cancel := context.WithTimeout(context.Background(), store.options.StatementTimeout)
	read.revision, read.err = store.readNetworkRevision(readCtx, scope)
	cancel()
	reads.mu.Lock()
	read.at = time.Now()
	if read.err != nil && reads.entries[scope] == read {
		// A failure answers the waiting streams only.
		delete(reads.entries, scope)
	}
	reads.mu.Unlock()
	close(read.done)
}

// readNetworkRevision reads scope's Network revision in its own transaction.
func (store *Store) readNetworkRevision(ctx context.Context, scope network.Scope) (_ int64, resultErr error) {
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
