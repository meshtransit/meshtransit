package mapsession

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meshtransit/meshtransit/internal/control"
	appmapsession "github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
)

const (
	maximumStatementTimeout = time.Minute
	maximumIdleTimeout      = time.Minute
	rollbackTimeout         = 2 * time.Second
)

var (
	// ErrInvalidStore reports a missing dependency, identity, or unsafe resource bound.
	ErrInvalidStore = errors.New("invalid postgres map session store")
	// ErrLoadSnapshot classifies a map snapshot that could not be read consistently.
	ErrLoadSnapshot = errors.New("load postgres map session snapshot")
	// ErrSnapshotEvidence reports malformed or incomplete authoritative state.
	ErrSnapshotEvidence = errors.New("postgres map session snapshot evidence is invalid")
)

// Options bounds database work owned by one map snapshot load.
type Options struct {
	StatementTimeout   time.Duration
	IdleTimeout        time.Duration
	PeerCandidateLimit int
}

// Store loads exact-scope snapshots in read-only repeatable-read transactions.
// It owns no goroutine or process-local authorization state.
type Store struct {
	database database
	options  Options
	observer Observer
}

var _ appmapsession.SnapshotStore = (*Store)(nil)

// NewStore constructs a bounded PostgreSQL map-session store.
func NewStore(pool *pgxpool.Pool, options Options, observer Observer) (*Store, error) {
	return newStore(newPGXDatabase(pool), options, observer)
}

func newStore(database database, options Options, observer Observer) (*Store, error) {
	if database == nil || observer == nil || !validOptions(options) {
		return nil, ErrInvalidStore
	}
	return &Store{database: database, options: options, observer: observer}, nil
}

// Load resolves authority from the bound identity, installs exact RLS scope,
// and reads all first-response facts from one immutable database snapshot.
func (store *Store) Load(
	ctx context.Context,
	identity control.AuthenticatedNode,
) (snapshot appmapsession.Snapshot, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.observer != nil {
			store.observer.ObserveMapSession(OperationLoad, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || store.observer == nil ||
		!validOptions(store.options) || !identity.IsValid() {
		return appmapsession.Snapshot{}, ErrInvalidStore
	}
	if err := ctx.Err(); err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, err)
	}

	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollback(transaction))
		}
	}()
	if err := configure(ctx, transaction, store.options); err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, err)
	}

	fingerprint := identity.MachineFingerprint()
	nodeKey := identity.NodeKey().Bytes()
	var workspaceValue, networkValue string
	var recoveryEpoch int64
	if err := transaction.QueryRow(ctx, resolveScopeSQL, fingerprint[:], nodeKey[:]).Scan(
		&workspaceValue,
		&networkValue,
		&recoveryEpoch,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return appmapsession.Snapshot{}, appmapsession.ErrUnauthorized
		}
		return appmapsession.Snapshot{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("resolve authenticated scope: %w", err),
		)
	}

	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(ctx, setScopeSQL, workspaceValue, networkValue).Scan(
		&workspaceInternalID,
		&networkInternalID,
	); err != nil {
		return appmapsession.Snapshot{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("set exact scope: %w", err),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 || recoveryEpoch <= 0 {
		return appmapsession.Snapshot{}, ErrSnapshotEvidence
	}
	scope, err := scopeFromText(workspaceValue, networkValue)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}

	var record snapshotRecord
	if err := transaction.QueryRow(ctx, loadSnapshotSQL, fingerprint[:], nodeKey[:]).Scan(
		&record.numericNodeID,
		&record.numericOwnerID,
		&record.nodeID,
		&record.hostname,
		&record.machineKey,
		&record.nodeKey,
		&record.sessionGeneration,
		&record.createdAt,
		&record.keyExpiry,
		&record.networkRevision,
		&record.addresses,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return appmapsession.Snapshot{}, appmapsession.ErrUnauthorized
		}
		return appmapsession.Snapshot{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("read scoped snapshot: %w", err),
		)
	}
	peerCandidates, err := store.loadPeerCandidates(
		ctx,
		transaction,
		scope,
		fingerprint[:],
		nodeKey[:],
	)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	snapshot, err = record.snapshot(workspaceValue, networkValue, recoveryEpoch, peerCandidates)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("commit read snapshot: %w", err))
	}
	committed = true
	return snapshot, nil
}

func (store *Store) loadPeerCandidates(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	machineFingerprint []byte,
	nodeKey []byte,
) ([]appmapsession.PeerCandidate, error) {
	rows, err := transaction.Query(
		ctx,
		loadPeerCandidatesSQL,
		machineFingerprint,
		nodeKey,
		store.options.PeerCandidateLimit+1,
	)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read peer candidates: %w", err))
	}
	defer rows.Close()
	candidates := make(
		[]appmapsession.PeerCandidate,
		0,
		min(store.options.PeerCandidateLimit, 64),
	)
	for rows.Next() {
		if len(candidates) == store.options.PeerCandidateLimit {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPeerCandidateLimit)
		}
		var record peerCandidateRecord
		if err := rows.Scan(
			&record.nodeID,
			&record.ownerID,
			&record.hostname,
			&record.machineKey,
			&record.nodeKey,
			&record.sessionGeneration,
			&record.createdAt,
			&record.keyExpiry,
			&record.addresses,
		); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan peer candidate: %w", err))
		}
		candidate, err := record.candidate(scope)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate peer candidates: %w", err))
	}
	return candidates, nil
}

func configure(ctx context.Context, transaction databaseTransaction, options Options) error {
	if err := transaction.Exec(
		ctx,
		configureTransactionSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return fmt.Errorf("configure transaction timeouts: %w", err)
	}
	return nil
}

func validOptions(options Options) bool {
	return options.StatementTimeout >= time.Millisecond &&
		options.StatementTimeout <= maximumStatementTimeout &&
		options.IdleTimeout >= time.Millisecond && options.IdleTimeout <= maximumIdleTimeout &&
		options.PeerCandidateLimit > 0 &&
		options.PeerCandidateLimit <= appmapsession.MaximumPeerCandidates
}

func postgresTimeout(value time.Duration) string {
	return strconv.FormatInt(value.Milliseconds(), 10) + "ms"
}

func rollback(transaction databaseTransaction) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := transaction.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back map snapshot: %w", err)
	}
	return nil
}
