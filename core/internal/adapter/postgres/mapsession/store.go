package mapsession

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"meshtransit.net/core/internal/control"
	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/relay"
)

const (
	maximumStatementTimeout = time.Minute
	maximumIdleTimeout      = time.Minute
	rollbackTimeout         = 2 * time.Second
	maximumInventoryMaxAge  = 5 * time.Minute
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
	PolicyRuleLimit    int
	RelayDirectory     relay.Directory
	// RelayDirectories, when set, returns a Network's own relay directory
	// (the shared regions plus its Private Interchange regions); a failure
	// falls back to RelayDirectory.
	RelayDirectories    func(network.ID) (relay.Directory, error)
	EnableDeviceAliases bool
	// SharedInventory reads each Network's live Devices once per revision
	// and shares them between its Devices' snapshots, instead of reading
	// every other Device for each snapshot. InventoryStatementTimeout bounds
	// that read; InventoryMaxAge bounds how long one read answers for a
	// revision (state changes that do not advance the revision).
	SharedInventory           bool
	InventoryStatementTimeout time.Duration
	InventoryMaxAge           time.Duration
}

// Store loads exact-scope snapshots in read-only repeatable-read transactions.
// It owns no goroutine or process-local authorization state.
type Store struct {
	database    database
	options     Options
	observer    Observer
	inventories *inventoryCache // nil unless SharedInventory
	stats       inventoryStats
}

// InventoryStats counts how map snapshots got their candidates.
type InventoryStats struct {
	// Shared snapshots used a Network inventory (Reads of them read it).
	Shared uint64
	Reads  uint64
	// Direct snapshots read their candidates themselves: the shared
	// inventory is off, or none answered for that exact read.
	Direct uint64
	// PolicyMismatches counts Devices whose policy expanded from the
	// Network policy differed from their own policy read (shadow check
	// before the expansion replaces that read); they were read directly.
	PolicyMismatches uint64
	// Derived snapshots were refreshed from the shared view alone, without
	// reading the Device.
	Derived uint64
}

type inventoryStats struct {
	shared, reads, direct, policyMismatch, derived atomic.Uint64
}

// InventoryStats returns the counters since the store was built.
func (store *Store) InventoryStats() InventoryStats {
	return InventoryStats{Shared: store.stats.shared.Load(), Reads: store.stats.reads.Load(),
		Direct: store.stats.direct.Load(), PolicyMismatches: store.stats.policyMismatch.Load(),
		Derived: store.stats.derived.Load()}
}

// policyMatches checks, for a Device without direct projections, that the
// Network policy expanded for it equals its own policy read (scale-out S2
// shadow phase). A Device with direct projections keeps its own read.
func (store *Store) policyMatches(cached cachedInventory, read snapshotRead) bool {
	snapshot := read.snapshot
	if !cached.policy.IsValid() || cached.policy.Revision() != snapshot.PacketPolicy().Revision() {
		return false
	}
	if snapshot.HasDirectProjections() {
		return true
	}
	expanded, err := cached.policy.For(snapshot.NodeID(), read.readAt, store.options.PolicyRuleLimit)
	if err == nil && expanded.Equal(snapshot.PacketPolicy()) {
		return true
	}
	store.stats.policyMismatch.Add(1)
	return false
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
	store := &Store{database: database, options: options, observer: observer}
	if options.SharedInventory {
		store.inventories = newInventoryCache(options.InventoryMaxAge)
	}
	return store, nil
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
	if store.inventories != nil {
		read, err := store.loadSnapshot(ctx, identity, true)
		if err != nil || read.complete {
			return read.snapshot, err
		}
		shared, ok, err := store.withSharedInventory(ctx, read)
		if err != nil || ok {
			if ok {
				store.stats.shared.Add(1)
			}
			return shared, err
		}
		// No inventory answers for this exact read (the Network moved on, or
		// the read raced a change): read the candidates directly, afresh.
	}
	read, err := store.loadSnapshot(ctx, identity, false)
	if err == nil {
		store.stats.direct.Add(1)
	}
	return read.snapshot, err
}

// snapshotRead is one transaction's result: a complete snapshot, or (for a
// shared-inventory read) the Device's own facts awaiting the inventory of
// revision, read at the PostgreSQL time readAt.
type snapshotRead struct {
	snapshot       appmapsession.Snapshot
	complete       bool
	revision       int64
	readAt         time.Time
	workspaceValue string
	networkValue   string
}

// withSharedInventory completes a shared-inventory read with the Network's
// inventory of exactly that revision, which must list self exactly as self.
func (store *Store) withSharedInventory(ctx context.Context, read snapshotRead) (appmapsession.Snapshot, bool, error) {
	scope := read.snapshot.Scope()
	cached, found, err := store.inventories.get(ctx, scope, read.revision, read.readAt,
		func(readCtx context.Context) (cachedInventory, error) {
			store.stats.reads.Add(1)
			return store.readInventory(readCtx, scope, read.workspaceValue, read.networkValue)
		})
	if err != nil {
		return appmapsession.Snapshot{}, false, err
	}
	if !found {
		return appmapsession.Snapshot{}, false, nil
	}
	if !store.policyMatches(cached, read) {
		return appmapsession.Snapshot{}, false, nil
	}
	inventory := cached.inventory
	self, listed := inventory.Device(read.snapshot.NodeID())
	if !listed || self.NumericNodeID() != read.snapshot.NumericNodeID() ||
		self.MachineKey() != read.snapshot.MachineKey() || self.NodeKey() != read.snapshot.NodeKey() {
		return appmapsession.Snapshot{}, false, nil
	}
	snapshot, err := read.snapshot.WithInventory(inventory)
	if err != nil {
		return appmapsession.Snapshot{}, false, errors.Join(ErrSnapshotEvidence, err)
	}
	return snapshot, true, nil
}

// loadSnapshot reads one Device's snapshot in one repeatable-read
// transaction. With shared, it skips the per-Device candidate read and
// returns the Device's own facts for withSharedInventory.
func (store *Store) loadSnapshot(
	ctx context.Context,
	identity control.AuthenticatedNode,
	shared bool,
) (read snapshotRead, resultErr error) {

	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return snapshotRead{}, errors.Join(ErrLoadSnapshot, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollback(transaction))
		}
	}()
	if err := configure(ctx, transaction, store.options); err != nil {
		return snapshotRead{}, errors.Join(ErrLoadSnapshot, err)
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
			return snapshotRead{}, suspendedOrUnauthorized(
				ctx,
				transaction,
				fingerprint[:],
				nodeKey[:],
			)
		}
		return snapshotRead{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("resolve authenticated scope: %w", err),
		)
	}

	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(ctx, setScopeSQL, workspaceValue, networkValue).Scan(
		&workspaceInternalID,
		&networkInternalID,
	); err != nil {
		return snapshotRead{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("set exact scope: %w", err),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 || recoveryEpoch <= 0 {
		return snapshotRead{}, ErrSnapshotEvidence
	}
	scope, err := scopeFromText(workspaceValue, networkValue)
	if err != nil {
		return snapshotRead{}, err
	}

	var record snapshotRecord
	if err := transaction.QueryRow(ctx, loadSnapshotSQL, fingerprint[:], nodeKey[:]).Scan(
		&record.numericNodeID,
		&record.numericOwnerID,
		&record.networkName,
		&record.nodeID,
		&record.hostname,
		&record.machineKey,
		&record.nodeKey,
		&record.sessionGeneration,
		&record.createdAt,
		&record.keyExpiry,
		&record.networkRevision,
		&record.policyRevision,
		&record.addresses,
		&record.readAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return snapshotRead{}, appmapsession.ErrUnauthorized
		}
		return snapshotRead{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("read scoped snapshot: %w", err),
		)
	}
	// A shared-inventory read takes the candidates from the Network's
	// inventory after commit; the empty list keeps direct projections
	// decodable meanwhile (they are checked against the inventory then).
	peerCandidates := []appmapsession.PeerCandidate{}
	if !shared {
		var err error
		peerCandidates, err = store.loadPeerCandidates(
			ctx,
			transaction,
			scope,
			fingerprint[:],
			nodeKey[:],
		)
		if err != nil {
			return snapshotRead{}, err
		}
	}
	packetPolicy, err := store.loadPacketPolicy(
		ctx,
		transaction,
		scope,
		record.numericNodeID,
		record.policyRevision,
	)
	if err != nil {
		return snapshotRead{}, err
	}
	snapshot, err := record.snapshot(
		workspaceValue,
		networkValue,
		recoveryEpoch,
		peerCandidates,
		packetPolicy,
		store.relayDirectory(scope.NetworkID()),
	)
	if err != nil {
		return snapshotRead{}, err
	}
	snapshot, err = store.loadDirectEdges(ctx, transaction, snapshot, fingerprint[:], nodeKey[:])
	if err != nil {
		return snapshotRead{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return snapshotRead{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("commit read snapshot: %w", err))
	}
	committed = true
	return snapshotRead{
		snapshot: snapshot, complete: !shared, revision: record.networkRevision, readAt: record.readAt,
		workspaceValue: workspaceValue, networkValue: networkValue,
	}, nil
}

func (store *Store) loadPacketPolicy(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	numericNodeID int64,
	policyRevision int64,
) (policy.Snapshot, error) {
	rows, err := transaction.Query(
		ctx,
		loadPacketPolicySQL,
		numericNodeID,
		policyRevision,
		store.options.PolicyRuleLimit+1,
	)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return policy.Snapshot{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("read packet policy: %w", err),
		)
	}
	defer rows.Close()
	rules := make([]policy.Rule, 0, min(store.options.PolicyRuleLimit, 64))
	releaseFound := false
	for rows.Next() {
		var record policyRuleRecord
		if err := rows.Scan(
			&record.policyRevision,
			&record.ruleID,
			&record.sourceNodeID,
			&record.destinationNodeID,
			&record.protocol,
			&record.portRangeFirst,
			&record.portRangeLast,
		); err != nil {
			return policy.Snapshot{}, errors.Join(
				ErrLoadSnapshot,
				fmt.Errorf("scan packet policy: %w", err),
			)
		}
		if record.policyRevision != policyRevision {
			return policy.Snapshot{}, ErrSnapshotEvidence
		}
		releaseFound = true
		if record.ruleID == nil {
			if !record.isEmptyRelease() {
				return policy.Snapshot{}, ErrSnapshotEvidence
			}
			continue
		}
		if len(rules) == store.options.PolicyRuleLimit {
			return policy.Snapshot{}, errors.Join(
				ErrLoadSnapshot,
				appmapsession.ErrPacketPolicyLimit,
			)
		}
		rule, err := record.rule(scope)
		if err != nil {
			return policy.Snapshot{}, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return policy.Snapshot{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("iterate packet policy: %w", err),
		)
	}
	if !releaseFound && policyRevision != 1 {
		return policy.Snapshot{}, ErrSnapshotEvidence
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    scope,
		Revision: policyRevision,
		Rules:    rules,
	})
	if err != nil {
		return policy.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
	}
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
			&record.numericNodeID,
			&record.numericOwnerID,
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
		options.PeerCandidateLimit <= appmapsession.MaximumPeerCandidates &&
		options.PolicyRuleLimit > 0 &&
		options.PolicyRuleLimit <= appmapsession.MaximumPacketPolicyRules &&
		options.RelayDirectory.IsValid() &&
		(!options.SharedInventory || options.InventoryStatementTimeout >= time.Millisecond &&
			options.InventoryStatementTimeout <= maximumStatementTimeout &&
			options.InventoryMaxAge >= time.Second && options.InventoryMaxAge <= maximumInventoryMaxAge)
}

// relayDirectory returns the Network's relay directory.
func (store *Store) relayDirectory(id network.ID) relay.Directory {
	if store.options.RelayDirectories == nil {
		return store.options.RelayDirectory
	}
	directory, err := store.options.RelayDirectories(id)
	if err != nil || !directory.IsValid() || directory.Revision() < store.options.RelayDirectory.Revision() {
		return store.options.RelayDirectory
	}
	return directory
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

// suspendedOrUnauthorized tells a suspended Device apart from one without
// authority, so the client waits instead of stopping for good.
func suspendedOrUnauthorized(
	ctx context.Context,
	transaction databaseTransaction,
	fingerprint []byte,
	nodeKey []byte,
) error {
	var suspended bool
	if err := transaction.QueryRow(ctx, mapSessionSuspendedSQL, fingerprint, nodeKey).Scan(&suspended); err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("read suspension: %w", err))
	}
	if suspended {
		return appmapsession.ErrSuspended
	}
	return appmapsession.ErrUnauthorized
}
