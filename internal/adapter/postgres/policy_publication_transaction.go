package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/network"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
)

type policyPublicationTransactionState uint8

const (
	policyPublicationTransactionOpen policyPublicationTransactionState = iota
	policyPublicationTransactionResolved
	policyPublicationTransactionApplied
	policyPublicationTransactionClosed
)

type policyPublicationAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type policyPublicationTransaction struct {
	mu sync.Mutex

	database   policyPublicationDatabaseTransaction
	scope      network.Scope
	metrics    *postgresPoolMetrics
	state      policyPublicationTransactionState
	resolution publication.Resolution
	audit      policyPublicationAuditHead
}

var _ publication.Transaction = (*policyPublicationTransaction)(nil)

func (transaction *policyPublicationTransaction) Resolve(
	ctx context.Context,
	command publication.Command,
) (resolution publication.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationResolve, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !command.IsValid() {
		return publication.Resolution{}, ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != policyPublicationTransactionOpen ||
		command.Candidate().Snapshot().Scope() != transaction.scope {
		return publication.Resolution{}, ErrPolicyPublicationState
	}

	resolution, err := transaction.resolveLocked(ctx)
	if err != nil {
		return publication.Resolution{}, errors.Join(
			ErrResolvePolicyPublication,
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = policyPublicationTransactionResolved
	return resolution, nil
}

func (transaction *policyPublicationTransaction) resolveLocked(
	ctx context.Context,
) (publication.Resolution, error) {
	var networkRevision, inventoryRevision, groupRevision, policyRevision int64
	var dnsRevision, routeRevision, sharingRevision, isolationGeneration int64
	if err := transaction.database.QueryRow(ctx, lockPolicyPublicationRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
		&groupRevision,
		&policyRevision,
		&dnsRevision,
		&routeRevision,
		&sharingRevision,
		&isolationGeneration,
	); err != nil {
		return publication.Resolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if networkRevision <= 0 || inventoryRevision <= 0 || groupRevision <= 0 || policyRevision <= 0 ||
		dnsRevision <= 0 || routeRevision <= 0 || sharingRevision <= 0 || isolationGeneration <= 0 {
		return publication.Resolution{}, ErrPolicyPublicationEvidence
	}

	var activeReleaseValue string
	var activePolicyRevision int64
	var activeSemanticHashValue []byte
	err := transaction.database.QueryRow(
		ctx,
		lockActivePolicyReleaseSQL,
	).Scan(&activeReleaseValue, &activePolicyRevision, &activeSemanticHashValue)
	var activeReleaseID publication.ReleaseID
	var activeSemanticHash publication.SemanticHash
	if errors.Is(err, pgx.ErrNoRows) {
		if policyRevision != 1 {
			return publication.Resolution{}, ErrPolicyPublicationEvidence
		}
	} else if err != nil {
		return publication.Resolution{}, fmt.Errorf("lock active Policy Release: %w", err)
	} else {
		activeReleaseID, err = publication.ParseReleaseID(activeReleaseValue)
		if err != nil {
			return publication.Resolution{}, ErrPolicyPublicationEvidence
		}
		activeSemanticHash, err = policyPublicationSemanticHash(activeSemanticHashValue)
		if err != nil || activePolicyRevision != policyRevision {
			return publication.Resolution{}, ErrPolicyPublicationEvidence
		}
	}

	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockPolicyPublicationAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return publication.Resolution{}, fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return publication.Resolution{}, ErrPolicyPublicationEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)

	resolution, err := publication.NewResolution(publication.ResolutionParams{
		Scope:              transaction.scope,
		NetworkRevision:    networkRevision,
		PolicyRevision:     policyRevision,
		ActiveReleaseID:    activeReleaseID,
		ActiveSemanticHash: activeSemanticHash,
	})
	if err != nil {
		return publication.Resolution{}, ErrPolicyPublicationEvidence
	}
	return resolution, nil
}

func (transaction *policyPublicationTransaction) Apply(
	ctx context.Context,
	change publication.Change,
) (result publication.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationApply, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !change.IsValid() {
		return publication.Result{}, ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != policyPublicationTransactionResolved ||
		change.Resolution() != transaction.resolution ||
		change.Command().Candidate().Snapshot().Scope() != transaction.scope {
		return publication.Result{}, ErrPolicyPublicationState
	}

	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return publication.Result{}, errors.Join(
			ErrApplyPolicyPublication,
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	transaction.state = policyPublicationTransactionApplied
	return result, nil
}

func (transaction *policyPublicationTransaction) applyLocked(
	ctx context.Context,
	change publication.Change,
) (publication.Result, error) {
	rules, err := encodePolicyPublicationRules(change)
	if err != nil {
		return publication.Result{}, err
	}
	if err := transaction.database.Exec(
		ctx,
		setPolicyPublicationChangeSQL,
		change.MutationIDs().ChangeID().String(),
	); err != nil {
		return publication.Result{}, fmt.Errorf("set authority change context: %w", err)
	}

	command := change.Command()
	semanticHash := command.Candidate().SemanticHash().Bytes()
	var networkRevision, policyRevision, releaseVersion int64
	if err := transaction.database.QueryRow(
		ctx,
		publishCompiledPolicySQL,
		change.MutationIDs().ReleaseID().String(),
		command.BasePolicyRevision(),
		semanticHash[:],
		command.Candidate().CompilerFormatVersion(),
		change.OccurredAt(),
		rules,
	).Scan(&networkRevision, &policyRevision, &releaseVersion); err != nil {
		return publication.Result{}, fmt.Errorf("publish compiled policy: %w", err)
	}
	if networkRevision != transaction.resolution.NetworkRevision()+1 ||
		policyRevision != command.Candidate().Snapshot().Revision() || releaseVersion != 1 {
		return publication.Result{}, ErrPolicyPublicationEvidence
	}
	if err := transaction.appendPolicyPublicationEvidence(
		ctx,
		change,
		releaseVersion,
		networkRevision,
	); err != nil {
		return publication.Result{}, err
	}
	result, err := publication.NewResult(publication.ResultParams{
		ReleaseID:       change.MutationIDs().ReleaseID(),
		Scope:           transaction.scope,
		NetworkRevision: networkRevision,
		PolicyRevision:  policyRevision,
		SemanticHash:    command.Candidate().SemanticHash(),
	})
	if err != nil {
		return publication.Result{}, ErrPolicyPublicationEvidence
	}
	return result, nil
}

func (transaction *policyPublicationTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationCommit, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != policyPublicationTransactionApplied {
		return ErrPolicyPublicationState
	}
	transaction.state = policyPublicationTransactionClosed
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(
			ErrCommitPolicyPublication,
			classifyPolicyPublicationCommitError(ctx, err),
		)
	}
	return nil
}

func (transaction *policyPublicationTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationRollback, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrPolicyPublicationState
	}
	if transaction.state == policyPublicationTransactionClosed {
		return nil
	}
	transaction.state = policyPublicationTransactionClosed
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(
			ErrRollbackPolicyPublication,
			fmt.Errorf("roll back database transaction: %w", err),
		)
	}
	return nil
}

func (transaction *policyPublicationTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction == nil {
		return
	}
	transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
}

func policyPublicationSemanticHash(value []byte) (publication.SemanticHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return publication.SemanticHash{}, ErrPolicyPublicationEvidence
	}
	copy(fixed[:], value)
	hash, err := publication.NewSemanticHash(fixed)
	if err != nil {
		return publication.SemanticHash{}, ErrPolicyPublicationEvidence
	}
	return hash, nil
}
