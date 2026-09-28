package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	approval "github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	policyApprovalRequestOperation  = "policy.approval.request"
	policyApprovalDecisionOperation = "policy.approval.approve"
)

type policyApprovalTransactionState uint8

const (
	policyApprovalTransactionOpen policyApprovalTransactionState = iota
	policyApprovalTransactionResolved
	policyApprovalTransactionApplied
	policyApprovalTransactionClosed
)

type policyApprovalAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type policyApprovalAuthorizationEvidence struct {
	accountSessionID              publicid.ID
	roleBindingID                 publicid.ID
	roleDefinitionID              publicid.ID
	scopeAuthorityGeneration      int64
	membershipAuthorityGeneration int64
	bindingAuthorityGeneration    int64
	roleAuthorityGeneration       int64
}

func (evidence policyApprovalAuthorizationEvidence) isValid() bool {
	return evidence.accountSessionID.IsValid() && evidence.roleBindingID.IsValid() &&
		evidence.roleDefinitionID.IsValid() && evidence.scopeAuthorityGeneration > 0 &&
		evidence.membershipAuthorityGeneration > 0 && evidence.bindingAuthorityGeneration > 0 &&
		evidence.roleAuthorityGeneration > 0
}

type policyApprovalTransactionCore struct {
	mu sync.Mutex

	database      policyApprovalDatabaseTransaction
	scope         network.Scope
	metrics       *postgresPoolMetrics
	state         policyApprovalTransactionState
	audit         policyApprovalAuditHead
	authorization policyApprovalAuthorizationEvidence
}

func (transaction *policyApprovalTransactionCore) resolveAuthorization(
	ctx context.Context,
	session accountsession.Session,
	permission string,
	evaluatedAt time.Time,
) (policyApprovalAuthorizationEvidence, error) {
	var bindingIDValue, roleIDValue string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := transaction.database.QueryRow(
		ctx,
		authorizePolicyApprovalSQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		transaction.scope.WorkspaceID().String(),
		transaction.scope.NetworkID().String(),
		permission,
		evaluatedAt,
	).Scan(
		&bindingIDValue,
		&roleIDValue,
		&scopeGeneration,
		&membershipGeneration,
		&bindingGeneration,
		&roleGeneration,
		&hasExpiry,
		&expiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return policyApprovalAuthorizationEvidence{}, approval.ErrForbidden
	}
	if err != nil {
		return policyApprovalAuthorizationEvidence{}, classifyPolicyApprovalDatabaseError(ctx, err)
	}
	if hasExpiry && !expiresAt.After(evaluatedAt) {
		return policyApprovalAuthorizationEvidence{}, approval.ErrForbidden
	}
	bindingID, bindingErr := publicid.Parse(bindingIDValue)
	roleID, roleErr := publicid.Parse(roleIDValue)
	evidence := policyApprovalAuthorizationEvidence{
		accountSessionID: publicid.ID(session.ID()),
		roleBindingID:    bindingID, roleDefinitionID: roleID,
		scopeAuthorityGeneration:      scopeGeneration,
		membershipAuthorityGeneration: membershipGeneration,
		bindingAuthorityGeneration:    bindingGeneration,
		roleAuthorityGeneration:       roleGeneration,
	}
	if bindingErr != nil || roleErr != nil || !evidence.isValid() {
		return policyApprovalAuthorizationEvidence{}, errors.Join(
			ErrPolicyApprovalEvidence, bindingErr, roleErr,
		)
	}
	return evidence, nil
}

func (transaction *policyApprovalTransactionCore) lockRevision(
	ctx context.Context,
) (accessgraph.RevisionVector, error) {
	var values [8]int64
	if err := transaction.database.QueryRow(ctx, lockPolicyApprovalRevisionSQL).Scan(
		&values[0], &values[1], &values[2], &values[3],
		&values[4], &values[5], &values[6], &values[7],
	); err != nil {
		return accessgraph.RevisionVector{}, classifyPolicyApprovalDatabaseError(ctx, err)
	}
	vector, err := policyApprovalRevisionVector(values)
	if err != nil {
		return accessgraph.RevisionVector{}, ErrPolicyApprovalEvidence
	}
	return vector, nil
}

type policyApprovalIdempotencyRecord struct {
	recordID              string
	requestHash           []byte
	state                 string
	resultKind            *string
	resultPublicID        *string
	resultVersion         *int64
	resultNetworkRevision *int64
	resultPayload         []byte
	expiresAt             time.Time
	created               bool
}

func (transaction *policyApprovalTransactionCore) claimIdempotency(
	ctx context.Context,
	recordID publicid.ID,
	actorID string,
	operation string,
	digestKeyID string,
	keyDigest [32]byte,
	requestHash [32]byte,
	occurredAt time.Time,
	expiresAt time.Time,
) (policyApprovalIdempotencyRecord, error) {
	var record policyApprovalIdempotencyRecord
	if err := transaction.database.QueryRow(
		ctx,
		claimPolicyApprovalIdempotencySQL,
		recordID.String(),
		actorID,
		operation,
		digestKeyID,
		keyDigest[:],
		requestHash[:],
		occurredAt,
		expiresAt,
	).Scan(
		&record.recordID,
		&record.requestHash,
		&record.state,
		&record.resultKind,
		&record.resultPublicID,
		&record.resultVersion,
		&record.resultNetworkRevision,
		&record.resultPayload,
		&record.expiresAt,
		&record.created,
	); err != nil {
		return policyApprovalIdempotencyRecord{}, classifyPolicyApprovalDatabaseError(ctx, err)
	}
	parsedRecordID, err := publicid.Parse(record.recordID)
	if err != nil || !bytes.Equal(record.requestHash, requestHash[:]) ||
		!record.expiresAt.Equal(expiresAt) {
		return policyApprovalIdempotencyRecord{}, ErrPolicyApprovalEvidence
	}
	if record.state == "pending" {
		if !record.created || parsedRecordID != recordID || record.resultKind != nil ||
			record.resultPublicID != nil || record.resultVersion != nil ||
			record.resultNetworkRevision != nil || len(record.resultPayload) != 0 {
			return policyApprovalIdempotencyRecord{}, ErrPolicyApprovalEvidence
		}
		return record, nil
	}
	if record.state != "completed" || record.created || record.resultKind == nil ||
		record.resultPublicID == nil || record.resultVersion == nil ||
		record.resultNetworkRevision == nil || *record.resultVersion <= 0 ||
		*record.resultNetworkRevision <= 0 {
		return policyApprovalIdempotencyRecord{}, ErrPolicyApprovalEvidence
	}
	return record, nil
}

func (record policyApprovalIdempotencyRecord) parsedRecordID() (publicid.ID, error) {
	id, err := publicid.Parse(record.recordID)
	if err != nil {
		return publicid.ID{}, ErrPolicyApprovalEvidence
	}
	return id, nil
}

func (record policyApprovalIdempotencyRecord) isCompleted(
	resultKind string,
) (string, bool) {
	returnValue := ""
	if record.state == "completed" && record.resultKind != nil &&
		record.resultPublicID != nil && *record.resultKind == resultKind {
		returnValue = *record.resultPublicID
	}
	return returnValue, returnValue != ""
}

func (record policyApprovalIdempotencyRecord) matchesCompletedResult(
	resultVersion int64,
	networkRevision int64,
) bool {
	return record.resultVersion != nil && *record.resultVersion == resultVersion &&
		record.resultNetworkRevision != nil &&
		*record.resultNetworkRevision == networkRevision &&
		bytes.Equal(bytes.TrimSpace(record.resultPayload), []byte(`{}`))
}

func (transaction *policyApprovalTransactionCore) lockAuditHead(ctx context.Context) error {
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockPolicyApprovalAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return classifyPolicyApprovalDatabaseError(ctx, err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return ErrPolicyApprovalEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)
	return nil
}

func (transaction *policyApprovalTransactionCore) commit(
	ctx context.Context,
	operation postgresOperation,
) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), resultErr)
	}()
	if ctx == nil || transaction == nil {
		return ErrPolicyApprovalState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != policyApprovalTransactionApplied {
		return ErrPolicyApprovalState
	}
	if err := transaction.database.Commit(ctx); err != nil {
		transaction.state = policyApprovalTransactionClosed
		return errors.Join(ErrCommitPolicyApproval, classifyPolicyApprovalCommitError(ctx, err))
	}
	transaction.state = policyApprovalTransactionClosed
	return nil
}

func (transaction *policyApprovalTransactionCore) rollback(
	ctx context.Context,
	operation postgresOperation,
) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), resultErr)
	}()
	if ctx == nil || transaction == nil {
		return ErrPolicyApprovalState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrPolicyApprovalState
	}
	if transaction.state == policyApprovalTransactionClosed {
		return nil
	}
	err := transaction.database.Rollback(ctx)
	transaction.state = policyApprovalTransactionClosed
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(ErrRollbackPolicyApproval, err)
	}
	return nil
}

func (transaction *policyApprovalTransactionCore) completeIdempotency(
	ctx context.Context,
	recordID publicid.ID,
	actorID string,
	operation string,
	digestKeyID string,
	keyDigest [32]byte,
	requestHash [32]byte,
	resultKind string,
	resultID string,
	resultVersion int64,
	networkRevision int64,
	outboxID publicid.ID,
	completedAt time.Time,
) error {
	var completedID string
	if err := transaction.database.QueryRow(
		ctx,
		completePolicyApprovalIdempotencySQL,
		recordID.String(), actorID, operation, digestKeyID, keyDigest[:], requestHash[:],
		resultKind, resultID, resultVersion, networkRevision, []byte(`{}`),
		outboxID.String(), completedAt,
	).Scan(&completedID); err != nil {
		return classifyPolicyApprovalDatabaseError(ctx, err)
	}
	if completedID != recordID.String() {
		return ErrPolicyApprovalEvidence
	}
	return nil
}

func (transaction *policyApprovalTransactionCore) validateOpen(scope network.Scope) error {
	if transaction == nil || transaction.database == nil ||
		transaction.state != policyApprovalTransactionOpen || transaction.scope != scope {
		return fmt.Errorf("%w: transaction is not open", ErrPolicyApprovalState)
	}
	return nil
}
