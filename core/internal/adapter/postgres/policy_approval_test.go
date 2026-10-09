package postgres

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/authorization"
	approval "meshtransit.net/core/internal/domain/policy/approval"
)

func TestPolicyApprovalRequestTransactionPersistsAtomicEvidence(t *testing.T) {
	t.Parallel()

	now := policyApprovalTestTime()
	idempotencyExpiresAt := now.Add(time.Hour)
	binding := policyApprovalBindingFixture(t)
	proposer := policyApprovalSessionFixture(t, 401, 811)
	command := policyApprovalRequestCommandFixture(t, binding, proposer)
	mutationIDs := policyApprovalRequestMutationIDsFixture(t)
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}

	databaseTransaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(databaseTransaction)
	enqueuePolicyApprovalAuthorization(databaseTransaction)
	enqueuePolicyApprovalRevision(databaseTransaction, binding.BaselineVector())
	enqueuePolicyApprovalPendingClaim(
		databaseTransaction,
		mutationIDs.IdempotencyRecordID(),
		requestHash.Bytes(),
		idempotencyExpiresAt,
	)
	enqueuePolicyApprovalAuditHead(databaseTransaction)
	databaseTransaction.enqueueRow(createPolicyApprovalRequestSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 1
			return nil
		},
	})
	enqueuePolicyApprovalEvidenceAppend(databaseTransaction)
	enqueuePolicyApprovalCompletion(databaseTransaction, mutationIDs.IdempotencyRecordID())
	database := &fakePolicyApprovalDatabase{
		transactions: []*fakePolicyApprovalTransaction{databaseTransaction},
	}
	store := testPolicyApprovalStore(t, database)

	transaction, err := store.BeginApprovalRequest(t.Context(), binding.Scope())
	if err != nil {
		t.Fatalf("BeginApprovalRequest() error = %v", err)
	}
	resolution, err := transaction.Resolve(
		t.Context(), command, mutationIDs, now, idempotencyExpiresAt,
	)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change, err := approval.NewRequestChange(approval.RequestChangeParams{
		Command: command, Resolution: resolution, MutationIDs: mutationIDs,
		OccurredAt: now, RequestExpiresAt: now.Add(approval.RequestLifetime),
		IdempotencyExpiresAt: idempotencyExpiresAt,
	})
	if err != nil {
		t.Fatalf("approval.NewRequestChange() error = %v", err)
	}
	result, err := transaction.Apply(t.Context(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !result.IsValid() || result.RequestID() != mutationIDs.RequestID() ||
		!result.Binding().Equal(binding) || result.RequestVersion() != 1 {
		t.Fatalf("Apply() result = %+v", result)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() after Commit error = %v", err)
	}

	wantQueries := []string{
		configurePolicyApprovalTransactionSQL,
		setPolicyApprovalScopeSQL,
		authorizePolicyApprovalSQL,
		lockPolicyApprovalRevisionSQL,
		claimPolicyApprovalIdempotencySQL,
		lockPolicyApprovalAuditStreamSQL,
		setPolicyApprovalChangeSQL,
		createPolicyApprovalRequestSQL,
		appendPolicyApprovalEvidenceSQL,
		completePolicyApprovalIdempotencySQL,
	}
	if got := policyApprovalQueries(databaseTransaction.calls); !slices.Equal(got, wantQueries) {
		t.Fatalf("queries = %v, want %v", got, wantQueries)
	}
	if got := databaseTransaction.calls[2].arguments[11]; got != string(authorization.PermissionPolicyValidate) {
		t.Fatalf("authorization permission = %v", got)
	}
	if len(database.readOnly) != 1 || database.readOnly[0] ||
		databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf(
			"readOnly = %v, commitCalls = %d, rollbackCalls = %d",
			database.readOnly,
			databaseTransaction.commitCalls,
			databaseTransaction.rollbackCalls,
		)
	}
}

func TestPolicyApprovalDecisionTransactionPersistsIndependentApproval(t *testing.T) {
	t.Parallel()

	now := policyApprovalTestTime()
	requestCreatedAt := now.Add(-time.Minute)
	idempotencyExpiresAt := now.Add(time.Hour)
	binding := policyApprovalBindingFixture(t)
	proposer := policyApprovalSessionFixture(t, 401, 811)
	approver := policyApprovalSessionFixture(t, 402, 812)
	requestIDs := policyApprovalRequestMutationIDsFixture(t)
	mutationIDs := policyApprovalMutationIDsFixture(t)
	command := policyApprovalCommandFixture(t, binding, approver, requestIDs.RequestID())
	decisionHash, err := command.DecisionHash()
	if err != nil {
		t.Fatal(err)
	}

	databaseTransaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(databaseTransaction)
	enqueuePolicyApprovalAuthorization(databaseTransaction)
	enqueuePolicyApprovalPendingClaim(
		databaseTransaction,
		mutationIDs.IdempotencyRecordID(),
		decisionHash.Bytes(),
		idempotencyExpiresAt,
	)
	enqueueLockedPolicyApprovalRequest(
		databaseTransaction, binding, proposer, requestCreatedAt,
	)
	enqueuePolicyApprovalAuditHead(databaseTransaction)
	databaseTransaction.enqueueRow(approvePolicyApprovalRequestSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 2
			*destinations[1].(*int64) = 1
			return nil
		},
	})
	enqueuePolicyApprovalEvidenceAppend(databaseTransaction)
	enqueuePolicyApprovalCompletion(databaseTransaction, mutationIDs.IdempotencyRecordID())
	database := &fakePolicyApprovalDatabase{
		transactions: []*fakePolicyApprovalTransaction{databaseTransaction},
	}
	store := testPolicyApprovalStore(t, database)

	transaction, err := store.BeginPolicyApproval(t.Context(), binding.Scope())
	if err != nil {
		t.Fatalf("BeginPolicyApproval() error = %v", err)
	}
	resolution, err := transaction.Resolve(
		t.Context(), command, mutationIDs, now, idempotencyExpiresAt,
	)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change, err := approval.NewChange(approval.ChangeParams{
		Command: command, Resolution: resolution, MutationIDs: mutationIDs,
		OccurredAt: now, IdempotencyExpiresAt: idempotencyExpiresAt,
	})
	if err != nil {
		t.Fatalf("approval.NewChange() error = %v", err)
	}
	result, err := transaction.Apply(t.Context(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !result.IsValid() || result.EvidenceID() != mutationIDs.EvidenceID() ||
		result.RequestID() != requestIDs.RequestID() || result.RequestVersion() != 2 ||
		result.EvidenceVersion() != 1 ||
		result.ProposerPrincipalID() == result.ApproverPrincipalID() {
		t.Fatalf("Apply() result = %+v", result)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() after Commit error = %v", err)
	}

	wantQueries := []string{
		configurePolicyApprovalTransactionSQL,
		setPolicyApprovalScopeSQL,
		authorizePolicyApprovalSQL,
		claimPolicyApprovalIdempotencySQL,
		lockPolicyApprovalRequestSQL,
		lockPolicyApprovalAuditStreamSQL,
		setPolicyApprovalChangeSQL,
		approvePolicyApprovalRequestSQL,
		appendPolicyApprovalEvidenceSQL,
		completePolicyApprovalIdempotencySQL,
	}
	if got := policyApprovalQueries(databaseTransaction.calls); !slices.Equal(got, wantQueries) {
		t.Fatalf("queries = %v, want %v", got, wantQueries)
	}
	if got := databaseTransaction.calls[2].arguments[11]; got != string(authorization.PermissionPolicyApprove) {
		t.Fatalf("authorization permission = %v", got)
	}
	if len(database.readOnly) != 1 || database.readOnly[0] ||
		databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf(
			"readOnly = %v, commitCalls = %d, rollbackCalls = %d",
			database.readOnly,
			databaseTransaction.commitCalls,
			databaseTransaction.rollbackCalls,
		)
	}
}

func TestPolicyApprovalCommittedResolversUseReadOnlyTransactions(t *testing.T) {
	t.Parallel()

	now := policyApprovalTestTime()
	binding := policyApprovalBindingFixture(t)
	proposer := policyApprovalSessionFixture(t, 401, 811)
	approver := policyApprovalSessionFixture(t, 402, 812)
	requestCommand := policyApprovalRequestCommandFixture(t, binding, proposer)
	requestIDs := policyApprovalRequestMutationIDsFixture(t)
	decisionCommand := policyApprovalCommandFixture(t, binding, approver, requestIDs.RequestID())
	decisionIDs := policyApprovalMutationIDsFixture(t)

	requestTransaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(requestTransaction)
	enqueueLoadedPolicyApprovalRequest(requestTransaction, binding, proposer, now)
	decisionTransaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(decisionTransaction)
	enqueueLoadedPolicyApprovalEvidence(
		decisionTransaction,
		binding,
		requestIDs.RequestID(),
		proposer,
		approver,
		now.Add(time.Minute),
		now.Add(approval.RequestLifetime),
	)
	database := &fakePolicyApprovalDatabase{
		transactions: []*fakePolicyApprovalTransaction{requestTransaction, decisionTransaction},
	}
	store := testPolicyApprovalStore(t, database)

	requestResult, found, err := store.ResolveCommittedApprovalRequest(
		t.Context(), requestCommand, requestIDs,
	)
	if err != nil || !found || !requestResult.IsValid() ||
		requestResult.RequestID() != requestIDs.RequestID() {
		t.Fatalf(
			"ResolveCommittedApprovalRequest() result = %+v, found = %v, error = %v",
			requestResult,
			found,
			err,
		)
	}
	decisionResult, found, err := store.ResolveCommittedPolicyApproval(
		t.Context(), decisionCommand, decisionIDs,
	)
	if err != nil || !found || !decisionResult.IsValid() ||
		decisionResult.EvidenceID() != decisionIDs.EvidenceID() {
		t.Fatalf(
			"ResolveCommittedPolicyApproval() result = %+v, found = %v, error = %v",
			decisionResult,
			found,
			err,
		)
	}
	if !slices.Equal(database.readOnly, []bool{true, true}) ||
		requestTransaction.commitCalls != 1 || decisionTransaction.commitCalls != 1 {
		t.Fatalf(
			"readOnly = %v, request commits = %d, decision commits = %d",
			database.readOnly,
			requestTransaction.commitCalls,
			decisionTransaction.commitCalls,
		)
	}
}

func TestPolicyApprovalTransactionsResolveCompletedIdempotencyEvidence(t *testing.T) {
	t.Parallel()

	now := policyApprovalTestTime()
	idempotencyExpiresAt := now.Add(time.Hour)
	binding := policyApprovalBindingFixture(t)
	proposer := policyApprovalSessionFixture(t, 401, 811)
	approver := policyApprovalSessionFixture(t, 402, 812)
	requestCommand := policyApprovalRequestCommandFixture(t, binding, proposer)
	requestIDs := policyApprovalRequestMutationIDsFixture(t)
	decisionCommand := policyApprovalCommandFixture(t, binding, approver, requestIDs.RequestID())
	decisionIDs := policyApprovalMutationIDsFixture(t)
	requestHash, err := requestCommand.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	decisionHash, err := decisionCommand.DecisionHash()
	if err != nil {
		t.Fatal(err)
	}

	requestTransaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(requestTransaction)
	enqueuePolicyApprovalAuthorization(requestTransaction)
	enqueuePolicyApprovalRevision(requestTransaction, binding.BaselineVector())
	enqueuePolicyApprovalCompletedClaim(
		requestTransaction,
		requestIDs.IdempotencyRecordID(),
		requestHash.Bytes(),
		policyApprovalRequestResultKind,
		requestIDs.RequestID().String(),
		1,
		binding.BaselineVector().NetworkRevision(),
		idempotencyExpiresAt,
	)
	enqueueLoadedPolicyApprovalRequest(requestTransaction, binding, proposer, now)

	decisionTransaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(decisionTransaction)
	enqueuePolicyApprovalAuthorization(decisionTransaction)
	enqueuePolicyApprovalCompletedClaim(
		decisionTransaction,
		decisionIDs.IdempotencyRecordID(),
		decisionHash.Bytes(),
		policyApprovalDecisionResultKind,
		decisionIDs.EvidenceID().String(),
		1,
		binding.BaselineVector().NetworkRevision(),
		idempotencyExpiresAt,
	)
	enqueueLoadedPolicyApprovalEvidence(
		decisionTransaction,
		binding,
		requestIDs.RequestID(),
		proposer,
		approver,
		now.Add(time.Minute),
		now.Add(approval.RequestLifetime),
	)
	database := &fakePolicyApprovalDatabase{
		transactions: []*fakePolicyApprovalTransaction{requestTransaction, decisionTransaction},
	}
	store := testPolicyApprovalStore(t, database)

	request, err := store.BeginApprovalRequest(t.Context(), binding.Scope())
	if err != nil {
		t.Fatalf("BeginApprovalRequest() error = %v", err)
	}
	requestResolution, err := request.Resolve(
		t.Context(), requestCommand, requestIDs, now, idempotencyExpiresAt,
	)
	if err != nil || !requestResolution.IsCompleted() ||
		requestResolution.CompletedResult().RequestID() != requestIDs.RequestID() {
		t.Fatalf("request Resolve() resolution = %+v, error = %v", requestResolution, err)
	}
	if err := request.Rollback(t.Context()); err != nil {
		t.Fatalf("request Rollback() error = %v", err)
	}

	decision, err := store.BeginPolicyApproval(t.Context(), binding.Scope())
	if err != nil {
		t.Fatalf("BeginPolicyApproval() error = %v", err)
	}
	decisionResolution, err := decision.Resolve(
		t.Context(), decisionCommand, decisionIDs, now, idempotencyExpiresAt,
	)
	if err != nil || !decisionResolution.IsCompleted() ||
		decisionResolution.CompletedResult().EvidenceID() != decisionIDs.EvidenceID() {
		t.Fatalf("decision Resolve() resolution = %+v, error = %v", decisionResolution, err)
	}
	if err := decision.Rollback(t.Context()); err != nil {
		t.Fatalf("decision Rollback() error = %v", err)
	}
	if requestTransaction.rollbackCalls != 1 || decisionTransaction.rollbackCalls != 1 {
		t.Fatalf(
			"rollback calls request=%d decision=%d, want 1/1",
			requestTransaction.rollbackCalls,
			decisionTransaction.rollbackCalls,
		)
	}
}

func TestClassifyPolicyApprovalDatabaseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code string
		want error
	}{
		{name: "impact changed", code: "MT006", want: approval.ErrImpactChanged},
		{name: "request version", code: "MT002", want: approval.ErrRequestVersionConflict},
		{name: "request state", code: "MT003", want: approval.ErrRequestStateConflict},
		{name: "request expired", code: "MT008", want: approval.ErrRequestExpired},
		{name: "candidate changed", code: "MT009", want: approval.ErrCandidateChanged},
		{name: "independent approver", code: "MT010", want: approval.ErrIndependentApproverRequired},
		{name: "forbidden", code: "42501", want: approval.ErrForbidden},
		{name: "serialization", code: "40001", want: approval.ErrRetryableTransaction},
		{name: "deadlock", code: "40P01", want: approval.ErrRetryableTransaction},
		{name: "lock unavailable", code: "55P03", want: approval.ErrRetryableTransaction},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := classifyPolicyApprovalDatabaseError(
				t.Context(),
				&pgconn.PgError{Code: test.code},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("classifyPolicyApprovalDatabaseError() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPolicyApprovalUnknownCommitRollbackIsIdempotent(t *testing.T) {
	t.Parallel()

	databaseTransaction := newFakePolicyApprovalTransaction()
	databaseTransaction.commitErr = errors.New("lost commit acknowledgement")
	transaction := &policyApprovalTransactionCore{
		database: databaseTransaction,
		state:    policyApprovalTransactionApplied,
	}
	if err := transaction.commit(
		t.Context(),
		postgresOperationPolicyApprovalRequestCommit,
	); !errors.Is(err, approval.ErrCommitOutcomeUnknown) {
		t.Fatalf("commit() error = %v, want ErrCommitOutcomeUnknown", err)
	}
	if err := transaction.rollback(
		t.Context(),
		postgresOperationPolicyApprovalRequestRollback,
	); err != nil {
		t.Fatalf("rollback() after unknown Commit error = %v", err)
	}
	if databaseTransaction.rollbackCalls != 0 {
		t.Fatalf("database rollback calls = %d, want 0", databaseTransaction.rollbackCalls)
	}
}

func policyApprovalQueries(calls []policyApprovalTestCall) []string {
	queries := make([]string, 0, len(calls))
	for _, call := range calls {
		queries = append(queries, call.query)
	}
	return queries
}
