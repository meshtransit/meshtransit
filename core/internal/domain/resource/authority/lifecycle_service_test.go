package authority

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
)

func TestLifecycleServiceCommitsResourceSuspension(t *testing.T) {
	command := lifecycleCommandFixture(t, LifecycleSuspendResource)
	ids := lifecycleMutationIDsFixture(t)
	resolution := lifecycleResolutionFixture(t, command, ids, 7, 3, 2)
	transaction := &fakeLifecycleTransaction{resolution: resolution}
	transactions := &fakeLifecycleTransactions{transactions: []*fakeLifecycleTransaction{transaction}}
	service := lifecycleServiceFixture(t, transactions, ids)

	result, err := service.Transition(t.Context(), command)
	if err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	if result.ResourceID() != command.ResourceID() || result.State() != resource.StateSuspended ||
		result.Version() != 2 || result.NetworkRevision() != 8 ||
		result.SubsystemRevision() != 4 || transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("Transition() result = %+v transaction = %+v", result, transaction)
	}
}

func TestLifecycleServiceRetriesWithStableEvidence(t *testing.T) {
	command := lifecycleCommandFixture(t, LifecycleDeleteGroup)
	ids := lifecycleMutationIDsFixture(t)
	resolution := lifecycleResolutionFixture(t, command, ids, 7, 3, 2)
	first := &fakeLifecycleTransaction{
		resolution: resolution,
		applyErr:   errors.Join(ErrRetryableTransaction, errors.New("deadlock")),
	}
	second := &fakeLifecycleTransaction{resolution: resolution}
	transactions := &fakeLifecycleTransactions{
		transactions: []*fakeLifecycleTransaction{first, second},
	}
	service := lifecycleServiceFixture(t, transactions, ids)

	result, err := service.Transition(t.Context(), command)
	if err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	if result.GroupID() != command.GroupID() || result.State() != resource.StateDeleted ||
		first.rollbacks != 1 || second.commits != 1 ||
		first.changes[0].MutationIDs().ChangeID() != second.changes[0].MutationIDs().ChangeID() ||
		!first.changes[0].OccurredAt().Equal(second.changes[0].OccurredAt()) {
		t.Fatalf("retry result=%+v first=%+v second=%+v", result, first, second)
	}
}

func TestLifecycleServiceReturnsCompletedReplayWithoutMutation(t *testing.T) {
	command := lifecycleCommandFixture(t, LifecycleResumeResource)
	ids := lifecycleMutationIDsFixture(t)
	committed := lifecycleResultFixture(t, command, 8, 4)
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := NewCompletedLifecycleResolution(
		committed, ids.IdempotencyRecordID(), requestHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	transaction := &fakeLifecycleTransaction{resolution: resolution}
	service := lifecycleServiceFixture(
		t,
		&fakeLifecycleTransactions{transactions: []*fakeLifecycleTransaction{transaction}},
		ids,
	)

	result, err := service.Transition(t.Context(), command)
	if err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	if result != committed || transaction.applies != 0 || transaction.commits != 0 ||
		transaction.rollbacks != 1 {
		t.Fatalf("replay result=%+v transaction=%+v", result, transaction)
	}
}

func TestLifecycleCommandHashBindsOperationAndVersion(t *testing.T) {
	suspend := lifecycleCommandFixture(t, LifecycleSuspendResource)
	resume, err := NewResourceLifecycleCommand(
		LifecycleResumeResource, suspend.Scope(), suspend.ResourceID(), suspend.ExpectedVersion(),
		suspend.AccountSession(), suspend.AuditReason(), suspend.IdempotencyEvidence(),
	)
	if err != nil {
		t.Fatal(err)
	}
	nextVersion, err := NewResourceLifecycleCommand(
		LifecycleSuspendResource, suspend.Scope(), suspend.ResourceID(), suspend.ExpectedVersion()+1,
		suspend.AccountSession(), suspend.AuditReason(), suspend.IdempotencyEvidence(),
	)
	if err != nil {
		t.Fatal(err)
	}
	suspendHash, _ := suspend.RequestHash()
	resumeHash, _ := resume.RequestHash()
	nextVersionHash, _ := nextVersion.RequestHash()
	if suspendHash == resumeHash || suspendHash == nextVersionHash {
		t.Fatal("lifecycle request hash did not bind operation and version")
	}
}

type fakeLifecycleTransactions struct {
	transactions []*fakeLifecycleTransaction
	begins       int
	committed    LifecycleResult
	found        bool
	resolveErr   error
}

func (transactions *fakeLifecycleTransactions) BeginLifecycle(
	context.Context,
	network.Scope,
) (LifecycleTransaction, error) {
	if transactions.begins >= len(transactions.transactions) {
		return nil, errors.New("unexpected begin")
	}
	transaction := transactions.transactions[transactions.begins]
	transactions.begins++
	return transaction, nil
}

func (transactions *fakeLifecycleTransactions) ResolveCommittedLifecycle(
	context.Context,
	LifecycleCommand,
	LifecycleMutationIDs,
) (LifecycleResult, bool, error) {
	return transactions.committed, transactions.found, transactions.resolveErr
}

type fakeLifecycleTransaction struct {
	resolution LifecycleResolution
	applyErr   error
	commitErr  error
	changes    []LifecycleChange
	applies    int
	commits    int
	rollbacks  int
}

func (*fakeLifecycleTransaction) DecisionTime() time.Time { return authorityDecisionTime }

func (transaction *fakeLifecycleTransaction) Resolve(
	context.Context,
	LifecycleCommand,
	LifecycleMutationIDs,
	time.Time,
	time.Time,
) (LifecycleResolution, error) {
	return transaction.resolution, nil
}

func (transaction *fakeLifecycleTransaction) Apply(
	_ context.Context,
	change LifecycleChange,
) (LifecycleResult, error) {
	transaction.applies++
	transaction.changes = append(transaction.changes, change)
	if transaction.applyErr != nil {
		return LifecycleResult{}, transaction.applyErr
	}
	command := change.Command()
	subsystemRevision := change.Resolution().InventoryRevision() + 1
	if command.Operation().IsGroup() {
		subsystemRevision = change.Resolution().GroupRevision() + 1
	}
	return NewLifecycleResult(
		command.Operation(), command.ResourceID(), command.GroupID(), command.Scope(),
		command.Operation().TargetState(), command.ExpectedVersion()+1,
		change.Resolution().NetworkRevision()+1, subsystemRevision,
		resource.SemanticHash([32]byte{31: 1}),
	)
}

func (transaction *fakeLifecycleTransaction) Commit(context.Context) error {
	transaction.commits++
	return transaction.commitErr
}

func (transaction *fakeLifecycleTransaction) Rollback(context.Context) error {
	transaction.rollbacks++
	return nil
}

type fixedLifecycleMutationIDs struct{ ids LifecycleMutationIDs }

func (generator fixedLifecycleMutationIDs) NewLifecycleMutationIDs(
	LifecycleCommand,
) (LifecycleMutationIDs, error) {
	return generator.ids, nil
}

func lifecycleServiceFixture(
	t *testing.T,
	transactions *fakeLifecycleTransactions,
	ids LifecycleMutationIDs,
) *LifecycleService {
	t.Helper()
	service, err := NewLifecycleService(
		Options{MaxAttempts: 3, RollbackTimeout: time.Second, IdempotencyWindow: time.Hour},
		LifecycleDependencies{
			Transactions: transactions, CommittedResults: transactions,
			MutationIDs: fixedLifecycleMutationIDs{ids: ids},
			Retry:       noAuthorityRetryDelay{},
		},
	)
	if err != nil {
		t.Fatalf("NewLifecycleService() error = %v", err)
	}
	return service
}

func lifecycleCommandFixture(t *testing.T, operation LifecycleOperation) LifecycleCommand {
	t.Helper()
	scope := authorityScopeFixture(t)
	session := authoritySessionFixture(t, authorityPrincipalID(t, 11))
	reason, err := NewAuditReason("qualification lifecycle transition")
	if err != nil {
		t.Fatal(err)
	}
	if operation.IsGroup() {
		id, err := resource.ParseGroupID(authorityPublicID(502))
		if err != nil {
			t.Fatal(err)
		}
		command, err := NewGroupLifecycleCommand(
			operation, scope, id, 1, session, reason, authorityIdempotencyProofFixture(t),
		)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	id, err := resource.ParseID(authorityPublicID(501))
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewResourceLifecycleCommand(
		operation, scope, id, 1, session, reason, authorityIdempotencyProofFixture(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func lifecycleMutationIDsFixture(t *testing.T) LifecycleMutationIDs {
	t.Helper()
	ids, err := NewLifecycleMutationIDs(
		authorityPublicIDValue(t, 921), authorityPublicIDValue(t, 922),
		authorityPublicIDValue(t, 923), authorityPublicIDValue(t, 924),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func lifecycleResolutionFixture(
	t *testing.T,
	command LifecycleCommand,
	ids LifecycleMutationIDs,
	networkRevision, inventoryRevision, groupRevision int64,
) LifecycleResolution {
	t.Helper()
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := NewLifecycleResolution(
		command.Scope(), networkRevision, inventoryRevision, groupRevision,
		ids.IdempotencyRecordID(), hash,
	)
	if err != nil {
		t.Fatal(err)
	}
	return resolution
}

func lifecycleResultFixture(
	t *testing.T,
	command LifecycleCommand,
	networkRevision, subsystemRevision int64,
) LifecycleResult {
	t.Helper()
	result, err := NewLifecycleResult(
		command.Operation(), command.ResourceID(), command.GroupID(), command.Scope(),
		command.Operation().TargetState(), command.ExpectedVersion()+1,
		networkRevision, subsystemRevision, authorityDeviceDefinitionFixture(t).SemanticHash(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
