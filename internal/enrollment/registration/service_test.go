package registration_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	registration "github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/node"
)

var errControlled = errors.New("controlled failure")

func TestServiceRegisterCreatesNodeAtomically(t *testing.T) {
	t.Parallel()

	command := mustCommand(t)
	nodeID := mustNodeID(t, "01890f20-0000-7000-8000-000000000006")
	transaction := &fakeTransaction{resolution: mustOpenResolution(t, command, node.ID{})}
	transaction.apply = func(change registration.Change) (registration.Result, error) {
		return resultFromChange(t, change), nil
	}
	queue := &transactionQueue{transactions: []*fakeTransaction{transaction}}
	ids := &fixedNodeIDs{nodeID: nodeID}
	retry := &recordedRetry{}

	result, err := mustService(t, queue, ids, retry).Register(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Register() error = %v", err)
	}
	if !result.IsValid() || result.NodeID() != nodeID ||
		result.Disposition() != registration.DispositionCreated || result.NetworkRevision() != 9 {
		t.Fatalf("Service.Register() result = %+v, want created Node", result)
	}
	if ids.calls != 1 || len(retry.calls) != 0 || len(queue.beginScopes) != 1 ||
		queue.beginScopes[0] != command.Scope {
		t.Fatalf("dependency calls: ids=%d retry=%v begin=%d", ids.calls, retry.calls, len(queue.beginScopes))
	}
	if !slices.Equal(transaction.calls, []string{"resolve", "apply", "commit"}) {
		t.Fatalf("transaction calls = %v, want resolve/apply/commit", transaction.calls)
	}
	if len(transaction.changes) != 1 {
		t.Fatalf("len(transaction changes) = %d, want 1", len(transaction.changes))
	}
	change := transaction.changes[0]
	completedNodeID, completed := change.Registration().NodeID()
	if !change.IsValid() || change.Credential().UsedCount() != 1 || !completed ||
		completedNodeID != nodeID || change.OccurredAt() != fixtureTime ||
		change.Identity() != command.Identity || change.Hostname() != command.Hostname {
		t.Fatal("registration change did not preserve the atomic domain decision")
	}
}

func TestServiceRegisterResumesExistingNode(t *testing.T) {
	t.Parallel()

	command := mustCommand(t)
	existingNode := mustNodeID(t, "01890f20-0000-7000-8000-000000000007")
	transaction := &fakeTransaction{resolution: mustOpenResolution(t, command, existingNode)}
	transaction.apply = func(change registration.Change) (registration.Result, error) {
		return resultFromChange(t, change), nil
	}
	queue := &transactionQueue{transactions: []*fakeTransaction{transaction}}
	ids := &fixedNodeIDs{nodeID: mustNodeID(t, "01890f20-0000-7000-8000-000000000008")}

	result, err := mustService(t, queue, ids, &recordedRetry{}).Register(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Register() error = %v", err)
	}
	if result.NodeID() != existingNode || result.Disposition() != registration.DispositionResumed {
		t.Fatalf("Service.Register() = (%q, %v), want resumed existing Node", result.NodeID(), result.Disposition())
	}
	if ids.calls != 0 {
		t.Fatalf("Node ID generator calls = %d, want 0 on resume", ids.calls)
	}
}

func TestServiceRegisterReplaysCompletedIntentWithoutCommit(t *testing.T) {
	t.Parallel()

	command := mustCommand(t)
	nodeID := mustNodeID(t, "01890f20-0000-7000-8000-000000000009")
	result, err := registration.NewResult(
		command.RegistrationID,
		command.Scope,
		nodeID,
		command.Hostname,
		registration.DispositionCreated,
		11,
	)
	if err != nil {
		t.Fatalf("registration.NewResult() error = %v", err)
	}
	transaction := &fakeTransaction{resolution: mustCompletedResolution(t, command, result)}
	queue := &transactionQueue{transactions: []*fakeTransaction{transaction}}
	ids := &fixedNodeIDs{nodeID: nodeID}

	got, err := mustService(t, queue, ids, &recordedRetry{}).Register(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Register() error = %v", err)
	}
	if got != result {
		t.Fatalf("Service.Register() = %+v, want committed replay %+v", got, result)
	}
	if !slices.Equal(transaction.calls, []string{"resolve", "rollback"}) || ids.calls != 0 {
		t.Fatalf("replay calls = %v, id calls = %d; want resolve/rollback and no generation", transaction.calls, ids.calls)
	}
}

func TestServiceRegisterRejectsReusedIntentWithDifferentNodeKey(t *testing.T) {
	t.Parallel()

	original := mustCommand(t)
	nodeID := mustNodeID(t, "01890f20-0000-7000-8000-000000000013")
	result, err := registration.NewResult(
		original.RegistrationID,
		original.Scope,
		nodeID,
		original.Hostname,
		registration.DispositionCreated,
		11,
	)
	if err != nil {
		t.Fatalf("registration.NewResult() error = %v", err)
	}
	transaction := &fakeTransaction{resolution: mustCompletedResolution(t, original, result)}
	queue := &transactionQueue{transactions: []*fakeTransaction{transaction}}
	changed := original
	differentNodeKey, err := node.NewKey(filled32(0x33))
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	changed.Identity, err = node.NewRegistrationIdentity(original.Identity.MachineKey(), differentNodeKey)
	if err != nil {
		t.Fatalf("node.NewRegistrationIdentity() error = %v", err)
	}

	_, err = mustService(
		t,
		queue,
		&fixedNodeIDs{nodeID: nodeID},
		&recordedRetry{},
	).Register(t.Context(), changed)
	if !errors.Is(err, registration.ErrRegistrationFailed) ||
		!errors.Is(err, registration.ErrIntentConflict) {
		t.Fatalf("Service.Register(reused intent) error = %v, want ErrIntentConflict", err)
	}
	if !slices.Equal(transaction.calls, []string{"resolve", "rollback"}) {
		t.Fatalf("reused intent transaction calls = %v, want resolve/rollback", transaction.calls)
	}
}

func TestServiceRegisterRetriesWholeTransactionWithStableDecision(t *testing.T) {
	t.Parallel()

	command := mustCommand(t)
	nodeID := mustNodeID(t, "01890f20-0000-7000-8000-000000000010")
	first := &fakeTransaction{resolution: mustOpenResolution(t, command, node.ID{})}
	first.apply = func(registration.Change) (registration.Result, error) {
		return registration.Result{}, errors.Join(registration.ErrRetryableTransaction, errControlled)
	}
	second := &fakeTransaction{resolution: mustOpenResolution(t, command, node.ID{})}
	second.apply = func(change registration.Change) (registration.Result, error) {
		return resultFromChange(t, change), nil
	}
	queue := &transactionQueue{transactions: []*fakeTransaction{first, second}}
	ids := &fixedNodeIDs{nodeID: nodeID}
	retry := &recordedRetry{}

	result, err := mustService(t, queue, ids, retry).Register(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Register() error = %v", err)
	}
	if result.NodeID() != nodeID || ids.calls != 1 || !slices.Equal(retry.calls, []int{1}) {
		t.Fatalf("retry outcome: Node=%q id calls=%d retry=%v", result.NodeID(), ids.calls, retry.calls)
	}
	if !slices.Equal(first.calls, []string{"resolve", "apply", "rollback"}) ||
		!slices.Equal(second.calls, []string{"resolve", "apply", "commit"}) {
		t.Fatalf("transaction attempts = %v then %v", first.calls, second.calls)
	}
	if len(first.changes) != 1 || len(second.changes) != 1 ||
		first.changes[0].NodeID() != second.changes[0].NodeID() ||
		first.changes[0].OccurredAt() != second.changes[0].OccurredAt() {
		t.Fatal("whole-transaction retry changed idempotent Node ID or decision time")
	}
}

func TestServiceRegisterResolvesUnknownCommitOutcome(t *testing.T) {
	t.Parallel()

	command := mustCommand(t)
	nodeID := mustNodeID(t, "01890f20-0000-7000-8000-000000000011")
	transaction := &fakeTransaction{resolution: mustOpenResolution(t, command, node.ID{})}
	transaction.apply = func(change registration.Change) (registration.Result, error) {
		return resultFromChange(t, change), nil
	}
	transaction.commitErr = errors.Join(registration.ErrCommitOutcomeUnknown, errControlled)
	committed := resultFromChange(t, mustChange(t, command, nodeID, registration.DispositionCreated))
	queue := &transactionQueue{
		transactions:    []*fakeTransaction{transaction},
		committedResult: committed,
		committedFound:  true,
	}
	ids := &fixedNodeIDs{nodeID: nodeID}
	retry := &recordedRetry{}

	result, err := mustService(t, queue, ids, retry).Register(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Register() error = %v", err)
	}
	if result != committed || queue.resolveCalls != 1 || len(retry.calls) != 0 ||
		!slices.Equal(transaction.calls, []string{"resolve", "apply", "commit", "rollback"}) {
		t.Fatalf(
			"unknown commit resolution: result=%+v resolve=%d retry=%v calls=%v",
			result,
			queue.resolveCalls,
			retry.calls,
			transaction.calls,
		)
	}
}

func TestServiceRegisterFailsClosed(t *testing.T) {
	t.Parallel()

	command := mustCommand(t)
	tests := []struct {
		name        string
		configure   func(*fakeTransaction, *recordedRetry)
		wantError   error
		wantRetries int
	}{
		{
			name: "non-retryable resolve failure",
			configure: func(transaction *fakeTransaction, _ *recordedRetry) {
				transaction.resolveErr = errControlled
			},
			wantError: errControlled,
		},
		{
			name: "rollback failure suppresses unsafe retry",
			configure: func(transaction *fakeTransaction, _ *recordedRetry) {
				transaction.resolveErr = errors.Join(registration.ErrRetryableTransaction, errControlled)
				transaction.rollbackErr = errControlled
			},
			wantError: registration.ErrRollbackFailed,
		},
		{
			name: "canceled backoff",
			configure: func(transaction *fakeTransaction, retry *recordedRetry) {
				transaction.resolveErr = errors.Join(registration.ErrRetryableTransaction, errControlled)
				retry.err = context.Canceled
			},
			wantError:   context.Canceled,
			wantRetries: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			transaction := &fakeTransaction{resolution: mustOpenResolution(t, command, node.ID{})}
			retry := &recordedRetry{}
			test.configure(transaction, retry)
			queue := &transactionQueue{transactions: []*fakeTransaction{transaction}}
			_, err := mustService(
				t,
				queue,
				&fixedNodeIDs{nodeID: mustNodeID(t, "01890f20-0000-7000-8000-000000000012")},
				retry,
			).Register(t.Context(), command)
			if !errors.Is(err, registration.ErrRegistrationFailed) || !errors.Is(err, test.wantError) {
				t.Fatalf("Service.Register() error = %v, want classified %v", err, test.wantError)
			}
			if len(retry.calls) != test.wantRetries {
				t.Fatalf("retry calls = %v, want %d", retry.calls, test.wantRetries)
			}
		})
	}
}

func TestNewServiceAndCommandValidation(t *testing.T) {
	t.Parallel()

	validOptions := registration.Options{MaxAttempts: 1, RollbackTimeout: time.Second}
	command := mustCommand(t)
	queue := &transactionQueue{}
	ids := &fixedNodeIDs{}
	retry := &recordedRetry{}
	clock := fixedClock{now: fixtureTime}

	tests := []struct {
		name    string
		options registration.Options
		queue   registration.Transactions
		ids     registration.NodeIDGenerator
		clock   registration.Clock
		retry   registration.RetryWaiter
	}{
		{name: "missing transactions", options: validOptions, ids: ids, clock: clock, retry: retry},
		{name: "missing ids", options: validOptions, queue: queue, clock: clock, retry: retry},
		{name: "missing clock", options: validOptions, queue: queue, ids: ids, retry: retry},
		{name: "missing retry", options: validOptions, queue: queue, ids: ids, clock: clock},
		{name: "zero attempts", options: registration.Options{RollbackTimeout: time.Second}, queue: queue, ids: ids, clock: clock, retry: retry},
		{name: "too many attempts", options: registration.Options{MaxAttempts: 6, RollbackTimeout: time.Second}, queue: queue, ids: ids, clock: clock, retry: retry},
		{name: "unbounded rollback", options: registration.Options{MaxAttempts: 1, RollbackTimeout: time.Minute}, queue: queue, ids: ids, clock: clock, retry: retry},
	}
	for _, test := range tests {
		if _, err := registration.NewService(test.options, test.queue, test.ids, test.clock, test.retry); !errors.Is(err, registration.ErrInvalidService) {
			t.Fatalf("NewService(%s) error = %v, want ErrInvalidService", test.name, err)
		}
	}

	service, err := registration.NewService(validOptions, queue, ids, clock, retry)
	if err != nil {
		t.Fatalf("registration.NewService(valid) error = %v", err)
	}
	command.RecoveryEpoch = 0
	if _, err := service.Register(t.Context(), command); !errors.Is(err, registration.ErrInvalidCommand) {
		t.Fatalf("Service.Register(invalid) error = %v, want ErrInvalidCommand", err)
	}
}

func mustChange(
	t *testing.T,
	command registration.Command,
	nodeID node.ID,
	disposition registration.Disposition,
) registration.Change {
	t.Helper()

	resolution := mustOpenResolution(t, command, node.ID{})
	credential, err := resolution.Credential().Consume(fixtureTime, command.RecoveryEpoch)
	if err != nil {
		t.Fatalf("Credential.Consume() error = %v", err)
	}
	state, err := resolution.Registration().Authorize(fixtureTime)
	if err != nil {
		t.Fatalf("Registration.Authorize() error = %v", err)
	}
	state, err = state.Complete(nodeID, fixtureTime)
	if err != nil {
		t.Fatalf("Registration.Complete() error = %v", err)
	}
	change, err := registration.NewChange(
		state,
		credential,
		command.Identity,
		nodeID,
		command.Hostname,
		disposition,
		fixtureTime,
	)
	if err != nil {
		t.Fatalf("registration.NewChange() error = %v", err)
	}
	return change
}
