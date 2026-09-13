package registration_test

import (
	"context"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	registration "github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

var fixtureTime = time.Date(2026, time.September, 13, 10, 0, 0, 0, time.UTC)

type transactionQueue struct {
	transactions    []*fakeTransaction
	next            int
	beginScopes     []network.Scope
	committedResult registration.Result
	committedFound  bool
	committedErr    error
	resolveCalls    int
}

func (queue *transactionQueue) Begin(
	_ context.Context,
	scope network.Scope,
) (registration.Transaction, error) {
	queue.beginScopes = append(queue.beginScopes, scope)
	if queue.next >= len(queue.transactions) {
		return nil, errControlled
	}
	transaction := queue.transactions[queue.next]
	queue.next++
	if transaction.beginErr != nil {
		return nil, transaction.beginErr
	}
	return transaction, nil
}

func (queue *transactionQueue) ResolveCommitted(
	context.Context,
	registration.Command,
) (registration.Result, bool, error) {
	queue.resolveCalls++
	return queue.committedResult, queue.committedFound, queue.committedErr
}

type fakeTransaction struct {
	beginErr    error
	resolution  registration.Resolution
	resolveErr  error
	apply       func(registration.Change) (registration.Result, error)
	commitErr   error
	rollbackErr error
	calls       []string
	changes     []registration.Change
}

func (transaction *fakeTransaction) Resolve(
	context.Context,
	registration.Command,
) (registration.Resolution, error) {
	transaction.calls = append(transaction.calls, "resolve")
	return transaction.resolution, transaction.resolveErr
}

func (transaction *fakeTransaction) Apply(
	_ context.Context,
	change registration.Change,
) (registration.Result, error) {
	transaction.calls = append(transaction.calls, "apply")
	transaction.changes = append(transaction.changes, change)
	if transaction.apply == nil {
		return registration.Result{}, errControlled
	}
	return transaction.apply(change)
}

func (transaction *fakeTransaction) Commit(context.Context) error {
	transaction.calls = append(transaction.calls, "commit")
	return transaction.commitErr
}

func (transaction *fakeTransaction) Rollback(context.Context) error {
	transaction.calls = append(transaction.calls, "rollback")
	return transaction.rollbackErr
}

type fixedNodeIDs struct {
	nodeID node.ID
	err    error
	calls  int
}

func (ids *fixedNodeIDs) NewNodeID() (node.ID, error) {
	ids.calls++
	return ids.nodeID, ids.err
}

type fixedClock struct {
	now time.Time
}

func (clock fixedClock) Now() time.Time { return clock.now }

type recordedRetry struct {
	calls []int
	err   error
}

func (retry *recordedRetry) Wait(_ context.Context, attempt int) error {
	retry.calls = append(retry.calls, attempt)
	return retry.err
}

func mustService(
	t *testing.T,
	queue *transactionQueue,
	ids *fixedNodeIDs,
	retry *recordedRetry,
) *registration.Service {
	t.Helper()

	service, err := registration.NewService(
		registration.Options{MaxAttempts: 3, RollbackTimeout: time.Second},
		queue,
		ids,
		fixedClock{now: fixtureTime},
		retry,
	)
	if err != nil {
		t.Fatalf("registration.NewService() error = %v", err)
	}
	return service
}

func mustCommand(t *testing.T) registration.Command {
	t.Helper()

	machineKey, err := node.NewMachineKey(filled32(0x21))
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey(filled32(0x22))
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatalf("node.NewRegistrationIdentity() error = %v", err)
	}
	hostname, err := node.ParseHostname("Node-One.Example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	return registration.Command{
		RegistrationID: mustRegistrationID(t, "01890f20-0000-7000-8000-000000000001"),
		Scope:          mustScope(t),
		CredentialID:   mustCredentialID(t, "01890f20-0000-7000-8000-000000000002"),
		Identity:       identity,
		Hostname:       hostname,
		RecoveryEpoch:  7,
	}
}

func mustOpenResolution(
	t *testing.T,
	command registration.Command,
	existingNode node.ID,
) registration.Resolution {
	t.Helper()

	pending := mustRegistration(t, command, enrollment.RegistrationStatePending, node.ID{})
	limit, err := enrollment.NewBoundedUseLimit(2)
	if err != nil {
		t.Fatalf("enrollment.NewBoundedUseLimit() error = %v", err)
	}
	credential, err := enrollment.NewCredential(enrollment.CredentialParams{
		ID:                  command.CredentialID,
		ProfileID:           pending.ProfileID(),
		State:               enrollment.CredentialStateActive,
		UseLimit:            limit,
		UsedCount:           0,
		IssuedRecoveryEpoch: command.RecoveryEpoch,
		ValidFrom:           fixtureTime.Add(-time.Hour),
		ExpiresAt:           fixtureTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("enrollment.NewCredential() error = %v", err)
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	resolution, err := registration.NewOpenResolution(pending, credential, existingNode, requestHash)
	if err != nil {
		t.Fatalf("registration.NewOpenResolution() error = %v", err)
	}
	return resolution
}

func mustCompletedResolution(
	t *testing.T,
	command registration.Command,
	result registration.Result,
) registration.Resolution {
	t.Helper()

	completed := mustRegistration(t, command, enrollment.RegistrationStateCompleted, result.NodeID())
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	resolution, err := registration.NewCompletedResolution(
		completed,
		command.CredentialID,
		command.Identity,
		requestHash,
		result,
	)
	if err != nil {
		t.Fatalf("registration.NewCompletedResolution() error = %v", err)
	}
	return resolution
}

func mustRegistration(
	t *testing.T,
	command registration.Command,
	state enrollment.RegistrationState,
	nodeID node.ID,
) enrollment.Registration {
	t.Helper()

	profileID, err := enrollment.ParseProfileID("01890f20-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatalf("enrollment.ParseProfileID() error = %v", err)
	}
	value, err := enrollment.NewRegistration(enrollment.RegistrationParams{
		ID:                 command.RegistrationID,
		Scope:              command.Scope,
		ProfileID:          profileID,
		MachineFingerprint: command.Identity.MachineKey().Fingerprint(),
		State:              state,
		NodeID:             nodeID,
		CreatedAt:          fixtureTime.Add(-time.Minute),
		ExpiresAt:          fixtureTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("enrollment.NewRegistration() error = %v", err)
	}
	return value
}

func resultFromChange(t *testing.T, change registration.Change) registration.Result {
	t.Helper()

	result, err := registration.NewResult(
		change.Registration().ID(),
		change.Registration().Scope(),
		change.NodeID(),
		change.Hostname(),
		change.Disposition(),
		9,
	)
	if err != nil {
		t.Fatalf("registration.NewResult() error = %v", err)
	}
	return result
}

func mustScope(t *testing.T) network.Scope {
	t.Helper()

	workspaceID, err := workspace.ParseID("01890f20-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f20-0000-7000-8000-000000000005")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func mustNodeID(t *testing.T, value string) node.ID {
	t.Helper()

	id, err := node.ParseID(value)
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	return id
}

func mustRegistrationID(t *testing.T, value string) enrollment.RegistrationID {
	t.Helper()

	id, err := enrollment.ParseRegistrationID(value)
	if err != nil {
		t.Fatalf("enrollment.ParseRegistrationID() error = %v", err)
	}
	return id
}

func mustCredentialID(t *testing.T, value string) enrollment.CredentialID {
	t.Helper()

	id, err := enrollment.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("enrollment.ParseCredentialID() error = %v", err)
	}
	return id
}

func filled32(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}
